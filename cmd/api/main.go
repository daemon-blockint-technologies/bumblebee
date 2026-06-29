// Command api is an HTTP wrapper around the bumblebee scanner.
//
// It exposes a REST API to trigger on-demand and async scans, manage
// scheduled scans, and return NDJSON results. Designed for deployment
// on Railway (or any container platform) with health checks, bearer-token
// auth, rate limiting, and streaming output.
//
// Endpoints:
//
//	GET  /health          — liveness probe (200 OK)
//	GET  /openapi.json    — OpenAPI 3.1 specification
//	GET  /catalogs        — list available threat_intel catalogs
//	POST /scan            — trigger a sync scan, stream NDJSON back
//	POST /scan/async      — submit an async scan job, returns job_id
//	GET  /scan/{job_id}   — get async scan job status
//	GET  /scan/{job_id}/results — get async scan NDJSON results
//	GET  /schedules       — list scheduled scans
//	POST /schedules       — create a scheduled scan (cron + webhook)
//	DELETE /schedules?name=N — delete a scheduled scan
//
// Auth: Bearer token via API_TOKEN env var. If unset, auth is disabled
// (development only). In production, always set API_TOKEN.
//
// Rate limiting: RATE_LIMIT_PER_HOUR env var (default 60). Per-client IP.
// Scheduled scans: SCHEDULES env var (JSON array) for bootstrap config.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/perplexityai/bumblebee/internal/endpoint"
	"github.com/perplexityai/bumblebee/internal/exposure"
	"github.com/perplexityai/bumblebee/internal/model"
	"github.com/perplexityai/bumblebee/internal/output"
	"github.com/perplexityai/bumblebee/internal/scanner"
)

var (
	version      = "dev"
	apiToken     = os.Getenv("API_TOKEN")
	catalogDir   = os.Getenv("CATALOG_DIR")
	rateLimitPer = getEnvInt("RATE_LIMIT_PER_HOUR", 60)
	jobs         *jobQueue
	schedMgr     *scheduleManager
)

func main() {
	addr := flag.String("addr", getEnvDefault("ADDR", ":8080"), "listen address")
	flag.Parse()

	jobs = newJobQueue(100)
	schedMgr = newScheduleManager(jobs)
	schedMgr.initFromEnv()
	schedMgr.start()

	rl := newRateLimiter(rateLimitPer, time.Hour)
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			rl.cleanup()
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/openapi.json", openAPIHandler)
	mux.HandleFunc("/catalogs", authMiddleware(rateLimitMiddleware(rl, catalogsHandler)))
	mux.HandleFunc("/scan", authMiddleware(rateLimitMiddleware(rl, scanHandler)))
	mux.HandleFunc("/scan/async", authMiddleware(rateLimitMiddleware(rl, jobs.asyncScanHandler)))
	mux.HandleFunc("/scan/", authMiddleware(rateLimitMiddleware(rl, jobs.scanSubHandler)))
	mux.HandleFunc("/schedules", authMiddleware(rateLimitMiddleware(rl, schedMgr.handleSchedules)))

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      0, // streaming responses
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}()

	fmt.Fprintf(os.Stderr, "bumblebee-api %s listening on %s\n", version, *addr)
	fmt.Fprintf(os.Stderr, "rate limit: %d req/hour per IP\n", rateLimitPer)
	if apiToken == "" {
		fmt.Fprintf(os.Stderr, "WARNING: API_TOKEN not set — auth disabled (development mode)\n")
	}
	if catalogDir != "" {
		fmt.Fprintf(os.Stderr, "catalog directory: %s\n", catalogDir)
	}

	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
	schedMgr.stop()
}

func getEnvDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getEnvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"version": version,
	})
}

func catalogsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	dir := catalogDir
	if dir == "" {
		dir = "threat_intel"
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		http.Error(w, fmt.Sprintf("read catalog dir: %v", err), http.StatusInternalServerError)
		return
	}

	var catalogs []map[string]interface{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".json") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var cat struct {
			SchemaVersion string `json:"schema_version"`
			Entries       []struct {
				ID        string `json:"id"`
				Ecosystem string `json:"ecosystem"`
				Package   string `json:"package"`
				Severity  string `json:"severity"`
			} `json:"entries"`
		}
		if err := json.Unmarshal(data, &cat); err != nil {
			continue
		}
		ecosystems := map[string]int{}
		for _, entry := range cat.Entries {
			ecosystems[entry.Ecosystem]++
		}
		catalogs = append(catalogs, map[string]interface{}{
			"file":       e.Name(),
			"entries":    len(cat.Entries),
			"ecosystems": ecosystems,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"catalogs":  catalogs,
		"directory": dir,
	})
}

type scanRequest struct {
	Profile         string   `json:"profile"`
	Roots           []string `json:"roots"`
	Ecosystems      []string `json:"ecosystems"`
	ExposureCatalog string   `json:"exposure_catalog"`
	FindingsOnly    bool     `json:"findings_only"`
	MaxDuration     string   `json:"max_duration"`
	MaxFileSize     int64    `json:"max_file_size"`
	Concurrency     int      `json:"concurrency"`
}

func scanHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req scanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	profile := req.Profile
	if profile == "" {
		profile = model.ProfileDeep
	}
	if !isValidProfile(profile) {
		http.Error(w, fmt.Sprintf("invalid profile %q (want: baseline, project, deep)", profile), http.StatusBadRequest)
		return
	}

	if profile == model.ProfileDeep && len(req.Roots) == 0 {
		http.Error(w, "profile deep requires at least one root", http.StatusBadRequest)
		return
	}

	var maxDuration time.Duration
	if req.MaxDuration != "" {
		d, err := time.ParseDuration(req.MaxDuration)
		if err != nil {
			http.Error(w, fmt.Sprintf("invalid max_duration: %v", err), http.StatusBadRequest)
			return
		}
		maxDuration = d
	}

	maxFileSize := req.MaxFileSize
	if maxFileSize <= 0 {
		maxFileSize = 5 * 1024 * 1024
	}

	concurrency := req.Concurrency
	if concurrency < 1 {
		concurrency = 4
	}

	var catalog *exposure.Catalog
	catalogPath := req.ExposureCatalog
	if catalogPath == "" && catalogDir != "" {
		catalogPath = catalogDir
	}
	if catalogPath != "" {
		var err error
		catalog, err = exposure.Load(catalogPath, 64*1024*1024)
		if err != nil {
			http.Error(w, fmt.Sprintf("load exposure catalog: %v", err), http.StatusBadRequest)
			return
		}
	}

	if req.FindingsOnly && catalog == nil {
		http.Error(w, "findings_only requires exposure_catalog", http.StatusBadRequest)
		return
	}

	var ecosystemFilter map[string]bool
	if len(req.Ecosystems) > 0 {
		ecosystemFilter = make(map[string]bool)
		for _, e := range req.Ecosystems {
			e = strings.TrimSpace(strings.ToLower(e))
			if !model.IsSupportedEcosystem(e) {
				http.Error(w, fmt.Sprintf("unsupported ecosystem %q (supported: %s)", e, strings.Join(model.SupportedEcosystems(), ", ")), http.StatusBadRequest)
				return
			}
			ecosystemFilter[e] = true
		}
	}

	roots := make([]scanner.Root, 0, len(req.Roots))
	for _, p := range req.Roots {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		kind := classifyRoot(profile, p)
		roots = append(roots, scanner.Root{Path: p, Kind: kind})
	}

	if profile != model.ProfileDeep && len(roots) == 0 {
		resolved, err := resolveDefaultRoots(profile)
		if err != nil {
			http.Error(w, fmt.Sprintf("resolve roots: %v", err), http.StatusInternalServerError)
			return
		}
		roots = resolved
	}

	runID := newRunID()
	scanTime := time.Now().UTC().Format(time.RFC3339Nano)

	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("X-Run-ID", runID)
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)

	emitter := output.New(w, io.Discard, runID)

	ep := endpoint.Current("")
	base := model.Record{
		RecordType:     model.RecordTypePackage,
		SchemaVersion:  model.SchemaVersion,
		ScannerName:    model.ScannerName,
		ScannerVersion: version,
		RunID:          runID,
		ScanTime:       scanTime,
		Endpoint:       ep,
		Profile:        profile,
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	cfg := scanner.Config{
		Profile:      profile,
		Roots:        roots,
		Ecosystems:   ecosystemFilter,
		MaxFileSize:  maxFileSize,
		MaxDuration:  maxDuration,
		Concurrency:  concurrency,
		Catalog:      catalog,
		FindingsOnly: req.FindingsOnly,
		BaseRecord:   base,
		Emitter:      emitter,
	}

	go func() {
		<-ctx.Done()
	}()

	res, runErr := scanner.Run(ctx, cfg)
	if runErr != nil {
		emitter.Diag("error", "", runErr.Error())
	}

	status := model.ScanStatusComplete
	errMsg := ""
	if runErr != nil {
		if res.RecordsEmitted > 0 {
			status = model.ScanStatusPartial
		} else {
			status = model.ScanStatusError
		}
		errMsg = runErr.Error()
	}

	summaryRoots := make([]model.SummaryRoot, 0, len(roots))
	for _, rt := range roots {
		summaryRoots = append(summaryRoots, model.SummaryRoot{Path: rt.Path, Kind: rt.Kind})
	}
	counts := map[string]int{
		model.RecordTypePackage: res.RecordsEmitted,
		model.RecordTypeFinding: res.FindingsEmitted,
	}
	emitter.EmitSummary(model.ScanSummary{
		SchemaVersion:         model.SchemaVersion,
		ScannerName:           model.ScannerName,
		ScannerVersion:        version,
		RunID:                 runID,
		ScanTime:              scanTime,
		EndTime:               time.Now().UTC().Format(time.RFC3339Nano),
		Endpoint:              ep,
		Profile:               profile,
		Status:                status,
		Roots:                 summaryRoots,
		Counts:                counts,
		PackageRecordsEmitted: res.RecordsEmitted,
		FindingsEmitted:       res.FindingsEmitted,
		Duplicates:            res.Duplicates,
		DiagnosticsCount:      res.Diagnostics,
		FilesConsidered:       res.FilesConsidered,
		TimedOut:              res.TimedOut,
		DurationMS:            res.Duration.Milliseconds(),
		Error:                 errMsg,
	})

	if flusher != nil {
		flusher.Flush()
	}
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if apiToken == "" {
			next(w, r)
			return
		}
		auth := r.Header.Get("Authorization")
		if auth == "" {
			http.Error(w, "missing Authorization header", http.StatusUnauthorized)
			return
		}
		if !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, "expected Bearer token", http.StatusUnauthorized)
			return
		}
		token := strings.TrimPrefix(auth, "Bearer ")
		if token != apiToken {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func isValidProfile(p string) bool {
	switch p {
	case model.ProfileBaseline, model.ProfileProject, model.ProfileDeep:
		return true
	}
	return false
}

func classifyRoot(profile, path string) string {
	switch profile {
	case model.ProfileBaseline:
		return model.RootKindGlobalPackage
	case model.ProfileProject:
		return model.RootKindProject
	case model.ProfileDeep:
		return model.RootKindDeepHome
	}
	return model.RootKindUnknown
}

func resolveDefaultRoots(profile string) ([]scanner.Root, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("resolve home: %w", err)
	}

	var candidates []string
	switch profile {
	case model.ProfileBaseline:
		candidates = []string{
			filepath.Join(home, ".npm"),
			filepath.Join(home, ".cargo"),
			filepath.Join(home, ".local", "share"),
			filepath.Join(home, ".vscode", "extensions"),
			filepath.Join(home, ".cursor", "extensions"),
		}
	case model.ProfileProject:
		candidates = []string{
			filepath.Join(home, "code"),
			filepath.Join(home, "src"),
			filepath.Join(home, "Developer"),
			filepath.Join(home, "Projects"),
			filepath.Join(home, "workspace"),
		}
	}

	var roots []scanner.Root
	kind := classifyRoot(profile, "")
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			roots = append(roots, scanner.Root{Path: c, Kind: kind})
		}
	}
	return roots, nil
}

func newRunID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
