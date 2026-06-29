package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/perplexityai/bumblebee/internal/endpoint"
	"github.com/perplexityai/bumblebee/internal/exposure"
	"github.com/perplexityai/bumblebee/internal/model"
	"github.com/perplexityai/bumblebee/internal/output"
	"github.com/perplexityai/bumblebee/internal/scanner"
)

// jobStatus tracks an async scan job.
type jobStatus string

const (
	jobQueued   jobStatus = "queued"
	jobRunning  jobStatus = "running"
	jobComplete jobStatus = "complete"
	jobError    jobStatus = "error"
)

// scanJob holds the state of an async scan.
type scanJob struct {
	ID        string    `json:"job_id"`
	Status    jobStatus `json:"status"`
	Profile   string    `json:"profile"`
	CreatedAt string    `json:"created_at"`
	StartedAt string    `json:"started_at,omitempty"`
	EndedAt   string    `json:"ended_at,omitempty"`
	Findings  int       `json:"findings"`
	Packages  int       `json:"packages"`
	Error     string    `json:"error,omitempty"`
	Records   [][]byte  `json:"-"`
	mu        sync.Mutex
}

// jobQueue manages async scan jobs in memory.
type jobQueue struct {
	mu    sync.RWMutex
	jobs  map[string]*scanJob
	limit int
}

func newJobQueue(limit int) *jobQueue {
	return &jobQueue{
		jobs:  make(map[string]*scanJob),
		limit: limit,
	}
}

func (q *jobQueue) create(id, profile string) *scanJob {
	j := &scanJob{
		ID:        id,
		Status:    jobQueued,
		Profile:   profile,
		CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Records:   nil,
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.jobs) >= q.limit {
		// evict oldest completed job
		var oldestID string
		var oldestTime time.Time
		for jid, j := range q.jobs {
			if j.Status == jobComplete || j.Status == jobError {
				t, _ := time.Parse(time.RFC3339Nano, j.EndedAt)
				if oldestID == "" || t.Before(oldestTime) {
					oldestID = jid
					oldestTime = t
				}
			}
		}
		if oldestID != "" {
			delete(q.jobs, oldestID)
		}
	}
	q.jobs[id] = j
	return j
}

func (q *jobQueue) get(id string) (*scanJob, bool) {
	q.mu.RLock()
	defer q.mu.RUnlock()
	j, ok := q.jobs[id]
	return j, ok
}

func (q *jobQueue) list() []*scanJob {
	q.mu.RLock()
	defer q.mu.RUnlock()
	out := make([]*scanJob, 0, len(q.jobs))
	for _, j := range q.jobs {
		out = append(out, j)
	}
	return out
}

// asyncScanRequest is the body for POST /scan/async.
type asyncScanRequest struct {
	Profile         string   `json:"profile"`
	Roots           []string `json:"roots"`
	Ecosystems      []string `json:"ecosystems"`
	ExposureCatalog string   `json:"exposure_catalog"`
	FindingsOnly    bool     `json:"findings_only"`
	MaxDuration     string   `json:"max_duration"`
	MaxFileSize     int64    `json:"max_file_size"`
	Concurrency     int      `json:"concurrency"`
	WebhookURL      string   `json:"webhook_url"`
}

func (q *jobQueue) asyncScanHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req asyncScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	profile := req.Profile
	if profile == "" {
		profile = model.ProfileDeep
	}
	if !isValidProfile(profile) {
		http.Error(w, fmt.Sprintf("invalid profile %q", profile), http.StatusBadRequest)
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
	} else {
		maxDuration = 5 * time.Minute
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
				http.Error(w, fmt.Sprintf("unsupported ecosystem %q", e), http.StatusBadRequest)
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
		roots = append(roots, scanner.Root{Path: p, Kind: classifyRoot(profile, p)})
	}
	if profile != model.ProfileDeep && len(roots) == 0 {
		resolved, err := resolveDefaultRoots(profile)
		if err != nil {
			http.Error(w, fmt.Sprintf("resolve roots: %v", err), http.StatusInternalServerError)
			return
		}
		roots = resolved
	}

	jobID := newRunID()
	job := q.create(jobID, profile)

	go q.runJob(job, req, roots, ecosystemFilter, catalog, maxDuration, maxFileSize, concurrency)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(job)
}

func (q *jobQueue) runJob(job *scanJob, req asyncScanRequest, roots []scanner.Root, ecosystemFilter map[string]bool, catalog *exposure.Catalog, maxDuration time.Duration, maxFileSize int64, concurrency int) {
	job.mu.Lock()
	job.Status = jobRunning
	job.StartedAt = time.Now().UTC().Format(time.RFC3339Nano)
	job.mu.Unlock()

	runID := job.ID
	scanTime := job.StartedAt

	var buf bytes.Buffer
	emitter := output.New(&buf, io.Discard, runID)

	ep := endpoint.Current("")
	base := model.Record{
		RecordType:     model.RecordTypePackage,
		SchemaVersion:  model.SchemaVersion,
		ScannerName:    model.ScannerName,
		ScannerVersion: version,
		RunID:          runID,
		ScanTime:       scanTime,
		Endpoint:       ep,
		Profile:        job.Profile,
	}

	ctx, cancel := context.WithTimeout(context.Background(), maxDuration)
	defer cancel()

	cfg := scanner.Config{
		Profile:      job.Profile,
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

	res, runErr := scanner.Run(ctx, cfg)

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
		Profile:               job.Profile,
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

	records := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))

	job.mu.Lock()
	job.Status = jobComplete
	job.EndedAt = time.Now().UTC().Format(time.RFC3339Nano)
	job.Findings = res.FindingsEmitted
	job.Packages = res.RecordsEmitted
	job.Records = records
	if runErr != nil {
		job.Status = jobError
		job.Error = errMsg
	}
	job.mu.Unlock()

	if req.WebhookURL != "" && res.FindingsEmitted > 0 {
		sendWebhookNotification(req.WebhookURL, job, res.FindingsEmitted)
	}
}

// scanSubHandler routes /scan/{job_id} and /scan/{job_id}/results.
func (q *jobQueue) scanSubHandler(w http.ResponseWriter, r *http.Request) {
	path := strings.Trim(r.URL.Path, "/")
	parts := strings.Split(path, "/")
	// parts: ["scan", job_id] or ["scan", job_id, "results"]
	if len(parts) < 2 {
		http.Error(w, `{"error":"job_id required"}`, http.StatusBadRequest)
		return
	}
	if len(parts) == 3 && parts[2] == "results" {
		q.jobResultsHandler(w, r)
		return
	}
	q.jobStatusHandler(w, r)
}

func (q *jobQueue) jobStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	jobID := strings.TrimPrefix(r.URL.Path, "/scan/")
	jobID = strings.Trim(jobID, "/")
	if jobID == "" {
		http.Error(w, "job_id required", http.StatusBadRequest)
		return
	}

	job, ok := q.get(jobID)
	if !ok {
		http.Error(w, `{"error":"job_not_found"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(job)
}

func (q *jobQueue) jobResultsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 3 || parts[0] != "scan" || parts[2] != "results" {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	jobID := parts[1]

	job, ok := q.get(jobID)
	if !ok {
		http.Error(w, `{"error":"job_not_found"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/x-ndjson")
	job.mu.Lock()
	for _, rec := range job.Records {
		if len(rec) == 0 {
			continue
		}
		w.Write(rec)
		w.Write([]byte("\n"))
	}
	job.mu.Unlock()
}

// sendWebhookNotification posts findings to a Discord/Slack-compatible webhook.
func sendWebhookNotification(webhookURL string, job *scanJob, findingsCount int) {
	var payload map[string]interface{}

	if strings.Contains(webhookURL, "discord.com/api/webhooks") {
		payload = map[string]interface{}{
			"embeds": []map[string]interface{}{
				{
					"title":       fmt.Sprintf("🚨 Bumblebee: %d exposure findings detected", findingsCount),
					"description": fmt.Sprintf("Scan job `%s` (profile: %s) found %d findings and %d packages.", job.ID, job.Profile, findingsCount, job.Packages),
					"color":       16711680,
					"timestamp":   job.EndedAt,
					"footer": map[string]interface{}{
						"text": fmt.Sprintf("bumblebee-api %s", version),
					},
				},
			},
		}
	} else {
		// Slack format
		payload = map[string]interface{}{
			"attachments": []map[string]interface{}{
				{
					"color":  "danger",
					"title":  fmt.Sprintf("🚨 Bumblebee: %d exposure findings detected", findingsCount),
					"text":   fmt.Sprintf("Scan job `%s` (profile: %s) found %d findings and %d packages.", job.ID, job.Profile, findingsCount, job.Packages),
					"footer": fmt.Sprintf("bumblebee-api %s", version),
					"ts":     time.Now().Unix(),
				},
			},
		}
	}

	body, _ := json.Marshal(payload)
	resp, err := http.Post(webhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Fprintf(os.Stderr, "webhook notification failed: %v\n", err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		fmt.Fprintf(os.Stderr, "webhook returned %d\n", resp.StatusCode)
	}
}

// parseCronSchedule parses a simple cron expression and returns the next tick.
// Supports: 5-field cron with *, */n, and specific values.
// This is a minimal parser — for production use a proper cron library.
func nextCronTick(expr string, from time.Time) (time.Time, error) {
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return time.Time{}, fmt.Errorf("cron expression must have 5 fields, got %d", len(fields))
	}

	minute, hour, dom, month, dow := fields[0], fields[1], fields[2], fields[3], fields[4]

	// Start from the next minute
	t := from.Truncate(time.Minute).Add(time.Minute)

	for i := 0; i < 525600; i++ { // max 1 year of minutes
		if !cronMatch(month, int(t.Month()), 1, 12) {
			t = t.Add(time.Hour)
			continue
		}
		if !cronMatch(dom, t.Day(), 1, 31) {
			t = t.AddDate(0, 0, 1)
			t = time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
			continue
		}
		if !cronMatch(dow, int(t.Weekday()), 0, 6) {
			t = t.AddDate(0, 0, 1)
			t = time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
			continue
		}
		if !cronMatch(hour, t.Hour(), 0, 23) {
			t = t.Add(time.Minute)
			continue
		}
		if !cronMatch(minute, t.Minute(), 0, 59) {
			t = t.Add(time.Minute)
			continue
		}
		return t, nil
	}

	return time.Time{}, fmt.Errorf("no matching time found within 1 year")
}

func cronMatch(field string, val, min, max int) bool {
	if field == "*" {
		return true
	}
	if strings.HasPrefix(field, "*/") {
		var n int
		_, _ = fmt.Sscanf(field[2:], "%d", &n)
		if n <= 0 {
			return true
		}
		return val%n == 0
	}
	var n int
	if c, _ := fmt.Sscanf(field, "%d", &n); c == 1 {
		return val == n
	}
	return true
}

// scheduledScan represents a recurring scan configuration.
type scheduledScan struct {
	Name            string   `json:"name"`
	Cron            string   `json:"cron"`
	Profile         string   `json:"profile"`
	Roots           []string `json:"roots"`
	ExposureCatalog string   `json:"exposure_catalog"`
	FindingsOnly    bool     `json:"findings_only"`
	MaxDuration     string   `json:"max_duration"`
	WebhookURL      string   `json:"webhook_url,omitempty"`
	NextRun         string   `json:"next_run,omitempty"`
	LastRun         string   `json:"last_run,omitempty"`
	LastFindings    int      `json:"last_findings,omitempty"`
}

// scheduleManager handles cron-based scheduled scans.
type scheduleManager struct {
	mu        sync.RWMutex
	schedules map[string]*scheduledScan
	queue     *jobQueue
	stopCh    chan struct{}
}

func newScheduleManager(q *jobQueue) *scheduleManager {
	return &scheduleManager{
		schedules: make(map[string]*scheduledScan),
		queue:     q,
		stopCh:    make(chan struct{}),
	}
}

// handleSchedules dispatches by HTTP method: GET → list, POST → create, DELETE → delete.
func (sm *scheduleManager) handleSchedules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		sm.listSchedules(w, r)
	case http.MethodPost:
		sm.createSchedule(w, r)
	case http.MethodDelete:
		sm.deleteSchedule(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (sm *scheduleManager) createSchedule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var s scheduledScan
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		http.Error(w, fmt.Sprintf("invalid request: %v", err), http.StatusBadRequest)
		return
	}
	if s.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	if s.Cron == "" {
		http.Error(w, "cron is required", http.StatusBadRequest)
		return
	}
	if s.Profile == "" {
		s.Profile = model.ProfileBaseline
	}
	if !isValidProfile(s.Profile) {
		http.Error(w, "invalid profile", http.StatusBadRequest)
		return
	}
	if s.MaxDuration == "" {
		s.MaxDuration = "5m"
	}

	next, err := nextCronTick(s.Cron, time.Now())
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid cron: %v", err), http.StatusBadRequest)
		return
	}
	s.NextRun = next.Format(time.RFC3339)

	sm.mu.Lock()
	sm.schedules[s.Name] = &s
	sm.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(s)
}

func (sm *scheduleManager) listSchedules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sm.mu.RLock()
	list := make([]*scheduledScan, 0, len(sm.schedules))
	for _, s := range sm.schedules {
		list = append(list, s)
	}
	sm.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"schedules": list})
}

func (sm *scheduleManager) deleteSchedule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "name query param required", http.StatusBadRequest)
		return
	}
	sm.mu.Lock()
	if _, ok := sm.schedules[name]; !ok {
		sm.mu.Unlock()
		http.Error(w, `{"error":"not_found"}`, http.StatusNotFound)
		return
	}
	delete(sm.schedules, name)
	sm.mu.Unlock()

	w.WriteHeader(http.StatusNoContent)
}

func (sm *scheduleManager) start() {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				sm.tick()
			case <-sm.stopCh:
				return
			}
		}
	}()
}

func (sm *scheduleManager) stop() {
	close(sm.stopCh)
}

func (sm *scheduleManager) tick() {
	now := time.Now()
	sm.mu.RLock()
	var due []*scheduledScan
	for _, s := range sm.schedules {
		if s.NextRun == "" {
			continue
		}
		next, err := time.Parse(time.RFC3339, s.NextRun)
		if err != nil {
			continue
		}
		if !next.After(now) {
			due = append(due, s)
		}
	}
	sm.mu.RUnlock()

	for _, s := range due {
		sm.runScheduled(s)
	}
}

func (sm *scheduleManager) runScheduled(s *scheduledScan) {
	var maxDuration time.Duration
	if d, err := time.ParseDuration(s.MaxDuration); err == nil {
		maxDuration = d
	} else {
		maxDuration = 5 * time.Minute
	}

	var catalog *exposure.Catalog
	catalogPath := s.ExposureCatalog
	if catalogPath == "" && catalogDir != "" {
		catalogPath = catalogDir
	}
	if catalogPath != "" {
		c, err := exposure.Load(catalogPath, 64*1024*1024)
		if err == nil {
			catalog = c
		}
	}

	roots := make([]scanner.Root, 0, len(s.Roots))
	for _, p := range s.Roots {
		p = strings.TrimSpace(p)
		if p != "" {
			roots = append(roots, scanner.Root{Path: p, Kind: classifyRoot(s.Profile, p)})
		}
	}
	if s.Profile != model.ProfileDeep && len(roots) == 0 {
		resolved, err := resolveDefaultRoots(s.Profile)
		if err == nil {
			roots = resolved
		}
	}

	jobID := newRunID()
	job := sm.queue.create(jobID, s.Profile)

	req := asyncScanRequest{
		Profile:         s.Profile,
		Roots:           s.Roots,
		ExposureCatalog: s.ExposureCatalog,
		FindingsOnly:    s.FindingsOnly,
		MaxDuration:     s.MaxDuration,
		WebhookURL:      s.WebhookURL,
	}

	go sm.queue.runJob(job, req, roots, nil, catalog, maxDuration, 5*1024*1024, 4)

	// Update next run time
	next, err := nextCronTick(s.Cron, time.Now())
	if err == nil {
		sm.mu.Lock()
		s.NextRun = next.Format(time.RFC3339)
		s.LastRun = time.Now().UTC().Format(time.RFC3339)
		sm.mu.Unlock()
	}
}

// init loads schedules from env var SCHEDULES (JSON array) at startup.
func (sm *scheduleManager) initFromEnv() {
	schedulesJSON := os.Getenv("SCHEDULES")
	if schedulesJSON == "" {
		return
	}
	var schedules []scheduledScan
	if err := json.Unmarshal([]byte(schedulesJSON), &schedules); err != nil {
		fmt.Fprintf(os.Stderr, "parse SCHEDULES env: %v\n", err)
		return
	}
	for i := range schedules {
		s := schedules[i]
		if s.Name == "" || s.Cron == "" {
			continue
		}
		if s.Profile == "" {
			s.Profile = model.ProfileBaseline
		}
		if s.MaxDuration == "" {
			s.MaxDuration = "5m"
		}
		next, err := nextCronTick(s.Cron, time.Now())
		if err != nil {
			fmt.Fprintf(os.Stderr, "schedule %s: invalid cron: %v\n", s.Name, err)
			continue
		}
		s.NextRun = next.Format(time.RFC3339)
		sm.mu.Lock()
		sm.schedules[s.Name] = &s
		sm.mu.Unlock()
		fmt.Fprintf(os.Stderr, "loaded schedule %s (next: %s)\n", s.Name, s.NextRun)
	}
}
