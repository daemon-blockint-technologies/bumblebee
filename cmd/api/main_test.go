package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func setupTestServer(t *testing.T) (*httptest.Server, func()) {
	origToken := apiToken
	origCatalogDir := catalogDir
	apiToken = "test-token"
	catalogDir = ""

	tmpDir := t.TempDir()
	catalogDir = tmpDir

	// Write a minimal catalog
	catalogJSON := `{"schema_version":"0.1.0","entries":[
		{"id":"test-evil","name":"evil@1.2.3","ecosystem":"npm","package":"evil","versions":["1.2.3"],"severity":"critical"}
	]}`
	if err := os.WriteFile(filepath.Join(tmpDir, "test-catalog.json"), []byte(catalogJSON), 0644); err != nil {
		t.Fatal(err)
	}

	jobs = newJobQueue(10)
	schedMgr = newScheduleManager(jobs)

	rl := newRateLimiter(1000, time.Hour)
	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/openapi.json", openAPIHandler)
	mux.HandleFunc("/metrics", metricsHandler)
	mux.HandleFunc("/catalogs", authMiddleware(rateLimitMiddleware(rl, catalogsHandler)))
	mux.HandleFunc("/scan", authMiddleware(rateLimitMiddleware(rl, scanHandler)))
	mux.HandleFunc("/scan/async", authMiddleware(rateLimitMiddleware(rl, jobs.asyncScanHandler)))
	mux.HandleFunc("/scan/", authMiddleware(rateLimitMiddleware(rl, jobs.scanSubHandler)))
	mux.HandleFunc("/schedules", authMiddleware(rateLimitMiddleware(rl, schedMgr.handleSchedules)))

	srv := httptest.NewServer(mux)
	cleanup := func() {
		srv.Close()
		apiToken = origToken
		catalogDir = origCatalogDir
	}
	return srv, cleanup
}

func doRequest(t *testing.T, srv *httptest.Server, method, path string, body interface{}) *http.Response {
	var reqBody *bytes.Buffer
	if body != nil {
		b, _ := json.Marshal(body)
		reqBody = bytes.NewBuffer(b)
	} else {
		reqBody = &bytes.Buffer{}
	}
	req, err := http.NewRequest(method, srv.URL+path, reqBody)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer test-token")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestHealthEndpoint(t *testing.T) {
	srv, cleanup := setupTestServer(t)
	defer cleanup()

	resp := doRequest(t, srv, "GET", "/health", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("health status=%d", resp.StatusCode)
	}
	var body map[string]string
	json.NewDecoder(resp.Body).Decode(&body)
	if body["status"] != "ok" {
		t.Errorf("status=%q", body["status"])
	}
	resp.Body.Close()
}

func TestUnauthorizedWithoutToken(t *testing.T) {
	srv, cleanup := setupTestServer(t)
	defer cleanup()

	req, _ := http.NewRequest("GET", srv.URL+"/catalogs", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 401 {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestCatalogsEndpoint(t *testing.T) {
	srv, cleanup := setupTestServer(t)
	defer cleanup()

	resp := doRequest(t, srv, "GET", "/catalogs", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body)
	catalogs := body["catalogs"].([]interface{})
	if len(catalogs) != 1 {
		t.Fatalf("expected 1 catalog, got %d", len(catalogs))
	}
	cat := catalogs[0].(map[string]interface{})
	if cat["file"] != "test-catalog.json" {
		t.Errorf("file=%v", cat["file"])
	}
	resp.Body.Close()
}

func TestScanSync(t *testing.T) {
	srv, cleanup := setupTestServer(t)
	defer cleanup()

	tmpDir := t.TempDir()
	lockfile := `{"lockfileVersion":3,"packages":{"node_modules/evil":{"version":"1.2.3"}}}`
	os.WriteFile(filepath.Join(tmpDir, "package-lock.json"), []byte(lockfile), 0644)

	resp := doRequest(t, srv, "POST", "/scan", map[string]interface{}{
		"profile":          "deep",
		"roots":            []string{tmpDir},
		"exposure_catalog": catalogDir,
		"max_duration":     "5s",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	resp.Body.Close()

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected at least 2 lines, got %d", len(lines))
	}

	var lastRecord map[string]interface{}
	for _, line := range lines {
		if line == "" {
			continue
		}
		var rec map[string]interface{}
		json.Unmarshal([]byte(line), &rec)
		lastRecord = rec
	}
	if lastRecord["record_type"] != "scan_summary" {
		t.Errorf("last record_type=%v", lastRecord["record_type"])
	}
}

func TestScanAsync(t *testing.T) {
	srv, cleanup := setupTestServer(t)
	defer cleanup()

	tmpDir := t.TempDir()
	lockfile := `{"lockfileVersion":3,"packages":{"node_modules/evil":{"version":"1.2.3"}}}`
	os.WriteFile(filepath.Join(tmpDir, "package-lock.json"), []byte(lockfile), 0644)

	resp := doRequest(t, srv, "POST", "/scan/async", map[string]interface{}{
		"profile":          "deep",
		"roots":            []string{tmpDir},
		"exposure_catalog": catalogDir,
		"findings_only":    true,
		"max_duration":     "5s",
	})
	if resp.StatusCode != 202 {
		t.Fatalf("expected 202, got %d", resp.StatusCode)
	}
	var job scanJob
	json.NewDecoder(resp.Body).Decode(&job)
	resp.Body.Close()

	if job.ID == "" {
		t.Fatal("job_id empty")
	}

	// Poll for completion
	deadline := time.Now().Add(10 * time.Second)
	var status jobStatus
	for time.Now().Before(deadline) {
		resp := doRequest(t, srv, "GET", "/scan/"+job.ID, nil)
		if resp.StatusCode != 200 {
			t.Fatalf("status check: %d", resp.StatusCode)
		}
		var j scanJob
		json.NewDecoder(resp.Body).Decode(&j)
		resp.Body.Close()
		status = j.Status
		if status == jobComplete || status == jobError {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if status != jobComplete {
		t.Fatalf("job did not complete: %s", status)
	}
}

func TestSchedules(t *testing.T) {
	srv, cleanup := setupTestServer(t)
	defer cleanup()

	// Create schedule
	resp := doRequest(t, srv, "POST", "/schedules", map[string]interface{}{
		"name":          "test-schedule",
		"cron":          "0 */6 * * *",
		"profile":       "baseline",
		"findings_only": true,
		"max_duration":  "1m",
	})
	if resp.StatusCode != 201 {
		t.Fatalf("create: status=%d", resp.StatusCode)
	}
	resp.Body.Close()

	// List schedules
	resp = doRequest(t, srv, "GET", "/schedules", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("list: status=%d", resp.StatusCode)
	}
	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()
	schedules := body["schedules"].([]interface{})
	if len(schedules) != 1 {
		t.Fatalf("expected 1 schedule, got %d", len(schedules))
	}

	// Delete schedule
	req, _ := http.NewRequest("DELETE", srv.URL+"/schedules?name=test-schedule", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 204 {
		t.Fatalf("delete: status=%d", resp.StatusCode)
	}
	resp.Body.Close()

	// Verify deleted
	resp = doRequest(t, srv, "GET", "/schedules", nil)
	json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()
	schedules = body["schedules"].([]interface{})
	if len(schedules) != 0 {
		t.Fatalf("expected 0 schedules after delete, got %d", len(schedules))
	}
}

func TestOpenAPIEndpoint(t *testing.T) {
	srv, cleanup := setupTestServer(t)
	defer cleanup()

	resp := doRequest(t, srv, "GET", "/openapi.json", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	var body map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&body)
	resp.Body.Close()
	if body["openapi"] != "3.1.0" {
		t.Errorf("openapi=%v", body["openapi"])
	}
	paths := body["paths"].(map[string]interface{})
	if _, ok := paths["/scan"]; !ok {
		t.Error("missing /scan in paths")
	}
	if _, ok := paths["/scan/async"]; !ok {
		t.Error("missing /scan/async in paths")
	}
	if _, ok := paths["/schedules"]; !ok {
		t.Error("missing /schedules in paths")
	}
}

func TestRateLimiting(t *testing.T) {
	// Set catalogDir so catalogsHandler doesn't fail
	origCatalogDir := catalogDir
	catalogDir = t.TempDir()
	defer func() { catalogDir = origCatalogDir }()

	// Temporarily set a very low rate limit
	rl := newRateLimiter(2, time.Hour)
	mux := http.NewServeMux()
	mux.HandleFunc("/catalogs", authMiddleware(rateLimitMiddleware(rl, catalogsHandler)))
	srv2 := httptest.NewServer(mux)
	defer srv2.Close()

	// First 2 should succeed
	for i := 0; i < 2; i++ {
		req, _ := http.NewRequest("GET", srv2.URL+"/catalogs", nil)
		req.Header.Set("Authorization", "Bearer test-token")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("request %d: expected 200, got %d", i, resp.StatusCode)
		}
		resp.Body.Close()
	}

	// Third should be rate limited
	req, _ := http.NewRequest("GET", srv2.URL+"/catalogs", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 429 {
		t.Fatalf("expected 429, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestMetricsEndpoint(t *testing.T) {
	srv, cleanup := setupTestServer(t)
	defer cleanup()

	resp := doRequest(t, srv, "GET", "/metrics", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	resp.Body.Close()

	body := buf.String()
	if !strings.Contains(body, "bumblebee_scans_total") {
		t.Error("missing bumblebee_scans_total metric")
	}
	if !strings.Contains(body, "bumblebee_findings_total") {
		t.Error("missing bumblebee_findings_total metric")
	}
	if !strings.Contains(body, "bumblebee_api_uptime_seconds") {
		t.Error("missing uptime metric")
	}
}
