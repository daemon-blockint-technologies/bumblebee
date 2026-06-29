package main

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// metrics holds Prometheus-compatible counters and histograms.
type metrics struct {
	scansTotal       atomic.Int64
	scansAsyncTotal  atomic.Int64
	scansSyncTotal   atomic.Int64
	findingsTotal    atomic.Int64
	packagesTotal    atomic.Int64
	scanErrorsTotal  atomic.Int64
	scanDurationMs   sync.Map // histogram buckets
	rateLimitedTotal atomic.Int64
	requestsTotal    atomic.Int64
	startTime        time.Time
}

var metricsCollector = &metrics{
	startTime: time.Now(),
}

func (m *metrics) recordSyncScan(duration time.Duration, findings, packages int, err bool) {
	m.scansTotal.Add(1)
	m.scansSyncTotal.Add(1)
	m.requestsTotal.Add(1)
	m.findingsTotal.Add(int64(findings))
	m.packagesTotal.Add(int64(packages))
	if err {
		m.scanErrorsTotal.Add(1)
	}
	m.recordDuration(duration)
}

func (m *metrics) recordAsyncScan(duration time.Duration, findings, packages int, err bool) {
	m.scansTotal.Add(1)
	m.scansAsyncTotal.Add(1)
	m.findingsTotal.Add(int64(findings))
	m.packagesTotal.Add(int64(packages))
	if err {
		m.scanErrorsTotal.Add(1)
	}
	m.recordDuration(duration)
}

func (m *metrics) recordRateLimited() {
	m.rateLimitedTotal.Add(1)
}

func (m *metrics) recordRequest() {
	m.requestsTotal.Add(1)
}

func (m *metrics) recordDuration(d time.Duration) {
	ms := d.Milliseconds()
	buckets := []int64{100, 500, 1000, 5000, 10000, 30000, 60000, 300000}
	for _, b := range buckets {
		if ms <= b {
			key := fmt.Sprintf("le_%d", b)
			v, _ := m.scanDurationMs.LoadOrStore(key, &atomic.Int64{})
			v.(*atomic.Int64).Add(1)
			return
		}
	}
	v, _ := m.scanDurationMs.LoadOrStore("le_inf", &atomic.Int64{})
	v.(*atomic.Int64).Add(1)
}

func metricsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var sb strings.Builder
	sb.WriteString("# HELP bumblebee_api_uptime_seconds Time since the API server started\n")
	sb.WriteString("# TYPE bumblebee_api_uptime_seconds gauge\n")
	sb.WriteString(fmt.Sprintf("bumblebee_api_uptime_seconds %.0f\n", time.Since(metricsCollector.startTime).Seconds()))

	sb.WriteString("# HELP bumblebee_scans_total Total scans executed (sync + async)\n")
	sb.WriteString("# TYPE bumblebee_scans_total counter\n")
	sb.WriteString(fmt.Sprintf("bumblebee_scans_total %d\n", metricsCollector.scansTotal.Load()))

	sb.WriteString("# HELP bumblebee_scans_sync_total Total synchronous scans\n")
	sb.WriteString("# TYPE bumblebee_scans_sync_total counter\n")
	sb.WriteString(fmt.Sprintf("bumblebee_scans_sync_total %d\n", metricsCollector.scansSyncTotal.Load()))

	sb.WriteString("# HELP bumblebee_scans_async_total Total asynchronous scans\n")
	sb.WriteString("# TYPE bumblebee_scans_async_total counter\n")
	sb.WriteString(fmt.Sprintf("bumblebee_scans_async_total %d\n", metricsCollector.scansAsyncTotal.Load()))

	sb.WriteString("# HELP bumblebee_findings_total Total exposure findings across all scans\n")
	sb.WriteString("# TYPE bumblebee_findings_total counter\n")
	sb.WriteString(fmt.Sprintf("bumblebee_findings_total %d\n", metricsCollector.findingsTotal.Load()))

	sb.WriteString("# HELP bumblebee_packages_total Total packages inventoried across all scans\n")
	sb.WriteString("# TYPE bumblebee_packages_total counter\n")
	sb.WriteString(fmt.Sprintf("bumblebee_packages_total %d\n", metricsCollector.packagesTotal.Load()))

	sb.WriteString("# HELP bumblebee_scan_errors_total Total scans that ended with error status\n")
	sb.WriteString("# TYPE bumblebee_scan_errors_total counter\n")
	sb.WriteString(fmt.Sprintf("bumblebee_scan_errors_total %d\n", metricsCollector.scanErrorsTotal.Load()))

	sb.WriteString("# HELP bumblebee_rate_limited_total Total requests rejected by rate limiter\n")
	sb.WriteString("# TYPE bumblebee_rate_limited_total counter\n")
	sb.WriteString(fmt.Sprintf("bumblebee_rate_limited_total %d\n", metricsCollector.rateLimitedTotal.Load()))

	sb.WriteString("# HELP bumblebee_requests_total Total authenticated requests\n")
	sb.WriteString("# TYPE bumblebee_requests_total counter\n")
	sb.WriteString(fmt.Sprintf("bumblebee_requests_total %d\n", metricsCollector.requestsTotal.Load()))

	// Duration histogram
	sb.WriteString("# HELP bumblebee_scan_duration_ms_bucket Scan duration histogram buckets\n")
	sb.WriteString("# TYPE bumblebee_scan_duration_ms_bucket histogram\n")
	buckets := []struct {
		le  string
		val string
	}{
		{"100", "le_100"}, {"500", "le_500"}, {"1000", "le_1000"},
		{"5000", "le_5000"}, {"10000", "le_10000"}, {"30000", "le_30000"},
		{"60000", "le_60000"}, {"300000", "le_300000"}, {"+Inf", "le_inf"},
	}
	for _, b := range buckets {
		var val int64
		if v, ok := metricsCollector.scanDurationMs.Load(b.val); ok {
			val = v.(*atomic.Int64).Load()
		}
		sb.WriteString(fmt.Sprintf("bumblebee_scan_duration_ms_bucket{le=\"%s\"} %d\n", b.le, val))
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Write([]byte(sb.String()))
}
