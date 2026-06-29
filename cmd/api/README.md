# bumblebee API

HTTP API wrapper around the [bumblebee](../README.md) supply-chain exposure scanner.

## Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/health` | No | Liveness probe |
| `GET` | `/metrics` | No | Prometheus metrics |
| `GET` | `/openapi.json` | No | OpenAPI 3.1 specification |
| `GET` | `/catalogs` | Yes | List available threat intelligence catalogs |
| `POST` | `/scan` | Yes | Synchronous scan — streams NDJSON |
| `POST` | `/scan/async` | Yes | Asynchronous scan — returns job ID |
| `GET` | `/scan/{job_id}` | Yes | Get async scan job status |
| `GET` | `/scan/{job_id}/results` | Yes | Get async scan NDJSON results |
| `GET` | `/schedules` | Yes | List scheduled scans |
| `POST` | `/schedules` | Yes | Create a scheduled scan |
| `DELETE` | `/schedules?name=N` | Yes | Delete a scheduled scan |

## Authentication

All endpoints except `/health`, `/metrics`, and `/openapi.json` require a bearer token:

```
Authorization: Bearer <API_TOKEN>
```

Set `API_TOKEN` env var on the server. If unset, auth is disabled (development only).

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `API_TOKEN` | _(empty)_ | Bearer token for API auth. **Set in production.** |
| `ADDR` | `:8080` | Listen address |
| `CATALOG_DIR` | `threat_intel` | Path to exposure catalog directory |
| `RATE_LIMIT_PER_HOUR` | `60` | Max requests per client IP per hour |
| `SCHEDULES` | _(empty)_ | JSON array of schedule configs for bootstrap |

## Examples

### Health Check

```sh
curl https://bumblebee-api-production-1610.up.railway.app/health
```

```json
{"status":"ok","version":"0.1.1-api"}
```

### List Catalogs

```sh
curl -H "Authorization: Bearer $TOKEN" \
  https://bumblebee-api-production-1610.up.railway.app/catalogs
```

### Synchronous Scan (streaming NDJSON)

```sh
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "profile": "deep",
    "roots": ["/Users/dev/project"],
    "exposure_catalog": "threat_intel",
    "max_duration": "5m",
    "concurrency": 4
  }' \
  https://bumblebee-api-production-1610.up.railway.app/scan
```

Output (NDJSON, one record per line):

```json
{"record_type":"package","ecosystem":"npm","package_name":"left-pad","version":"1.3.0",...}
{"record_type":"finding","finding_type":"package_exposure","severity":"critical","catalog_id":"evil-001",...}
{"record_type":"scan_summary","status":"complete","package_records_emitted":42,"findings_emitted":3,...}
```

### Asynchronous Scan

Submit and get job ID:

```sh
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "profile": "deep",
    "roots": ["/Users/dev/project"],
    "findings_only": true,
    "max_duration": "5m",
    "webhook_url": "https://discord.com/api/webhooks/..."
  }' \
  https://bumblebee-api-production-1610.up.railway.app/scan/async
```

```json
{"job_id":"a1b2c3d4e5f6...","status":"queued","profile":"deep","created_at":"2026-06-29T10:00:00Z"}
```

Poll for status:

```sh
curl -H "Authorization: Bearer $TOKEN" \
  https://bumblebee-api-production-1610.up.railway.app/scan/a1b2c3d4e5f6
```

```json
{"job_id":"a1b2c3d4e5f6...","status":"complete","findings":3,"packages":42,"ended_at":"2026-06-29T10:00:05Z"}
```

Fetch results:

```sh
curl -H "Authorization: Bearer $TOKEN" \
  https://bumblebee-api-production-1610.up.railway.app/scan/a1b2c3d4e5f6/results
```

### Scheduled Scans

Create a recurring scan:

```sh
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "nightly-baseline",
    "cron": "0 2 * * *",
    "profile": "baseline",
    "findings_only": true,
    "max_duration": "5m",
    "webhook_url": "https://discord.com/api/webhooks/..."
  }' \
  https://bumblebee-api-production-1610.up.railway.app/schedules
```

List schedules:

```sh
curl -H "Authorization: Bearer $TOKEN" \
  https://bumblebee-api-production-1610.up.railway.app/schedules
```

Delete a schedule:

```sh
curl -X DELETE -H "Authorization: Bearer $TOKEN" \
  "https://bumblebee-api-production-1610.up.railway.app/schedules?name=nightly-baseline"
```

### Prometheus Metrics

```sh
curl https://bumblebee-api-production-1610.up.railway.app/metrics
```

```
# HELP bumblebee_scans_total Total scans executed (sync + async)
# TYPE bumblebee_scans_total counter
bumblebee_scans_total 15
# HELP bumblebee_findings_total Total exposure findings across all scans
# TYPE bumblebee_findings_total counter
bumblebee_findings_total 7
...
```

### Bootstrap Schedules via Environment

Set `SCHEDULES` env var to load schedules at startup:

```json
[
  {"name":"nightly","cron":"0 2 * * *","profile":"baseline","findings_only":true,"max_duration":"5m"},
  {"name":"hourly-deep","cron":"0 * * * *","profile":"deep","roots":["/app"],"findings_only":true,"max_duration":"2m","webhook_url":"https://discord.com/api/webhooks/..."}
]
```

## Scan Request Parameters

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `profile` | string | `deep` | Scan profile: `baseline`, `project`, `deep` |
| `roots` | []string | _(profile defaults)_ | Filesystem paths to scan (required for `deep`) |
| `ecosystems` | []string | _(all)_ | Filter: `npm`, `pypi`, `gomod`, `rubygems`, etc. |
| `exposure_catalog` | string | `CATALOG_DIR` | Path to catalog file or directory |
| `findings_only` | bool | `false` | Only emit finding records (requires catalog) |
| `max_duration` | string | _(none)_ | Go duration: `5m`, `30s`, `1h` |
| `max_file_size` | int | `5242880` | Max file size in bytes |
| `concurrency` | int | `4` | Parallel scanner workers |
| `webhook_url` | string | _(none)_ | Discord/Slack webhook for findings notification |

## Cron Format

5-field cron expressions are supported:

```
┌──────── minute (0-59)
│ ┌────── hour (0-23)
│ │ ┌──── day of month (1-31)
│ │ │ ┌── month (1-12)
│ │ │ │ ┌ day of week (0-6, Sun=0)
│ │ │ │ │
0 */6 * * *    # every 6 hours
0 2 * * *      # daily at 2am
0 0 * * 0      # weekly on Sunday
*/30 * * * *   # every 30 minutes
```

Supports `*`, specific values, and `*/n` step syntax.

## Deployment

See [Dockerfile](../Dockerfile) for the multi-stage build. Deployed on Railway with:

- 2 replicas (Southeast Asia)
- Healthcheck on `/health`
- Restart policy: `ON_FAILURE` (max 10 retries)
- Rate limiting: 60 req/hour per IP

## Development

```sh
# Build
go build ./cmd/api/

# Run locally
API_TOKEN=dev-token go run ./cmd/api/

# Test
go test -v ./cmd/api/

# Test with race detector
go test -race -timeout 60s ./cmd/api/
```

---

## NDJSON Record Schemas

Scan output streams (`POST /scan` and `GET /scan/{job_id}/results`) emit one JSON object per line. Each record has a `record_type` field:

### `package` — Discovered Package

```json
{
  "record_type": "package",
  "record_id": "sha256:...",
  "schema_version": "0.1.0",
  "scanner_name": "bumblebee",
  "run_id": "abc123",
  "scan_time": "2026-06-29T10:00:00Z",
  "endpoint": {"hostname": "dev-laptop", "os": "darwin", "arch": "arm64", "username": "dev", "uid": "501"},
  "profile": "deep",
  "ecosystem": "npm",
  "package_name": "left-pad",
  "normalized_name": "left-pad",
  "version": "1.3.0",
  "root_kind": "project_root",
  "source_type": "lockfile",
  "source_file": "package-lock.json",
  "has_lifecycle_scripts": false,
  "confidence": "high"
}
```

### `finding` — Exposure Match

```json
{
  "record_type": "finding",
  "record_id": "sha256:...",
  "finding_type": "package_exposure",
  "severity": "critical",
  "catalog_id": "evil-001",
  "catalog_name": "evil@1.2.3",
  "ecosystem": "npm",
  "package_name": "evil",
  "normalized_name": "evil",
  "version": "1.2.3",
  "confidence": "high"
}
```

### `scan_summary` — Run Terminator (always last line)

```json
{
  "record_type": "scan_summary",
  "run_id": "abc123",
  "status": "complete",
  "profile": "deep",
  "roots": [{"path": "/Users/dev/project", "kind": "project_root"}],
  "package_records_emitted": 42,
  "findings_emitted": 3,
  "duplicates": 1,
  "files_considered": 128,
  "timed_out": false,
  "duration_ms": 5234
}
```

**Scan summary status values:** `complete`, `partial` (some records emitted before error), `error`.

---

## Job Status Values

| Status | Description |
|--------|-------------|
| `queued` | Job accepted, waiting for worker |
| `running` | Scan in progress |
| `complete` | Scan finished successfully |
| `error` | Scan failed (see `error` field) |

Job queue limits: 100 concurrent jobs. Oldest completed/errored jobs evicted when full.

---

## Webhook Notifications

When a scan with `webhook_url` finds exposures (`findings > 0`), the API posts a notification.

**Discord** (auto-detected from `discord.com/api/webhooks` URL):

```json
{
  "embeds": [{
    "title": "🚨 Bumblebee: 3 exposure findings detected",
    "description": "Scan job `a1b2c3d4` (profile: deep) found 3 findings and 42 packages.",
    "color": 16711680,
    "timestamp": "2026-06-29T10:00:05Z",
    "footer": {"text": "bumblebee-api 0.1.1-api"}
  }]
}
```

**Slack** (all other URLs):

```json
{
  "attachments": [{
    "color": "danger",
    "title": "🚨 Bumblebee: 3 exposure findings detected",
    "text": "Scan job `a1b2c3d4` (profile: deep) found 3 findings and 42 packages.",
    "footer": "bumblebee-api 0.1.1-api",
    "ts": 1719655205
  }]
}
```

---

## Prometheus Metrics

`GET /metrics` — no auth required.

| Metric | Type | Description |
|--------|------|-------------|
| `bumblebee_api_uptime_seconds` | gauge | Seconds since server start |
| `bumblebee_scans_total` | counter | Total scans (sync + async) |
| `bumblebee_scans_sync_total` | counter | Synchronous scans |
| `bumblebee_scans_async_total` | counter | Asynchronous scans |
| `bumblebee_findings_total` | counter | Total findings across all scans |
| `bumblebee_packages_total` | counter | Total packages inventoried |
| `bumblebee_scan_errors_total` | counter | Scans that ended with error |
| `bumblebee_rate_limited_total` | counter | Requests rejected by rate limiter |
| `bumblebee_requests_total` | counter | Total authenticated requests |
| `bumblebee_scan_duration_ms_bucket` | histogram | Duration distribution (buckets: 100ms–5min) |

---

## Error Responses

| Status | Description |
|--------|-------------|
| `400` | Bad request — invalid JSON, missing required field, unsupported ecosystem |
| `401` | Unauthorized — missing or invalid bearer token |
| `404` | Not found — job ID or schedule name doesn't exist |
| `405` | Method not allowed — wrong HTTP method for endpoint |
| `409` | Conflict — results requested before job is complete |
| `429` | Rate limited — too many requests (includes `Retry-After` header) |
| `500` | Internal server error |

```json
{"error":"rate_limit_exceeded","message":"too many requests"}
```

---

## OpenAPI Spec

The full OpenAPI 3.1 specification is served at `/openapi.json`. Import into Swagger UI, Postman, or generate client SDKs:

```sh
curl https://bumblebee-api-production-1610.up.railway.app/openapi.json | jq '.paths | keys'
```
