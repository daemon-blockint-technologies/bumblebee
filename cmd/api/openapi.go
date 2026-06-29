package main

import (
	"encoding/json"
	"net/http"
)

// openAPISpec returns a minimal OpenAPI 3.1 spec for the bumblebee API.
// Served at GET /openapi.json and GET /docs (as Swagger UI redirect).
func openAPIHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(openAPIDoc())
}

func openAPIDoc() map[string]interface{} {
	return map[string]interface{}{
		"openapi": "3.1.0",
		"info": map[string]interface{}{
			"title":       "bumblebee API",
			"version":     version,
			"description": "Read-only supply-chain exposure scanner API. Trigger on-demand package inventory scans and match against threat intelligence catalogs.",
			"license": map[string]interface{}{
				"name": "Apache-2.0",
			},
		},
		"servers": []map[string]interface{}{
			{"url": "/", "description": "current host"},
		},
		"components": map[string]interface{}{
			"securitySchemes": map[string]interface{}{
				"bearerAuth": map[string]interface{}{
					"type":        "http",
					"scheme":      "bearer",
					"description": "Bearer token from API_TOKEN env var",
				},
			},
			"schemas": map[string]interface{}{
				"ScanRequest": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"profile":          map[string]interface{}{"type": "string", "enum": []string{"baseline", "project", "deep"}, "default": "deep"},
						"roots":            map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}, "description": "filesystem paths to scan (required for deep)"},
						"ecosystems":       map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}, "description": "limit to specific ecosystems"},
						"exposure_catalog": map[string]interface{}{"type": "string", "description": "path to catalog file or directory"},
						"findings_only":    map[string]interface{}{"type": "boolean", "default": false},
						"max_duration":     map[string]interface{}{"type": "string", "description": "Go duration string e.g. 5m, 30s"},
						"max_file_size":    map[string]interface{}{"type": "integer", "default": 5242880},
						"concurrency":      map[string]interface{}{"type": "integer", "default": 4},
						"webhook_url":      map[string]interface{}{"type": "string", "description": "optional webhook URL for findings notification"},
					},
				},
				"AsyncScanRequest": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"profile":          map[string]interface{}{"type": "string", "enum": []string{"baseline", "project", "deep"}, "default": "deep"},
						"roots":            map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
						"ecosystems":       map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
						"exposure_catalog": map[string]interface{}{"type": "string"},
						"findings_only":    map[string]interface{}{"type": "boolean", "default": true},
						"max_duration":     map[string]interface{}{"type": "string", "default": "5m"},
						"webhook_url":      map[string]interface{}{"type": "string"},
					},
				},
				"ScanJob": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"job_id":    map[string]interface{}{"type": "string"},
						"status":    map[string]interface{}{"type": "string", "enum": []string{"queued", "running", "complete", "error"}},
						"profile":   map[string]interface{}{"type": "string"},
						"created_at": map[string]interface{}{"type": "string"},
						"findings":  map[string]interface{}{"type": "integer"},
						"packages":  map[string]interface{}{"type": "integer"},
						"error":     map[string]interface{}{"type": "string"},
					},
				},
				"ScheduleRequest": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"name":             map[string]interface{}{"type": "string", "description": "unique schedule name"},
						"cron":             map[string]interface{}{"type": "string", "description": "cron expression (e.g. 0 */6 * * *)"},
						"profile":          map[string]interface{}{"type": "string", "enum": []string{"baseline", "project", "deep"}, "default": "baseline"},
						"roots":            map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
						"exposure_catalog": map[string]interface{}{"type": "string"},
						"findings_only":    map[string]interface{}{"type": "boolean", "default": true},
						"max_duration":     map[string]interface{}{"type": "string", "default": "5m"},
						"webhook_url":      map[string]interface{}{"type": "string", "description": "Discord/Slack webhook for findings"},
					},
				},
				"Error": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"error":   map[string]interface{}{"type": "string"},
						"message": map[string]interface{}{"type": "string"},
					},
				},
			},
		},
		"security": []map[string]interface{}{
			{"bearerAuth": []interface{}{}},
		},
		"paths": map[string]interface{}{
			"/health": map[string]interface{}{
				"get": map[string]interface{}{
					"summary": "Health check",
					"description": "Liveness probe. No auth required.",
					"security": []interface{}{},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "OK"},
					},
				},
			},
			"/catalogs": map[string]interface{}{
				"get": map[string]interface{}{
					"summary": "List available threat intelligence catalogs",
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Catalog list with entry counts"},
					},
				},
			},
			"/scan": map[string]interface{}{
				"post": map[string]interface{}{
					"summary": "Trigger a synchronous scan",
					"description": "Runs a scan and streams NDJSON results back. Blocks until complete.",
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{"$ref": "#/components/schemas/ScanRequest"},
							},
						},
					},
					"responses": map[string]interface{}{
						"200":     map[string]interface{}{"description": "NDJSON stream of package/finding/summary records"},
						"400":     map[string]interface{}{"description": "Bad request"},
						"401":     map[string]interface{}{"description": "Unauthorized"},
						"429":     map[string]interface{}{"description": "Rate limit exceeded"},
					},
				},
			},
			"/scan/async": map[string]interface{}{
				"post": map[string]interface{}{
					"summary": "Submit an async scan job",
					"description": "Queues a scan and returns a job ID immediately. Poll /scan/{job_id} for status.",
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{"$ref": "#/components/schemas/AsyncScanRequest"},
							},
						},
					},
					"responses": map[string]interface{}{
						"202": map[string]interface{}{"description": "Job queued", "content": map[string]interface{}{
							"application/json": map[string]interface{}{"schema": map[string]interface{}{"$ref": "#/components/schemas/ScanJob"}},
						}},
					},
				},
			},
			"/scan/{job_id}": map[string]interface{}{
				"get": map[string]interface{}{
					"summary": "Get async scan job status",
					"parameters": []interface{}{
						map[string]interface{}{"name": "job_id", "in": "path", "required": true, "schema": map[string]interface{}{"type": "string"}},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "Job status", "content": map[string]interface{}{
							"application/json": map[string]interface{}{"schema": map[string]interface{}{"$ref": "#/components/schemas/ScanJob"}},
						}},
						"404": map[string]interface{}{"description": "Job not found"},
					},
				},
			},
			"/schedules": map[string]interface{}{
				"get": map[string]interface{}{
					"summary": "List scheduled scans",
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "List of schedules"},
					},
				},
				"post": map[string]interface{}{
					"summary": "Create a scheduled scan",
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{"$ref": "#/components/schemas/ScheduleRequest"},
							},
						},
					},
					"responses": map[string]interface{}{
						"201": map[string]interface{}{"description": "Schedule created"},
						"400": map[string]interface{}{"description": "Bad request"},
					},
				},
				"delete": map[string]interface{}{
					"summary": "Delete a scheduled scan",
					"parameters": []interface{}{
						map[string]interface{}{"name": "name", "in": "query", "required": true, "schema": map[string]interface{}{"type": "string"}},
					},
					"responses": map[string]interface{}{
						"204": map[string]interface{}{"description": "Deleted"},
						"404": map[string]interface{}{"description": "Not found"},
					},
				},
			},
			"/openapi.json": map[string]interface{}{
				"get": map[string]interface{}{
					"summary": "OpenAPI specification",
					"security": []interface{}{},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{"description": "OpenAPI 3.1 JSON"},
					},
				},
			},
		},
	}
}
