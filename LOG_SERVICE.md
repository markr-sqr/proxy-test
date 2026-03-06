# Log Viewer Service

A web UI and JSON API that exposes structured proxy logs for querying. Runs on port **9999** inside the same container as the proxy.

## Deployment

The log viewer is included in the Docker image and starts automatically — no additional setup required.

```bash
docker compose up -d

# Web UI
open http://localhost:9999/ui/logs

# API
curl http://localhost:9999/api/logs
```

To run manually without Docker (requires Node.js 18+):

```bash
cd viewer && npm install && npx tsc && node dist/index.js
```

## How It Works

The proxy writes every request/response pair as a JSON line to `/tmp/proxy.log` (configurable via `PROXY_LOG_FILE` env var). The log viewer reads this file and serves it through a REST API with filtering and pagination. The web UI at `/ui/logs` provides a full-width sortable table with expandable detail rows showing request and response payloads, image previews, auto-decoding, scope-based target filtering, a settings modal, and a traffic dashboard.

## Endpoints

### `GET /`

Returns a list of available endpoints.

### `GET /health`

Health check.

**Response:**
```json
{"status": "ok"}
```

### `GET /api/logs`

Returns paginated, filterable proxy log entries.

**Query Parameters:**

| Parameter  | Type   | Default | Description                                              |
|------------|--------|---------|----------------------------------------------------------|
| `page`     | int    | 1       | Page number (1-indexed)                                  |
| `limit`    | int    | 50      | Results per page (1–1000)                                |
| `start`    | string | —       | ISO 8601 start time (inclusive)                          |
| `end`      | string | —       | ISO 8601 end time (inclusive)                            |
| `method`   | string | —       | HTTP method filter (case-insensitive exact match)        |
| `url`      | string | —       | URL substring search (case-insensitive)                  |
| `severity` | string | —       | Only entries with at least one risk of this severity     |

**Response:**
```json
{
  "page": 1,
  "limit": 50,
  "total": 123,
  "entries": [
    {
      "timestamp": "2026-03-03T21:54:47.145401+00:00",
      "client_ip": "172.24.0.1",
      "client_port": 39052,
      "method": "POST",
      "target": "http://example.com/api/data",
      "status": "200",
      "risks": [],
      "payload": {
        "request_line": "POST http://example.com/api/data HTTP/1.1",
        "headers": [
          ["Host", "example.com"],
          ["Content-Type", "application/json"],
          ["Content-Length", "27"]
        ],
        "body": "{\"user\":\"alice\",\"role\":\"admin\"}",
        "body_is_binary": false,
        "body_truncated": false
      },
      "response": {
        "status_line": "HTTP/1.1 200 OK",
        "headers": [
          ["Content-Type", "application/json"],
          ["Content-Length", "42"]
        ],
        "body": "{\"status\":\"ok\",\"id\":123}",
        "body_is_binary": false,
        "body_truncated": false
      }
    },
    {
      "timestamp": "2026-03-03T21:55:13.953356+00:00",
      "client_ip": "172.24.0.1",
      "client_port": 43754,
      "method": "GET",
      "target": "http://example.com/",
      "status": "200",
      "risks": [
        {
          "severity": "MEDIUM",
          "description": "Missing Content-Security-Policy (CSP) header"
        },
        {
          "severity": "LOW",
          "description": "Missing X-Content-Type-Options header"
        }
      ],
      "payload": {
        "request_line": "GET http://example.com/ HTTP/1.1",
        "headers": [
          ["Host", "example.com"],
          ["User-Agent", "curl/8.11.1"]
        ],
        "body": "",
        "body_is_binary": false,
        "body_truncated": false
      },
      "response": {
        "status_line": "HTTP/1.1 200 OK",
        "headers": [
          ["Content-Type", "text/html"],
          ["Content-Length", "1256"]
        ],
        "body": "<!doctype html>...",
        "body_is_binary": false,
        "body_truncated": false
      }
    }
  ]
}
```

## Log Entry Schema

Each entry in the JSONL file (and in API responses) has the following fields:

| Field         | Type      | Description                                    |
|---------------|-----------|------------------------------------------------|
| `timestamp`   | string    | ISO 8601 timestamp (UTC)                       |
| `client_ip`   | string    | Client IP address                              |
| `client_port` | int       | Client source port                             |
| `method`      | string    | HTTP method (`GET`, `POST`, `CONNECT`, etc.)   |
| `target`      | string    | Full request URL or `host:port` for CONNECT    |
| `status`      | string    | HTTP status code (`200`, `404`, `502`, etc.) or `MITM` for tunnel setup |
| `risks`       | Risk[]    | Detected security risks — request patterns + response header checks (may be empty) |
| `payload`     | Payload?  | Request payload, if available (absent for CONNECT without MITM) |
| `response`    | Response? | Response payload, if available (absent for CONNECT tunnel setup) |

### Risk Object

| Field         | Type   | Description                        |
|---------------|--------|------------------------------------|
| `severity`    | string | `HIGH`, `MEDIUM`, or `LOW`         |
| `description` | string | Human-readable risk description    |

### Payload Object

| Field            | Type               | Description                                        |
|------------------|--------------------|----------------------------------------------------|
| `request_line`   | string             | Full HTTP request line (e.g., `GET http://... HTTP/1.1`) |
| `headers`        | [string, string][] | Header name-value pairs                            |
| `body`           | string             | Request body text, or base64-encoded if binary     |
| `body_is_binary` | boolean            | `true` if body is base64-encoded binary content    |
| `body_truncated` | boolean            | `true` if body was truncated at 8 KB               |

### Response Object

| Field            | Type               | Description                                        |
|------------------|--------------------|----------------------------------------------------|
| `status_line`    | string             | Full HTTP status line (e.g., `HTTP/1.1 200 OK`)   |
| `headers`        | [string, string][] | Response header name-value pairs                   |
| `body`           | string             | Response body text, or base64-encoded if binary    |
| `body_is_binary` | boolean            | `true` if body is base64-encoded binary content    |
| `body_truncated` | boolean            | `true` if body was truncated at 8 KB               |

## Status Values

| Status              | Meaning                                      |
|---------------------|----------------------------------------------|
| `200`               | Request forwarded successfully                |
| `502`               | Upstream connection failed                    |
| `MITM`              | CONNECT tunnel established with interception  |
| `502-upstream(...)` | TLS upstream connection failed (MITM mode)    |
| `TLS-ERR(...)`      | Client TLS handshake failed (MITM mode)       |

## Configuration

| Environment Variable | Default           | Description                     |
|----------------------|-------------------|---------------------------------|
| `PROXY_LOG_FILE`     | `/tmp/proxy.log`  | Path to the JSONL log file      |
| `VIEWER_PORT`        | `9999`            | Port the log viewer listens on  |

## Docker Compose

The viewer port is exposed alongside the proxy:

```yaml
ports:
  - "${PROXY_PORT:-8080}:8080"    # proxy
  - "${VIEWER_PORT:-9999}:9999"   # log viewer
```

## OpenAPI Specification

A machine-readable OpenAPI 3.1 spec is available at [`openapi.yaml`](openapi.yaml). It covers all endpoints, query parameters, and response schemas documented below. Use it for code generation, API clients, or importing into tools like Swagger UI or Postman.

## Examples

```bash
# All logs (first page, 50 per page)
curl http://localhost:9999/api/logs

# Page 2, 10 per page
curl "http://localhost:9999/api/logs?page=2&limit=10"

# Only GET requests
curl "http://localhost:9999/api/logs?method=GET"

# Requests containing "example.com"
curl "http://localhost:9999/api/logs?url=example.com"

# Only entries with HIGH severity risks
curl "http://localhost:9999/api/logs?severity=HIGH"

# Time range filter
curl "http://localhost:9999/api/logs?start=2026-03-03T00:00:00Z&end=2026-03-03T23:59:59Z"

# Combined filters
curl "http://localhost:9999/api/logs?method=GET&severity=MEDIUM&limit=20"
```
