# Log Viewer Service

A JSON API that exposes structured proxy logs for querying. Runs on port **9999** inside the same container as the proxy.

## How It Works

The proxy writes every request as a JSON line to `/tmp/proxy.log` (configurable via `PROXY_LOG_FILE` env var). The log viewer reads this file and serves it through a REST API with filtering and pagination.

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
      "method": "GET",
      "target": "http://example.com/",
      "status": "200",
      "risks": []
    },
    {
      "timestamp": "2026-03-03T21:55:13.953356+00:00",
      "client_ip": "172.24.0.1",
      "client_port": 43754,
      "method": "GET",
      "target": "http://example.com/?password=secret",
      "status": "200",
      "risks": [
        {
          "severity": "MEDIUM",
          "description": "Sensitive data in URL: password="
        }
      ]
    }
  ]
}
```

## Log Entry Schema

Each entry in the JSONL file (and in API responses) has the following fields:

| Field         | Type     | Description                                    |
|---------------|----------|------------------------------------------------|
| `timestamp`   | string   | ISO 8601 timestamp (UTC)                       |
| `client_ip`   | string   | Client IP address                              |
| `client_port` | int      | Client source port                             |
| `method`      | string   | HTTP method (`GET`, `POST`, `CONNECT`, etc.)   |
| `target`      | string   | Full request URL or `host:port` for CONNECT    |
| `status`      | string   | Result status (`200`, `502`, `MITM`, etc.)     |
| `risks`       | Risk[]   | Detected security risks (may be empty)         |

### Risk Object

| Field         | Type   | Description                        |
|---------------|--------|------------------------------------|
| `severity`    | string | `HIGH`, `MEDIUM`, or `LOW`         |
| `description` | string | Human-readable risk description    |

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
