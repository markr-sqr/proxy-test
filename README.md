# MITM Web Proxy

A Python HTTP/HTTPS forward proxy with optional TLS interception (man-in-the-middle), built-in security risk detection, request payload capture, and a web-based log viewer. Designed for development, debugging, and traffic inspection.

## Features

- **HTTP forwarding** — proxies plain HTTP requests with full method, URL, and header visibility
- **HTTPS passthrough** — tunnels encrypted connections without inspection via CONNECT
- **MITM interception** — decrypts, logs, and re-encrypts HTTPS traffic using on-the-fly certificate generation
- **Security scanning** — inspects proxied requests for common attack patterns and authentication issues, plus response headers for missing security headers, logging colour-coded warnings in real time
- **Payload capture** — logs full request and response headers and bodies (up to 8 KB each), with auto-detection of binary content
- **Web log viewer** — browser-based UI with filtering, sortable columns, pagination, scope-based target filtering, payload inspection, settings/dashboard modals, and auto-decoding of base64, JWT, URL-encoded, and hex-encoded data
- **Zero-config certificate management** — auto-generates a CA and per-host certificates on first use, caches them on disk

## Quick Start (Docker — Recommended)

Docker is the recommended way to run the proxy. It bundles the proxy, log viewer, and all dependencies in a single container.

```bash
docker compose up -d
```

This starts:
- **Proxy** on port `8080` (MITM mode with `--no-verify` by default)
- **Log viewer** on port `9999`

Test it immediately:

```bash
# Send a request through the proxy
curl -x http://localhost:8080 http://example.com

# View logs in your browser
open http://localhost:9999/ui/logs

# Or query the API directly
curl http://localhost:9999/api/logs
```

For HTTPS interception, trust the generated CA certificate:

```bash
curl --cacert certs/ca.pem -x http://localhost:8080 https://example.com
```

### Docker configuration

Override defaults with environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PROXY_PORT` | `8080` | Host port for the proxy |
| `VIEWER_PORT` | `9999` | Host port for the log viewer |
| `PROXY_UID` | `1001` | UID the container runs as |
| `PROXY_GID` | `972` | GID the container runs as |

```bash
# Example: custom ports
PROXY_PORT=3128 VIEWER_PORT=8888 docker compose up -d
```

The `certs/` directory is bind-mounted, so generated CA and host certificates persist across container restarts.

### Docker commands

```bash
docker compose up -d          # Start in background
docker compose logs -f        # Follow proxy logs
docker compose restart        # Restart after config changes
docker compose down           # Stop and remove container
docker compose build          # Rebuild after code changes
```

## Alternative: Manual Setup (without Docker)

If you prefer to run directly on your host without Docker, you need Python 3.8+ and optionally Node.js 18+ (for the log viewer).

### Proxy only (passthrough mode — no dependencies)

```bash
python3 proxy.py
```

### Proxy with MITM mode

```bash
python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
python3 proxy.py --mitm --no-verify
```

### Proxy + log viewer (manual)

```bash
# Terminal 1: start the proxy
source .venv/bin/activate
python3 proxy.py --mitm --no-verify

# Terminal 2: start the log viewer
cd viewer && npm install && npx tsc && node dist/index.js
```

On first run a CA certificate is generated at `certs/ca.pem`. Test it with:

```bash
curl --cacert certs/ca.pem -x http://localhost:8080 https://example.com
```

### Requirements (manual setup)

- Python 3.8+
- `cryptography` library (only for MITM mode; installed automatically by the venv setup)
- Node.js 18+ (only for the log viewer)
- `curl`, `openssl`, `nc`, `ss` (for the test suite)

## Command-Line Reference

```
usage: proxy.py [-h] [-p PORT] [-b BIND] [--mitm] [--no-verify]
```

| Flag | Default | Description |
|------|---------|-------------|
| `-p`, `--port` | `8080` | Port to listen on |
| `-b`, `--bind` | `0.0.0.0` | Bind address (`127.0.0.1` for localhost only) |
| `--mitm` | off | Enable TLS interception |
| `--no-verify` | off | Skip upstream TLS certificate verification (use with `--mitm`) |

## Operating Modes

### 1. Passthrough (default)

HTTP requests are forwarded with full logging. HTTPS uses a blind TCP tunnel — the proxy sees only the CONNECT target (host:port), not the encrypted content.

```
Client ── CONNECT host:443 ──> Proxy ══ encrypted tunnel ══> Server
```

### 2. MITM (`--mitm`)

HTTPS traffic is decrypted and re-encrypted using forged per-host certificates signed by the proxy's CA. The proxy logs every request method and path in the clear.

```
Client ── TLS (forged cert) ──> Proxy ── TLS (real cert) ──> Server
                                  │
                            logs + scans
                          decrypted traffic
```

Clients must trust `certs/ca.pem` for this to work without certificate warnings.

### 3. MITM + `--no-verify`

Same as MITM but the proxy skips certificate verification when connecting upstream. Useful for self-signed certs or incomplete CA bundles in dev environments.

## Security Risk Detection

The proxy automatically inspects every proxied request and response, logging colour-coded warnings when it detects suspicious patterns. Request checks run against URLs and bodies; response checks inspect headers for missing security headers (HTML responses only).

### Request Detection

| Category | Severity | What it detects |
|----------|----------|-----------------|
| SQL Injection | HIGH | `UNION SELECT`, `OR 1=1`, `' OR '`, `DROP TABLE`, `;--` comments |
| XSS | HIGH | `<script>`, `javascript:`, `onerror=`, `onload=`, `eval(`, `document.cookie` |
| Path Traversal | HIGH | `../`, `..%2f`, `..%5c`, `%2e%2e` in URL path |
| Command Injection | HIGH | Backtick commands, `$(`, `&&`, `|` piping |
| Plaintext Basic Auth | HIGH | `Authorization: Basic` header sent over HTTP |
| Plaintext Bearer Token | HIGH | `Authorization: Bearer` header sent over HTTP |
| Plaintext Body Credentials | HIGH | `password=`, `passwd=`, `pass=`, `credential=` etc. in POST body over HTTP |
| Sensitive Data in URL | MEDIUM | `password=`, `secret=`, `api_key=`, `token=` etc. in query string |
| Cleartext Auth Endpoint | MEDIUM | HTTP (not HTTPS) request to `/login`, `/auth`, `/signin` |
| Proxy-Authorization | MEDIUM | `Proxy-Authorization` header exposing proxy credentials |
| SSRF Indicators | MEDIUM | Requests targeting private IPs (`10.x`, `172.16-31.x`, `192.168.x`, `127.x`, `169.254.x`, `localhost`) |
| Suspicious Methods | LOW | `TRACE`, `TRACK`, `DEBUG` HTTP methods |

### Response Security Header Detection

Checked on HTML responses (`Content-Type: text/html`) only:

| Missing Header | Severity | Notes |
|----------------|----------|-------|
| `Strict-Transport-Security` | HIGH | HTTPS responses only |
| `Content-Security-Policy` | MEDIUM | |
| `X-Content-Type-Options` | LOW | |
| `X-Frame-Options` | LOW | |
| `Referrer-Policy` | LOW | |
| `Permissions-Policy` | LOW | |

### Visibility by Mode

| Data available | HTTP | MITM HTTPS | Passthrough HTTPS |
|----------------|------|------------|-------------------|
| URL + query string | Full | Full | Host:port only |
| HTTP method | Yes | Yes | CONNECT only |
| Request headers | Yes | Yes | No |
| Request body | Yes (initial fragment) | Yes | No |
| Security scanning | Full | Full | SSRF check on CONNECT target |

### Example Log Output

```
[2026-03-03 14:00:05] 127.0.0.1:52344  ->   GET  http://example.com/search?q=1'+OR+'1'='1
  ⚠ [HIGH] SQL injection pattern: "' OR '"
[2026-03-03 14:00:06] 127.0.0.1:52348  ->   POST http://example.com/login
  ⚠ [HIGH] Plaintext HTTP Basic credentials in Authorization header
  ⚠ [MEDIUM] Cleartext request to authentication endpoint
```

HIGH warnings appear in bright red, MEDIUM in yellow, LOW in cyan.

## Log Viewer

The log viewer runs on port 9999 (configurable via `VIEWER_PORT`) and provides:

- **Web UI** at `/ui/logs` — full-width table with sortable columns, expandable detail rows, content-type badges, request and response payload inspection, image previews, and auto-decoding of encoded data
- **Settings modal** — configurable auto-refresh interval, font size, rows per page, compact view (persisted to localStorage)
- **Dashboard modal** — traffic over time, requests by method, status codes, top targets, risk breakdown (pure CSS charts)
- **Scope modal** — wildcard target filtering with per-row quick-add button; filters take effect immediately
- **REST API** at `/api/logs` — paginated, filterable JSON endpoint

See [LOG_SERVICE.md](LOG_SERVICE.md) for full API documentation.

## Log Format

### Console output

```
[TIMESTAMP] CLIENT_IP:PORT  STATUS  METHOD  TARGET
```

### JSONL file (`/tmp/proxy.log`)

Each request is also logged as a JSON line with full payload data:

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | string | ISO 8601 timestamp (UTC) |
| `client_ip` | string | Client IP address |
| `client_port` | int | Client source port |
| `method` | string | HTTP method |
| `target` | string | Full request URL or `host:port` for CONNECT |
| `status` | string | HTTP status code (`200`, `404`, `502`, etc.) or `MITM` for tunnel setup |
| `risks` | Risk[] | Detected security risks (request + response) |
| `payload` | Payload? | Request payload (headers + body), if available |
| `response` | Response? | Response payload (status line + headers + body), if available |

### Payload object

| Field | Type | Description |
|-------|------|-------------|
| `request_line` | string | Full HTTP request line |
| `headers` | [string, string][] | Header name-value pairs |
| `body` | string | Request body (UTF-8 text, or base64 for binary) |
| `body_is_binary` | boolean | Whether body is base64-encoded binary |
| `body_truncated` | boolean | Whether body was truncated at 8 KB |

### Response object

| Field | Type | Description |
|-------|------|-------------|
| `status_line` | string | Full HTTP status line (e.g., `HTTP/1.1 200 OK`) |
| `headers` | [string, string][] | Response header name-value pairs |
| `body` | string | Response body (UTF-8 text, or base64 for binary) |
| `body_is_binary` | boolean | Whether body is base64-encoded binary |
| `body_truncated` | boolean | Whether body was truncated at 8 KB |

### Status values

| Status | Meaning |
|--------|---------|
| `200`, `301`, `404`, etc. | Actual HTTP status code from upstream |
| `502` | Upstream unreachable |
| `MITM` | CONNECT tunnel established with interception |
| `502-upstream(...)` | Upstream TLS failure |
| `TLS-ERR(...)` | Client TLS handshake failure |

## Certificate Management

Certificates are generated automatically on first use and cached on disk:

```
certs/
  ca.pem              CA certificate (share with clients)
  ca-key.pem          CA private key (mode 0600, keep secret)
  hosts/
    example.com.pem   Per-host cert + key (auto-generated, cached)
```

| Component | Algorithm | Validity |
|-----------|-----------|----------|
| CA key | RSA 2048 | — |
| CA cert | SHA-256 | 10 years |
| Host key | EC P-256 | — |
| Host cert | SHA-256 | 1 year |

To regenerate everything: `rm -rf certs/` and restart with `--mitm`.

## Testing

The project has two test suites: a legacy bash/TAP suite (52 tests) and a comprehensive pytest suite (75 tests) covering sensitive data extraction, security detection, proxy core behaviour, viewer API, and browser UI.

### Pytest Suite (Recommended)

```bash
# 1. One-time setup
bash tests/setup_test_venv.sh

# 2. Smoke tests (~30 s, stops on first failure)
sg docker "bash tests/run_smoke.sh"

# 3. Full regression suite (~2-3 min)
sg docker "bash tests/run_regression.sh"
```

Reports are written to `tests/reports/` (HTML + JUnit XML). See [TEST_STRATEGY.md](TEST_STRATEGY.md) for the full testing strategy, test matrix, architecture, fixture reference, and critical success factors.

### Legacy Bash Suite

```bash
bash tests/run_all.sh
```

| Test file | Tests | Coverage |
|-----------|-------|----------|
| `test_startup.sh` | 7 | CLI flags, bind address, MITM startup, help |
| `test_http.sh` | 6 | HTTP GET/POST forwarding, logging, 502 errors |
| `test_https_passthrough.sh` | 4 | CONNECT tunnel, log format, no MITM leakage |
| `test_mitm.sh` | 9 | Cert generation, interception, caching, CA reuse |
| `test_certs.sh` | 7 | x509 validity, CA constraints, SAN, key permissions |
| `test_errors.sh` | 3 | Unreachable host, malformed request, CONNECT errors |
| `test_security.sh` | 16 | All security checks, false positive verification |
| **Total** | **52** | |

## Project Structure

```
proxy.py              Main proxy server with payload capture
mitm_certs.py         CA and per-host certificate generation
requirements.txt      Python dependencies (cryptography)
Dockerfile            Container image definition
docker-compose.yml    Docker Compose service configuration
entrypoint.sh         Container entrypoint (starts proxy + viewer)
.dockerignore         Docker build exclusions
INSTRUCTIONS.md       Detailed usage guide
LOG_SERVICE.md        Log viewer API documentation
viewer/               Web-based log viewer (Express + TypeScript)
  src/
    index.ts          Viewer server entry point
    types.ts          TypeScript interfaces (LogEntry, Payload, Risk)
    routes/logs.ts    API route handlers
    services/         Log file reading service
    public/logs.html  Log viewer UI (HTML/CSS/JS)
  package.json        Node.js dependencies
  tsconfig.json       TypeScript configuration
tests/
  run_all.sh          Test runner
  helpers.sh          Shared test utilities (TAP assertions, proxy management)
  setup_venv.sh       Venv bootstrap
  test_*.sh           Test scripts (7 files)
```

## Security Considerations

- **`certs/ca-key.pem` is sensitive** — anyone with this key can forge certificates for any domain. It is created with mode 0600.
- **Do not add the CA to production trust stores.** Use it only on development machines and remove it when done.
- **`--no-verify` disables upstream certificate validation.** Only use on trusted networks.
- **Bind to `127.0.0.1` on shared networks** — the proxy does not authenticate clients.

See [INSTRUCTIONS.md](INSTRUCTIONS.md) for detailed setup guides, browser configuration, system-wide proxy setup, and troubleshooting.
