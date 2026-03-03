# MITM Web Proxy

A Python HTTP/HTTPS forward proxy with optional TLS interception (man-in-the-middle) and built-in security risk detection. Designed for development, debugging, and traffic inspection.

## Features

- **HTTP forwarding** — proxies plain HTTP requests with full method, URL, and header visibility
- **HTTPS passthrough** — tunnels encrypted connections without inspection via CONNECT
- **MITM interception** — decrypts, logs, and re-encrypts HTTPS traffic using on-the-fly certificate generation
- **Security scanning** — inspects proxied requests for common attack patterns and authentication issues, logging colour-coded warnings in real time
- **Zero-config certificate management** — auto-generates a CA and per-host certificates on first use, caches them on disk

## Requirements

- Python 3.8+
- `cryptography` library (only for MITM mode; installed automatically by the venv setup)
- `curl`, `openssl`, `nc`, `ss` (for the test suite)

## Quick Start

### Passthrough mode (no dependencies)

```bash
python3 proxy.py
```

Starts on port 8080. HTTP requests are forwarded and logged. HTTPS is tunneled without inspection.

### MITM mode

```bash
python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
python3 proxy.py --mitm --no-verify
```

On first run a CA certificate is generated at `certs/ca.pem`. Test it with:

```bash
curl --cacert certs/ca.pem -x http://localhost:8080 https://example.com
```

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

The proxy automatically inspects every proxied request and logs colour-coded warnings when it detects suspicious patterns. Checks run against URLs, headers, and (where visible) request bodies.

### Detection Table

| Category | Severity | Colour | What it detects |
|----------|----------|--------|-----------------|
| SQL Injection | HIGH | Red | `UNION SELECT`, `OR 1=1`, `' OR '`, `DROP TABLE`, `--` comments, `;` chaining |
| XSS | HIGH | Red | `<script>`, `javascript:`, `onerror=`, `onload=`, `eval(`, `document.cookie` |
| Path Traversal | HIGH | Red | `../`, `..%2f`, `..%5c`, `%2e%2e` in URL path |
| Command Injection | HIGH | Red | Backticks, `$(`, `; `, `| `, `&& ` in query params or headers |
| Plaintext Basic Auth | HIGH | Red | `Authorization: Basic` header sent over HTTP |
| Plaintext Bearer Token | HIGH | Red | `Authorization: Bearer` header sent over HTTP |
| Plaintext Body Credentials | HIGH | Red | `password=`, `passwd=`, `pass=`, `credential=` etc. in POST body over HTTP |
| Sensitive Data in URL | MEDIUM | Yellow | `password=`, `secret=`, `api_key=`, `token=` etc. in query string |
| Cleartext Auth Endpoint | MEDIUM | Yellow | HTTP (not HTTPS) request to `/login`, `/auth`, `/signin` |
| Proxy-Authorization | MEDIUM | Yellow | `Proxy-Authorization` header exposing proxy credentials |
| SSRF Indicators | MEDIUM | Yellow | Requests targeting private IPs (`10.x`, `172.16-31.x`, `192.168.x`, `127.x`, `169.254.x`, `localhost`) |
| Suspicious Methods | LOW | Cyan | `TRACE`, `TRACK`, `DEBUG` HTTP methods |

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

## Log Format

```
[TIMESTAMP] CLIENT_IP:PORT  STATUS  METHOD  TARGET
```

| Status | Meaning |
|--------|---------|
| `->` | Request received |
| `200` | Forwarded successfully |
| `502` | Upstream unreachable |
| `MITM` | Decrypted HTTPS request |
| `intercepting` | MITM TLS session established |
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

```bash
bash tests/run_all.sh
```

The test suite bootstraps a venv automatically, runs all test scripts, and prints a TAP-style summary.

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

Run a single test file:

```bash
bash tests/test_security.sh
```

## Project Structure

```
proxy.py              Main proxy server (~430 lines)
mitm_certs.py         CA and per-host certificate generation
requirements.txt      Python dependencies (cryptography)
INSTRUCTIONS.md       Detailed usage guide
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
