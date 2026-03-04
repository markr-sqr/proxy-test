# MITM Web Proxy - Instructions

A Python-based HTTP/HTTPS forward proxy with optional TLS interception (man-in-the-middle) capability, request payload capture, and a web-based log viewer. Designed for development, debugging, and traffic inspection.

---

## Table of Contents

1. [Deployment (Docker — Recommended)](#deployment-docker--recommended)
2. [Alternative: Manual Setup](#alternative-manual-setup)
3. [Quick Start](#quick-start)
4. [Operating Modes](#operating-modes)
5. [Command-Line Reference](#command-line-reference)
6. [Using the Proxy with curl](#using-the-proxy-with-curl)
7. [Using the Proxy with a Browser](#using-the-proxy-with-a-browser)
8. [Using the Proxy System-Wide](#using-the-proxy-system-wide)
9. [Log Viewer](#log-viewer)
10. [Understanding the Log Output](#understanding-the-log-output)
11. [Certificate Management](#certificate-management)
12. [Testing](#testing)
13. [Troubleshooting](#troubleshooting)
14. [Security Considerations](#security-considerations)
15. [Architecture Overview](#architecture-overview)

---

## Deployment (Docker — Recommended)

Docker is the recommended way to deploy the proxy. A single container runs both the proxy and the web-based log viewer with all dependencies pre-installed. No Python venv, Node.js, or manual setup required.

### Prerequisites

- Docker Engine 20.10+ and Docker Compose v2+

### Start the proxy

```bash
docker compose up -d
```

This starts:
- **Proxy** on port `8080` — MITM mode with `--no-verify` by default
- **Log viewer** on port `9999` — web UI at `/ui/logs`, API at `/api/logs`

### Verify it is running

```bash
docker compose ps          # Check container health
docker compose logs -f     # Follow live log output
```

### Test it

```bash
# HTTP request through the proxy
curl -x http://localhost:8080 http://example.com

# HTTPS request (trust the generated CA)
curl --cacert certs/ca.pem -x http://localhost:8080 https://example.com

# View logs in your browser
open http://localhost:9999/ui/logs

# Query the log API
curl http://localhost:9999/api/logs
```

### Configuration

Override defaults with environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PROXY_PORT` | `8080` | Host port for the proxy |
| `VIEWER_PORT` | `9999` | Host port for the log viewer |
| `PROXY_UID` | `1000` | UID the container runs as |
| `PROXY_GID` | `1000` | GID the container runs as |

```bash
PROXY_PORT=3128 VIEWER_PORT=8888 docker compose up -d
```

### Persistent data

The `certs/` directory is bind-mounted from the host, so CA and per-host certificates persist across container restarts. Logs are stored inside the container at `/tmp/proxy.log` and reset on container recreation.

### Common Docker commands

```bash
docker compose up -d          # Start in background
docker compose logs -f        # Follow proxy + viewer logs
docker compose restart        # Restart after config changes
docker compose down           # Stop and remove container
docker compose build          # Rebuild after code changes
docker compose up -d --build  # Rebuild and restart in one step
```

### Passing custom proxy flags

The default entrypoint runs `proxy.py --mitm --no-verify`. To override, edit the `command` in `docker-compose.yml`:

```yaml
services:
  proxy:
    build: .
    command: ["--mitm"]  # e.g., enable upstream TLS verification
```

Or for passthrough mode (no MITM):

```yaml
    command: []  # no flags = passthrough mode
```

---

## Alternative: Manual Setup

If you prefer to run directly on your host without Docker, you need to install dependencies manually.

### Requirements

- Python 3.8+ (with the `venv` module)
- `cryptography` library (only for MITM mode)
- Node.js 18+ (only for the log viewer)
- `curl`, `openssl`, `nc`, `ss` (for the test suite)

### File Overview

```
proxy.py              Main proxy server with payload capture
mitm_certs.py         Certificate generation module (CA + per-host certs)
requirements.txt      Python dependencies (used by venv setup)
Dockerfile            Container image definition (for Docker deployment)
docker-compose.yml    Docker Compose service configuration
entrypoint.sh         Container entrypoint (starts proxy + viewer)
viewer/               Web-based log viewer (Express + TypeScript)
  src/
    index.ts          Viewer server entry point
    types.ts          TypeScript interfaces
    routes/logs.ts    API route handlers
    services/         Log file reading service
    public/logs.html  Log viewer UI
certs/                Auto-generated directory (created on first --mitm run)
  ca.pem              CA certificate (share this with clients)
  ca-key.pem          CA private key (keep this secret, mode 0600)
  hosts/              Cached per-host certificates
.venv/                Python virtual environment (auto-created by test suite)
tests/                Shell-based test suite
```

### Installation

#### Option A: manual venv setup

```bash
cd proxy-test
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

#### Option B: use the setup helper script

```bash
cd proxy-test
source tests/setup_venv.sh
```

This creates the `.venv/` (if it doesn't exist), installs dependencies, and exports a `$PYTHON` variable pointing at `.venv/bin/python3`.

```bash
$PYTHON proxy.py --mitm --no-verify
```

#### Option C: let the test suite do everything

```bash
bash tests/run_all.sh
```

After this, the `.venv/` exists and you can activate it or source the helper.

#### Log viewer (manual)

```bash
cd viewer && npm install && npx tsc && node dist/index.js
```

The viewer runs on port 9999 and reads from `/tmp/proxy.log`.

#### Passthrough mode without a venv

If you only need passthrough mode (no MITM), the proxy has no third-party dependencies:

```bash
python3 proxy.py
```

---

## Quick Start

### Docker (recommended)

```bash
docker compose up -d
curl -x http://localhost:8080 http://example.com
open http://localhost:9999/ui/logs
```

### Manual

All examples below assume you have set up the venv first (see [Alternative: Manual Setup](#alternative-manual-setup)).

```bash
source .venv/bin/activate
```

### Passthrough mode (no TLS inspection)

```bash
python3 proxy.py
```

The proxy starts on port 8080 by default. It forwards HTTP requests and blindly tunnels HTTPS connections without inspecting them.

### MITM mode (TLS interception with logging)

```bash
python3 proxy.py --mitm --no-verify
```

On first run, the proxy generates a CA certificate at `certs/ca.pem`. All HTTPS traffic is decrypted, logged, and re-encrypted transparently.

Test it immediately:

```bash
curl --cacert certs/ca.pem -x http://localhost:8080 https://example.com
```

---

## Operating Modes

### 1. Passthrough Mode (default)

```bash
python3 proxy.py -p 8080
```

**How it works:**

- HTTP requests are received, forwarded to the target server, and the response is relayed back to the client. The proxy logs each request's method and URL.
- HTTPS requests arrive as a `CONNECT` method. The proxy establishes a raw TCP tunnel between the client and the target server. Since the traffic is encrypted end-to-end, the proxy cannot see or log the actual HTTP requests inside the tunnel. It only logs the `CONNECT` target (hostname and port).

**When to use:** When you only need HTTP-level logging, or when you want to proxy traffic without breaking TLS trust chains.

### 2. MITM Mode

```bash
python3 proxy.py --mitm -p 8080
```

**How it works:**

- HTTP requests are handled identically to passthrough mode.
- HTTPS requests are intercepted. When a client sends a `CONNECT` request, the proxy:
  1. Responds with `200 Connection Established` to the client.
  2. Connects to the real upstream server over TLS.
  3. Generates a forged certificate for the target hostname, signed by the proxy's CA.
  4. Performs a TLS handshake with the client using the forged certificate.
  5. Relays decrypted HTTP traffic between client and server, logging every request.

**When to use:** When you need to inspect, log, or debug HTTPS traffic. This is the same approach used by professional tools like mitmproxy, Burp Suite, and Charles Proxy.

**Important:** Clients must trust the proxy's CA certificate (`certs/ca.pem`) for HTTPS interception to work without certificate errors. See [Certificate Management](#certificate-management) for details.

### 3. MITM Mode with --no-verify

```bash
python3 proxy.py --mitm --no-verify -p 8080
```

Same as MITM mode, but the proxy does not verify the upstream server's TLS certificate. This is useful when:

- Your system's CA certificate bundle is missing or incomplete.
- You are testing against servers with self-signed certificates.
- You are in a development environment where upstream cert validation is not important.

**Warning:** This disables a security check. The proxy will connect to any upstream server regardless of certificate validity. Only use this in trusted development environments.

---

## Command-Line Reference

```
usage: proxy.py [-h] [-p PORT] [-b BIND] [--mitm] [--no-verify]
```

| Flag | Default | Description |
|------|---------|-------------|
| `-p`, `--port` | `8080` | Port the proxy listens on. |
| `-b`, `--bind` | `0.0.0.0` | Network address to bind to. Use `127.0.0.1` to restrict to localhost only. Use `0.0.0.0` to accept connections from any interface. |
| `--mitm` | off | Enable TLS interception. Requires the `cryptography` library. Generates CA and per-host certificates automatically. |
| `--no-verify` | off | Skip TLS certificate verification when connecting to upstream servers. Only meaningful with `--mitm`. |
| `-h`, `--help` | | Show help message and exit. |

### Examples

```bash
# Listen on port 9090 instead of 8080
python3 proxy.py -p 9090

# Only accept connections from localhost
python3 proxy.py -b 127.0.0.1

# Full MITM mode on port 3128, localhost only, no upstream verification
python3 proxy.py --mitm --no-verify -b 127.0.0.1 -p 3128

# Passthrough on the default port
python3 proxy.py
```

---

## Using the Proxy with curl

### HTTP requests (any mode)

```bash
curl -x http://localhost:8080 http://example.com
```

### HTTPS requests in passthrough mode

```bash
# Works normally -- the proxy tunnels the encrypted connection
curl -x http://localhost:8080 https://example.com
```

### HTTPS requests in MITM mode

```bash
# Trust the proxy's CA certificate
curl --cacert certs/ca.pem -x http://localhost:8080 https://example.com

# Or skip certificate verification entirely on the client side
curl -k -x http://localhost:8080 https://example.com
```

### Verbose output for debugging

```bash
curl -v --cacert certs/ca.pem -x http://localhost:8080 https://example.com
```

This shows the full TLS handshake, including the proxy's forged certificate details.

### Downloading a file through the proxy

```bash
curl --cacert certs/ca.pem -x http://localhost:8080 -o file.zip https://example.com/file.zip
```

### POST request through the proxy

```bash
curl --cacert certs/ca.pem -x http://localhost:8080 \
  -X POST -d '{"key":"value"}' -H "Content-Type: application/json" \
  https://httpbin.org/post
```

---

## Using the Proxy with a Browser

### Firefox

1. Open **Settings** > **General** > scroll to **Network Settings** > click **Settings**.
2. Select **Manual proxy configuration**.
3. Set **HTTP Proxy** to `127.0.0.1`, **Port** to `8080`.
4. Check **Also use this proxy for HTTPS**.
5. Click **OK**.

To trust the CA certificate (required for MITM mode):

1. Open **Settings** > **Privacy & Security** > scroll to **Certificates** > click **View Certificates**.
2. Go to the **Authorities** tab > click **Import**.
3. Select `certs/ca.pem`.
4. Check **Trust this CA to identify websites** > click **OK**.

### Chrome / Chromium

Chrome uses the system certificate store. See [System-Wide Trust](#adding-the-ca-to-the-system-trust-store) below. For proxy settings, launch Chrome with:

```bash
google-chrome --proxy-server="http://127.0.0.1:8080"
```

---

## Using the Proxy System-Wide

Set the standard environment variables to route all HTTP/HTTPS traffic through the proxy:

```bash
export http_proxy=http://127.0.0.1:8080
export https_proxy=http://127.0.0.1:8080
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
```

To exclude certain hosts from proxying:

```bash
export no_proxy=localhost,127.0.0.1,.internal.corp
```

To unset:

```bash
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY no_proxy
```

Most command-line tools (curl, wget, pip, npm, apt) respect these environment variables automatically.

---

## Log Viewer

The proxy includes a web-based log viewer that runs alongside the proxy (started automatically in Docker, or manually via `node viewer/dist/index.js`).

### Web UI

Open `http://localhost:9999/ui/logs` in your browser. The UI provides:

- **Filterable table** — filter by method, URL substring, severity, and time range
- **Content-type badges** — each row shows the request content type (e.g., `image/png`, `application/json`) next to the method pill for quick identification
- **Expandable detail rows** — click any row to see:
  - Security risk details with severity badges
  - Full request line, headers, and body
  - Image previews for image payloads (rendered inline)
  - Auto-decoded data: base64, JWT tokens, URL-encoded forms, hex-encoded content
- **Auto-refresh** — toggle 5-second polling to watch requests in real time
- **Pagination** — navigate through large log files

### REST API

See [LOG_SERVICE.md](LOG_SERVICE.md) for full API documentation including query parameters, response schema, and examples.

```bash
# Quick examples
curl http://localhost:9999/api/logs                        # All logs
curl "http://localhost:9999/api/logs?method=POST"          # POST requests only
curl "http://localhost:9999/api/logs?severity=HIGH"        # High-risk entries
curl "http://localhost:9999/api/logs?url=example.com"      # URL search
```

---

## Understanding the Log Output

Every proxied request is logged to the console and to a JSONL file (`/tmp/proxy.log`) with full payload data.

### Log format

```
[TIMESTAMP] CLIENT_IP:PORT  STATUS  METHOD  TARGET
```

### Status codes in the log

| Status | Meaning |
|--------|---------|
| `->` | Request received, processing started. |
| `200` | Request successfully forwarded to upstream. |
| `502` | Could not connect to the upstream server (Bad Gateway). |
| `intercepting` | MITM TLS interception established for this connection. |
| `MITM` | Decrypted HTTPS request logged (only in MITM mode). |
| `502-upstream(...)` | Upstream TLS connection failed (details in parentheses). |
| `TLS-ERR(...)` | Client-side TLS handshake failed (details in parentheses). |

### Example: passthrough mode

```
[2026-03-03 14:00:01] 127.0.0.1:52340  ->   GET      http://example.com/
[2026-03-03 14:00:01] 127.0.0.1:52340  200  GET      http://example.com/
[2026-03-03 14:00:05] 127.0.0.1:52344  ->   CONNECT  example.com:443
[2026-03-03 14:00:05] 127.0.0.1:52344  200  CONNECT  example.com:443
```

Note: In passthrough mode, HTTPS shows only the `CONNECT` target. The actual request paths (e.g., `/api/data`) are encrypted and invisible to the proxy.

### Example: MITM mode

```
[2026-03-03 14:00:01] 127.0.0.1:52340  ->            GET      http://example.com/
[2026-03-03 14:00:01] 127.0.0.1:52340  200           GET      http://example.com/
[2026-03-03 14:00:05] 127.0.0.1:52344  ->            CONNECT  example.com:443
[2026-03-03 14:00:05] 127.0.0.1:52344  intercepting  MITM     example.com:443
[2026-03-03 14:00:05] 127.0.0.1:52344  MITM          GET      https://example.com/
[2026-03-03 14:00:06] 127.0.0.1:52344  MITM          POST     https://example.com/api/login
```

In MITM mode, you can see the full HTTPS request method and path after the `MITM` status tag.

---

## Certificate Management

### How certificates work in MITM mode

On the first run with `--mitm`, the proxy generates:

1. **A CA (Certificate Authority) certificate** (`certs/ca.pem`) and its private key (`certs/ca-key.pem`). This CA is valid for 10 years. It is reused across restarts.

2. **Per-host certificates** (e.g., `certs/hosts/example.com.pem`). These are generated on demand the first time a host is accessed, signed by the CA, and cached on disk for 1 year. They are reused across restarts.

### Trusting the CA certificate

For MITM mode to work without certificate warnings, the client must trust the proxy's CA. There are several ways to do this:

#### Per-command (curl)

```bash
curl --cacert certs/ca.pem -x http://localhost:8080 https://example.com
```

#### Per-command (wget)

```bash
wget --ca-certificate=certs/ca.pem -e use_proxy=yes -e https_proxy=http://localhost:8080 https://example.com
```

#### Per-command (Python requests)

```python
import requests

proxies = {"http": "http://localhost:8080", "https": "http://localhost:8080"}
response = requests.get("https://example.com", proxies=proxies, verify="certs/ca.pem")
```

#### Adding the CA to the system trust store

**Fedora / RHEL / CentOS:**

```bash
sudo cp certs/ca.pem /etc/pki/ca-trust/source/anchors/mitm-proxy-ca.pem
sudo update-ca-trust
```

**Ubuntu / Debian:**

```bash
sudo cp certs/ca.pem /usr/local/share/ca-certificates/mitm-proxy-ca.crt
sudo update-ca-certificates
```

**macOS:**

```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain certs/ca.pem
```

After adding the CA to the system trust store, most applications will trust the proxy's certificates automatically without needing `--cacert` or `verify=` flags.

#### Removing the CA from the system trust store

**Fedora / RHEL / CentOS:**

```bash
sudo rm /etc/pki/ca-trust/source/anchors/mitm-proxy-ca.pem
sudo update-ca-trust
```

**Ubuntu / Debian:**

```bash
sudo rm /usr/local/share/ca-certificates/mitm-proxy-ca.crt
sudo update-ca-certificates --fresh
```

**macOS:**

```bash
sudo security delete-certificate -c "MITM Dev Proxy CA" /Library/Keychains/System.keychain
```

### Regenerating certificates

To start fresh with a new CA (e.g., if the CA expired or was compromised):

```bash
rm -rf certs/
source .venv/bin/activate   # or: source tests/setup_venv.sh
python3 proxy.py --mitm
```

A new CA and empty host cache are created automatically. Remember to re-trust the new `certs/ca.pem` in any clients or system trust stores.

To regenerate only the per-host certificates (keeping the same CA):

```bash
rm -rf certs/hosts/
python3 proxy.py --mitm
```

### Inspecting certificates

View the CA certificate details:

```bash
openssl x509 -in certs/ca.pem -text -noout
```

View a per-host certificate:

```bash
openssl x509 -in certs/hosts/example.com.pem -text -noout
```

Verify a per-host certificate was signed by the CA:

```bash
openssl verify -CAfile certs/ca.pem certs/hosts/example.com.pem
```

---

## Testing

The project includes a shell-based test suite in `tests/`. It validates proxy startup, HTTP forwarding, HTTPS passthrough, MITM interception, certificate generation, and error handling.

### Running the full suite

```bash
bash tests/run_all.sh
```

On the first run this creates a `.venv/`, installs dependencies, then executes every `tests/test_*.sh` script. Subsequent runs reuse the cached venv. The runner prints TAP-style output (`ok` / `not ok`) and exits non-zero if any test fails.

### Running a single test file

```bash
bash tests/test_mitm.sh
```

Each test script is self-contained: it sources `helpers.sh` (which bootstraps the venv), starts its own proxy instance on a random high port, runs its assertions, and tears everything down via an EXIT trap.

### Test scripts overview

| Script | What it tests | Tests |
|--------|---------------|-------|
| `test_startup.sh` | CLI flags, listening message, `--mitm` startup, `--help` | 7 |
| `test_http.sh` | HTTP GET/POST forwarding, log output, 502 on unreachable host | 6 |
| `test_https_passthrough.sh` | CONNECT tunnel, log verification, no MITM leakage | 4 |
| `test_mitm.sh` | Cert generation, HTTPS interception, per-host caching, CA reuse | 9 |
| `test_certs.sh` | x509 validity, CA:TRUE/FALSE, CN, SAN, key permissions, chain verification | 7 |
| `test_errors.sh` | 502 on unreachable host, 400 on malformed request, CONNECT 502 | 3 |

### How the venv is managed

- `tests/setup_venv.sh` is sourced by `helpers.sh` at the start of every test script.
- It creates `.venv/` in the project root (if missing) and runs `pip install -r requirements.txt`.
- A stamp file (`.venv/.requirements.stamp`) stores the md5 hash of `requirements.txt`. The install step is skipped when the hash matches, making repeated runs fast.
- All proxy processes are launched using `$PYTHON` (the venv interpreter), so system Python is never modified.

### Adding a new test

1. Create `tests/test_<name>.sh`.
2. Start with the standard preamble:
   ```bash
   #!/usr/bin/env bash
   SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
   source "$SCRIPT_DIR/helpers.sh"
   ```
3. Use `start_proxy` / `stop_proxy` and the assertion helpers (`assert_eq`, `assert_contains`, `assert_matches`, `assert_not_contains`).
4. End with `print_summary` and `exit "$(test_exit_code; echo $?)"`.
5. `run_all.sh` picks up any `test_*.sh` file automatically.

---

## Troubleshooting

### Docker: container exits immediately

Check the logs for errors:

```bash
docker compose logs
```

Common causes: port conflict (another process using 8080 or 9999), or permission issues with the `certs/` volume.

### Docker: port conflict

```bash
# Use different host ports
PROXY_PORT=3128 VIEWER_PORT=8888 docker compose up -d
```

### Docker: rebuild after code changes

```bash
docker compose up -d --build
```

### "Address already in use" on startup (manual mode)

Another process is using the port. Either stop the other process or choose a different port:

```bash
python3 proxy.py -p 9090
```

Find what is using the port:

```bash
ss -tlnp | grep 8080
# or
lsof -i :8080
```

### HTTPS returns "Connection reset by peer" in MITM mode

**Cause:** The proxy cannot establish a TLS connection to the upstream server. This usually means the system CA bundle is missing or incomplete.

**Fix:** Use `--no-verify` to skip upstream certificate verification:

```bash
python3 proxy.py --mitm --no-verify
```

### curl says "SSL certificate problem" or "unable to get local issuer certificate"

**Cause:** The client does not trust the proxy's CA certificate.

**Fix:** Either pass the CA cert explicitly:

```bash
curl --cacert certs/ca.pem -x http://localhost:8080 https://example.com
```

Or skip verification on the client side (less secure):

```bash
curl -k -x http://localhost:8080 https://example.com
```

Or add the CA to your system trust store (see [Certificate Management](#adding-the-ca-to-the-system-trust-store)).

### No log output appears

Python buffers stdout when it is piped. Run with unbuffered output:

```bash
python3 -u proxy.py --mitm
```

Or set the environment variable:

```bash
PYTHONUNBUFFERED=1 python3 proxy.py --mitm
```

### MITM mode does not log HTTPS request paths

Ensure you are running with `--mitm`. Without it, the proxy operates in passthrough mode and can only see CONNECT targets, not the encrypted request paths.

### "ModuleNotFoundError: No module named 'cryptography'"

Set up the virtual environment and install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Or let the test suite do it for you:

```bash
source tests/setup_venv.sh
$PYTHON proxy.py --mitm
```

### Connection hangs or times out

The proxy has a 30-second idle timeout on connections. If neither side sends data within 30 seconds, the connection is closed. This is by design to prevent resource leaks from abandoned connections.

The upstream connection timeout is 10 seconds. If the target server does not respond within 10 seconds, the proxy returns a 502 Bad Gateway.

---

## Security Considerations

This tool is intended for **development and debugging only**. Keep the following in mind:

1. **The CA private key (`certs/ca-key.pem`) is sensitive.** Anyone with this key can forge certificates for any domain. It is created with mode 0600 (owner-read/write only). Do not share it.

2. **Do not add the CA to production trust stores.** Only add it to development machines. Remove it when you are done.

3. **`--no-verify` disables upstream security.** The proxy will connect to any server without verifying its identity. An attacker could intercept the proxy-to-server connection. Only use this on trusted networks.

4. **Binding to `0.0.0.0` exposes the proxy to the network.** If you are on a shared or public network, bind to `127.0.0.1` instead:

   ```bash
   python3 proxy.py -b 127.0.0.1 --mitm
   ```

5. **The proxy does not authenticate clients.** Anyone who can reach the proxy port can use it. On shared machines, restrict access with firewall rules or bind to localhost.

6. **Per-host certificates are cached on disk.** The `certs/hosts/` directory may reveal which sites you have visited through the proxy. Delete it if this is a concern:

   ```bash
   rm -rf certs/hosts/
   ```

---

## Architecture Overview

### Files

| File | Purpose |
|------|---------|
| `proxy.py` | Main proxy server. Handles HTTP forwarding, CONNECT tunneling, MITM interception, payload capture, and JSONL logging. Uses Python's `socket`, `select`, `ssl`, and `threading` modules. |
| `mitm_certs.py` | Certificate generation. Creates the root CA on first run, generates per-host certificates on demand, and provides SSL context factories. Uses the `cryptography` library. |
| `requirements.txt` | Python dependencies for the project (`cryptography`). Used by the venv setup. |
| `Dockerfile` | Container image definition. Bundles Python, Node.js, proxy, and viewer into a single image. |
| `docker-compose.yml` | Docker Compose service configuration. Exposes proxy (8080) and viewer (9999) ports, bind-mounts `certs/`. |
| `entrypoint.sh` | Container entrypoint. Starts both the proxy and viewer as background processes, handles graceful shutdown. |
| `viewer/src/index.ts` | Log viewer Express server. Serves the web UI and REST API on port 9999. |
| `viewer/src/routes/logs.ts` | API route handler for `/api/logs` with filtering and pagination. |
| `viewer/src/public/logs.html` | Log viewer web UI. Renders log table with payload inspection, image previews, and auto-decoding. |
| `tests/setup_venv.sh` | Venv bootstrap script. Creates `.venv/`, installs deps, exports `$PYTHON`. |
| `tests/helpers.sh` | Shared test utilities. Sources the venv setup, provides proxy start/stop, TAP assertion helpers, and cleanup traps. |
| `tests/run_all.sh` | Test runner. Executes all `test_*.sh` scripts and summarizes pass/fail counts. |
| `tests/test_*.sh` | Individual test scripts (7 files). Each is self-contained and sources `helpers.sh`. |

### Request flow: passthrough HTTPS

```
Client                    Proxy                     Server
  |  -- CONNECT host:443 -->  |                        |
  |  <-- 200 Established ---  |                        |
  |  ===== encrypted TCP tunnel (blind relay) ========  |
  |  <------------- TLS end-to-end ------------------>  |
```

The proxy sees only the CONNECT target. All data inside the tunnel is opaque.

### Request flow: MITM HTTPS

```
Client                    Proxy                        Server
  |  -- CONNECT host:443 -->  |                           |
  |  <-- 200 Established ---  |                           |
  |                           |  -- TLS connect --------> |
  |                           |  <-- TLS established ---  |
  |  <-- TLS handshake ----   |  (forged cert for host)   |
  |  -- TLS established -->   |                           |
  |  -- GET /path HTTP/1.1 -> |  (decrypted, logged)      |
  |                           |  -- GET /path HTTP/1.1 -> |
  |                           |  <-- 200 OK ------------- |
  |  <-- 200 OK ------------- |  (decrypted, relayed)     |
```

The proxy terminates TLS on both sides. It sees all HTTP traffic in plaintext and logs each request line.

### Threading model

Each client connection is handled in its own daemon thread. The main thread only accepts connections. Daemon threads ensure clean shutdown on Ctrl+C.

### Certificate generation details

| Component | Algorithm | Validity | Notes |
|-----------|-----------|----------|-------|
| CA key | RSA 2048 | N/A | Generated once, reused across restarts |
| CA cert | SHA-256 | 10 years | BasicConstraints: CA=True, pathlen=0 |
| Host key | EC P-256 (SECP256R1) | N/A | Fast generation for on-the-fly use |
| Host cert | SHA-256 | 1 year | SAN with DNSName, signed by CA |

Per-host certificates are cached in `certs/hosts/` and reused until deleted or expired.
