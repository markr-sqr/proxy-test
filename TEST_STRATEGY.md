# Test Strategy

Automated test suite for the MITM web proxy, covering the proxy engine (`proxy.py`), certificate generation (`mitm_certs.py`), and the log viewer (`viewer/`).

---

## Quick Start

```bash
# 1. One-time setup — create venv, install deps, install Playwright browser
bash tests/setup_test_venv.sh

# 2. Run smoke tests (~30 s, stops on first failure)
sg docker "bash tests/run_smoke.sh"

# 3. Run full regression suite (~2-3 min)
sg docker "bash tests/run_regression.sh"
```

**Prerequisites:** Docker running, Python 3.10+, network access.

**`sg docker` prefix** is needed for steps 2-3 if your shell doesn't have the
`docker` group active. See [Section 6.2](#62-docker-socket-permissions) for details.

**Reports** are written after each run to `tests/reports/`:

| Run | HTML (open in browser) | JUnit XML (feed to CI) |
|-----|------------------------|------------------------|
| Smoke | `tests/reports/smoke-report.html` | `tests/reports/smoke-junit.xml` |
| Regression | `tests/reports/regression-report.html` | `tests/reports/regression-junit.xml` |

---

## 1. Goals

| Goal | How it is met |
|------|---------------|
| Detect regressions in proxy forwarding, MITM interception, and logging | Integration tests run against a real Docker container |
| Validate all 16 sensitive-data extraction patterns | Dedicated test per pattern type, checked end-to-end via JSONL logs |
| Validate all 7 attack-pattern detectors | Dedicated test per detector with expected severity |
| Verify viewer API filtering, pagination, and resilience | HTTP-level API tests against the running viewer |
| Verify viewer UI rendering and interactivity | Playwright browser tests against the HTML frontend |
| Fast inner-loop feedback on pure logic | Unit tests import `proxy.py` directly, no container needed |
| Prevent deployment of broken builds | Smoke suite (`-x` fail-fast) gates longer regression run |

---

## 2. Test Pyramid

```
                  ┌──────────────┐
                  │  UI / E2E    │  4 Playwright tests
                  │  (browser)   │
                  ├──────────────┤
                  │ Integration  │  53 tests (smoke + regression)
                  │ (container)  │  against Docker, upstream server, viewer API
                  ├──────────────┤
                  │    Unit      │  21 tests (5 function groups)
                  │  (no infra)  │  pure Python, sub-second
                  └──────────────┘
```

**Total: 75 pytest tests** across 7 test files.

---

## 3. Test Types

### 3.1 Unit Tests — `tests/regression/test_helpers.py`

**What:** Pure-Python tests that import functions directly from `proxy.py` without starting any process or container.

**Why:** Fastest possible feedback on core logic. These run in <1 s and need no Docker, no network.

**Functions under test:**

| Function | Tests | What is validated |
|----------|-------|-------------------|
| `_parse_headers_list()` | 4 | Standard headers, no-space colon, empty input, values containing colons |
| `_encode_body()` | 4 | UTF-8 text, binary (base64), truncation at 8192 bytes, empty body |
| `_get_content_length()` | 3 | Present value, missing header, case-insensitive match |
| `_b64url_decode()` | 3 | Standard decode, padding restoration, URL-safe character translation |
| `_luhn_check()` | 7 | Valid Visa/Mastercard, invalid digit, too short/long, spaces, dashes |

**Execution:**
```bash
# Directly (no container)
.venv-test/bin/python -m pytest tests/regression/test_helpers.py -v
```

### 3.2 Smoke Tests — `tests/smoke/test_smoke.py`

**What:** 9 fast sanity checks that the containerised proxy is alive and its core features work. Designed to run with `-x` (stop on first failure) as a gate before longer suites.

**Why:** Catches build failures, port misconfiguration, and broken MITM before investing time in the full regression suite.

| ID | Test | What is validated |
|----|------|-------------------|
| S1 | `test_proxy_accepts_connections` | TCP connect to proxy port 8080 succeeds |
| S2 | `test_viewer_health` | `GET /health` returns `{"status":"ok"}` |
| S3 | `test_http_get_through_proxy` | HTTP GET is forwarded and upstream response returned |
| S4 | `test_https_connect_tunnel` | HTTPS request via MITM completes (httpbin.org) |
| S5 | `test_mitm_logs_decrypted_url` | MITM log entry contains `https://` target |
| S6 | `test_api_logs_valid_json` | `/api/logs` returns correct JSON schema |
| S7 | `test_bearer_token_sensitive_data` | Bearer token produces `sensitive_data` log entry |
| S8 | `test_sql_injection_risk` | `UNION SELECT` in URL produces HIGH risk |
| S9 | `test_missing_security_headers_risk` | HTML response missing CSP triggers risk |

**Execution:**
```bash
bash tests/run_smoke.sh
# or: .venv-test/bin/python -m pytest tests/smoke/ -v --timeout=120 -x --tb=short
```

### 3.3 Regression: Sensitive Data Extraction — `tests/regression/test_sensitive_data.py`

**What:** 19 end-to-end tests validating every sensitive-data pattern the proxy can detect. Each test sends a crafted request through the proxy, then polls the viewer API to verify the correct `sensitive_data` finding was logged.

| ID | Test | Pattern validated |
|----|------|-------------------|
| R1 | `test_bearer_token` | `Authorization: Bearer <token>` |
| R2 | `test_jwt_decode` | JWT in Authorization header is decoded to header+payload JSON |
| R3 | `test_basic_auth_decode` | `Authorization: Basic <b64>` decoded to `user:pass` |
| R4 | `test_api_key_header` | `X-Api-Key` header |
| R5 | `test_cookie_detection` | `Cookie` header |
| R6 | `test_set_cookie_response` | `Set-Cookie` in response header (source=response_header) |
| R7 | `test_session_headers` | `X-Session-Token` header |
| R8 | `test_url_params` | `?api_key=...` in URL query string |
| R9 | `test_form_body_password` | `password=...` in form-encoded body |
| R10 | `test_json_body_credentials` | `"password":"..."` in JSON body |
| R11 | `test_email_detection` | Email address pattern in body |
| R12 | `test_phone_detection` | US phone number pattern in body |
| R13 | `test_ssn_detection` | SSN pattern (XXX-XX-XXXX) in body |
| R14 | `test_credit_card_luhn` | Credit card number validated by Luhn algorithm |
| R15 | `test_pem_key` | `-----BEGIN RSA PRIVATE KEY-----` in body |
| R16 | `test_aws_key` | AWS access key ID (`AKIA...`) in body |
| R17 | `test_deduplication` | Duplicate (type, source, value) triples are collapsed |
| R18 | `test_binary_skip` | Binary response body does not produce false positives |
| R19 | `test_response_body_source` | Findings in response body are labelled `source=response_body` |

### 3.4 Regression: Security Detection — `tests/regression/test_security_detection.py`

**What:** 8 tests for attack-pattern and security-header detection.

| ID | Test | Pattern validated |
|----|------|-------------------|
| R20 | `test_sql_injection` | `OR 1=1 --` in URL produces HIGH risk |
| R21 | `test_xss` | `<script>alert(1)</script>` in URL produces HIGH risk |
| R22 | `test_path_traversal` | `../../etc/passwd` in URL produces HIGH risk |
| R23 | `test_command_injection` | Backtick command in URL produces HIGH risk |
| R24 | `test_sensitive_url_params_risk` | `?password=...` in URL produces MEDIUM risk |
| R25 | `test_missing_headers_html` | HTML response missing CSP triggers risk |
| R26 | `test_no_false_positive_non_html` | JSON response does NOT trigger header risks |
| R27 | `test_hsts_only_https` | HSTS risk is not flagged for plain HTTP targets |

### 3.5 Regression: Proxy Core — `tests/regression/test_proxy_core.py`

**What:** 8 tests for fundamental proxy behaviour: header handling, body forwarding, error codes, MITM certificates.

| ID | Test | What is validated |
|----|------|-------------------|
| R28 | `test_proxy_connection_stripped` | `Proxy-Connection` header is removed before forwarding |
| R29 | `test_post_body_forwarded` | POST request body arrives at upstream intact |
| R30 | `test_response_body_truncated` | Response >8 KB is marked `body_truncated: true` in log |
| R31 | `test_binary_base64_encoded` | Binary response body is base64-encoded in log |
| R32 | `test_502_unreachable` | Request to unreachable host returns 502 |
| R33 | `test_400_malformed` | Malformed HTTP request (missing version) returns 400 |
| R34 | `test_mitm_cert_san` | Generated MITM cert contains correct SAN for target host |
| R35 | `test_cert_reuse` | Second request to same host reuses cached cert (mtime unchanged) |

### 3.6 Regression: Viewer API — `tests/regression/test_viewer_api.py`

**What:** 6 tests for the Node.js log viewer's `/api/logs` endpoint.

| ID | Test | What is validated |
|----|------|-------------------|
| R36 | `test_method_filter` | `?method=POST` returns only POST entries |
| R37 | `test_url_filter` | `?url=<substr>` returns only matching URLs |
| R38 | `test_severity_filter` | `?severity=HIGH` returns only entries with HIGH risk |
| R39 | `test_pagination` | `?page=N&limit=M` returns correct page/limit/total and page slicing |
| R40 | `test_sensitive_data_in_api` | `sensitive_data` field is present in API response |
| R41 | `test_malformed_jsonl` | Malformed lines in `/tmp/proxy.log` don't crash the viewer |

### 3.7 Regression: UI (Playwright) — `tests/regression/test_ui_viewer.py`

**What:** 4 browser-based tests using Playwright (headless Chromium) against the viewer's `/ui/logs` page.

| ID | Test | What is validated |
|----|------|-------------------|
| UI1 | `test_log_table_renders` | `#log-body` table has at least one `<tr>` after traffic |
| UI2 | `test_detail_row_expands` | Clicking a row reveals a `tr.detail-row` element |
| UI3 | `test_sensitive_data_reveal` | Sensitive section has Reveal/Hide toggle button that works |
| UI4 | `test_sensitive_data_modal` | Clicking `#sensitive-btn` opens `#sensitive-modal.open` |

---

## 4. Architecture

### 4.1 Container Management

- The Docker image is built once per session from the project `Dockerfile` (tag `proxy-test:pytest`).
- A single container runs for all tests, with ports 8080 (proxy) and 9999 (viewer) mapped to random host ports.
- The `proxy_container` fixture waits for both TCP and HTTP health before yielding.
- On teardown, the container is force-removed.

### 4.2 Upstream Test Server

- A `pytest-httpserver` instance runs on `0.0.0.0` with a random port on the host.
- The container reaches this server via the Docker bridge gateway IP (typically `172.17.0.1` on Linux, detected dynamically).
- Each test registers a handler on a unique UUID-based path slug, ensuring complete isolation between tests even though they share a single proxy container.

### 4.3 Log Polling

- The `query_logs` fixture returns a callable that polls `GET /api/logs?url=<unique_slug>` with a configurable timeout (default 5 s, 0.3 s poll interval).
- Since each test uses a unique URL path, the `url=` substring filter isolates its log entries from all other tests.
- This removes the need for log-file resets or container restarts between tests.

### 4.4 MITM / HTTPS Tests

- The CA certificate is extracted from the container via `docker exec cat /app/certs/ca.pem` and written to a temporary file.
- This file is passed as `verify=` to `requests` for HTTPS tests.
- HTTPS smoke tests (S4, S5) and cert tests (R34, R35) use `httpbin.org` as an external target.

### 4.5 Playwright Browser

- A session-scoped Chromium browser is launched headlessly.
- Each UI test gets a fresh `page` fixture navigated to `{viewer_url}/ui/logs`.
- Tests interact via CSS selectors matching the real HTML IDs/classes (`#log-body`, `.detail-row`, `.sensitive-reveal-btn`, `#sensitive-btn`, `#sensitive-modal`).

### 4.6 Test Isolation

Tests run against a shared container but are isolated by:

1. **Unique URL paths** — every test generates a UUID slug (e.g., `/sens-a1b2c3d4`).
2. **Per-test upstream handlers** — `pytest-httpserver` handlers are registered per slug.
3. **URL-filtered log queries** — `query_logs(slug)` only returns entries matching that slug.

This means tests can run in any order without interfering with each other.

---

## 5. Fixture Reference

| Fixture | Scope | Provided by | Purpose |
|---------|-------|-------------|---------|
| `proxy_container` | session | `conftest.py` | Build + start Docker container; yields `{id, proxy_port, viewer_port}` |
| `proxy_host` | session | `conftest.py` | Always `127.0.0.1` |
| `proxy_port` | session | `conftest.py` | Random mapped port for proxy (8080 inside container) |
| `viewer_port` | session | `conftest.py` | Random mapped port for viewer (9999 inside container) |
| `proxy_url` | session | `conftest.py` | `http://127.0.0.1:{proxy_port}` |
| `viewer_url` | session | `conftest.py` | `http://127.0.0.1:{viewer_port}` |
| `ca_cert_path` | session | `conftest.py` | MITM CA cert extracted to temp file |
| `upstream_server` | session | `conftest.py` | `pytest-httpserver` on `0.0.0.0` |
| `upstream_base_url` | session | `conftest.py` | `http://{docker_gateway}:{upstream_port}` |
| `query_logs` | session | `conftest.py` | Callable that polls `/api/logs` with timeout and retry |
| `browser` | session | `conftest.py` | Playwright Chromium browser |
| `page` | function | `conftest.py` | Fresh browser page per test |

---

## 6. Execution

### 6.1 Prerequisites

- Docker daemon running (user must have access to the Docker socket)
- Python 3.10+
- Network access (HTTPS smoke tests reach `httpbin.org`)

### 6.2 Docker Socket Permissions

The smoke and regression test scripts (`run_smoke.sh`, `run_regression.sh`)
build and start a Docker container. This requires the process to have
read/write access to `/var/run/docker.sock`.

On most Linux systems the socket is owned by `root:docker`, so your user
must be a member of the `docker` group. Even if your user *is* in the group
(`id -nG | grep docker`), the group may not be active in your current shell
session — this commonly happens after the group was recently added, or when
a new shell is spawned by a script or venv activation.

If you see this error:

```
ERROR: permission denied while trying to connect to the Docker daemon
```

Prefix the command with `sg docker` to run it with the `docker` group active:

```bash
sg docker "bash tests/run_smoke.sh"
sg docker "bash tests/run_regression.sh"
```

`sg docker "..."` starts a subshell with `docker` as the effective group,
giving the process access to the socket without requiring `sudo`.

**Which scripts need this:**

| Script | Needs Docker | May need `sg docker` |
|--------|:---:|:---:|
| `tests/setup_test_venv.sh` | No | No |
| `tests/run_smoke.sh` | Yes | Yes |
| `tests/run_regression.sh` | Yes | Yes |

The setup script (`setup_test_venv.sh`) only creates a venv and installs
Python packages — it never touches Docker, so it never needs `sg docker`.

### 6.3 Quick Start — Three Scripts

There are three scripts. Run them in this order:

```bash
# 1. One-time setup: create venv, install deps, install Playwright Chromium
bash tests/setup_test_venv.sh

# 2. Smoke tests: fast gate, stops on first failure (~30 s)
sg docker "bash tests/run_smoke.sh"

# 3. Regression tests: full suite with reports (~2-3 min)
sg docker "bash tests/run_regression.sh"
```

Step 1 only needs to run once (or again after changing `requirements-test.txt`).
Steps 2 and 3 are the regular test workflow. Each run script also handles
venv setup internally, so if you skip step 1, the first run will be slightly
slower while it installs dependencies.

#### What each script does

| Script | Purpose | What it handles |
|--------|---------|-----------------|
| `tests/setup_test_venv.sh` | One-time environment setup | Creates `.venv-test/`, `pip install -r requirements-test.txt`, `playwright install chromium` |
| `tests/run_smoke.sh` | Run 9 smoke tests | Ensures venv exists, runs `pytest tests/smoke/` with `-x` (stop on first failure), writes reports |
| `tests/run_regression.sh` | Run 66 regression tests | Ensures venv exists, runs `pytest tests/regression/` (unit + integration + UI), writes reports |

#### Activating the venv manually

If you want to run pytest commands directly (not via the scripts):

```bash
# Option A: activate in current shell
source .venv-test/bin/activate

# Option B: setup + activate in one step
source tests/setup_test_venv.sh
```

### 6.4 Run Scripts in Detail

**Smoke tests** — fast gate:
```bash
bash tests/run_smoke.sh
```
- Runs `tests/smoke/` only (9 tests)
- `-x` stops on first failure
- `--timeout=120` per test
- `--tb=short` for compact tracebacks
- Reports: `tests/reports/smoke-report.html`, `tests/reports/smoke-junit.xml`

**Regression tests** — comprehensive:
```bash
bash tests/run_regression.sh
```
- Runs `tests/regression/` (66 tests: 21 unit + 41 integration + 4 UI)
- `--timeout=180` per test
- `--tb=long` for full tracebacks
- Reports: `tests/reports/regression-report.html`, `tests/reports/regression-junit.xml`

### 6.5 Selective Execution

With the venv activated, run specific test files or markers directly:

```bash
# Unit tests only (no Docker needed, sub-second)
python -m pytest tests/regression/test_helpers.py -v

# Skip Playwright UI tests
python -m pytest tests/regression/ -v -m "not ui"

# Single test by name
python -m pytest tests/regression/test_sensitive_data.py::test_jwt_decode -v

# All tests (smoke + regression)
python -m pytest tests/ -v --timeout=180
```

### 6.6 Pytest Markers

| Marker | Meaning |
|--------|---------|
| `smoke` | Fast sanity checks |
| `regression` | Comprehensive regression tests |
| `ui` | Playwright browser tests (requires Chromium) |

### 6.7 Passing Extra Arguments

Both run scripts forward extra arguments to pytest:

```bash
bash tests/run_smoke.sh -k "test_bearer"       # filter by name
bash tests/run_regression.sh --tb=no -q         # quiet output
bash tests/run_regression.sh -m "not ui"        # skip browser tests
```

---

## 7. Reporting

Every test run produces two consolidated report artifacts written to `tests/reports/`:

### 7.1 HTML Report (`pytest-html`)

A self-contained HTML file (CSS/JS inlined, no external dependencies) that you can open directly in a browser or publish as a CI artifact.

**Contents:**
- Environment metadata (Python version, platform, proxy image)
- Summary bar — total / passed / failed / skipped / errors with durations
- Sortable & filterable table of every test — outcome, duration, markers
- Expandable tracebacks for failures and errors
- Captured stdout/stderr per test

**Files generated:**

| Run script | Report path |
|------------|-------------|
| `run_smoke.sh` | `tests/reports/smoke-report.html` |
| `run_regression.sh` | `tests/reports/regression-report.html` |

### 7.2 JUnit XML

Standard JUnit XML format consumed by CI systems (GitHub Actions, Jenkins, GitLab CI, Azure DevOps). Machine-readable; used for test result badges, trend graphs, and failure annotations in pull requests.

**Files generated:**

| Run script | Report path |
|------------|-------------|
| `run_smoke.sh` | `tests/reports/smoke-junit.xml` |
| `run_regression.sh` | `tests/reports/regression-junit.xml` |

### 7.3 Report Locations

```
tests/reports/
├── smoke-report.html          # HTML — open in browser
├── smoke-junit.xml            # JUnit — feed to CI
├── regression-report.html     # HTML — open in browser
└── regression-junit.xml       # JUnit — feed to CI
```

After each run, the script prints the report paths to the terminal:

```
── Reports ──────────────────────────────────────────────────────
  HTML  : tests/reports/smoke-report.html
  JUnit : tests/reports/smoke-junit.xml
```

### 7.4 CI Integration Example (GitHub Actions)

```yaml
- name: Run smoke tests
  run: bash tests/run_smoke.sh

- name: Upload test reports
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: test-reports
    path: tests/reports/

- name: Publish JUnit results
  if: always()
  uses: dorny/test-reporter@v1
  with:
    name: Smoke Tests
    path: tests/reports/smoke-junit.xml
    reporter: java-junit
```

---

## 8. Dependencies

Defined in `tests/requirements-test.txt`:

| Package | Version | Purpose |
|---------|---------|---------|
| `pytest` | >= 8.0 | Test framework |
| `pytest-timeout` | >= 2.2 | Per-test timeout enforcement |
| `pytest-html` | >= 4.1 | Self-contained HTML test reports |
| `testcontainers` | >= 4.0 | Docker container lifecycle (available, not currently used as fixture — container managed via subprocess for flexibility) |
| `requests` | >= 2.31 | HTTP client for proxy and API tests |
| `pytest-httpserver` | >= 1.0 | Upstream mock HTTP server |
| `playwright` | >= 1.40 | Browser automation for UI tests |
| `cryptography` | >= 42.0 | X.509 cert inspection for MITM tests |

---

## 9. File Structure

```
tests/
├── conftest.py                         # Shared fixtures (container, upstream, log polling, Playwright)
├── requirements-test.txt               # Python test dependencies
├── pytest.ini                          # Pytest configuration and markers
├── run_smoke.sh                        # Venv-aware smoke test runner
├── run_regression.sh                   # Venv-aware regression test runner
├── reports/                            # Generated report artifacts (gitignored)
│   ├── smoke-report.html
│   ├── smoke-junit.xml
│   ├── regression-report.html
│   └── regression-junit.xml
├── helpers/
│   └── __init__.py
├── smoke/
│   ├── __init__.py
│   └── test_smoke.py                   # S1-S9: smoke tests (9 tests)
└── regression/
    ├── __init__.py
    ├── test_sensitive_data.py           # R1-R19: sensitive data extraction (19 tests)
    ├── test_security_detection.py       # R20-R27: attack pattern detection (8 tests)
    ├── test_proxy_core.py              # R28-R35: HTTP/CONNECT/MITM/error handling (8 tests)
    ├── test_viewer_api.py              # R36-R41: viewer API pagination and filtering (6 tests)
    ├── test_helpers.py                 # R42-R46: pure Python unit tests (21 tests, 5 groups)
    └── test_ui_viewer.py              # UI1-UI4: Playwright browser tests (4 tests)
```

---

## 10. Coverage Map

How the test suite maps to project source files:

| Source file | Covered by |
|-------------|-----------|
| `proxy.py` — `_b64url_decode`, `_decode_jwt`, `_luhn_check`, `_parse_headers_list`, `_encode_body`, `_get_content_length` | Unit tests (R42-R46) |
| `proxy.py` — `_scan_headers`, `_scan_url`, `_scan_body`, `_extract_sensitive_data` | Sensitive data tests (R1-R19) |
| `proxy.py` — `_check_risks`, `_check_response_risks` | Security detection tests (R20-R27) |
| `proxy.py` — `handle_http`, `handle_connect`, `handle_client` | Proxy core tests (R28-R35), smoke tests (S1-S5) |
| `mitm_certs.py` — `ensure_ca`, `get_host_cert_path`, `make_server_ctx` | MITM tests (S4-S5, R34-R35) |
| `viewer/src/services/logReader.ts` — `queryLogs` | Viewer API tests (R36-R41) |
| `viewer/src/index.ts` — `/health`, `/api/logs` | Smoke tests (S2, S6), viewer API tests |
| `viewer/src/public/logs.html` — UI rendering | Playwright tests (UI1-UI4) |
| `Dockerfile` + `entrypoint.sh` — container build and startup | All integration tests (container fixture) |
