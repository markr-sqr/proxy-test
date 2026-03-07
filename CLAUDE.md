# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

MITM Web Proxy — a Python HTTP/HTTPS forward proxy with optional TLS interception, security risk detection, request/response payload capture, and a web-based log viewer. Runs standalone or via Docker.

## Architecture

Two main components communicate via a JSONL log file (`/tmp/proxy.log`):

1. **Proxy** (`proxy.py` + `mitm_certs.py`) — Python 3.8+, stdlib + `cryptography`. Threaded server handling HTTP forwarding, HTTPS CONNECT tunneling, and optional MITM interception with on-the-fly certificate generation. Logs each request as a JSON line.

2. **Log Viewer** (`viewer/`) — Express + TypeScript (Node 18+). Reads the JSONL log file and serves a REST API (`/api/logs`) and browser UI (`/ui/logs`). The UI is a single HTML file (`viewer/src/public/logs.html`) with inline CSS/JS.

Certificates are auto-generated under `certs/` (CA + per-host). The `mitm_certs.py` module handles all crypto.

## Commands

### Run the proxy (Docker — recommended)
```bash
docker compose up -d          # proxy on :8080, viewer on :9999
docker compose build          # rebuild after code changes
```

### Run the proxy (manual)
```bash
python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
python3 proxy.py --mitm --no-verify
```

### Run the log viewer (manual)
```bash
cd viewer && npm install && npx tsc && node dist/index.js
```

### Tests — Pytest suite (requires Docker)
```bash
# One-time setup
bash tests/setup_test_venv.sh

# Smoke tests (~30s, stops on first failure)
sg docker "bash tests/run_smoke.sh"

# Full regression (~2-3 min)
sg docker "bash tests/run_regression.sh"

# Single test file
sg docker ".venv-test/bin/python -m pytest tests/regression/test_security_detection.py -v --timeout=180"

# Single test
sg docker ".venv-test/bin/python -m pytest tests/regression/test_security_detection.py::test_name -v --timeout=180"
```

Tests use `sg docker` because they build/run Docker containers. The test venv lives at `.venv-test/`. Reports go to `tests/reports/`.

### Tests — Legacy bash suite
```bash
bash tests/run_all.sh
```

## Key Files

- `proxy.py` — main proxy server, security scanning, payload capture, JSONL logging
- `mitm_certs.py` — CA and per-host certificate generation using `cryptography`
- `viewer/src/index.ts` — viewer Express server entry point
- `viewer/src/routes/logs.ts` — `/api/logs` endpoint with pagination and filtering
- `viewer/src/types.ts` — TypeScript interfaces (LogEntry, Payload, Risk)
- `viewer/src/public/logs.html` — full log viewer UI (single-file HTML/CSS/JS)
- `tests/conftest.py` — pytest fixtures: Docker container lifecycle, upstream test server, log polling, Playwright browser
- `openapi.yaml` — OpenAPI 3.1 spec for the viewer API

## Test Architecture

Pytest tests run against a Docker container (built and started by session-scoped fixtures in `conftest.py`). Tests use `pytest-httpserver` as an upstream target, accessed from inside the container via the Docker bridge gateway IP. UI tests use Playwright (Chromium, headless).

## Conventions

- Proxy has zero external dependencies in passthrough mode; `cryptography` is only needed for `--mitm`
- Log file path is configurable via `PROXY_LOG_FILE` env var (default `/tmp/proxy.log`)
- Viewer port configurable via `VIEWER_PORT` env var (default `9999`)
- The viewer TypeScript compiles to `viewer/dist/` (not committed)
