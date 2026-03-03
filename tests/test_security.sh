#!/usr/bin/env bash
# test_security.sh - Security risk detection tests

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/helpers.sh"

echo "# test_security.sh"

start_proxy

# We use a local listener to avoid depending on external hosts.
# The proxy will connect to it and we just need the log output.
BACKEND_PORT="$(pick_port)"
# Simple one-shot HTTP server: responds 200 to any request then exits
(echo -e "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK" | nc -l -p "$BACKEND_PORT" -q 1 >/dev/null 2>&1) &
BACKEND_PID=$!

# ── Test: SQL injection detection ────────────────────────────────────────────
# Use URL-encoded quotes (%27) so curl sends them verbatim
curl -s -o /dev/null --max-time 5 \
    -x "http://127.0.0.1:$PROXY_PORT" \
    "http://127.0.0.1:$BACKEND_PORT/search?q=1%27%20OR%20%271%27%3D%271" 2>/dev/null || true
wait "$BACKEND_PID" 2>/dev/null || true

sleep 0.3
log_out="$(proxy_log)"
assert_contains "SQL injection detected" "$log_out" "SQL injection pattern"

# ── Test: XSS detection ─────────────────────────────────────────────────────
(echo -e "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK" | nc -l -p "$BACKEND_PORT" -q 1 >/dev/null 2>&1) &
BACKEND_PID=$!

curl -s -o /dev/null --max-time 5 \
    -x "http://127.0.0.1:$PROXY_PORT" \
    "http://127.0.0.1:$BACKEND_PORT/page?input=%3Cscript%3Ealert(1)%3C/script%3E" 2>/dev/null || true
wait "$BACKEND_PID" 2>/dev/null || true

sleep 0.3
log_out="$(proxy_log)"
assert_contains "XSS detected" "$log_out" "XSS pattern"

# ── Test: Path traversal detection ───────────────────────────────────────────
(echo -e "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK" | nc -l -p "$BACKEND_PORT" -q 1 >/dev/null 2>&1) &
BACKEND_PID=$!

# Use --path-as-is so curl doesn't normalize ../
curl -s -o /dev/null --max-time 5 --path-as-is \
    -x "http://127.0.0.1:$PROXY_PORT" \
    "http://127.0.0.1:$BACKEND_PORT/../../etc/passwd" 2>/dev/null || true
wait "$BACKEND_PID" 2>/dev/null || true

sleep 0.3
log_out="$(proxy_log)"
assert_contains "Path traversal detected" "$log_out" "Path traversal pattern"

# ── Test: Sensitive data in URL ──────────────────────────────────────────────
(echo -e "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK" | nc -l -p "$BACKEND_PORT" -q 1 >/dev/null 2>&1) &
BACKEND_PID=$!

curl -s -o /dev/null --max-time 5 \
    -x "http://127.0.0.1:$PROXY_PORT" \
    "http://127.0.0.1:$BACKEND_PORT/api?password=hunter2&user=admin" 2>/dev/null || true
wait "$BACKEND_PID" 2>/dev/null || true

sleep 0.3
log_out="$(proxy_log)"
assert_contains "Sensitive data in URL detected" "$log_out" "Sensitive data in URL"

# ── Test: Cleartext auth endpoint ────────────────────────────────────────────
(echo -e "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK" | nc -l -p "$BACKEND_PORT" -q 1 >/dev/null 2>&1) &
BACKEND_PID=$!

curl -s -o /dev/null --max-time 5 \
    -x "http://127.0.0.1:$PROXY_PORT" \
    "http://127.0.0.1:$BACKEND_PORT/login" 2>/dev/null || true
wait "$BACKEND_PID" 2>/dev/null || true

sleep 0.3
log_out="$(proxy_log)"
assert_contains "Cleartext auth endpoint detected" "$log_out" "Cleartext request to authentication endpoint"

# ── Test: SSRF private IP detection ──────────────────────────────────────────
# The request itself will likely fail, but we just need the log entry
curl -s -o /dev/null --max-time 3 \
    -x "http://127.0.0.1:$PROXY_PORT" \
    "http://192.168.1.1/admin" 2>/dev/null || true

sleep 0.3
log_out="$(proxy_log)"
assert_contains "SSRF private IP detected" "$log_out" "private/internal IP"

# ── Test: Suspicious method detection ────────────────────────────────────────
(echo -e "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK" | nc -l -p "$BACKEND_PORT" -q 1 >/dev/null 2>&1) &
BACKEND_PID=$!

curl -s -o /dev/null --max-time 5 \
    -x "http://127.0.0.1:$PROXY_PORT" \
    -X TRACE \
    "http://127.0.0.1:$BACKEND_PORT/debug" 2>/dev/null || true
wait "$BACKEND_PID" 2>/dev/null || true

sleep 0.3
log_out="$(proxy_log)"
assert_contains "Suspicious method detected" "$log_out" "Suspicious HTTP method"

# ── Test: Command injection detection ────────────────────────────────────────
(echo -e "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK" | nc -l -p "$BACKEND_PORT" -q 1 >/dev/null 2>&1) &
BACKEND_PID=$!

curl -s -o /dev/null --max-time 5 \
    -x "http://127.0.0.1:$PROXY_PORT" \
    "http://127.0.0.1:$BACKEND_PORT/run?cmd=id%3B%20cat%20%2Fetc%2Fpasswd" 2>/dev/null || true
wait "$BACKEND_PID" 2>/dev/null || true

sleep 0.3
log_out="$(proxy_log)"
assert_contains "Command injection detected" "$log_out" "Command injection pattern"

# ── Test: Plaintext Basic auth over HTTP ─────────────────────────────────────
(echo -e "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK" | nc -l -p "$BACKEND_PORT" -q 1 >/dev/null 2>&1) &
BACKEND_PID=$!

curl -s -o /dev/null --max-time 5 \
    -x "http://127.0.0.1:$PROXY_PORT" \
    -H "Authorization: Basic dXNlcjpwYXNz" \
    "http://127.0.0.1:$BACKEND_PORT/api/data" 2>/dev/null || true
wait "$BACKEND_PID" 2>/dev/null || true

sleep 0.3
log_out="$(proxy_log)"
assert_contains "Plaintext Basic auth detected" "$log_out" "Plaintext HTTP Basic credentials"

# ── Test: Plaintext Bearer token over HTTP ───────────────────────────────────
(echo -e "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK" | nc -l -p "$BACKEND_PORT" -q 1 >/dev/null 2>&1) &
BACKEND_PID=$!

curl -s -o /dev/null --max-time 5 \
    -x "http://127.0.0.1:$PROXY_PORT" \
    -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.test" \
    "http://127.0.0.1:$BACKEND_PORT/api/data" 2>/dev/null || true
wait "$BACKEND_PID" 2>/dev/null || true

sleep 0.3
log_out="$(proxy_log)"
assert_contains "Plaintext Bearer token detected" "$log_out" "Plaintext Bearer token"

# ── Test: Proxy-Authorization credentials ────────────────────────────────────
(echo -e "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK" | nc -l -p "$BACKEND_PORT" -q 1 >/dev/null 2>&1) &
BACKEND_PID=$!

curl -s -o /dev/null --max-time 5 \
    -x "http://127.0.0.1:$PROXY_PORT" \
    -H "Proxy-Authorization: Basic cHJveHk6c2VjcmV0" \
    "http://127.0.0.1:$BACKEND_PORT/resource" 2>/dev/null || true
wait "$BACKEND_PID" 2>/dev/null || true

sleep 0.3
log_out="$(proxy_log)"
assert_contains "Proxy-Authorization detected" "$log_out" "Proxy authentication credentials"

# ── Test: Plaintext credentials in POST body ─────────────────────────────────
(echo -e "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK" | nc -l -p "$BACKEND_PORT" -q 1 >/dev/null 2>&1) &
BACKEND_PID=$!

curl -s -o /dev/null --max-time 5 \
    -x "http://127.0.0.1:$PROXY_PORT" \
    -X POST -d "username=admin&password=secret123" \
    "http://127.0.0.1:$BACKEND_PORT/login" 2>/dev/null || true
wait "$BACKEND_PID" 2>/dev/null || true

sleep 0.3
log_out="$(proxy_log)"
assert_contains "Plaintext body credentials detected" "$log_out" "Plaintext credentials in request body"

# ── Test: Clean request produces no warnings ─────────────────────────────────
# Restart proxy with fresh log to check for false positives
# Use example.com (non-private IP) to avoid triggering SSRF on localhost backend
stop_proxy
start_proxy

curl -s -o /dev/null --max-time 5 \
    -x "http://127.0.0.1:$PROXY_PORT" \
    "http://example.com/hello?name=world" 2>/dev/null || true

sleep 0.3
log_out="$(proxy_log)"
assert_not_contains "Clean request has no HIGH warnings" "$log_out" "[HIGH]"
assert_not_contains "Clean request has no MEDIUM warnings" "$log_out" "[MEDIUM]"
assert_not_contains "Clean request has no LOW warnings" "$log_out" "[LOW]"

# ── Test: Severity levels use correct labels ─────────────────────────────────
stop_proxy
start_proxy

LABEL_BACKEND_PORT="$(pick_port)"
(echo -e "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK" | nc -l -p "$LABEL_BACKEND_PORT" -q 1 >/dev/null 2>&1) &
BACKEND_PID=$!

# Use fully URL-encoded SQL injection
curl -s -o /dev/null --max-time 5 \
    -x "http://127.0.0.1:$PROXY_PORT" \
    "http://127.0.0.1:$LABEL_BACKEND_PORT/search?q=%27%20OR%20%271%27%3D%271" 2>/dev/null || true
wait "$BACKEND_PID" 2>/dev/null || true

sleep 0.3
log_out="$(proxy_log)"
assert_contains "HIGH severity label present" "$log_out" "[HIGH]"

stop_proxy
print_summary
exit "$(test_exit_code; echo $?)"
