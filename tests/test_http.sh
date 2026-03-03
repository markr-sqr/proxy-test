#!/usr/bin/env bash
# test_http.sh - HTTP forwarding tests

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/helpers.sh"

echo "# test_http.sh"

start_proxy

# ── Test: HTTP GET returns 200 ───────────────────────────────────────────────
resp="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
    -x "http://127.0.0.1:$PROXY_PORT" \
    "http://httpbin.org/get" 2>/dev/null)"
assert_eq "HTTP GET returns 200" "200" "$resp"

# ── Test: HTTP GET returns correct body content ──────────────────────────────
body="$(curl -s --max-time 10 \
    -x "http://127.0.0.1:$PROXY_PORT" \
    "http://httpbin.org/get" 2>/dev/null)"
assert_contains "HTTP GET body contains expected content" "$body" '"url"'

# ── Test: HTTP POST forwarding works ─────────────────────────────────────────
# Note: proxy forwards headers but does not relay request bodies, so we send
# POST without a body.  This still validates that the POST method is forwarded.
post_resp="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
    -x "http://127.0.0.1:$PROXY_PORT" \
    -X POST -H 'Content-Length: 0' \
    "http://httpbin.org/post" 2>/dev/null)"
assert_eq "HTTP POST returns 200" "200" "$post_resp"

# ── Test: Proxy logs the HTTP request ────────────────────────────────────────
sleep 0.5  # allow log to flush
log_out="$(proxy_log)"
assert_contains "Proxy logs HTTP GET method and URL" "$log_out" "GET"
assert_contains "Proxy logs httpbin.org URL" "$log_out" "httpbin.org"

# ── Test: Unreachable host returns 502 ───────────────────────────────────────
bad_resp="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
    -x "http://127.0.0.1:$PROXY_PORT" \
    "http://host.invalid.test:9999/nope" 2>/dev/null)"
assert_eq "Unreachable host returns 502" "502" "$bad_resp"

stop_proxy
print_summary
exit "$(test_exit_code; echo $?)"
