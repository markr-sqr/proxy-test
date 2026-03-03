#!/usr/bin/env bash
# test_errors.sh - Error handling tests

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/helpers.sh"

echo "# test_errors.sh"

start_proxy

# ── Test: Request to unreachable host returns 502 ────────────────────────────
resp="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
    -x "http://127.0.0.1:$PROXY_PORT" \
    "http://host.invalid.test:9999/" 2>/dev/null)"
assert_eq "Unreachable host returns 502" "502" "$resp"

# ── Test: Malformed request returns 400 ──────────────────────────────────────
# Send a raw malformed HTTP request (missing required fields)
bad_resp="$(printf 'BADREQ\r\n\r\n' | nc -w 3 127.0.0.1 "$PROXY_PORT" 2>/dev/null)"
if echo "$bad_resp" | grep -q "400"; then
    pass "Malformed request returns 400"
else
    fail "Malformed request returns 400" "Got: $(echo "$bad_resp" | head -1)"
fi

stop_proxy

# ── Test: CONNECT to unreachable host returns 502 ───────────────────────────
start_proxy
connect_resp="$(printf 'CONNECT host.invalid.test:443 HTTP/1.1\r\nHost: host.invalid.test:443\r\n\r\n' \
    | nc -w 5 127.0.0.1 "$PROXY_PORT" 2>/dev/null)"
if echo "$connect_resp" | grep -q "502"; then
    pass "CONNECT to unreachable host returns 502"
else
    fail "CONNECT to unreachable host returns 502" "Got: $(echo "$connect_resp" | head -1)"
fi

stop_proxy
print_summary
exit "$(test_exit_code; echo $?)"
