#!/usr/bin/env bash
# test_https_passthrough.sh - HTTPS passthrough (non-MITM) tests

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/helpers.sh"

echo "# test_https_passthrough.sh"

start_proxy

# ── Test: CONNECT tunnel returns 200 ─────────────────────────────────────────
resp="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
    -x "http://127.0.0.1:$PROXY_PORT" \
    -k "https://httpbin.org/get" 2>/dev/null)"
assert_eq "HTTPS CONNECT tunnel returns 200" "200" "$resp"

# ── Test: Proxy logs CONNECT target ──────────────────────────────────────────
sleep 0.5
log_out="$(proxy_log)"
assert_contains "Proxy logs CONNECT target" "$log_out" "CONNECT"
assert_contains "Proxy logs CONNECT host" "$log_out" "httpbin.org:443"

# ── Test: Proxy does NOT log decrypted paths (only CONNECT) ─────────────────
# In passthrough mode, the proxy should only see CONNECT, not GET /get
assert_not_contains "Proxy does NOT log decrypted paths in passthrough" "$log_out" "MITM"

stop_proxy
print_summary
exit "$(test_exit_code; echo $?)"
