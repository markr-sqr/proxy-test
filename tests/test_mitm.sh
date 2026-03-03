#!/usr/bin/env bash
# test_mitm.sh - MITM interception tests

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/helpers.sh"

echo "# test_mitm.sh"

# Use a private working directory so cert generation is isolated
MITM_DIR="$TEST_TMP/mitm_work"
mkdir -p "$MITM_DIR"
cp "$PROJECT_DIR/proxy.py" "$MITM_DIR/proxy.py"
cp "$PROJECT_DIR/mitm_certs.py" "$MITM_DIR/mitm_certs.py"

# ── Helper: start MITM proxy in isolated dir ────────────────────────────────
MITM_PID=""
MITM_PORT=""
MITM_LOG="$TEST_TMP/mitm.log"

start_mitm() {
    MITM_PORT="$(pick_port)"
    (cd "$MITM_DIR" && "$PYTHON" proxy.py -p "$MITM_PORT" -b 127.0.0.1 --mitm --no-verify) \
        >"$MITM_LOG" 2>&1 &
    MITM_PID=$!

    local tries=0
    while [ $tries -lt 50 ]; do
        if grep -q "Proxy listening" "$MITM_LOG" 2>/dev/null; then
            return 0
        fi
        if ! kill -0 "$MITM_PID" 2>/dev/null; then
            echo "# MITM proxy died during startup" >&2
            cat "$MITM_LOG" >&2
            return 1
        fi
        sleep 0.1
        tries=$((tries + 1))
    done
    echo "# MITM proxy did not start within 5s" >&2
    cat "$MITM_LOG" >&2
    return 1
}

stop_mitm() {
    if [ -n "$MITM_PID" ] && kill -0 "$MITM_PID" 2>/dev/null; then
        kill "$MITM_PID" 2>/dev/null
        wait "$MITM_PID" 2>/dev/null || true
    fi
    MITM_PID=""
}

# Extra cleanup
_mitm_cleanup() {
    stop_mitm
}
trap '_mitm_cleanup; _cleanup' EXIT

CA_PEM="$MITM_DIR/certs/ca.pem"
CA_KEY="$MITM_DIR/certs/ca-key.pem"
HOSTS_DIR="$MITM_DIR/certs/hosts"

start_mitm

# ── Test: MITM generates ca.pem and ca-key.pem ──────────────────────────────
if [ -f "$CA_PEM" ] && [ -f "$CA_KEY" ]; then
    pass "MITM mode generates ca.pem and ca-key.pem"
else
    fail "MITM mode generates ca.pem and ca-key.pem"
fi

# ── Test: HTTPS GET through MITM returns 200 ────────────────────────────────
resp="$(curl -s -o "$TEST_TMP/mitm_body.txt" -w '%{http_code}' --max-time 15 \
    -x "http://127.0.0.1:$MITM_PORT" \
    --cacert "$CA_PEM" \
    "https://httpbin.org/get" 2>/dev/null)"
assert_eq "HTTPS GET through MITM returns 200" "200" "$resp"

# ── Test: Response body is correct ───────────────────────────────────────────
body="$(cat "$TEST_TMP/mitm_body.txt" 2>/dev/null)"
assert_contains "MITM response body contains expected content" "$body" '"url"'

# ── Test: Proxy logs decrypted request with MITM status ─────────────────────
sleep 0.5
log_out="$(cat "$MITM_LOG" 2>/dev/null)"
assert_contains "Proxy logs MITM-intercepted request method" "$log_out" "MITM"
assert_matches "Proxy logs full URL in MITM mode" "$log_out" "https://httpbin.org"

# ── Test: Per-host cert is generated ─────────────────────────────────────────
if [ -f "$HOSTS_DIR/httpbin.org.pem" ]; then
    pass "Per-host cert generated for httpbin.org"
else
    fail "Per-host cert generated for httpbin.org" "File not found: $HOSTS_DIR/httpbin.org.pem"
fi

# ── Test: Second host generates a separate cert ─────────────────────────────
curl -s -o /dev/null --max-time 15 \
    -x "http://127.0.0.1:$MITM_PORT" \
    --cacert "$CA_PEM" \
    "https://example.com/" 2>/dev/null || true
sleep 0.5

if [ -f "$HOSTS_DIR/example.com.pem" ]; then
    pass "Separate per-host cert generated for example.com"
else
    fail "Separate per-host cert generated for example.com"
fi

# ── Test: Per-host certs are cached (second request reuses same file) ────────
stat1="$(stat -c '%Y%s' "$HOSTS_DIR/httpbin.org.pem" 2>/dev/null)"
curl -s -o /dev/null --max-time 15 \
    -x "http://127.0.0.1:$MITM_PORT" \
    --cacert "$CA_PEM" \
    "https://httpbin.org/ip" 2>/dev/null || true
sleep 0.5
stat2="$(stat -c '%Y%s' "$HOSTS_DIR/httpbin.org.pem" 2>/dev/null)"
assert_eq "Per-host cert is cached (reused on second request)" "$stat1" "$stat2"

# ── Test: CA cert is reused across proxy restarts ────────────────────────────
ca_before="$(md5sum "$CA_PEM" 2>/dev/null | awk '{print $1}')"
stop_mitm

# Restart the proxy in the same directory
start_mitm
ca_after="$(md5sum "$CA_PEM" 2>/dev/null | awk '{print $1}')"
assert_eq "CA cert is reused across proxy restarts" "$ca_before" "$ca_after"

stop_mitm
print_summary
exit "$(test_exit_code; echo $?)"
