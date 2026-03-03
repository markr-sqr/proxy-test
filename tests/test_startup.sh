#!/usr/bin/env bash
# test_startup.sh - Startup and CLI flag tests

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/helpers.sh"

echo "# test_startup.sh"

# ── Test: Proxy starts on custom port ────────────────────────────────────────
start_proxy
if kill -0 "$PROXY_PID" 2>/dev/null; then
    pass "Proxy starts on custom port (-p $PROXY_PORT)"
else
    fail "Proxy starts on custom port"
fi

# ── Test: Proxy prints listening message ─────────────────────────────────────
log_out="$(proxy_log)"
assert_contains "Proxy prints listening message" "$log_out" "Proxy listening on 127.0.0.1:$PROXY_PORT"

stop_proxy

# ── Test: Proxy starts on custom bind address ────────────────────────────────
start_proxy
log_out="$(proxy_log)"
assert_contains "Proxy starts on custom bind address (-b 127.0.0.1)" "$log_out" "127.0.0.1"
stop_proxy

# ── Test: --mitm generates CA cert on first run ─────────────────────────────
# Use a private cert dir so we don't clobber existing certs
MITM_TMP="$TEST_TMP/mitm_startup"
mkdir -p "$MITM_TMP"
cp "$PROJECT_DIR/proxy.py" "$MITM_TMP/proxy.py"
cp "$PROJECT_DIR/mitm_certs.py" "$MITM_TMP/mitm_certs.py"

PROXY_PORT_MITM="$(pick_port)"
(cd "$MITM_TMP" && "$PYTHON" proxy.py -p "$PROXY_PORT_MITM" -b 127.0.0.1 --mitm --no-verify) >"$TEST_TMP/mitm_startup.log" 2>&1 &
MITM_PID=$!

tries=0
while [ $tries -lt 50 ]; do
    if grep -q "Proxy listening" "$TEST_TMP/mitm_startup.log" 2>/dev/null; then
        break
    fi
    sleep 0.1
    tries=$((tries + 1))
done

mitm_log="$(cat "$TEST_TMP/mitm_startup.log" 2>/dev/null)"

if [ -f "$MITM_TMP/certs/ca.pem" ]; then
    pass "--mitm generates CA cert on first run"
else
    fail "--mitm generates CA cert on first run" "ca.pem not found in $MITM_TMP/certs/"
fi

# ── Test: --mitm --no-verify prints verification disabled ────────────────────
assert_contains "--no-verify prints verification disabled message" "$mitm_log" "Upstream TLS verification DISABLED"

# ── Test: --mitm prints CA cert path ────────────────────────────────────────
assert_contains "--mitm prints CA certificate path" "$mitm_log" "MITM CA certificate:"

kill "$MITM_PID" 2>/dev/null; wait "$MITM_PID" 2>/dev/null || true

# ── Test: --help shows usage ────────────────────────────────────────────────
help_out="$("$PYTHON" "$PROXY" --help 2>&1)"
assert_contains "--help shows usage" "$help_out" "usage:"

print_summary
exit "$(test_exit_code; echo $?)"
