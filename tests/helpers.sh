#!/usr/bin/env bash
# helpers.sh - Shared utilities for proxy test scripts
#
# Source this file from each test script:
#   SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
#   source "$SCRIPT_DIR/helpers.sh"

# ── Paths ────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PROXY="$PROJECT_DIR/proxy.py"

# ── Venv bootstrap ───────────────────────────────────────────────────────────
source "$SCRIPT_DIR/setup_venv.sh"
# After this point, $PYTHON points to the venv interpreter

# Force unbuffered Python output so log messages appear immediately in files
export PYTHONUNBUFFERED=1

# ── Temp directory (cleaned up on exit) ──────────────────────────────────────
TEST_TMP="$(mktemp -d /tmp/proxy-test.XXXXXX)"

# ── TAP-style test counters ──────────────────────────────────────────────────
_test_num=0
_test_pass=0
_test_fail=0

pass() {
    _test_num=$((_test_num + 1))
    _test_pass=$((_test_pass + 1))
    echo "ok $_test_num - $1"
}

fail() {
    _test_num=$((_test_num + 1))
    _test_fail=$((_test_fail + 1))
    echo "not ok $_test_num - $1"
    if [ -n "${2:-}" ]; then
        echo "  # $2"
    fi
}

assert_eq() {
    local desc="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        pass "$desc"
    else
        fail "$desc" "expected '$expected', got '$actual'"
    fi
}

assert_contains() {
    local desc="$1" haystack="$2" needle="$3"
    if echo "$haystack" | grep -qF "$needle"; then
        pass "$desc"
    else
        fail "$desc" "expected output to contain '$needle'"
    fi
}

assert_matches() {
    local desc="$1" haystack="$2" pattern="$3"
    if echo "$haystack" | grep -qE "$pattern"; then
        pass "$desc"
    else
        fail "$desc" "expected output to match pattern '$pattern'"
    fi
}

assert_not_contains() {
    local desc="$1" haystack="$2" needle="$3"
    if echo "$haystack" | grep -qF "$needle"; then
        fail "$desc" "output should NOT contain '$needle'"
    else
        pass "$desc"
    fi
}

assert_http_status() {
    local desc="$1" expected="$2" actual_headers="$3"
    local status_line
    status_line="$(echo "$actual_headers" | head -1)"
    if echo "$status_line" | grep -q "$expected"; then
        pass "$desc"
    else
        fail "$desc" "expected status $expected in '$status_line'"
    fi
}

# ── Port selection ───────────────────────────────────────────────────────────
pick_port() {
    # Find an unused high port
    local port
    while true; do
        port=$((RANDOM % 10000 + 20000))
        if ! ss -tln 2>/dev/null | grep -q ":${port} " && \
           ! ss -tln 2>/dev/null | grep -q ":${port}$"; then
            echo "$port"
            return
        fi
    done
}

# ── Proxy management ────────────────────────────────────────────────────────
PROXY_PID=""
PROXY_PORT=""
PROXY_LOG="$TEST_TMP/proxy.log"

start_proxy() {
    # Usage: start_proxy [extra args...]
    # Sets PROXY_PORT and PROXY_PID
    PROXY_PORT="$(pick_port)"
    PROXY_LOG="$TEST_TMP/proxy.log"

    "$PYTHON" "$PROXY" -p "$PROXY_PORT" -b 127.0.0.1 "$@" >"$PROXY_LOG" 2>&1 &
    PROXY_PID=$!

    # Wait for proxy to start listening (up to 5s)
    local tries=0
    while [ $tries -lt 50 ]; do
        if grep -q "Proxy listening" "$PROXY_LOG" 2>/dev/null; then
            return 0
        fi
        if ! kill -0 "$PROXY_PID" 2>/dev/null; then
            echo "# Proxy process died during startup" >&2
            cat "$PROXY_LOG" >&2
            return 1
        fi
        sleep 0.1
        tries=$((tries + 1))
    done
    echo "# Proxy did not start within 5 seconds" >&2
    cat "$PROXY_LOG" >&2
    return 1
}

stop_proxy() {
    if [ -n "$PROXY_PID" ] && kill -0 "$PROXY_PID" 2>/dev/null; then
        kill "$PROXY_PID" 2>/dev/null
        wait "$PROXY_PID" 2>/dev/null || true
    fi
    PROXY_PID=""
}

proxy_log() {
    cat "$PROXY_LOG" 2>/dev/null || true
}

# ── Cleanup ──────────────────────────────────────────────────────────────────
_cleanup() {
    stop_proxy
    rm -rf "$TEST_TMP"
}
trap _cleanup EXIT

# ── Summary ──────────────────────────────────────────────────────────────────
print_summary() {
    echo ""
    echo "1..$_test_num"
    echo "# pass: $_test_pass"
    echo "# fail: $_test_fail"
    if [ "$_test_fail" -gt 0 ]; then
        return 1
    fi
    return 0
}

# Export the exit code helper
test_exit_code() {
    if [ "$_test_fail" -gt 0 ]; then
        return 1
    fi
    return 0
}
