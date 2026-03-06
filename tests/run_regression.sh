#!/usr/bin/env bash
# Run regression tests — full report
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VENV_DIR="$PROJECT_DIR/.venv-test"
REQ_FILE="$SCRIPT_DIR/requirements-test.txt"
REPORT_DIR="$SCRIPT_DIR/reports"

# ── Create / reuse venv ──────────────────────────────────────────────────────
if [ ! -d "$VENV_DIR" ]; then
    echo "# Creating test venv at $VENV_DIR ..."
    python3 -m venv "$VENV_DIR"
fi

stamp="$VENV_DIR/.requirements-test.stamp"
req_hash="$(md5sum "$REQ_FILE" 2>/dev/null | awk '{print $1}')"

if [ ! -f "$stamp" ] || [ "$(cat "$stamp" 2>/dev/null)" != "$req_hash" ]; then
    echo "# Installing test dependencies into venv ..."
    "$VENV_DIR/bin/pip" install --quiet --upgrade pip >/dev/null 2>&1
    "$VENV_DIR/bin/pip" install --quiet -r "$REQ_FILE"
    "$VENV_DIR/bin/python" -m playwright install chromium 2>/dev/null || true
    echo "$req_hash" > "$stamp"
fi

PYTHON="$VENV_DIR/bin/python"

# ── Ensure report directory exists ────────────────────────────────────────────
mkdir -p "$REPORT_DIR"

# ── Run regression tests ─────────────────────────────────────────────────────
cd "$SCRIPT_DIR"
RC=0
"$PYTHON" -m pytest regression/ -v --timeout=180 --tb=long \
    --junitxml="$REPORT_DIR/regression-junit.xml" \
    --html="$REPORT_DIR/regression-report.html" --self-contained-html \
    "$@" || RC=$?

echo ""
echo "── Reports ──────────────────────────────────────────────────────"
echo "  HTML  : $REPORT_DIR/regression-report.html"
echo "  JUnit : $REPORT_DIR/regression-junit.xml"
exit $RC
