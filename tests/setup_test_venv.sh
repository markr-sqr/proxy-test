#!/usr/bin/env bash
# setup_test_venv.sh - Create (or reuse) the test venv and install all deps
#
# Usage:
#   bash tests/setup_test_venv.sh          # setup only
#   source tests/setup_test_venv.sh        # setup + activate in current shell
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VENV_DIR="$PROJECT_DIR/.venv-test"
REQ_FILE="$SCRIPT_DIR/requirements-test.txt"

# ── 1. Create venv ───────────────────────────────────────────────────────────
if [ ! -d "$VENV_DIR" ]; then
    echo "# Creating test venv at $VENV_DIR ..."
    python3 -m venv "$VENV_DIR"
fi

# ── 2. Install / update dependencies ─────────────────────────────────────────
stamp="$VENV_DIR/.requirements-test.stamp"
req_hash="$(md5sum "$REQ_FILE" 2>/dev/null | awk '{print $1}')"

if [ ! -f "$stamp" ] || [ "$(cat "$stamp" 2>/dev/null)" != "$req_hash" ]; then
    echo "# Installing test dependencies ..."
    "$VENV_DIR/bin/pip" install --quiet --upgrade pip >/dev/null 2>&1
    "$VENV_DIR/bin/pip" install --quiet -r "$REQ_FILE"
    echo "$req_hash" > "$stamp"
else
    echo "# Dependencies up to date (skipping pip install)"
fi

# ── 3. Install Playwright Chromium ────────────────────────────────────────────
# Install Playwright browsers (chromium + headless shell)
PW_CHROMIUM_HS="$HOME/.cache/ms-playwright/chromium_headless_shell-"*
if ! "$VENV_DIR/bin/python" -c "from playwright.sync_api import sync_playwright" 2>/dev/null \
   || ! ls $PW_CHROMIUM_HS >/dev/null 2>&1; then
    echo "# Installing Playwright Chromium ..."
    "$VENV_DIR/bin/python" -m playwright install chromium
else
    echo "# Playwright already installed"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "Test venv ready: $VENV_DIR"
echo ""
echo "  Activate:   source $VENV_DIR/bin/activate"
echo "  Unit tests: $VENV_DIR/bin/python -m pytest tests/regression/test_helpers.py -v"
echo "  Smoke:      bash tests/run_smoke.sh"
echo "  Regression: bash tests/run_regression.sh"

# If sourced, activate the venv in the caller's shell
if [ "${BASH_SOURCE[0]}" != "$0" ]; then
    source "$VENV_DIR/bin/activate"
    echo ""
    echo "  (venv activated)"
fi
