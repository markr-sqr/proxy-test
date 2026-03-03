#!/usr/bin/env bash
# setup_venv.sh - Create (or reuse) a Python venv for the proxy test suite
#
# Usage:
#   source tests/setup_venv.sh   # creates venv, installs deps, exports PYTHON
#   bash  tests/setup_venv.sh    # same, but prints the venv python path
#
# The venv lives at <project>/.venv so it persists across test runs.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VENV_DIR="$PROJECT_DIR/.venv"
REQ_FILE="$PROJECT_DIR/requirements.txt"

_setup_venv() {
    if [ ! -d "$VENV_DIR" ]; then
        echo "# Creating venv at $VENV_DIR ..."
        python3 -m venv "$VENV_DIR"
    fi

    # Stamp file to skip pip install if requirements haven't changed
    local stamp="$VENV_DIR/.requirements.stamp"
    local req_hash
    req_hash="$(md5sum "$REQ_FILE" 2>/dev/null | awk '{print $1}')"

    if [ ! -f "$stamp" ] || [ "$(cat "$stamp" 2>/dev/null)" != "$req_hash" ]; then
        echo "# Installing dependencies into venv ..."
        "$VENV_DIR/bin/pip" install --quiet --upgrade pip >/dev/null 2>&1
        "$VENV_DIR/bin/pip" install --quiet -r "$REQ_FILE"
        echo "$req_hash" > "$stamp"
    fi

    # Export the venv python for use by callers
    PYTHON="$VENV_DIR/bin/python3"
    export PYTHON
}

_setup_venv

# When run as a standalone script (not sourced), print the python path
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    echo "$PYTHON"
fi
