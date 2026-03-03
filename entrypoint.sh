#!/bin/bash
set -e

cleanup() {
    kill "$PROXY_PID" "$VIEWER_PID" 2>/dev/null || true
    wait "$PROXY_PID" "$VIEWER_PID" 2>/dev/null || true
}
trap cleanup INT TERM

# Ensure log file is writable (compose user override may differ from Dockerfile)
touch /tmp/proxy.log 2>/dev/null || true

# Start the log viewer in the background
node /app/viewer/dist/index.js &
VIEWER_PID=$!

# Start the proxy in the background, passing through any extra args
python3 -u /app/proxy.py "$@" &
PROXY_PID=$!

# Wait for either process to exit; if one dies, stop the other
wait -n "$PROXY_PID" "$VIEWER_PID" 2>/dev/null || true
cleanup
