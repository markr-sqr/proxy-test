#!/usr/bin/env bash
# test_certs.sh - Certificate validation tests

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/helpers.sh"

echo "# test_certs.sh"

# Generate certs by starting MITM proxy in isolated dir and making one request
CERT_DIR="$TEST_TMP/cert_work"
mkdir -p "$CERT_DIR"
cp "$PROJECT_DIR/proxy.py" "$CERT_DIR/proxy.py"
cp "$PROJECT_DIR/mitm_certs.py" "$CERT_DIR/mitm_certs.py"

CERT_PORT="$(pick_port)"
CERT_LOG="$TEST_TMP/cert_proxy.log"
(cd "$CERT_DIR" && "$PYTHON" proxy.py -p "$CERT_PORT" -b 127.0.0.1 --mitm --no-verify) \
    >"$CERT_LOG" 2>&1 &
CERT_PID=$!

tries=0
while [ $tries -lt 50 ]; do
    if grep -q "Proxy listening" "$CERT_LOG" 2>/dev/null; then
        break
    fi
    sleep 0.1
    tries=$((tries + 1))
done

CA_PEM="$CERT_DIR/certs/ca.pem"
CA_KEY="$CERT_DIR/certs/ca-key.pem"
HOSTS_DIR="$CERT_DIR/certs/hosts"

# Make a request to generate a per-host cert
curl -s -o /dev/null --max-time 15 \
    -x "http://127.0.0.1:$CERT_PORT" \
    --cacert "$CA_PEM" \
    "https://httpbin.org/get" 2>/dev/null || true
sleep 0.5

HOST_PEM="$HOSTS_DIR/httpbin.org.pem"

# Stop proxy - we only need the certs
kill "$CERT_PID" 2>/dev/null; wait "$CERT_PID" 2>/dev/null || true

# ── Test: CA cert is valid x509 ─────────────────────────────────────────────
ca_x509="$(openssl x509 -in "$CA_PEM" -noout -text 2>&1)"
if [ $? -eq 0 ]; then
    pass "CA cert is valid x509"
else
    fail "CA cert is valid x509" "openssl x509 failed"
fi

# ── Test: CA cert has BasicConstraints CA:TRUE ───────────────────────────────
assert_contains "CA cert has BasicConstraints CA:TRUE" "$ca_x509" "CA:TRUE"

# ── Test: CA cert has correct CN ─────────────────────────────────────────────
ca_subject="$(openssl x509 -in "$CA_PEM" -noout -subject 2>/dev/null)"
assert_contains "CA cert has correct CN (MITM Dev Proxy CA)" "$ca_subject" "MITM Dev Proxy CA"

# ── Test: CA key file has restricted permissions ─────────────────────────────
key_perms="$(stat -c '%a' "$CA_KEY" 2>/dev/null)"
assert_eq "CA key file has restricted permissions (0600)" "600" "$key_perms"

# ── Test: Per-host cert has correct SAN ──────────────────────────────────────
if [ -f "$HOST_PEM" ]; then
    host_x509="$(openssl x509 -in "$HOST_PEM" -noout -text 2>&1)"
    assert_contains "Per-host cert has correct SAN for httpbin.org" "$host_x509" "DNS:httpbin.org"

    # ── Test: Per-host cert is signed by the CA ──────────────────────────────
    verify_out="$(openssl verify -CAfile "$CA_PEM" "$HOST_PEM" 2>&1)"
    if echo "$verify_out" | grep -q ": OK"; then
        pass "Per-host cert is signed by the CA"
    else
        fail "Per-host cert is signed by the CA" "$verify_out"
    fi

    # ── Test: Per-host cert has BasicConstraints CA:FALSE ────────────────────
    assert_contains "Per-host cert has BasicConstraints CA:FALSE" "$host_x509" "CA:FALSE"
else
    fail "Per-host cert has correct SAN" "Host cert not found: $HOST_PEM"
    fail "Per-host cert is signed by the CA" "Host cert not found"
    fail "Per-host cert has BasicConstraints CA:FALSE" "Host cert not found"
fi

print_summary
exit "$(test_exit_code; echo $?)"
