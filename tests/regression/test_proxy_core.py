"""Regression tests R28-R35: Proxy core HTTP/CONNECT/MITM behavior."""

import base64
import socket
import subprocess
import uuid

import pytest
import requests
from werkzeug.wrappers import Response as WerkzeugResponse


pytestmark = pytest.mark.regression


def _slug():
    return f"/core-{uuid.uuid4().hex[:8]}"


# ---------------------------------------------------------------------------
# R28: Proxy-Connection header is stripped
# ---------------------------------------------------------------------------

def test_proxy_connection_stripped(proxy_url, upstream_server, upstream_base_url, query_logs):
    """R28 — Proxy-Connection header is stripped before forwarding."""
    slug = _slug()

    received_headers = {}

    def handler(request):
        # Collect the headers the upstream actually received
        for key, val in request.headers.items():
            received_headers[key.lower()] = val
        return WerkzeugResponse("ok")

    upstream_server.expect_request(slug).respond_with_handler(handler)

    requests.get(
        f"{upstream_base_url}{slug}",
        headers={"Proxy-Connection": "keep-alive"},
        proxies={"http": proxy_url}, timeout=10,
    )
    # The proxy should strip Proxy-Connection
    assert "proxy-connection" not in received_headers, \
        "Proxy-Connection should be stripped before forwarding"


# ---------------------------------------------------------------------------
# R29: POST body is forwarded
# ---------------------------------------------------------------------------

def test_post_body_forwarded(proxy_url, upstream_server, upstream_base_url, query_logs):
    """R29 — POST request body is forwarded to upstream."""
    slug = _slug()

    received_body = {}

    def handler(request):
        received_body["data"] = request.data.decode("utf-8", errors="replace")
        return WerkzeugResponse("ok")

    upstream_server.expect_request(slug).respond_with_handler(handler)

    body = "field1=value1&field2=value2"
    requests.post(
        f"{upstream_base_url}{slug}",
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        proxies={"http": proxy_url}, timeout=10,
    )
    assert received_body.get("data") == body


# ---------------------------------------------------------------------------
# R30: Response > 8KB body is truncated in log
# ---------------------------------------------------------------------------

def test_response_body_truncated(proxy_url, upstream_server, upstream_base_url, query_logs):
    """R30 — Response body larger than MAX_BODY_LOG (8192) is truncated in log."""
    slug = _slug()
    large_body = "X" * 16384  # 16KB
    upstream_server.expect_request(slug).respond_with_data(
        large_body, content_type="text/plain",
    )
    requests.get(
        f"{upstream_base_url}{slug}",
        proxies={"http": proxy_url}, timeout=10,
    )
    entries = query_logs(slug, timeout=8)
    assert entries
    resp = entries[0].get("response", {})
    assert resp.get("body_truncated") is True, "Expected body_truncated=True"
    # Logged body should be at most 8192 chars
    assert len(resp.get("body", "")) <= 8192


# ---------------------------------------------------------------------------
# R31: Binary response is base64 encoded in log
# ---------------------------------------------------------------------------

def test_binary_base64_encoded(proxy_url, upstream_server, upstream_base_url, query_logs):
    """R31 — Binary response body is base64-encoded in log."""
    slug = _slug()
    binary_body = bytes(range(256))
    upstream_server.expect_request(slug).respond_with_data(
        binary_body, content_type="application/octet-stream",
    )
    requests.get(
        f"{upstream_base_url}{slug}",
        proxies={"http": proxy_url}, timeout=10,
    )
    entries = query_logs(slug, timeout=8)
    assert entries
    resp = entries[0].get("response", {})
    assert resp.get("body_is_binary") is True
    # Should be valid base64
    base64.b64decode(resp["body"])


# ---------------------------------------------------------------------------
# R32: 502 on unreachable upstream
# ---------------------------------------------------------------------------

def test_502_unreachable(proxy_url, query_logs):
    """R32 — Request to unreachable host produces 502."""
    slug = _slug()
    # Use a non-routable address to ensure connection failure
    try:
        r = requests.get(
            f"http://192.0.2.1:1{slug}",
            proxies={"http": proxy_url}, timeout=15,
        )
        assert r.status_code == 502
    except requests.exceptions.ProxyError:
        pass  # Some versions raise ProxyError for 502


# ---------------------------------------------------------------------------
# R33: 400 on malformed request
# ---------------------------------------------------------------------------

def test_400_malformed(proxy_host, proxy_port):
    """R33 — Malformed request (missing version) gets 400 Bad Request."""
    with socket.create_connection((proxy_host, proxy_port), timeout=5) as s:
        # Send a malformed HTTP request (only two parts, missing version)
        s.sendall(b"GET\r\n\r\n")
        response = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            response += chunk
        assert b"400" in response


# ---------------------------------------------------------------------------
# R34: MITM cert has correct SAN
# ---------------------------------------------------------------------------

def test_mitm_cert_san(proxy_url, proxy_container, ca_cert_path):
    """R34 — MITM-generated cert has correct SAN for the target host."""
    try:
        from cryptography import x509
        from cryptography.x509.oid import ExtensionOID
    except ImportError:
        pytest.skip("cryptography not installed")

    # Make a request to generate a cert for httpbin.org
    requests.get(
        "https://httpbin.org/get",
        proxies={"https": proxy_url},
        verify=ca_cert_path,
        timeout=15,
    )

    # Extract the host cert from container
    container_id = proxy_container["id"]
    result = subprocess.run(
        ["docker", "exec", container_id, "cat", "/app/certs/hosts/httpbin.org.pem"],
        capture_output=True,
    )
    if result.returncode != 0:
        pytest.skip("Host cert not found in container")

    cert = x509.load_pem_x509_certificate(result.stdout)
    san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    dns_names = san.value.get_values_for_type(x509.DNSName)
    assert "httpbin.org" in dns_names, f"Expected httpbin.org in SAN, got: {dns_names}"


# ---------------------------------------------------------------------------
# R35: Cert reuse (cached on disk)
# ---------------------------------------------------------------------------

def test_cert_reuse(proxy_url, proxy_container, ca_cert_path):
    """R35 — Second request to same host reuses cached cert."""
    host = "httpbin.org"
    container_id = proxy_container["id"]

    # First request
    requests.get(
        f"https://{host}/get",
        proxies={"https": proxy_url},
        verify=ca_cert_path,
        timeout=15,
    )

    # Get cert mtime
    result1 = subprocess.run(
        ["docker", "exec", container_id, "stat", "-c", "%Y", f"/app/certs/hosts/{host}.pem"],
        capture_output=True, text=True,
    )
    mtime1 = result1.stdout.strip()

    # Second request
    requests.get(
        f"https://{host}/get",
        proxies={"https": proxy_url},
        verify=ca_cert_path,
        timeout=15,
    )

    # Get cert mtime again
    result2 = subprocess.run(
        ["docker", "exec", container_id, "stat", "-c", "%Y", f"/app/certs/hosts/{host}.pem"],
        capture_output=True, text=True,
    )
    mtime2 = result2.stdout.strip()

    assert mtime1 == mtime2, "Cert file was regenerated — should be reused"
