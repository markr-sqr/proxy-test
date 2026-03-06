"""Smoke tests (S1-S9): fast sanity checks that the proxy container works."""

import socket
import uuid

import pytest
import requests


pytestmark = pytest.mark.smoke


# ---------------------------------------------------------------------------
# S1: TCP connect to proxy port
# ---------------------------------------------------------------------------

def test_proxy_accepts_connections(proxy_host, proxy_port):
    """S1 — Proxy port accepts TCP connections."""
    with socket.create_connection((proxy_host, proxy_port), timeout=5):
        pass  # connection succeeded


# ---------------------------------------------------------------------------
# S2: Viewer health endpoint
# ---------------------------------------------------------------------------

def test_viewer_health(viewer_url):
    """S2 — GET /health returns 200 with status ok."""
    r = requests.get(f"{viewer_url}/health", timeout=5)
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


# ---------------------------------------------------------------------------
# S3: HTTP GET through proxy
# ---------------------------------------------------------------------------

def test_http_get_through_proxy(proxy_url, upstream_server, upstream_base_url):
    """S3 — HTTP GET returns the upstream response body."""
    slug = f"/s3-{uuid.uuid4().hex[:8]}"
    upstream_server.expect_request(slug).respond_with_data(
        "hello-proxy", content_type="text/plain",
    )

    r = requests.get(
        f"{upstream_base_url}{slug}",
        proxies={"http": proxy_url},
        timeout=10,
    )
    assert r.status_code == 200
    assert r.text == "hello-proxy"


# ---------------------------------------------------------------------------
# S4: HTTPS CONNECT tunnel via MITM
# ---------------------------------------------------------------------------

def test_https_connect_tunnel(proxy_url, ca_cert_path):
    """S4 — HTTPS request via MITM proxy succeeds (httpbin.org)."""
    r = requests.get(
        "https://httpbin.org/get",
        proxies={"https": proxy_url},
        verify=ca_cert_path,
        timeout=15,
    )
    assert r.status_code == 200
    data = r.json()
    assert "headers" in data


# ---------------------------------------------------------------------------
# S5: MITM logs decrypted URL
# ---------------------------------------------------------------------------

def test_mitm_logs_decrypted_url(proxy_url, ca_cert_path, query_logs):
    """S5 — MITM entry in logs has https:// target URL."""
    slug = f"/s5-{uuid.uuid4().hex[:8]}"
    target = f"https://httpbin.org{slug}"

    requests.get(
        target,
        proxies={"https": proxy_url},
        verify=ca_cert_path,
        timeout=15,
    )

    entries = query_logs(slug, timeout=8)
    assert len(entries) > 0, "No log entry found for MITM request"
    found = [e for e in entries if e["target"].startswith("https://")]
    assert found, "Expected https:// target in MITM log entry"


# ---------------------------------------------------------------------------
# S6: /api/logs returns valid JSON
# ---------------------------------------------------------------------------

def test_api_logs_valid_json(viewer_url):
    """S6 — /api/logs returns correct JSON schema."""
    r = requests.get(f"{viewer_url}/api/logs", timeout=5)
    assert r.status_code == 200
    data = r.json()
    assert "entries" in data
    assert "total" in data
    assert "page" in data
    assert "limit" in data
    assert isinstance(data["entries"], list)


# ---------------------------------------------------------------------------
# S7: Bearer token produces sensitive_data finding
# ---------------------------------------------------------------------------

def test_bearer_token_sensitive_data(proxy_url, upstream_server, upstream_base_url, query_logs):
    """S7 — Bearer token in Authorization header → sensitive_data entry."""
    slug = f"/s7-{uuid.uuid4().hex[:8]}"
    upstream_server.expect_request(slug).respond_with_data("ok")

    requests.get(
        f"{upstream_base_url}{slug}",
        headers={"Authorization": "Bearer my-secret-token-123"},
        proxies={"http": proxy_url},
        timeout=10,
    )

    entries = query_logs(slug, timeout=8)
    assert len(entries) > 0
    entry = entries[0]
    assert entry.get("sensitive_data"), "Expected sensitive_data in log entry"
    types = [sd["type"] for sd in entry["sensitive_data"]]
    assert "bearer_token" in types or "jwt" in types


# ---------------------------------------------------------------------------
# S8: SQL injection risk detection
# ---------------------------------------------------------------------------

def test_sql_injection_risk(proxy_url, upstream_server, upstream_base_url, query_logs):
    """S8 — UNION SELECT in URL produces HIGH risk."""
    slug = f"/s8-{uuid.uuid4().hex[:8]}"
    path = f"{slug}?q=1 UNION SELECT * FROM users"
    upstream_server.expect_request(slug).respond_with_data("ok")

    requests.get(
        f"{upstream_base_url}{path}",
        proxies={"http": proxy_url},
        timeout=10,
    )

    entries = query_logs(slug, timeout=8)
    assert len(entries) > 0
    risks = entries[0].get("risks", [])
    high_risks = [r for r in risks if r["severity"] == "HIGH"]
    assert high_risks, "Expected HIGH risk for SQL injection"
    assert any("sql" in r["description"].lower() for r in high_risks)


# ---------------------------------------------------------------------------
# S9: Missing security headers risk
# ---------------------------------------------------------------------------

def test_missing_security_headers_risk(proxy_url, upstream_server, upstream_base_url, query_logs):
    """S9 — HTML response without CSP → security header risk."""
    slug = f"/s9-{uuid.uuid4().hex[:8]}"
    upstream_server.expect_request(slug).respond_with_data(
        "<html><body>Hello</body></html>",
        content_type="text/html",
    )

    requests.get(
        f"{upstream_base_url}{slug}",
        proxies={"http": proxy_url},
        timeout=10,
    )

    entries = query_logs(slug, timeout=8)
    assert len(entries) > 0
    risks = entries[0].get("risks", [])
    desc_lower = " ".join(r["description"].lower() for r in risks)
    assert "content-security-policy" in desc_lower or "csp" in desc_lower, \
        f"Expected CSP risk, got: {risks}"
