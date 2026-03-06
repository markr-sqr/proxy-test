"""Regression tests R20-R27: Security / attack pattern detection."""

import uuid

import pytest
import requests


pytestmark = pytest.mark.regression


def _slug():
    return f"/sec-{uuid.uuid4().hex[:8]}"


# ---------------------------------------------------------------------------
# R20: SQL injection
# ---------------------------------------------------------------------------

def test_sql_injection(proxy_url, upstream_server, upstream_base_url, query_logs):
    """R20 — SQL injection patterns produce HIGH risk."""
    slug = _slug()
    upstream_server.expect_request(slug).respond_with_data("ok")
    requests.get(
        f"{upstream_base_url}{slug}?id=1 OR 1=1 --",
        proxies={"http": proxy_url}, timeout=10,
    )
    entries = query_logs(slug, timeout=8)
    assert entries
    risks = entries[0].get("risks", [])
    assert any(r["severity"] == "HIGH" and "sql" in r["description"].lower() for r in risks)


# ---------------------------------------------------------------------------
# R21: XSS
# ---------------------------------------------------------------------------

def test_xss(proxy_url, upstream_server, upstream_base_url, query_logs):
    """R21 — XSS patterns produce HIGH risk."""
    slug = _slug()
    upstream_server.expect_request(slug).respond_with_data("ok")
    requests.get(
        f"{upstream_base_url}{slug}?q=<script>alert(1)</script>",
        proxies={"http": proxy_url}, timeout=10,
    )
    entries = query_logs(slug, timeout=8)
    assert entries
    risks = entries[0].get("risks", [])
    assert any(r["severity"] == "HIGH" and "xss" in r["description"].lower() for r in risks)


# ---------------------------------------------------------------------------
# R22: Path traversal
# ---------------------------------------------------------------------------

def test_path_traversal(proxy_url, upstream_server, upstream_base_url, query_logs):
    """R22 — Path traversal ../../etc/passwd produces HIGH risk."""
    slug = _slug()
    # Put traversal in query param — requests normalizes ../ out of the path
    upstream_server.expect_request(slug).respond_with_data("ok")
    requests.get(
        f"{upstream_base_url}{slug}?file=../../etc/passwd",
        proxies={"http": proxy_url}, timeout=10,
    )
    entries = query_logs(slug, timeout=8)
    assert entries
    risks = entries[0].get("risks", [])
    assert any(r["severity"] == "HIGH" and "path traversal" in r["description"].lower() for r in risks)


# ---------------------------------------------------------------------------
# R23: Command injection
# ---------------------------------------------------------------------------

def test_command_injection(proxy_url, upstream_server, upstream_base_url, query_logs):
    """R23 — Command injection pattern produces HIGH risk."""
    slug = _slug()
    upstream_server.expect_request(slug).respond_with_data("ok")
    requests.get(
        f"{upstream_base_url}{slug}?cmd=`id`",
        proxies={"http": proxy_url}, timeout=10,
    )
    entries = query_logs(slug, timeout=8)
    assert entries
    risks = entries[0].get("risks", [])
    assert any(r["severity"] == "HIGH" and "command injection" in r["description"].lower() for r in risks)


# ---------------------------------------------------------------------------
# R24: Sensitive URL parameters risk
# ---------------------------------------------------------------------------

def test_sensitive_url_params_risk(proxy_url, upstream_server, upstream_base_url, query_logs):
    """R24 — password= in URL → MEDIUM risk."""
    slug = _slug()
    upstream_server.expect_request(slug).respond_with_data("ok")
    requests.get(
        f"{upstream_base_url}{slug}?password=secret123",
        proxies={"http": proxy_url}, timeout=10,
    )
    entries = query_logs(slug, timeout=8)
    assert entries
    risks = entries[0].get("risks", [])
    assert any(r["severity"] == "MEDIUM" and "sensitive data in url" in r["description"].lower() for r in risks)


# ---------------------------------------------------------------------------
# R25: Missing security headers on HTML
# ---------------------------------------------------------------------------

def test_missing_headers_html(proxy_url, upstream_server, upstream_base_url, query_logs):
    """R25 — HTML response missing security headers → risks detected."""
    slug = _slug()
    upstream_server.expect_request(slug).respond_with_data(
        "<html><body>Test</body></html>",
        content_type="text/html",
    )
    requests.get(
        f"{upstream_base_url}{slug}",
        proxies={"http": proxy_url}, timeout=10,
    )
    entries = query_logs(slug, timeout=8)
    assert entries
    risks = entries[0].get("risks", [])
    descs = " ".join(r["description"].lower() for r in risks)
    assert "content-security-policy" in descs, f"Expected CSP risk, got: {risks}"


# ---------------------------------------------------------------------------
# R26: No false positives on non-HTML
# ---------------------------------------------------------------------------

def test_no_false_positive_non_html(proxy_url, upstream_server, upstream_base_url, query_logs):
    """R26 — JSON response should NOT trigger missing security header risks."""
    slug = _slug()
    upstream_server.expect_request(slug).respond_with_data(
        '{"status": "ok"}',
        content_type="application/json",
    )
    requests.get(
        f"{upstream_base_url}{slug}",
        proxies={"http": proxy_url}, timeout=10,
    )
    entries = query_logs(slug, timeout=8)
    assert entries
    risks = entries[0].get("risks", [])
    header_risks = [r for r in risks if "missing" in r["description"].lower() and "header" in r["description"].lower()]
    assert not header_risks, f"Unexpected security header risks on JSON: {header_risks}"


# ---------------------------------------------------------------------------
# R27: HSTS only on HTTPS
# ---------------------------------------------------------------------------

def test_hsts_only_https(proxy_url, upstream_server, upstream_base_url, query_logs):
    """R27 — HSTS risk should not be flagged for plain HTTP targets."""
    slug = _slug()
    upstream_server.expect_request(slug).respond_with_data(
        "<html><body>Test</body></html>",
        content_type="text/html",
    )
    requests.get(
        f"{upstream_base_url}{slug}",
        proxies={"http": proxy_url}, timeout=10,
    )
    entries = query_logs(slug, timeout=8)
    assert entries
    risks = entries[0].get("risks", [])
    hsts_risks = [r for r in risks if "strict-transport-security" in r["description"].lower()
                  or "hsts" in r["description"].lower()]
    assert not hsts_risks, f"HSTS risk should not appear for HTTP: {hsts_risks}"
