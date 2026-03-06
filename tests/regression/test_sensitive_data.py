"""Regression tests R1-R19: Sensitive data extraction."""

import base64
import json
import uuid

import pytest
import requests


pytestmark = pytest.mark.regression


def _slug():
    return f"/sens-{uuid.uuid4().hex[:8]}"


# ---------------------------------------------------------------------------
# R1: Bearer token detection
# ---------------------------------------------------------------------------

def test_bearer_token(proxy_url, upstream_server, upstream_base_url, query_logs):
    """R1 — Bearer token in request header is detected."""
    slug = _slug()
    upstream_server.expect_request(slug).respond_with_data("ok")
    requests.get(
        f"{upstream_base_url}{slug}",
        headers={"Authorization": "Bearer abc123xyz"},
        proxies={"http": proxy_url}, timeout=10,
    )
    entries = query_logs(slug, timeout=8)
    assert entries
    sd = entries[0].get("sensitive_data", [])
    assert any(f["type"] == "bearer_token" for f in sd)


# ---------------------------------------------------------------------------
# R2: JWT decode
# ---------------------------------------------------------------------------

def test_jwt_decode(proxy_url, upstream_server, upstream_base_url, query_logs):
    """R2 — JWT in Authorization header is decoded."""
    slug = _slug()
    upstream_server.expect_request(slug).respond_with_data("ok")
    # Construct a minimal JWT
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps({"sub": "1234567890", "name": "Test"}).encode()).rstrip(b"=").decode()
    jwt_token = f"{header}.{payload}.fakesig"
    requests.get(
        f"{upstream_base_url}{slug}",
        headers={"Authorization": f"Bearer {jwt_token}"},
        proxies={"http": proxy_url}, timeout=10,
    )
    entries = query_logs(slug, timeout=8)
    assert entries
    sd = entries[0].get("sensitive_data", [])
    jwt_findings = [f for f in sd if f["type"] == "jwt"]
    assert jwt_findings, "JWT not detected"
    assert jwt_findings[0].get("decoded"), "JWT not decoded"


# ---------------------------------------------------------------------------
# R3: Basic auth decode
# ---------------------------------------------------------------------------

def test_basic_auth_decode(proxy_url, upstream_server, upstream_base_url, query_logs):
    """R3 — Basic auth credentials are decoded."""
    slug = _slug()
    upstream_server.expect_request(slug).respond_with_data("ok")
    cred = base64.b64encode(b"admin:secret123").decode()
    requests.get(
        f"{upstream_base_url}{slug}",
        headers={"Authorization": f"Basic {cred}"},
        proxies={"http": proxy_url}, timeout=10,
    )
    entries = query_logs(slug, timeout=8)
    assert entries
    sd = entries[0].get("sensitive_data", [])
    basic = [f for f in sd if f["type"] == "basic_auth"]
    assert basic, "Basic auth not detected"
    assert "admin:secret123" in basic[0].get("decoded", "")


# ---------------------------------------------------------------------------
# R4: API key header
# ---------------------------------------------------------------------------

def test_api_key_header(proxy_url, upstream_server, upstream_base_url, query_logs):
    """R4 — X-Api-Key header is detected."""
    slug = _slug()
    upstream_server.expect_request(slug).respond_with_data("ok")
    requests.get(
        f"{upstream_base_url}{slug}",
        headers={"X-Api-Key": "sk-1234567890abcdef"},
        proxies={"http": proxy_url}, timeout=10,
    )
    entries = query_logs(slug, timeout=8)
    assert entries
    sd = entries[0].get("sensitive_data", [])
    assert any(f["type"] == "api_key" for f in sd)


# ---------------------------------------------------------------------------
# R5: Cookie detection
# ---------------------------------------------------------------------------

def test_cookie_detection(proxy_url, upstream_server, upstream_base_url, query_logs):
    """R5 — Cookie header is detected in sensitive data."""
    slug = _slug()
    upstream_server.expect_request(slug).respond_with_data("ok")
    requests.get(
        f"{upstream_base_url}{slug}",
        headers={"Cookie": "session=abc123; token=xyz"},
        proxies={"http": proxy_url}, timeout=10,
    )
    entries = query_logs(slug, timeout=8)
    assert entries
    sd = entries[0].get("sensitive_data", [])
    assert any(f["type"] == "cookie" for f in sd)


# ---------------------------------------------------------------------------
# R6: Set-Cookie in response
# ---------------------------------------------------------------------------

def test_set_cookie_response(proxy_url, upstream_server, upstream_base_url, query_logs):
    """R6 — Set-Cookie in response header is detected."""
    slug = _slug()
    upstream_server.expect_request(slug).respond_with_data(
        "ok", headers={"Set-Cookie": "sessionid=deadbeef; Path=/; HttpOnly"},
    )
    requests.get(
        f"{upstream_base_url}{slug}",
        proxies={"http": proxy_url}, timeout=10,
    )
    entries = query_logs(slug, timeout=8)
    assert entries
    sd = entries[0].get("sensitive_data", [])
    cookies = [f for f in sd if f["type"] == "cookie"]
    assert cookies, "Set-Cookie not detected"
    assert any(f["source"] == "response_header" for f in cookies)


# ---------------------------------------------------------------------------
# R7: Session headers
# ---------------------------------------------------------------------------

def test_session_headers(proxy_url, upstream_server, upstream_base_url, query_logs):
    """R7 — X-Session-Token header is detected."""
    slug = _slug()
    upstream_server.expect_request(slug).respond_with_data("ok")
    requests.get(
        f"{upstream_base_url}{slug}",
        headers={"X-Session-Token": "sess-abcdef123456"},
        proxies={"http": proxy_url}, timeout=10,
    )
    entries = query_logs(slug, timeout=8)
    assert entries
    sd = entries[0].get("sensitive_data", [])
    assert any(f["type"] == "session_token" for f in sd)


# ---------------------------------------------------------------------------
# R8: Sensitive URL parameters
# ---------------------------------------------------------------------------

def test_url_params(proxy_url, upstream_server, upstream_base_url, query_logs):
    """R8 — Sensitive URL params (api_key=...) are detected."""
    slug = _slug()
    upstream_server.expect_request(slug).respond_with_data("ok")
    requests.get(
        f"{upstream_base_url}{slug}?api_key=SECRETKEY123",
        proxies={"http": proxy_url}, timeout=10,
    )
    entries = query_logs(slug, timeout=8)
    assert entries
    sd = entries[0].get("sensitive_data", [])
    assert any(f["source"] == "request_url" for f in sd)


# ---------------------------------------------------------------------------
# R9: Form body password
# ---------------------------------------------------------------------------

def test_form_body_password(proxy_url, upstream_server, upstream_base_url, query_logs):
    """R9 — password=... in form-encoded body is detected."""
    slug = _slug()
    upstream_server.expect_request(slug).respond_with_data("ok")
    requests.post(
        f"{upstream_base_url}{slug}",
        data="username=admin&password=hunter2",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        proxies={"http": proxy_url}, timeout=10,
    )
    entries = query_logs(slug, timeout=8)
    assert entries
    sd = entries[0].get("sensitive_data", [])
    assert any(f["type"] == "password" and f["source"] == "request_body" for f in sd)


# ---------------------------------------------------------------------------
# R10: JSON body credentials
# ---------------------------------------------------------------------------

def test_json_body_credentials(proxy_url, upstream_server, upstream_base_url, query_logs):
    """R10 — JSON body with "password" field is detected."""
    slug = _slug()
    upstream_server.expect_request(slug).respond_with_data("ok")
    requests.post(
        f"{upstream_base_url}{slug}",
        json={"username": "admin", "password": "s3cret"},
        proxies={"http": proxy_url}, timeout=10,
    )
    entries = query_logs(slug, timeout=8)
    assert entries
    sd = entries[0].get("sensitive_data", [])
    assert any(f["type"] == "password" and f["source"] == "request_body" for f in sd)


# ---------------------------------------------------------------------------
# R11: Email detection
# ---------------------------------------------------------------------------

def test_email_detection(proxy_url, upstream_server, upstream_base_url, query_logs):
    """R11 — Email in body is detected."""
    slug = _slug()
    upstream_server.expect_request(slug).respond_with_data("ok")
    requests.post(
        f"{upstream_base_url}{slug}",
        data="contact=user@example.com&name=Test",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        proxies={"http": proxy_url}, timeout=10,
    )
    entries = query_logs(slug, timeout=8)
    assert entries
    sd = entries[0].get("sensitive_data", [])
    assert any(f["type"] == "email" for f in sd)


# ---------------------------------------------------------------------------
# R12: Phone number detection
# ---------------------------------------------------------------------------

def test_phone_detection(proxy_url, upstream_server, upstream_base_url, query_logs):
    """R12 — US phone number in body is detected."""
    slug = _slug()
    upstream_server.expect_request(slug).respond_with_data("ok")
    requests.post(
        f"{upstream_base_url}{slug}",
        data="phone=(555) 123-4567&name=Test",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        proxies={"http": proxy_url}, timeout=10,
    )
    entries = query_logs(slug, timeout=8)
    assert entries
    sd = entries[0].get("sensitive_data", [])
    assert any(f["type"] == "phone" for f in sd)


# ---------------------------------------------------------------------------
# R13: SSN detection
# ---------------------------------------------------------------------------

def test_ssn_detection(proxy_url, upstream_server, upstream_base_url, query_logs):
    """R13 — SSN pattern in body is detected."""
    slug = _slug()
    upstream_server.expect_request(slug).respond_with_data("ok")
    requests.post(
        f"{upstream_base_url}{slug}",
        data="ssn=123-45-6789&name=Test",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        proxies={"http": proxy_url}, timeout=10,
    )
    entries = query_logs(slug, timeout=8)
    assert entries
    sd = entries[0].get("sensitive_data", [])
    assert any(f["type"] == "ssn" for f in sd)


# ---------------------------------------------------------------------------
# R14: Credit card (Luhn valid)
# ---------------------------------------------------------------------------

def test_credit_card_luhn(proxy_url, upstream_server, upstream_base_url, query_logs):
    """R14 — Valid credit card number (Luhn check) is detected."""
    slug = _slug()
    upstream_server.expect_request(slug).respond_with_data("ok")
    # 4111111111111111 is a well-known Luhn-valid test card number
    requests.post(
        f"{upstream_base_url}{slug}",
        data="card=4111 1111 1111 1111&cvv=123",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        proxies={"http": proxy_url}, timeout=10,
    )
    entries = query_logs(slug, timeout=8)
    assert entries
    sd = entries[0].get("sensitive_data", [])
    assert any(f["type"] == "credit_card" for f in sd)


# ---------------------------------------------------------------------------
# R15: PEM private key detection
# ---------------------------------------------------------------------------

def test_pem_key(proxy_url, upstream_server, upstream_base_url, query_logs):
    """R15 — PEM private key in body is detected."""
    slug = _slug()
    upstream_server.expect_request(slug).respond_with_data("ok")
    pem_body = "data=-----BEGIN RSA PRIVATE KEY-----\nMIIBog...fake\n-----END RSA PRIVATE KEY-----"
    requests.post(
        f"{upstream_base_url}{slug}",
        data=pem_body,
        proxies={"http": proxy_url}, timeout=10,
    )
    entries = query_logs(slug, timeout=8)
    assert entries
    sd = entries[0].get("sensitive_data", [])
    assert any(f["type"] == "private_key" for f in sd)


# ---------------------------------------------------------------------------
# R16: AWS access key detection
# ---------------------------------------------------------------------------

def test_aws_key(proxy_url, upstream_server, upstream_base_url, query_logs):
    """R16 — AWS access key ID pattern is detected."""
    slug = _slug()
    upstream_server.expect_request(slug).respond_with_data("ok")
    requests.post(
        f"{upstream_base_url}{slug}",
        data="aws_access_key_id=AKIAIOSFODNN7EXAMPLE&aws_secret=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        proxies={"http": proxy_url}, timeout=10,
    )
    entries = query_logs(slug, timeout=8)
    assert entries
    sd = entries[0].get("sensitive_data", [])
    assert any(f["type"] == "aws_credentials" for f in sd)


# ---------------------------------------------------------------------------
# R17: Deduplication
# ---------------------------------------------------------------------------

def test_deduplication(proxy_url, upstream_server, upstream_base_url, query_logs):
    """R17 — Duplicate sensitive data findings are deduplicated."""
    slug = _slug()
    # Respond with same Bearer token in Set-Cookie so same value appears twice
    upstream_server.expect_request(slug).respond_with_data("ok")
    # Send same Bearer token; should appear only once per (type, source, value)
    requests.get(
        f"{upstream_base_url}{slug}",
        headers={"Authorization": "Bearer dedup-test-token-abc"},
        proxies={"http": proxy_url}, timeout=10,
    )
    entries = query_logs(slug, timeout=8)
    assert entries
    sd = entries[0].get("sensitive_data", [])
    # Check no duplicate (type, source, value) triples
    keys = [(f["type"], f["source"], f["value"]) for f in sd]
    assert len(keys) == len(set(keys)), "Duplicate findings detected"


# ---------------------------------------------------------------------------
# R18: Binary body skip
# ---------------------------------------------------------------------------

def test_binary_skip(proxy_url, upstream_server, upstream_base_url, query_logs):
    """R18 — Binary body does not produce false sensitive data findings."""
    slug = _slug()
    # Binary content with >30% non-printable chars (the proxy's skip threshold).
    # Avoid sequential digits (0-9) which can match phone regex.
    import os
    binary_body = os.urandom(1024)
    upstream_server.expect_request(slug).respond_with_data(
        binary_body, content_type="application/octet-stream",
    )
    requests.get(
        f"{upstream_base_url}{slug}",
        proxies={"http": proxy_url}, timeout=10,
    )
    entries = query_logs(slug, timeout=8)
    assert entries
    sd = entries[0].get("sensitive_data", [])
    # Binary response should not trigger body-scan findings from response_body
    resp_body_findings = [f for f in sd if f["source"] == "response_body"]
    assert not resp_body_findings, f"Unexpected findings in binary body: {resp_body_findings}"


# ---------------------------------------------------------------------------
# R19: Response body source
# ---------------------------------------------------------------------------

def test_response_body_source(proxy_url, upstream_server, upstream_base_url, query_logs):
    """R19 — Sensitive data in response body is labelled source=response_body."""
    slug = _slug()
    upstream_server.expect_request(slug).respond_with_data(
        '{"password": "resp-secret-456"}',
        content_type="application/json",
    )
    requests.get(
        f"{upstream_base_url}{slug}",
        proxies={"http": proxy_url}, timeout=10,
    )
    entries = query_logs(slug, timeout=8)
    assert entries
    sd = entries[0].get("sensitive_data", [])
    resp_findings = [f for f in sd if f["source"] == "response_body"]
    assert resp_findings, "Expected finding with source=response_body"
    assert any(f["type"] == "password" for f in resp_findings)
