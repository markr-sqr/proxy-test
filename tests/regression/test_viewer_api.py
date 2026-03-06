"""Regression tests R36-R41: Viewer API (pagination, filtering, malformed)."""

import uuid

import pytest
import requests


pytestmark = pytest.mark.regression


def _slug():
    return f"/api-{uuid.uuid4().hex[:8]}"


def _make_request(proxy_url, upstream_server, upstream_base_url, slug, method="GET",
                  body=None, resp_data="ok", resp_content_type="text/plain",
                  resp_headers=None, extra_req_headers=None):
    """Helper to send a request through the proxy and return."""
    upstream_server.expect_request(slug).respond_with_data(
        resp_data, content_type=resp_content_type,
        headers=resp_headers or {},
    )
    kwargs = {
        "proxies": {"http": proxy_url},
        "timeout": 10,
    }
    if extra_req_headers:
        kwargs["headers"] = extra_req_headers
    if method == "POST":
        kwargs["data"] = body or ""
        return requests.post(f"{upstream_base_url}{slug}", **kwargs)
    return requests.get(f"{upstream_base_url}{slug}", **kwargs)


# ---------------------------------------------------------------------------
# R36: Method filter
# ---------------------------------------------------------------------------

def test_method_filter(proxy_url, upstream_server, upstream_base_url, viewer_url, query_logs):
    """R36 — /api/logs?method=POST filters by HTTP method."""
    slug = _slug()
    # Send a POST
    upstream_server.expect_request(slug).respond_with_data("ok")
    requests.post(
        f"{upstream_base_url}{slug}",
        data="x=1",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        proxies={"http": proxy_url}, timeout=10,
    )
    # Wait for it to appear
    query_logs(slug, timeout=8)

    # Filter by POST
    r = requests.get(f"{viewer_url}/api/logs", params={"method": "POST", "url": slug}, timeout=5)
    data = r.json()
    assert data["total"] >= 1
    assert all(e["method"] == "POST" for e in data["entries"])


# ---------------------------------------------------------------------------
# R37: URL filter
# ---------------------------------------------------------------------------

def test_url_filter(proxy_url, upstream_server, upstream_base_url, viewer_url, query_logs):
    """R37 — /api/logs?url=<substr> filters by URL substring."""
    slug = _slug()
    upstream_server.expect_request(slug).respond_with_data("ok")
    requests.get(
        f"{upstream_base_url}{slug}",
        proxies={"http": proxy_url}, timeout=10,
    )
    query_logs(slug, timeout=8)

    r = requests.get(f"{viewer_url}/api/logs", params={"url": slug}, timeout=5)
    data = r.json()
    assert data["total"] >= 1
    assert all(slug in e["target"] for e in data["entries"])


# ---------------------------------------------------------------------------
# R38: Severity filter
# ---------------------------------------------------------------------------

def test_severity_filter(proxy_url, upstream_server, upstream_base_url, viewer_url, query_logs):
    """R38 — /api/logs?severity=HIGH filters by risk severity."""
    slug = _slug()
    upstream_server.expect_request(slug).respond_with_data("ok")
    # Trigger HIGH risk with SQL injection
    requests.get(
        f"{upstream_base_url}{slug}?q=UNION SELECT 1",
        proxies={"http": proxy_url}, timeout=10,
    )
    query_logs(slug, timeout=8)

    r = requests.get(f"{viewer_url}/api/logs", params={"severity": "HIGH", "url": slug}, timeout=5)
    data = r.json()
    assert data["total"] >= 1
    for e in data["entries"]:
        assert any(risk["severity"] == "HIGH" for risk in e.get("risks", []))


# ---------------------------------------------------------------------------
# R39: Pagination
# ---------------------------------------------------------------------------

def test_pagination(proxy_url, upstream_server, upstream_base_url, viewer_url, query_logs):
    """R39 — Pagination returns correct page/limit/total."""
    # Create a unique tag for this batch
    batch = f"/pag-{uuid.uuid4().hex[:8]}"

    # Send 3 requests with same batch tag
    for i in range(3):
        slug = f"{batch}-{i}"
        upstream_server.expect_request(slug).respond_with_data(f"resp-{i}")
        requests.get(
            f"{upstream_base_url}{slug}",
            proxies={"http": proxy_url}, timeout=10,
        )

    # Wait for all to appear
    query_logs(batch, timeout=10, min_entries=3)

    # Request page 1 with limit 2
    r = requests.get(f"{viewer_url}/api/logs",
                     params={"url": batch, "page": 1, "limit": 2}, timeout=5)
    data = r.json()
    assert data["page"] == 1
    assert data["limit"] == 2
    assert data["total"] >= 3
    assert len(data["entries"]) == 2

    # Request page 2
    r2 = requests.get(f"{viewer_url}/api/logs",
                      params={"url": batch, "page": 2, "limit": 2}, timeout=5)
    data2 = r2.json()
    assert data2["page"] == 2
    assert len(data2["entries"]) >= 1


# ---------------------------------------------------------------------------
# R40: sensitive_data in API response
# ---------------------------------------------------------------------------

def test_sensitive_data_in_api(proxy_url, upstream_server, upstream_base_url, viewer_url, query_logs):
    """R40 — sensitive_data field is included in /api/logs response."""
    slug = _slug()
    upstream_server.expect_request(slug).respond_with_data("ok")
    requests.get(
        f"{upstream_base_url}{slug}",
        headers={"Authorization": "Bearer secret-token-for-api-test"},
        proxies={"http": proxy_url}, timeout=10,
    )
    entries = query_logs(slug, timeout=8)
    assert entries
    assert "sensitive_data" in entries[0]

    # Also verify through /api/logs directly
    r = requests.get(f"{viewer_url}/api/logs", params={"url": slug}, timeout=5)
    api_entries = r.json()["entries"]
    assert any("sensitive_data" in e and e["sensitive_data"] for e in api_entries)


# ---------------------------------------------------------------------------
# R41: Malformed JSONL lines don't crash
# ---------------------------------------------------------------------------

def test_malformed_jsonl(proxy_url, upstream_server, upstream_base_url, proxy_container, viewer_url, query_logs):
    """R41 — Malformed lines in the log file don't crash the viewer."""
    container_id = proxy_container["id"]
    import subprocess

    # Inject a malformed line into the log file
    subprocess.run(
        ["docker", "exec", container_id, "sh", "-c",
         'echo "THIS IS NOT JSON" >> /tmp/proxy.log'],
        check=True,
    )

    # The viewer should still work
    r = requests.get(f"{viewer_url}/api/logs", timeout=5)
    assert r.status_code == 200
    data = r.json()
    assert "entries" in data

    # And we can still add new entries
    slug = _slug()
    upstream_server.expect_request(slug).respond_with_data("ok")
    requests.get(
        f"{upstream_base_url}{slug}",
        proxies={"http": proxy_url}, timeout=10,
    )
    entries = query_logs(slug, timeout=8)
    assert entries, "New entries should still work after malformed line"
