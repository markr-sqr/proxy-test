"""Regression tests: Playwright UI tests for the log viewer."""

import uuid

import pytest
import requests


pytestmark = [pytest.mark.regression, pytest.mark.ui]


def _slug():
    return f"/ui-{uuid.uuid4().hex[:8]}"


def _send_request_with_sensitive_data(proxy_url, upstream_server, upstream_base_url):
    """Send a request that generates log entry with sensitive data and risks."""
    slug = _slug()
    upstream_server.expect_request(slug).respond_with_data(
        "<html><body>Test</body></html>",
        content_type="text/html",
    )
    requests.get(
        f"{upstream_base_url}{slug}",
        headers={"Authorization": "Bearer ui-test-secret-token"},
        proxies={"http": proxy_url},
        timeout=10,
    )
    return slug


# ---------------------------------------------------------------------------
# UI1: Log table renders with entries
# ---------------------------------------------------------------------------

def test_log_table_renders(page, proxy_url, upstream_server, upstream_base_url, query_logs):
    """UI1 — Log table renders entries after traffic is generated."""
    slug = _send_request_with_sensitive_data(proxy_url, upstream_server, upstream_base_url)
    query_logs(slug, timeout=8)

    # Reload page to pick up new entries
    page.reload(wait_until="networkidle")

    # Wait for the log table body to have rows
    page.wait_for_selector("#log-body tr", timeout=10000)
    rows = page.query_selector_all("#log-body tr")
    assert len(rows) > 0, "Expected at least one row in log table"


# ---------------------------------------------------------------------------
# UI2: Detail row expands on click
# ---------------------------------------------------------------------------

def test_detail_row_expands(page, proxy_url, upstream_server, upstream_base_url, query_logs):
    """UI2 — Clicking a log row expands a detail section."""
    slug = _send_request_with_sensitive_data(proxy_url, upstream_server, upstream_base_url)
    query_logs(slug, timeout=8)

    page.reload(wait_until="networkidle")
    page.wait_for_selector("#log-body tr", timeout=10000)

    # Click the first data row
    first_row = page.query_selector("#log-body tr")
    first_row.click()

    # A detail row should appear
    detail = page.wait_for_selector("tr.detail-row", timeout=5000)
    assert detail is not None
    assert detail.is_visible()


# ---------------------------------------------------------------------------
# UI3: Sensitive data section with masked values + reveal toggle
# ---------------------------------------------------------------------------

def test_sensitive_data_reveal(page, proxy_url, upstream_server, upstream_base_url, query_logs):
    """UI3 — Sensitive data section shows masked values and a Reveal button."""
    slug = _send_request_with_sensitive_data(proxy_url, upstream_server, upstream_base_url)
    query_logs(slug, timeout=8)

    # Use URL filter to narrow to our entry with sensitive data
    page.reload(wait_until="networkidle")
    url_input = page.wait_for_selector("#f-url", timeout=5000)
    url_input.fill(slug)
    page.click("button[type='submit']")
    page.wait_for_selector("#log-body tr", timeout=10000)

    # Click the row to expand detail
    first_row = page.query_selector("#log-body tr")
    first_row.click()
    page.wait_for_selector("tr.detail-row", timeout=5000)

    # Look for sensitive data section
    sensitive_section = page.query_selector(".sensitive-section")
    assert sensitive_section is not None, "Sensitive data section not found for entry with Bearer token"

    # Check for reveal button
    reveal_btn = page.query_selector(".sensitive-reveal-btn")
    assert reveal_btn is not None, "Expected Reveal button in sensitive data section"
    assert reveal_btn.inner_text().strip() == "Reveal"

    # Click reveal and check it toggles
    reveal_btn.click()
    assert reveal_btn.inner_text().strip() == "Hide"


# ---------------------------------------------------------------------------
# UI4: Sensitive data summary modal
# ---------------------------------------------------------------------------

def test_sensitive_data_modal(page, proxy_url, upstream_server, upstream_base_url, query_logs):
    """UI4 — Sensitive data summary modal opens and shows grouped findings."""
    slug = _send_request_with_sensitive_data(proxy_url, upstream_server, upstream_base_url)
    query_logs(slug, timeout=8)

    page.reload(wait_until="networkidle")
    page.wait_for_selector("#log-body tr", timeout=10000)

    # Click the sensitive data summary button
    sens_btn = page.query_selector("#sensitive-btn")
    assert sens_btn is not None, "Sensitive data summary button not found"
    sens_btn.click()

    # Wait for modal to appear
    modal = page.wait_for_selector("#sensitive-modal.open", timeout=5000)
    assert modal is not None
    assert modal.is_visible()
