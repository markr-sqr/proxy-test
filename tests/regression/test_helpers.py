"""Regression tests R42-R46: Pure Python unit tests (no container needed).

Tests for helper functions imported directly from proxy.py.
"""

import os
import sys

import pytest

# Add project root to sys.path so we can import proxy.py
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from proxy import _parse_headers_list, _encode_body, _get_content_length, _b64url_decode, _luhn_check


pytestmark = pytest.mark.regression


# ---------------------------------------------------------------------------
# R42: _parse_headers_list
# ---------------------------------------------------------------------------

class TestParseHeadersList:
    """R42 — Header parsing."""

    def test_standard_headers(self):
        raw = "Host: example.com\r\nContent-Type: text/plain\r\nAccept: */*"
        result = _parse_headers_list(raw)
        assert result == [
            ["Host", "example.com"],
            ["Content-Type", "text/plain"],
            ["Accept", "*/*"],
        ]

    def test_no_space_after_colon(self):
        raw = "Host:example.com"
        result = _parse_headers_list(raw)
        assert result == [["Host", "example.com"]]

    def test_empty_string(self):
        assert _parse_headers_list("") == []

    def test_value_with_colon(self):
        raw = "Location: http://example.com:8080/path"
        result = _parse_headers_list(raw)
        assert result == [["Location", "http://example.com:8080/path"]]


# ---------------------------------------------------------------------------
# R43: _encode_body
# ---------------------------------------------------------------------------

class TestEncodeBody:
    """R43 — Body encoding for JSON logging."""

    def test_utf8_text(self):
        body, is_binary, truncated = _encode_body(b"Hello, world!")
        assert body == "Hello, world!"
        assert is_binary is False
        assert truncated is False

    def test_binary_data(self):
        body, is_binary, truncated = _encode_body(bytes(range(256)))
        assert is_binary is True
        assert truncated is False
        # Should be valid base64
        import base64
        base64.b64decode(body)

    def test_truncation(self):
        large = b"A" * 16384
        body, is_binary, truncated = _encode_body(large)
        assert truncated is True
        assert len(body) <= 8192

    def test_empty_body(self):
        body, is_binary, truncated = _encode_body(b"")
        assert body == ""
        assert is_binary is False
        assert truncated is False


# ---------------------------------------------------------------------------
# R44: _get_content_length
# ---------------------------------------------------------------------------

class TestGetContentLength:
    """R44 — Content-Length extraction."""

    def test_present(self):
        headers = "Host: example.com\r\nContent-Length: 42\r\nAccept: */*"
        assert _get_content_length(headers) == 42

    def test_missing(self):
        headers = "Host: example.com\r\nAccept: */*"
        assert _get_content_length(headers) == 0

    def test_case_insensitive(self):
        headers = "content-length: 100"
        assert _get_content_length(headers) == 100


# ---------------------------------------------------------------------------
# R45: _b64url_decode
# ---------------------------------------------------------------------------

class TestB64UrlDecode:
    """R45 — Base64url decoding."""

    def test_standard(self):
        import base64
        original = b"Hello, World!"
        encoded = base64.urlsafe_b64encode(original).rstrip(b"=").decode()
        assert _b64url_decode(encoded) == original

    def test_with_padding(self):
        # "ab" base64url encodes to "YWI" (3 chars, needs 1 pad)
        result = _b64url_decode("YWI")
        assert result == b"ab"

    def test_url_safe_chars(self):
        # base64url uses - and _ instead of + and /
        import base64
        data = bytes(range(256))
        encoded = base64.urlsafe_b64encode(data).rstrip(b"=").decode()
        assert _b64url_decode(encoded) == data


# ---------------------------------------------------------------------------
# R46: _luhn_check
# ---------------------------------------------------------------------------

class TestLuhnCheck:
    """R46 — Luhn algorithm validation."""

    def test_valid_visa(self):
        assert _luhn_check("4111111111111111") is True

    def test_valid_mastercard(self):
        assert _luhn_check("5500000000000004") is True

    def test_invalid_number(self):
        assert _luhn_check("4111111111111112") is False

    def test_too_short(self):
        assert _luhn_check("123456") is False

    def test_too_long(self):
        assert _luhn_check("1" * 20) is False

    def test_with_spaces(self):
        # Digits only are extracted, spaces/dashes ignored
        assert _luhn_check("4111 1111 1111 1111") is True

    def test_with_dashes(self):
        assert _luhn_check("4111-1111-1111-1111") is True
