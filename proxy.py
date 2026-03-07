#!/usr/bin/env python3
"""HTTP/HTTPS forward proxy server with optional TLS interception."""

import argparse
import base64
import json
import os
import re
import socket
import select
import ssl
import struct
import threading
from datetime import datetime, timezone
from urllib.parse import unquote_plus

BUFFER_SIZE = 65536
DEFAULT_PORT = 8080
LOG_FILE = os.environ.get("PROXY_LOG_FILE", "/tmp/proxy.log")
MAX_BODY_LOG = 8192
MAX_WS_FRAMES = 200
MAX_WS_PAYLOAD = 4096

_log_lock = threading.Lock()
_ca_cert = None
_ca_key = None
_mitm_enabled = False
_mitm_verify_upstream = True


# ── Security risk detection ──────────────────────────────────────────────────
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

_SEVERITY_COLOUR = {"HIGH": RED, "MEDIUM": YELLOW, "LOW": CYAN}

# Pre-compiled patterns
_SQL_RE = re.compile(
    r"(?:UNION\s+SELECT|OR\s+1\s*=\s*1|'\s*OR\s*'|DROP\s+TABLE|;\s*--)",
    re.IGNORECASE,
)
_XSS_RE = re.compile(
    r"(?:<script|javascript:|onerror\s*=|onload\s*=|eval\s*\(|document\.cookie)",
    re.IGNORECASE,
)
_PATH_TRAVERSAL_RE = re.compile(
    r"(?:\.\./|\.\.%2[fF]|\.\.%5[cC]|%2[eE]%2[eE])",
)
_CMD_INJECTION_RE = re.compile(
    r"(?:`[^`]+`|\$\(|&&\s*\w|(?<!=)\|\s*\w)",
)
_SENSITIVE_PARAM_RE = re.compile(
    r"(?:^|[?&])(?:password|passwd|secret|api_key|token|apikey)=",
    re.IGNORECASE,
)
_AUTH_PATH_RE = re.compile(
    r"/(?:login|auth|signin)(?:[/?#]|$)",
    re.IGNORECASE,
)
_PRIVATE_IP_RE = re.compile(
    r"(?:^|://)(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|169\.254\.\d{1,3}\.\d{1,3}"
    r"|localhost)(?:[:/?#]|$)",
    re.IGNORECASE,
)
_BASIC_AUTH_RE = re.compile(
    r"^Authorization:\s*Basic\s+\S",
    re.IGNORECASE | re.MULTILINE,
)
_BEARER_AUTH_RE = re.compile(
    r"^Authorization:\s*Bearer\s+\S",
    re.IGNORECASE | re.MULTILINE,
)
_PROXY_AUTH_RE = re.compile(
    r"^Proxy-Authorization:\s*\S",
    re.IGNORECASE | re.MULTILINE,
)
_BODY_CRED_RE = re.compile(
    r"(?:^|&)(?:password|passwd|pass|credential|user_password|old_password|new_password)=[^&\s]+",
    re.IGNORECASE,
)

# ── Sensitive data detection patterns ────────────────────────────────────────
_SENS_BEARER_RE = re.compile(
    r"^Authorization:\s*Bearer\s+(\S+)", re.IGNORECASE | re.MULTILINE,
)
_SENS_BASIC_RE = re.compile(
    r"^Authorization:\s*Basic\s+(\S+)", re.IGNORECASE | re.MULTILINE,
)
_SENS_APIKEY_HEADER_RE = re.compile(
    r"^(X-Api-Key|Api-Key|Apikey):\s*(\S+)", re.IGNORECASE | re.MULTILINE,
)
_SENS_COOKIE_RE = re.compile(
    r"^(Cookie|Set-Cookie):\s*(.+)", re.IGNORECASE | re.MULTILINE,
)
_SENS_JWT_RE = re.compile(
    r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]*)?",
)
_SENS_EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
)
_SENS_PHONE_RE = re.compile(
    r"(?<!\d)(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)",
)
_SENS_SSN_RE = re.compile(
    r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)",
)
_SENS_CC_RE = re.compile(
    r"(?<!\d)(\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4})(?!\d)",
)
_SENS_PEM_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
)
_SENS_AWS_KEY_RE = re.compile(
    r"(?<![A-Z0-9])((?:AKIA|ASIA)[A-Z0-9]{16})(?![A-Z0-9])",
)
_SENS_AWS_SECRET_RE = re.compile(
    r"(?<![A-Za-z0-9/+=])([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])",
)
_SENS_URL_PARAM_RE = re.compile(
    r"[?&](api_key|apikey|token|access_token|secret|password|passwd|session_id|sid)=([^&#\s]+)",
    re.IGNORECASE,
)
_SENS_SESSION_HEADER_RE = re.compile(
    r"^(X-Session-Token|X-Auth-Token|X-CSRF-Token):\s*(\S+)", re.IGNORECASE | re.MULTILINE,
)
_SENS_BODY_PASS_RE = re.compile(
    r"(?:^|&)(password|passwd|pass|credential|secret|old_password|new_password)=([^&\s]+)",
    re.IGNORECASE,
)
_SENS_BODY_JSON_RE = re.compile(
    r'"(password|passwd|secret|token|api_key|apikey|access_token|private_key|credential|ssn|credit_card)"\s*:\s*"([^"]+)"',
    re.IGNORECASE,
)


def _b64url_decode(s):
    """Decode a base64url-encoded string (with padding fix)."""
    s = s.replace("-", "+").replace("_", "/")
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.b64decode(s)


def _decode_jwt(token):
    """Decode JWT header and payload (no signature verification)."""
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None
        header = json.loads(_b64url_decode(parts[0]).decode("utf-8", errors="replace"))
        payload = json.loads(_b64url_decode(parts[1]).decode("utf-8", errors="replace"))
        return json.dumps({"header": header, "payload": payload}, indent=2)
    except Exception:
        return None


def _decode_basic_auth(b64):
    """Decode Basic auth base64 to username:password."""
    try:
        return _b64url_decode(b64).decode("utf-8", errors="replace")
    except Exception:
        return None


def _luhn_check(digits):
    """Validate a credit card number using the Luhn algorithm."""
    try:
        nums = [int(d) for d in digits if d.isdigit()]
        if len(nums) < 13 or len(nums) > 19:
            return False
        total = 0
        for i, n in enumerate(reversed(nums)):
            if i % 2 == 1:
                n *= 2
                if n > 9:
                    n -= 9
            total += n
        return total % 10 == 0
    except Exception:
        return False


def _scan_headers(headers_str, source, findings):
    """Extract sensitive data from headers."""
    # Bearer token
    m = _SENS_BEARER_RE.search(headers_str)
    if m:
        token = m.group(1)
        finding = {
            "type": "bearer_token", "source": source,
            "field_name": "Authorization", "value": token,
        }
        # Check if JWT
        decoded = _decode_jwt(token) if token.startswith("eyJ") else None
        if decoded:
            finding["type"] = "jwt"
            finding["decoded"] = decoded
        findings.append(finding)

    # Basic auth
    m = _SENS_BASIC_RE.search(headers_str)
    if m:
        b64 = m.group(1)
        finding = {
            "type": "basic_auth", "source": source,
            "field_name": "Authorization", "value": b64,
        }
        decoded = _decode_basic_auth(b64)
        if decoded:
            finding["decoded"] = decoded
        findings.append(finding)

    # API key headers
    for m in _SENS_APIKEY_HEADER_RE.finditer(headers_str):
        findings.append({
            "type": "api_key", "source": source,
            "field_name": m.group(1), "value": m.group(2),
        })

    # Cookie / Set-Cookie
    for m in _SENS_COOKIE_RE.finditer(headers_str):
        findings.append({
            "type": "cookie", "source": source,
            "field_name": m.group(1), "value": m.group(2),
        })

    # Session headers
    for m in _SENS_SESSION_HEADER_RE.finditer(headers_str):
        findings.append({
            "type": "session_token", "source": source,
            "field_name": m.group(1), "value": m.group(2),
        })


def _scan_url(url, findings):
    """Extract sensitive data from URL query parameters."""
    for m in _SENS_URL_PARAM_RE.finditer(url):
        param_name = m.group(1)
        param_val = m.group(2)
        typ = "api_key"
        if param_name.lower() in ("password", "passwd"):
            typ = "password"
        elif param_name.lower() in ("token", "access_token"):
            typ = "bearer_token"
        elif param_name.lower() in ("session_id", "sid"):
            typ = "session_token"
        findings.append({
            "type": typ, "source": "request_url",
            "field_name": param_name, "value": param_val,
        })


def _scan_body(body, source, findings):
    """Extract sensitive data from request/response body."""
    if not body or len(body) < 4:
        return
    # Skip binary content (high ratio of non-printable chars)
    sample = body[:512]
    non_print = sum(1 for c in sample if ord(c) < 32 and c not in "\r\n\t")
    if non_print > len(sample) * 0.3:
        return

    # Form-encoded passwords
    for m in _SENS_BODY_PASS_RE.finditer(body):
        findings.append({
            "type": "password", "source": source,
            "field_name": m.group(1), "value": m.group(2),
        })

    # JSON credential fields
    for m in _SENS_BODY_JSON_RE.finditer(body):
        field = m.group(1).lower()
        typ = "password"
        if field in ("token", "access_token"):
            typ = "bearer_token"
        elif field in ("api_key", "apikey"):
            typ = "api_key"
        elif field in ("secret", "private_key"):
            typ = "private_key"
        elif field == "ssn":
            typ = "ssn"
        elif field == "credit_card":
            typ = "credit_card"
        findings.append({
            "type": typ, "source": source,
            "field_name": m.group(1), "value": m.group(2),
        })

    # JWT in body
    for m in _SENS_JWT_RE.finditer(body):
        decoded = _decode_jwt(m.group())
        finding = {
            "type": "jwt", "source": source,
            "field_name": "jwt_token", "value": m.group(),
        }
        if decoded:
            finding["decoded"] = decoded
        findings.append(finding)

    # Email
    for m in _SENS_EMAIL_RE.finditer(body):
        findings.append({
            "type": "email", "source": source,
            "field_name": "email", "value": m.group(),
        })

    # Phone
    for m in _SENS_PHONE_RE.finditer(body):
        findings.append({
            "type": "phone", "source": source,
            "field_name": "phone", "value": m.group(),
        })

    # SSN
    for m in _SENS_SSN_RE.finditer(body):
        findings.append({
            "type": "ssn", "source": source,
            "field_name": "ssn", "value": m.group(),
        })

    # Credit card (with Luhn check)
    for m in _SENS_CC_RE.finditer(body):
        digits = re.sub(r"[\s-]", "", m.group(1))
        if _luhn_check(digits):
            findings.append({
                "type": "credit_card", "source": source,
                "field_name": "credit_card", "value": m.group(1),
            })

    # PEM private key
    if _SENS_PEM_RE.search(body):
        findings.append({
            "type": "private_key", "source": source,
            "field_name": "private_key", "value": "(PEM private key detected)",
        })

    # AWS access key
    for m in _SENS_AWS_KEY_RE.finditer(body):
        findings.append({
            "type": "aws_credentials", "source": source,
            "field_name": "aws_access_key", "value": m.group(1),
        })

    # AWS secret (only flag near known context to reduce false positives)
    if "aws" in body.lower() or "AKIA" in body or "ASIA" in body:
        for m in _SENS_AWS_SECRET_RE.finditer(body):
            findings.append({
                "type": "aws_credentials", "source": source,
                "field_name": "aws_secret_key", "value": m.group(1),
            })


def _headers_from_payload(payload_dict):
    """Reconstruct header string from parsed header pairs."""
    if not payload_dict or "headers" not in payload_dict:
        return ""
    return "\r\n".join(f"{h[0]}: {h[1]}" for h in payload_dict["headers"])


def _extract_sensitive_data(url, req_headers, req_body, resp_headers="", resp_body=""):
    """Scan request and response for sensitive data.

    Returns a list of finding dicts.
    """
    findings = []
    _scan_headers(req_headers, "request_header", findings)
    _scan_url(url, findings)
    _scan_body(req_body, "request_body", findings)
    if resp_headers:
        _scan_headers(resp_headers, "response_header", findings)
    if resp_body:
        _scan_body(resp_body, "response_body", findings)

    # Deduplicate by (type, source, value)
    seen = set()
    unique = []
    for f in findings:
        key = (f["type"], f["source"], f["value"])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


_PROXY_CONN_RE = re.compile(
    r"Proxy-Connection:[^\r\n]*\r\n", re.IGNORECASE,
)
_CONTENT_LENGTH_RE = re.compile(
    r"^Content-Length:\s*(\d+)", re.IGNORECASE | re.MULTILINE,
)
_SUSPICIOUS_METHODS = {"TRACE", "TRACK", "DEBUG"}

# ── WebSocket support ────────────────────────────────────────────────────────
_UPGRADE_WS_RE = re.compile(r"^Upgrade:\s*websocket\s*$", re.IGNORECASE | re.MULTILINE)
_CONNECTION_UPGRADE_RE = re.compile(r"^Connection:.*\bUpgrade\b", re.IGNORECASE | re.MULTILINE)


def _is_websocket_upgrade(headers_str):
    """Check if headers indicate a WebSocket upgrade request."""
    return bool(_UPGRADE_WS_RE.search(headers_str) and _CONNECTION_UPGRADE_RE.search(headers_str))


_WS_OPCODES = {
    0x0: "continuation",
    0x1: "text",
    0x2: "binary",
    0x8: "close",
    0x9: "ping",
    0xA: "pong",
}


def _parse_ws_frame(data, offset=0):
    """Parse a single WebSocket frame from data starting at offset.

    Returns (frame_dict, bytes_consumed) or (None, 0) if incomplete.
    """
    remaining = len(data) - offset
    if remaining < 2:
        return None, 0

    b0 = data[offset]
    b1 = data[offset + 1]
    fin = bool(b0 & 0x80)
    opcode = b0 & 0x0F
    masked = bool(b1 & 0x80)
    payload_len = b1 & 0x7F

    header_size = 2
    if payload_len == 126:
        if remaining < 4:
            return None, 0
        payload_len = struct.unpack("!H", data[offset + 2:offset + 4])[0]
        header_size = 4
    elif payload_len == 127:
        if remaining < 10:
            return None, 0
        payload_len = struct.unpack("!Q", data[offset + 2:offset + 10])[0]
        header_size = 10

    if masked:
        header_size += 4

    total = header_size + payload_len
    if remaining < total:
        return None, 0

    mask_key = None
    if masked:
        mask_start = header_size - 4
        mask_key = data[offset + mask_start:offset + mask_start + 4]

    payload_start = offset + header_size
    payload_bytes = bytearray(data[payload_start:payload_start + payload_len])

    if masked and mask_key:
        for i in range(len(payload_bytes)):
            payload_bytes[i] ^= mask_key[i % 4]

    # Encode payload for logging
    truncated = payload_len > MAX_WS_PAYLOAD
    display_bytes = bytes(payload_bytes[:MAX_WS_PAYLOAD])

    if opcode == 0x1:  # text
        payload_str = display_bytes.decode("utf-8", errors="replace")
    else:
        payload_str = base64.b64encode(display_bytes).decode("ascii")

    opcode_name = _WS_OPCODES.get(opcode, f"unknown(0x{opcode:02x})")

    frame = {
        "direction": "",  # filled by caller
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "opcode": opcode,
        "opcode_name": opcode_name,
        "fin": fin,
        "masked": masked,
        "payload_len": payload_len,
        "payload": payload_str,
        "payload_truncated": truncated,
    }
    return frame, total


def _ws_relay(client_sock, remote_sock, url, addr, req_payload, resp_payload,
              risks, header_rest, body_text):
    """Relay WebSocket frames bidirectionally, logging frames."""
    sockets = [client_sock, remote_sock]
    ws_frames = []
    client_buf = b""
    server_buf = b""

    def _drain_pending(sock):
        """Drain SSL-buffered data if sock is an SSLSocket."""
        chunks = b""
        if isinstance(sock, ssl.SSLSocket):
            while sock.pending() > 0:
                extra = sock.recv(sock.pending())
                if not extra:
                    break
                chunks += extra
        return chunks

    try:
        while True:
            readable, _, exceptional = select.select(sockets, [], sockets, 30)
            if exceptional:
                break
            if not readable:
                continue

            for sock in readable:
                try:
                    data = sock.recv(BUFFER_SIZE)
                except (ssl.SSLError, OSError):
                    data = b""
                if not data:
                    # Connection closed
                    raise _WSClosed()

                # Forward raw bytes immediately
                target_sock = remote_sock if sock is client_sock else client_sock
                target_sock.sendall(data)

                # Drain any SSL-buffered data
                extra = _drain_pending(sock)
                if extra:
                    target_sock.sendall(extra)
                    data += extra

                # Parse frames for logging
                direction = "client" if sock is client_sock else "server"
                buf = client_buf if sock is client_sock else server_buf
                buf += data

                while len(ws_frames) < MAX_WS_FRAMES:
                    frame, consumed = _parse_ws_frame(buf, 0)
                    if frame is None:
                        break
                    frame["direction"] = direction
                    ws_frames.append(frame)

                    # Scan text payloads for sensitive data
                    if frame["opcode"] == 0x1:
                        findings_placeholder = []
                        _scan_body(frame["payload"], f"ws_frame_{direction}", findings_placeholder)

                    buf = buf[consumed:]

                if sock is client_sock:
                    client_buf = buf
                else:
                    server_buf = buf

    except _WSClosed:
        pass
    except Exception:
        pass
    finally:
        # Build sensitive data from request/response + ws frames
        resp_headers = ""
        resp_body_text = ""
        if resp_payload:
            resp_headers = "\r\n".join(f"{h[0]}: {h[1]}" for h in resp_payload.get("headers", []))
            resp_body_text = resp_payload.get("body", "")
        sens = _extract_sensitive_data(url, header_rest, body_text, resp_headers, resp_body_text)

        # Also scan WS frame payloads
        for frame in ws_frames:
            if frame["opcode"] == 0x1:
                _scan_body(frame["payload"], f"ws_frame_{frame['direction']}", sens)

        log_request(addr, "WS", url, "101", risks, payload=req_payload,
                    response=resp_payload, sensitive_data=sens or None,
                    ws_frames=ws_frames)

        for s in sockets:
            try:
                s.close()
            except OSError:
                pass


class _WSClosed(Exception):
    """Sentinel for WebSocket connection close."""
    pass


def _check_risks(method, url, headers="", body=""):
    """Inspect a request for common attack patterns.

    Returns a list of (severity, description) tuples.
    """
    risks = []
    url_decoded = unquote_plus(url)
    # URL + body for injection checks (headers contain benign semicolons etc.)
    injectable = url_decoded + "\n" + body

    # SQL injection — scan URL + body only
    m = _SQL_RE.search(injectable)
    if m:
        risks.append(("HIGH", f"SQL injection pattern: {m.group()!r}"))

    # XSS — scan URL + headers (onerror/onload can appear in injected headers)
    m = _XSS_RE.search(url_decoded + "\n" + headers)
    if m:
        risks.append(("HIGH", f"XSS pattern: {m.group()!r}"))

    # Path traversal
    m = _PATH_TRAVERSAL_RE.search(url)
    if m:
        risks.append(("HIGH", f"Path traversal pattern: {m.group()!r}"))

    # Command injection — scan URL + body only
    m = _CMD_INJECTION_RE.search(injectable)
    if m:
        risks.append(("HIGH", f"Command injection pattern: {m.group()!r}"))

    # Sensitive data in URL
    if "?" in url:
        query = url.split("?", 1)[1]
        m = _SENSITIVE_PARAM_RE.search("?" + query)
        if m:
            risks.append(("MEDIUM", f"Sensitive data in URL: {m.group().strip('?&')}"))

    # Cleartext credentials (HTTP to auth paths)
    if url.startswith("http://") and _AUTH_PATH_RE.search(url):
        risks.append(("MEDIUM", "Cleartext request to authentication endpoint"))

    # Plaintext auth headers over HTTP
    is_cleartext = url.startswith("http://")
    if is_cleartext and _BASIC_AUTH_RE.search(headers):
        risks.append(("HIGH", "Plaintext HTTP Basic credentials in Authorization header"))
    if is_cleartext and _BEARER_AUTH_RE.search(headers):
        risks.append(("HIGH", "Plaintext Bearer token in Authorization header"))

    # Proxy-Authorization exposes credentials to the proxy
    if _PROXY_AUTH_RE.search(headers):
        risks.append(("MEDIUM", "Proxy authentication credentials in request"))

    # Plaintext credentials in request body
    if is_cleartext and body and _BODY_CRED_RE.search(body):
        risks.append(("HIGH", "Plaintext credentials in request body"))

    # SSRF indicators
    if _PRIVATE_IP_RE.search(url):
        risks.append(("MEDIUM", "Request targets private/internal IP address"))

    # Suspicious methods
    if method.upper() in _SUSPICIOUS_METHODS:
        risks.append(("LOW", f"Suspicious HTTP method: {method}"))

    return risks


_SECURITY_HEADERS = {
    "strict-transport-security": ("HIGH", "Missing Strict-Transport-Security (HSTS) header"),
    "content-security-policy": ("MEDIUM", "Missing Content-Security-Policy (CSP) header"),
    "x-content-type-options": ("LOW", "Missing X-Content-Type-Options header"),
    "x-frame-options": ("LOW", "Missing X-Frame-Options header"),
    "referrer-policy": ("LOW", "Missing Referrer-Policy header"),
    "permissions-policy": ("LOW", "Missing Permissions-Policy header"),
}


def _check_response_risks(resp_headers_str, url=""):
    """Check response headers for missing security headers.

    Only flags missing headers on HTML responses (Content-Type text/html)
    to avoid noise on API/image/font responses.
    """
    risks = []
    headers_lower = resp_headers_str.lower()

    # Only check security headers on HTML responses
    is_html = "content-type:" in headers_lower and "text/html" in headers_lower
    if not is_html:
        return risks

    present = set()
    for line in resp_headers_str.split("\r\n"):
        if ":" in line:
            name = line.split(":", 1)[0].strip().lower()
            present.add(name)

    for header, (severity, desc) in _SECURITY_HEADERS.items():
        if header not in present:
            # HSTS only relevant for HTTPS
            if header == "strict-transport-security" and url.startswith("http://"):
                continue
            risks.append((severity, desc))

    return risks


def _check_host_risks(host):
    """Check SSRF indicators on a host string (for CONNECT targets)."""
    risks = []
    if _PRIVATE_IP_RE.search(host):
        risks.append(("MEDIUM", "CONNECT targets private/internal IP address"))
    return risks


def _parse_headers_list(headers_str):
    """Parse a raw header string into a list of [name, value] pairs."""
    headers = []
    for line in headers_str.split("\r\n"):
        if not line:
            continue
        if ": " in line:
            name, value = line.split(": ", 1)
            headers.append([name, value])
        elif ":" in line:
            name, value = line.split(":", 1)
            headers.append([name, value.lstrip()])
    return headers


def _encode_body(body_bytes):
    """Encode body bytes for JSON logging. Returns (body, is_binary, truncated)."""
    truncated = len(body_bytes) > MAX_BODY_LOG
    body_chunk = body_bytes[:MAX_BODY_LOG]
    try:
        body = body_chunk.decode("utf-8")
        return body, False, truncated
    except UnicodeDecodeError:
        body = base64.b64encode(body_chunk).decode("ascii")
        return body, True, truncated


def _build_payload(request_line, headers_str, body_bytes):
    """Build a payload dict from raw request components."""
    body, body_is_binary, truncated = _encode_body(body_bytes)
    return {
        "request_line": request_line,
        "headers": _parse_headers_list(headers_str),
        "body": body,
        "body_is_binary": body_is_binary,
        "body_truncated": truncated,
    }


def _build_response_payload(status_line, headers_str, body_bytes):
    """Build a response payload dict from raw response components."""
    body, body_is_binary, truncated = _encode_body(body_bytes)
    return {
        "status_line": status_line,
        "headers": _parse_headers_list(headers_str),
        "body": body,
        "body_is_binary": body_is_binary,
        "body_truncated": truncated,
    }


def _parse_response(data):
    """Parse raw HTTP response bytes into (status_line, headers_str, body_bytes, status_code)."""
    header_end = data.find(b"\r\n\r\n")
    if header_end == -1:
        return None
    header_block = data[:header_end].decode("ascii", errors="replace")
    body_bytes = data[header_end + 4:]
    first_line_end = header_block.find("\r\n")
    if first_line_end == -1:
        status_line = header_block
        headers_str = ""
    else:
        status_line = header_block[:first_line_end]
        headers_str = header_block[first_line_end + 2:]
    # Extract status code
    parts = status_line.split(" ", 2)
    status_code = parts[1] if len(parts) >= 2 else "???"
    return status_line, headers_str, body_bytes, status_code


def log_request(client_addr, method, target, status="->", risks=None, payload=None,
                response=None, sensitive_data=None, ws_frames=None):
    """Log a request to stdout and append a JSONL line to LOG_FILE."""
    if risks is None:
        risks = []
    ts = datetime.now(timezone.utc)
    ts_str = ts.strftime("%Y-%m-%d %H:%M:%S")

    with _log_lock:
        print(f"[{ts_str}] {client_addr[0]}:{client_addr[1]}  {status}  {method}  {target}")
        for severity, desc in risks:
            colour = _SEVERITY_COLOUR.get(severity, "")
            print(f"  {colour}\u26a0 [{severity}] {desc}{RESET}")
        if sensitive_data:
            print(f"  {YELLOW}\U0001f512 {len(sensitive_data)} sensitive data finding(s){RESET}")
            for sd in sensitive_data:
                print(f"    {sd['type']}: {sd['field_name']} [{sd['source']}]")
        if ws_frames:
            print(f"  {CYAN}\U0001f310 WebSocket: {len(ws_frames)} frame(s) captured{RESET}")

        entry = {
            "timestamp": ts.isoformat(),
            "client_ip": client_addr[0],
            "client_port": client_addr[1],
            "method": method,
            "target": target,
            "status": status,
            "risks": [{"severity": s, "description": d} for s, d in risks],
        }
        if payload is not None:
            entry["payload"] = payload
        if response is not None:
            entry["response"] = response
        if sensitive_data:
            entry["sensitive_data"] = sensitive_data
        if ws_frames:
            entry["ws_frames"] = ws_frames
        try:
            with open(LOG_FILE, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except OSError:
            pass


def _blind_tunnel(client_sock, remote_sock):
    """Shuttle bytes between two sockets until one side closes."""
    sockets = [client_sock, remote_sock]
    try:
        while True:
            readable, _, exceptional = select.select(sockets, [], sockets, 30)
            if exceptional:
                break
            for sock in readable:
                data = sock.recv(BUFFER_SIZE)
                if not data:
                    return
                target = remote_sock if sock is client_sock else client_sock
                target.sendall(data)
    finally:
        remote_sock.close()
        client_sock.close()


_HTTP_METHODS = frozenset((b"GET", b"POST", b"PUT", b"DELETE", b"PATCH",
                           b"HEAD", b"OPTIONS", b"TRACE"))


def _parse_mitm_request(data, host):
    """Parse decrypted MITM request data.

    Returns (method, full_url, risks, payload) or None for non-HTTP data.
    """
    try:
        # Quick check: valid HTTP requests start with an ASCII method token
        first_space = data.find(b" ")
        if first_space < 3 or first_space > 7:
            return None
        method_bytes = data[:first_space]
        if method_bytes not in _HTTP_METHODS:
            return None

        first_line_end = data.find(b"\r\n")
        if first_line_end == -1:
            first_line_end = data.find(b"\n")
        if first_line_end == -1:
            first_line = data[:80]
        else:
            first_line = data[:first_line_end]

        decoded = first_line.decode("ascii", errors="replace")
        parts = decoded.split()
        if len(parts) >= 2:
            method, path = parts[0], parts[1]
            full_url = f"https://{host}{path}"
            # Parse headers and body for payload capture
            header_body = data.split(b"\r\n\r\n", 1)
            if len(header_body) == 2:
                header_block = header_body[0].decode("ascii", errors="replace")
                body_bytes = header_body[1]
                _, headers_str = header_block.split("\r\n", 1) if "\r\n" in header_block else (header_block, "")
            else:
                headers_str = ""
                body_bytes = b""

            body_text = body_bytes.decode("ascii", errors="replace") if body_bytes else ""
            risks = _check_risks(method, full_url, headers_str, body_text)

            request_line = f"{method} {full_url} {parts[2] if len(parts) >= 3 else 'HTTP/1.1'}"
            payload = _build_payload(request_line, headers_str, body_bytes)
            return (method, full_url, risks, payload)
    except Exception:
        pass
    return None


def _mitm_relay(client_tls, remote_tls, host, addr):
    """Relay decrypted HTTP between client and server, logging requests+responses."""
    sockets = [client_tls, remote_tls]
    # Track pending request to pair with its response
    pending_req = None  # (method, full_url, risks, payload)
    response_buf = b""
    _pending_ws_upgrade = None  # (full_url, risks, payload, header_rest, body_text)

    def _flush_response():
        nonlocal pending_req, response_buf, _pending_ws_upgrade
        if pending_req and response_buf:
            method, full_url, risks, payload = pending_req
            parsed = _parse_response(response_buf)
            if parsed:
                status_line, resp_headers, resp_body, status_code = parsed
                resp_risks = _check_response_risks(resp_headers, full_url)
                all_risks = risks + resp_risks
                resp_payload = _build_response_payload(status_line, resp_headers, resp_body)
                req_hdrs = _headers_from_payload(payload) if payload else ""
                req_body = payload.get("body", "") if payload else ""
                resp_body_text = resp_body.decode("utf-8", errors="replace") if resp_body else ""
                sens = _extract_sensitive_data(full_url, req_hdrs, req_body, resp_headers, resp_body_text)
                log_request(addr, method, full_url, status_code, all_risks, payload=payload,
                            response=resp_payload, sensitive_data=sens or None)
            else:
                req_hdrs = _headers_from_payload(payload) if payload else ""
                req_body = payload.get("body", "") if payload else ""
                sens = _extract_sensitive_data(full_url, req_hdrs, req_body)
                log_request(addr, method, full_url, "MITM", risks, payload=payload,
                            sensitive_data=sens or None)
        elif pending_req:
            method, full_url, risks, payload = pending_req
            req_hdrs = _headers_from_payload(payload) if payload else ""
            req_body = payload.get("body", "") if payload else ""
            sens = _extract_sensitive_data(full_url, req_hdrs, req_body)
            log_request(addr, method, full_url, "MITM", risks, payload=payload,
                        sensitive_data=sens or None)
        pending_req = None
        response_buf = b""
        _pending_ws_upgrade = None

    while True:
        readable, _, exceptional = select.select(sockets, [], sockets, 30)
        if exceptional:
            break
        if not readable:
            continue
        for sock in readable:
            try:
                data = sock.recv(BUFFER_SIZE)
            except ssl.SSLError:
                _flush_response()
                return
            if not data:
                _flush_response()
                return

            if sock is client_tls:
                # New request from client — flush any pending response first
                _flush_response()
                pending_req = _parse_mitm_request(data, host)
                remote_tls.sendall(data)

                # Check for WebSocket upgrade
                if pending_req:
                    _, full_url, risks, payload = pending_req
                    # Extract headers from the raw data
                    header_body = data.split(b"\r\n\r\n", 1)
                    if len(header_body) == 2:
                        hdr_block = header_body[0].decode("ascii", errors="replace")
                        body_bytes = header_body[1]
                        if "\r\n" in hdr_block:
                            _, hdrs_str = hdr_block.split("\r\n", 1)
                        else:
                            hdrs_str = ""
                    else:
                        hdrs_str = ""
                        body_bytes = b""

                    if _is_websocket_upgrade(hdrs_str):
                        body_text = body_bytes.decode("ascii", errors="replace") if body_bytes else ""
                        _pending_ws_upgrade = (full_url, risks, payload, hdrs_str, body_text)
            else:
                # Response from server
                if len(response_buf) < MAX_BODY_LOG + 8192:
                    response_buf += data

                # Check for WebSocket 101 upgrade response
                if _pending_ws_upgrade:
                    if b"\r\n\r\n" in response_buf:
                        parsed = _parse_response(response_buf)
                        if parsed and parsed[3] == "101":
                            # Forward the 101 to client
                            client_tls.sendall(response_buf)
                            full_url, risks, payload, hdrs_str, body_text = _pending_ws_upgrade
                            resp_payload = _build_response_payload(parsed[0], parsed[1], parsed[2])
                            pending_req = None
                            response_buf = b""
                            _pending_ws_upgrade = None
                            # Enter WS relay — it will log and close sockets
                            _ws_relay(client_tls, remote_tls, full_url, addr, payload,
                                      resp_payload, risks, hdrs_str, body_text)
                            return
                        else:
                            # Not 101, flush buffered data
                            _pending_ws_upgrade = None
                            client_tls.sendall(response_buf)
                    # Still waiting for full headers — don't forward yet
                else:
                    client_tls.sendall(data)

            # Drain any SSL-buffered data not visible to select()
            while sock.pending() > 0:
                extra = sock.recv(sock.pending())
                if not extra:
                    _flush_response()
                    return
                if sock is client_tls:
                    remote_tls.sendall(extra)
                else:
                    if len(response_buf) < MAX_BODY_LOG + 8192:
                        response_buf += extra
                    client_tls.sendall(extra)

    _flush_response()


def handle_connect(client_sock, host, port, addr):
    """Handle CONNECT: blind tunnel or TLS interception."""
    target = f"{host}:{port}"
    risks = _check_host_risks(host)

    if not _mitm_enabled:
        try:
            remote_sock = socket.create_connection((host, port), timeout=10)
        except Exception as e:
            log_request(addr, "CONNECT", target, "502", risks)
            client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            client_sock.close()
            return

        log_request(addr, "CONNECT", target, "200", risks)
        client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        _blind_tunnel(client_sock, remote_sock)
        return

    # --- MITM mode ---
    from mitm_certs import get_host_cert_path, make_server_ctx

    # Tell client the tunnel is established (before TLS handshake)
    client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

    # Connect to real upstream over TLS
    try:
        raw_remote = socket.create_connection((host, port), timeout=10)
        upstream_ctx = ssl.create_default_context()
        if not _mitm_verify_upstream:
            upstream_ctx.check_hostname = False
            upstream_ctx.verify_mode = ssl.CERT_NONE
        upstream_ctx.set_alpn_protocols(["http/1.1"])
        remote_tls = upstream_ctx.wrap_socket(raw_remote, server_hostname=host)
    except Exception as e:
        log_request(addr, "CONNECT", target, f"502-upstream({e})", risks)
        client_sock.close()
        return

    # Wrap client socket in TLS using the forged cert
    try:
        cert_path = get_host_cert_path(host, _ca_cert, _ca_key)
        server_ctx = make_server_ctx(cert_path)
        client_tls = server_ctx.wrap_socket(client_sock, server_side=True)
    except Exception as e:
        log_request(addr, "CONNECT", target, f"TLS-ERR({e})", risks)
        remote_tls.close()
        client_sock.close()
        return

    log_request(addr, "CONNECT", target, "MITM", risks)
    try:
        _mitm_relay(client_tls, remote_tls, host, addr)
    finally:
        client_tls.close()
        remote_tls.close()


def handle_http(client_sock, method, url, version, header_rest, addr,
                body_start=b""):
    """Handle plain HTTP requests by forwarding them."""
    body_text = body_start.decode("ascii", errors="replace") if body_start else ""
    risks = _check_risks(method, url, header_rest, body_text)

    url_no_scheme = url.split("://", 1)[1] if "://" in url else url
    slash_idx = url_no_scheme.find("/")
    if slash_idx == -1:
        host_port = url_no_scheme
        path = "/"
    else:
        host_port = url_no_scheme[:slash_idx]
        path = url_no_scheme[slash_idx:]

    if ":" in host_port:
        host, port = host_port.rsplit(":", 1)
        port = int(port)
    else:
        host = host_port
        port = 80

    request_line = f"{method} {url} {version}"
    payload = _build_payload(request_line, header_rest, body_start)

    # Strip hop-by-hop Proxy-Connection header before forwarding
    forwarded_headers = _PROXY_CONN_RE.sub("", header_rest)

    try:
        remote_sock = socket.create_connection((host, port), timeout=10)
    except Exception as e:
        sens = _extract_sensitive_data(url, header_rest, body_text)
        log_request(addr, method, url, "502", risks, payload=payload,
                    sensitive_data=sens or None)
        client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        client_sock.close()
        return

    request = f"{method} {path} {version}\r\n{forwarded_headers}"
    is_ws_upgrade = _is_websocket_upgrade(header_rest)

    try:
        remote_sock.sendall(request.encode())
        if body_start:
            remote_sock.sendall(body_start)

        response_buf = b""
        while True:
            readable, _, _ = select.select([remote_sock], [], [], 30)
            if not readable:
                break
            data = remote_sock.recv(BUFFER_SIZE)
            if not data:
                break
            if len(response_buf) < MAX_BODY_LOG + 8192:
                response_buf += data

            # Check for WebSocket 101 response
            if is_ws_upgrade:
                if b"\r\n\r\n" in response_buf:
                    parsed_resp = _parse_response(response_buf)
                    if parsed_resp and parsed_resp[3] == "101":
                        # Forward the 101 to client
                        client_sock.sendall(response_buf)
                        resp_payload = _build_response_payload(
                            parsed_resp[0], parsed_resp[1], parsed_resp[2])
                        # Enter WS relay — it will log and close sockets
                        _ws_relay(client_sock, remote_sock, url, addr, payload,
                                  resp_payload, risks, header_rest, body_text)
                        return
                    else:
                        # Not 101, flush buffered data and fall through
                        is_ws_upgrade = False
                        client_sock.sendall(response_buf)
                        continue
                # Still waiting for full headers — don't forward yet
                continue

            client_sock.sendall(data)

        # Parse and log response
        parsed = _parse_response(response_buf)
        if parsed:
            status_line, resp_headers, resp_body, status_code = parsed
            resp_risks = _check_response_risks(resp_headers, url)
            all_risks = risks + resp_risks
            resp_payload = _build_response_payload(status_line, resp_headers, resp_body)
            resp_body_text = resp_body.decode("utf-8", errors="replace") if resp_body else ""
            sens = _extract_sensitive_data(url, header_rest, body_text, resp_headers, resp_body_text)
            log_request(addr, method, url, status_code, all_risks, payload=payload,
                        response=resp_payload, sensitive_data=sens or None)
        else:
            sens = _extract_sensitive_data(url, header_rest, body_text)
            log_request(addr, method, url, "->", risks, payload=payload,
                        sensitive_data=sens or None)
    finally:
        remote_sock.close()
        client_sock.close()


def _get_content_length(header_text):
    """Extract Content-Length from header text, or return 0."""
    m = _CONTENT_LENGTH_RE.search(header_text)
    if m:
        try:
            return int(m.group(1))
        except ValueError:
            return 0
    return 0


def handle_client(client_sock, addr):
    """Dispatch a client connection to the right handler."""
    try:
        raw = b""
        while b"\r\n\r\n" not in raw:
            chunk = client_sock.recv(BUFFER_SIZE)
            if not chunk:
                client_sock.close()
                return
            raw += chunk

        header_end = raw.index(b"\r\n\r\n") + 4
        header_block = raw[:header_end].decode(errors="replace")
        first_line, rest = header_block.split("\r\n", 1)
        parts = first_line.split()
        if len(parts) < 3:
            client_sock.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            client_sock.close()
            return

        method, target, version = parts[0], parts[1], parts[2]

        body_start = raw[header_end:]

        # Read remaining body bytes based on Content-Length
        if method.upper() != "CONNECT":
            content_length = _get_content_length(rest)
            if content_length > 0:
                remaining = content_length - len(body_start)
                while remaining > 0:
                    chunk = client_sock.recv(min(BUFFER_SIZE, remaining))
                    if not chunk:
                        break
                    body_start += chunk
                    remaining -= len(chunk)

        if method.upper() == "CONNECT":
            if ":" in target:
                host, port = target.rsplit(":", 1)
                port = int(port)
            else:
                host = target
                port = 443
            handle_connect(client_sock, host, port, addr)
        else:
            handle_http(client_sock, method, target, version, rest, addr,
                        body_start)

    except Exception as e:
        print(f"[!] Error handling {addr}: {e}")
        try:
            client_sock.close()
        except OSError:
            pass


def main():
    global _ca_cert, _ca_key, _mitm_enabled, _mitm_verify_upstream

    parser = argparse.ArgumentParser(description="HTTP/HTTPS forward proxy")
    parser.add_argument(
        "-p", "--port", type=int, default=DEFAULT_PORT,
        help=f"Port to listen on (default: {DEFAULT_PORT})",
    )
    parser.add_argument(
        "-b", "--bind", default="0.0.0.0",
        help="Address to bind to (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--mitm", action="store_true",
        help="Enable TLS interception (MITM mode)",
    )
    parser.add_argument(
        "--no-verify", action="store_true",
        help="Skip upstream TLS certificate verification (use with --mitm)",
    )
    args = parser.parse_args()

    # Ensure log file exists and is writable
    try:
        with open(LOG_FILE, "a"):
            pass
        print(f"[*] Logging to {LOG_FILE}")
    except OSError as e:
        print(f"[!] Warning: cannot write to {LOG_FILE}: {e}")

    if args.mitm:
        from mitm_certs import ensure_ca, CA_CERT_PATH
        _ca_cert, _ca_key = ensure_ca()
        _mitm_enabled = True
        if args.no_verify:
            _mitm_verify_upstream = False
            print("[*] Upstream TLS verification DISABLED")
        print(f"[*] MITM CA certificate: {CA_CERT_PATH}")
        print(f"[*] Trust it with: curl --cacert {CA_CERT_PATH} ...")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((args.bind, args.port))
    server.listen(100)
    print(f"[*] Proxy listening on {args.bind}:{args.port}")

    try:
        while True:
            client_sock, addr = server.accept()
            t = threading.Thread(target=handle_client, args=(client_sock, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("\n[*] Shutting down.")
    finally:
        server.close()


if __name__ == "__main__":
    main()
