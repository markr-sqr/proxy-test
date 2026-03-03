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
import threading
from datetime import datetime, timezone
from urllib.parse import unquote_plus

BUFFER_SIZE = 65536
DEFAULT_PORT = 8080
LOG_FILE = os.environ.get("PROXY_LOG_FILE", "/tmp/proxy.log")
MAX_BODY_LOG = 8192

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
    r"(?:UNION\s+SELECT|OR\s+1\s*=\s*1|'\s*OR\s*'|DROP\s+TABLE|;\s*--|;\s*\w)",
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
    r"(?:`|\$\(|;\s|(?<!=)\|\s|&&\s)",
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
_SUSPICIOUS_METHODS = {"TRACE", "TRACK", "DEBUG"}


def _check_risks(method, url, headers=""):
    """Inspect a request for common attack patterns.

    Returns a list of (severity, description) tuples.
    """
    risks = []
    url_decoded = unquote_plus(url)
    combined = url_decoded + "\n" + headers

    # SQL injection
    m = _SQL_RE.search(combined)
    if m:
        risks.append(("HIGH", f"SQL injection pattern: {m.group()!r}"))

    # XSS
    m = _XSS_RE.search(combined)
    if m:
        risks.append(("HIGH", f"XSS pattern: {m.group()!r}"))

    # Path traversal
    m = _PATH_TRAVERSAL_RE.search(url)
    if m:
        risks.append(("HIGH", f"Path traversal pattern: {m.group()!r}"))

    # Command injection
    m = _CMD_INJECTION_RE.search(combined)
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
    if is_cleartext and _BODY_CRED_RE.search(headers):
        risks.append(("HIGH", "Plaintext credentials in request body"))

    # SSRF indicators
    if _PRIVATE_IP_RE.search(url):
        risks.append(("MEDIUM", "Request targets private/internal IP address"))

    # Suspicious methods
    if method.upper() in _SUSPICIOUS_METHODS:
        risks.append(("LOW", f"Suspicious HTTP method: {method}"))

    return risks


def _check_host_risks(host):
    """Check SSRF indicators on a host string (for CONNECT targets)."""
    risks = []
    if _PRIVATE_IP_RE.search(host):
        risks.append(("MEDIUM", "CONNECT targets private/internal IP address"))
    return risks


def _build_payload(request_line, headers_str, body_bytes):
    """Build a payload dict from raw request components."""
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

    truncated = len(body_bytes) > MAX_BODY_LOG
    body_chunk = body_bytes[:MAX_BODY_LOG]

    try:
        body = body_chunk.decode("utf-8")
        body_is_binary = False
    except UnicodeDecodeError:
        body = base64.b64encode(body_chunk).decode("ascii")
        body_is_binary = True

    return {
        "request_line": request_line,
        "headers": headers,
        "body": body,
        "body_is_binary": body_is_binary,
        "body_truncated": truncated,
    }


def log_request(client_addr, method, target, status="->", risks=None, payload=None):
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


def _log_mitm_request(data, host, addr):
    """Log the HTTP request line from decrypted MITM data."""
    try:
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
            header_text = data.decode("ascii", errors="replace")
            risks = _check_risks(method, full_url, header_text)

            # Parse headers and body for payload capture
            header_body = data.split(b"\r\n\r\n", 1)
            if len(header_body) == 2:
                header_block = header_body[0].decode("ascii", errors="replace")
                body_bytes = header_body[1]
                # Skip the request line to get just headers
                _, headers_str = header_block.split("\r\n", 1) if "\r\n" in header_block else (header_block, "")
            else:
                headers_str = ""
                body_bytes = b""

            request_line = f"{method} {full_url} {parts[2] if len(parts) >= 3 else 'HTTP/1.1'}"
            payload = _build_payload(request_line, headers_str, body_bytes)
            log_request(addr, method, full_url, "MITM", risks, payload=payload)
        else:
            log_request(addr, "???", f"https://{host} (unparseable)", "MITM")
    except Exception:
        pass


def _mitm_relay(client_tls, remote_tls, host, addr):
    """Relay decrypted HTTP between client and server, logging requests."""
    sockets = [client_tls, remote_tls]
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
                return
            if not data:
                return

            if sock is client_tls:
                _log_mitm_request(data, host, addr)
                remote_tls.sendall(data)
            else:
                client_tls.sendall(data)

            # Drain any SSL-buffered data not visible to select()
            while sock.pending() > 0:
                extra = sock.recv(sock.pending())
                if not extra:
                    return
                target = remote_tls if sock is client_tls else client_tls
                target.sendall(extra)


def handle_connect(client_sock, host, port, addr):
    """Handle CONNECT: blind tunnel or TLS interception."""
    target = f"{host}:{port}"
    risks = _check_host_risks(host)

    if not _mitm_enabled:
        try:
            remote_sock = socket.create_connection((host, port), timeout=10)
        except Exception as e:
            log_request(addr, "CONNECT", target, "502", risks)
            client_sock.sendall(f"HTTP/1.1 502 Bad Gateway\r\n\r\n{e}".encode())
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
    scan_text = header_rest
    if body_start:
        scan_text += body_start.decode("ascii", errors="replace")
    risks = _check_risks(method, url, scan_text)

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

    try:
        remote_sock = socket.create_connection((host, port), timeout=10)
    except Exception as e:
        log_request(addr, method, url, "502", risks, payload=payload)
        client_sock.sendall(f"HTTP/1.1 502 Bad Gateway\r\n\r\n{e}".encode())
        client_sock.close()
        return

    log_request(addr, method, url, "200", risks, payload=payload)
    request = f"{method} {path} {version}\r\n{header_rest}"
    try:
        remote_sock.sendall(request.encode())

        while True:
            readable, _, _ = select.select([remote_sock], [], [], 30)
            if not readable:
                break
            data = remote_sock.recv(BUFFER_SIZE)
            if not data:
                break
            client_sock.sendall(data)
    finally:
        remote_sock.close()
        client_sock.close()


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
