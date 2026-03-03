#!/usr/bin/env python3
"""HTTP/HTTPS forward proxy server with optional TLS interception."""

import argparse
import socket
import select
import ssl
import threading
from datetime import datetime

BUFFER_SIZE = 65536
DEFAULT_PORT = 8080

_log_lock = threading.Lock()
_ca_cert = None
_ca_key = None
_mitm_enabled = False
_mitm_verify_upstream = True


def log(client_addr, method, target, status="->"):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with _log_lock:
        print(f"[{ts}] {client_addr[0]}:{client_addr[1]}  {status}  {method}  {target}")


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


def _log_request(data, host, addr):
    """Log the HTTP request line from decrypted data."""
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
            log(addr, method, f"https://{host}{path}", "MITM")
        else:
            log(addr, "???", f"https://{host} (unparseable)", "MITM")
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
                _log_request(data, host, addr)
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
    log(addr, "CONNECT", f"{host}:{port}")

    if not _mitm_enabled:
        try:
            remote_sock = socket.create_connection((host, port), timeout=10)
        except Exception as e:
            log(addr, "CONNECT", f"{host}:{port}", "502")
            client_sock.sendall(f"HTTP/1.1 502 Bad Gateway\r\n\r\n{e}".encode())
            client_sock.close()
            return

        log(addr, "CONNECT", f"{host}:{port}", "200")
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
        log(addr, "CONNECT", f"{host}:{port}", f"502-upstream({e})")
        client_sock.close()
        return

    # Wrap client socket in TLS using the forged cert
    try:
        cert_path = get_host_cert_path(host, _ca_cert, _ca_key)
        server_ctx = make_server_ctx(cert_path)
        client_tls = server_ctx.wrap_socket(client_sock, server_side=True)
    except Exception as e:
        log(addr, "CONNECT", f"{host}:{port}", f"TLS-ERR({e})")
        remote_tls.close()
        client_sock.close()
        return

    log(addr, "MITM", f"{host}:{port}", "intercepting")
    try:
        _mitm_relay(client_tls, remote_tls, host, addr)
    finally:
        client_tls.close()
        remote_tls.close()


def handle_http(client_sock, method, url, version, header_rest, addr):
    """Handle plain HTTP requests by forwarding them."""
    log(addr, method, url)
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

    try:
        remote_sock = socket.create_connection((host, port), timeout=10)
    except Exception as e:
        log(addr, method, url, "502")
        client_sock.sendall(f"HTTP/1.1 502 Bad Gateway\r\n\r\n{e}".encode())
        client_sock.close()
        return

    log(addr, method, url, "200")
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

        if method.upper() == "CONNECT":
            if ":" in target:
                host, port = target.rsplit(":", 1)
                port = int(port)
            else:
                host = target
                port = 443
            handle_connect(client_sock, host, port, addr)
        else:
            handle_http(client_sock, method, target, version, rest, addr)

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
