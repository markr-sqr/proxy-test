"""Shared fixtures for proxy test suite.

Provides Docker container, upstream test server, log polling, and Playwright browser.
"""

import os
import platform
import socket
import subprocess
import tempfile
import time

import pytest
import requests


PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ---------------------------------------------------------------------------
# Docker container fixtures
# ---------------------------------------------------------------------------

def _find_free_port():
    """Find a free TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def _wait_tcp(host, port, timeout=30):
    """Wait until a TCP port is accepting connections."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=2):
                return True
        except OSError:
            time.sleep(0.3)
    raise TimeoutError(f"TCP {host}:{port} not reachable after {timeout}s")


def _wait_http(url, timeout=30):
    """Wait until an HTTP endpoint returns 200."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(url, timeout=2)
            if r.status_code == 200:
                return True
        except requests.ConnectionError:
            pass
        time.sleep(0.3)
    raise TimeoutError(f"HTTP {url} not reachable after {timeout}s")


@pytest.fixture(scope="session")
def proxy_container():
    """Build and start the proxy Docker container.

    Returns the container ID.  Automatically stopped and removed on teardown.
    """
    image_tag = "proxy-test:pytest"

    # Build the image
    build = subprocess.run(
        ["docker", "build", "-t", image_tag, "."],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    if build.returncode != 0:
        print("=== Docker build FAILED ===")
        print(build.stdout[-3000:] if build.stdout else "(no stdout)")
        print(build.stderr[-3000:] if build.stderr else "(no stderr)")
        build.check_returncode()  # raises CalledProcessError

    proxy_host_port = _find_free_port()
    viewer_host_port = _find_free_port()

    # Start container with mapped ports
    result = subprocess.run(
        [
            "docker", "run", "-d",
            "--name", f"proxy-pytest-{os.getpid()}",
            "-p", f"{proxy_host_port}:8080",
            "-p", f"{viewer_host_port}:9999",
            image_tag,
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    container_id = result.stdout.strip()

    # Store ports on the container_id for other fixtures
    container_info = {
        "id": container_id,
        "proxy_port": proxy_host_port,
        "viewer_port": viewer_host_port,
    }

    # Wait for services to be ready
    try:
        _wait_tcp("127.0.0.1", proxy_host_port, timeout=40)
        _wait_http(f"http://127.0.0.1:{viewer_host_port}/health", timeout=40)
    except TimeoutError:
        # Dump logs for debugging
        logs = subprocess.run(
            ["docker", "logs", container_id], capture_output=True, text=True
        )
        print("=== Container logs ===")
        print(logs.stdout[-2000:] if logs.stdout else "(empty)")
        print(logs.stderr[-2000:] if logs.stderr else "(empty)")
        subprocess.run(["docker", "rm", "-f", container_id], capture_output=True)
        raise

    yield container_info

    # Teardown
    subprocess.run(["docker", "rm", "-f", container_id], capture_output=True)


@pytest.fixture(scope="session")
def proxy_host():
    return "127.0.0.1"


@pytest.fixture(scope="session")
def proxy_port(proxy_container):
    return proxy_container["proxy_port"]


@pytest.fixture(scope="session")
def viewer_port(proxy_container):
    return proxy_container["viewer_port"]


@pytest.fixture(scope="session")
def proxy_url(proxy_host, proxy_port):
    return f"http://{proxy_host}:{proxy_port}"


@pytest.fixture(scope="session")
def viewer_url(proxy_host, viewer_port):
    return f"http://{proxy_host}:{viewer_port}"


# ---------------------------------------------------------------------------
# CA certificate for MITM / HTTPS tests
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def ca_cert_path(proxy_container):
    """Extract the MITM CA cert from the container to a temp file."""
    container_id = proxy_container["id"]
    result = subprocess.run(
        ["docker", "exec", container_id, "cat", "/app/certs/ca.pem"],
        capture_output=True,
    )
    if result.returncode != 0:
        pytest.skip("CA cert not available (MITM may not be enabled)")

    tmp = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
    tmp.write(result.stdout)
    tmp.close()
    yield tmp.name
    os.unlink(tmp.name)


# ---------------------------------------------------------------------------
# Upstream test server (pytest-httpserver)
# ---------------------------------------------------------------------------

def _docker_gateway_ip():
    """Return the IP the container can use to reach the host.

    On Linux, the Docker bridge gateway is typically 172.17.0.1.
    On macOS / Windows Docker Desktop, host.docker.internal works, but we use
    the gateway IP for consistency.
    """
    if platform.system() == "Linux":
        try:
            result = subprocess.run(
                ["docker", "network", "inspect", "bridge",
                 "--format", "{{(index .IPAM.Config 0).Gateway}}"],
                capture_output=True, text=True, check=True,
            )
            gw = result.stdout.strip()
            if gw:
                return gw
        except (subprocess.CalledProcessError, IndexError):
            pass
        return "172.17.0.1"
    return "host.docker.internal"


@pytest.fixture(scope="session")
def upstream_server():
    """Start a pytest-httpserver on 0.0.0.0 with a random port."""
    from pytest_httpserver import HTTPServer

    server = HTTPServer(host="0.0.0.0")
    server.start()
    yield server
    server.clear()
    if server.is_running():
        server.stop()


@pytest.fixture(scope="session")
def upstream_base_url(upstream_server):
    """URL the container should use to reach the upstream test server."""
    gateway = _docker_gateway_ip()
    port = upstream_server.port
    return f"http://{gateway}:{port}"


# ---------------------------------------------------------------------------
# Log polling helper
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def query_logs(viewer_url):
    """Return a callable that polls /api/logs for entries matching a URL substring.

    Usage: entries = query_logs("/my-unique-path", timeout=5)
    """
    def _query(url_substr, timeout=5, interval=0.3, min_entries=1, **extra_params):
        deadline = time.time() + timeout
        params = {"url": url_substr, "limit": 100}
        params.update(extra_params)
        while time.time() < deadline:
            try:
                r = requests.get(f"{viewer_url}/api/logs", params=params, timeout=3)
                if r.status_code == 200:
                    data = r.json()
                    if data.get("total", 0) >= min_entries:
                        return data["entries"]
            except requests.ConnectionError:
                pass
            time.sleep(interval)
        # One final attempt — return whatever we have
        try:
            r = requests.get(f"{viewer_url}/api/logs", params=params, timeout=3)
            if r.status_code == 200:
                data = r.json()
                return data.get("entries", [])
        except requests.ConnectionError:
            pass
        return []
    return _query


# ---------------------------------------------------------------------------
# Playwright browser fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def browser():
    """Session-scoped Playwright Chromium browser."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        pytest.skip("playwright not installed")

    pw = sync_playwright().start()
    br = pw.chromium.launch(headless=True)
    yield br
    br.close()
    pw.stop()


@pytest.fixture(scope="function")
def page(browser, viewer_url):
    """Fresh browser page per test, navigated to the log viewer UI."""
    pg = browser.new_page()
    pg.goto(f"{viewer_url}/ui/logs", wait_until="networkidle")
    yield pg
    pg.close()
