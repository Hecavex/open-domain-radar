"""Exercise the intended TLS-terminating reverse-proxy deployment shape."""

from __future__ import annotations

import datetime
import http.client
import ipaddress
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import suppress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "upgrade"}

pytestmark = pytest.mark.release


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def wait_ready(origin: str, process: subprocess.Popen[str]) -> None:
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"application exited before readiness: {process.returncode}")
        try:
            with urlopen(f"{origin}/health/ready", timeout=1) as response:  # noqa: S310 - fixed loopback URL
                if response.status == 200:
                    return
        except (OSError, URLError):
            time.sleep(0.15)
    raise TimeoutError("application did not become ready")


class LoopbackTLSProxy(ThreadingHTTPServer):
    """Minimal test-only TLS terminator forwarding to one loopback upstream."""

    daemon_threads = True

    def __init__(self, address: tuple[str, int], upstream_port: int):
        super().__init__(address, ProxyHandler)
        self.upstream_port = upstream_port


class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._forward()

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._forward()

    def do_PUT(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._forward()

    def _forward(self) -> None:
        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length) if content_length else None
        headers = {
            key: value
            for key, value in self.headers.items()
            if key.lower() not in HOP_BY_HOP | {"content-length", "host"}
        }
        headers.update(
            {
                "Host": self.headers.get("Host", ""),
                "X-Forwarded-For": "203.0.113.10",
                "X-Forwarded-Proto": "https",
            }
        )
        if body is not None:
            headers["Content-Length"] = str(len(body))

        connection = http.client.HTTPConnection("127.0.0.1", self.server.upstream_port, timeout=10)  # type: ignore[attr-defined]
        try:
            connection.request(self.command, self.path, body=body, headers=headers)
            upstream = connection.getresponse()
            payload = upstream.read()
            self.send_response(upstream.status)
            for key, value in upstream.getheaders():
                if key.lower() not in HOP_BY_HOP | {"content-length", "transfer-encoding"}:
                    self.send_header(key, value)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            # Browsers may cancel speculative or superseded asset requests.
            with suppress(BrokenPipeError, ConnectionResetError, ssl.SSLEOFError):
                self.wfile.write(payload)
        finally:
            connection.close()

    def log_message(self, _format: str, *args: object) -> None:
        return


def create_test_certificate(directory: Path) -> tuple[Path, Path]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .sign(key, hashes.SHA256())
    )
    certificate_path = directory / "proxy-cert.pem"
    key_path = directory / "proxy-key.pem"
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return certificate_path, key_path


def test_tls_reverse_proxy_serves_public_and_authenticated_surfaces() -> None:
    upstream_port = free_port()
    proxy_port = free_port()
    upstream_origin = f"http://127.0.0.1:{upstream_port}"
    public_origin = f"https://127.0.0.1:{proxy_port}"

    with tempfile.TemporaryDirectory(prefix="open-domain-radar-proxy-") as directory:
        data_dir = Path(directory)
        environment = os.environ.copy()
        environment.update(
            {
                "ODR_DATA_DIR": str(data_dir / "state"),
                "ODR_HOST": "127.0.0.1",
                "ODR_PORT": str(upstream_port),
                "ODR_PUBLIC_ORIGIN": public_origin,
                "ODR_EMBED_WORKER": "false",
                "PYTHONUNBUFFERED": "1",
            }
        )
        subprocess.run(
            [sys.executable, "-m", "open_domain_radar.cli", "init"],
            cwd=ROOT,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            [
                sys.executable,
                "-m",
                "open_domain_radar.cli",
                "create-admin",
                "--username",
                "operator",
                "--password-stdin",
            ],
            cwd=ROOT,
            env=environment,
            input="correct-horse-battery-staple\n",
            check=True,
            capture_output=True,
            text=True,
        )
        process = subprocess.Popen(  # noqa: S603 - controlled interpreter/module argv
            [sys.executable, "-m", "open_domain_radar.cli", "serve"],
            cwd=ROOT,
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        proxy = LoopbackTLSProxy(("127.0.0.1", proxy_port), upstream_port)
        certificate_path, key_path = create_test_certificate(data_dir)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # Match the production deployment floor; TLS 1.0 and 1.1 must not be
        # accepted even by this short-lived loopback rehearsal proxy.
        tls.minimum_version = ssl.TLSVersion.TLSv1_2
        tls.load_cert_chain(certificate_path, key_path)
        proxy.socket = tls.wrap_socket(proxy.socket, server_side=True)
        thread = threading.Thread(target=proxy.serve_forever, daemon=True)
        try:
            wait_ready(upstream_origin, process)
            thread.start()
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch()
                context = browser.new_context(ignore_https_errors=True, viewport={"width": 1280, "height": 900})
                page = context.new_page()
                response = page.goto(public_origin, wait_until="networkidle")
                assert response is not None and response.status == 200
                assert response.headers["strict-transport-security"] == "max-age=31536000"
                page.get_by_role("heading", name="Potential impersonation domains, surfaced for review.").wait_for()

                page.goto(f"{public_origin}/admin", wait_until="networkidle")
                page.locator("#login-username").fill("operator")
                page.locator("#login-password").fill("correct-horse-battery-staple")
                page.locator("#login-form button[type='submit']").click()
                page.locator("#workspace").wait_for(state="visible")
                cookies = context.cookies(f"{public_origin}/api/admin/v1/session")
                session = next(cookie for cookie in cookies if cookie["name"] == "odr_session")
                assert session["secure"] is True
                assert session["httpOnly"] is True
                context.close()
                browser.close()
        finally:
            proxy.shutdown()
            proxy.server_close()
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
