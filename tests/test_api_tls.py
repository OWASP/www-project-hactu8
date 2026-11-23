"""TLS for the API and console: the self-signed certificate, a real HTTPS server, headers, HTTP fallback."""

import contextlib
import http.client
import io
import json
import os
import socket
import ssl
import stat
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

from hactu8 import tls

ROOT = Path(__file__).resolve().parents[1]
TLS_ENV = ("HACTU8_TLS", "HACTU8_TLS_DIR", "HACTU8_TLS_CERT", "HACTU8_TLS_KEY", "HACTU8_API_PORT", "HACTU8_PORT",
           "HACTU8_CONSOLE_DIR")


def _env(**values):
    env = {k: v for k, v in os.environ.items() if k not in TLS_ENV}
    env.update(values)
    return mock.patch.dict(os.environ, env, clear=True)


def _has(*modules):
    try:
        for name in modules:
            __import__(name)
    except ModuleNotFoundError:
        return False
    return True


@unittest.skipUnless(_has("cryptography"), "cryptography (api extra) not installed")
class CertificateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name).resolve() / "tls"

    def _ensure(self, **env):
        with _env(HACTU8_TLS_DIR=str(self.dir), **env):
            return tls.ensure()

    def test_generates_localhost_cert_with_private_key(self):
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import ec
        cert, key = self._ensure()
        self.assertEqual((cert, key), (self.dir / "cert.pem", self.dir / "key.pem"))
        loaded = x509.load_pem_x509_certificate(cert.read_bytes())
        san = loaded.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        self.assertEqual(san.get_values_for_type(x509.DNSName), ["localhost"])
        self.assertEqual({str(ip) for ip in san.get_values_for_type(x509.IPAddress)}, {"127.0.0.1", "::1"})
        self.assertFalse(loaded.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
        self.assertIsInstance(loaded.public_key(), ec.EllipticCurvePublicKey)
        days = (loaded.not_valid_after_utc - loaded.not_valid_before_utc).days
        self.assertTrue(360 <= days <= 366, days)
        self.assertEqual(stat.S_IMODE(key.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.dir.stat().st_mode), 0o700)
        self.assertIn(b"PRIVATE KEY", key.read_bytes())
        self.assertNotIn(b"PRIVATE KEY", cert.read_bytes())

    def test_default_dir_is_per_user_not_the_repo(self):
        with _env():
            self.assertEqual(tls.tls_dir(), Path.home() / ".hactu8" / "tls")
            self.assertFalse(tls.tls_dir().is_relative_to(ROOT))

    def test_reused_on_later_starts(self):
        cert, key = self._ensure()
        before = cert.read_bytes(), key.read_bytes()
        os.chmod(key, 0o644)
        self.assertEqual(self._ensure(), (cert, key))
        self.assertEqual((cert.read_bytes(), key.read_bytes()), before)
        self.assertEqual(stat.S_IMODE(key.stat().st_mode), 0o600)

    def test_regenerated_when_stale_broken_or_mismatched(self):
        cert, key = self._ensure()
        first = cert.read_bytes()
        with mock.patch.object(tls, "RENEW_DAYS", tls.VALID_DAYS + 1):  # as if it expires within the window
            self._ensure()
        second = cert.read_bytes()
        self.assertNotEqual(second, first)
        cert.write_bytes(first)  # a certificate that does not match the key
        self._ensure()
        self.assertNotEqual(cert.read_bytes(), first)
        key.write_text("garbage")
        self._ensure()
        self.assertIn(b"PRIVATE KEY", key.read_bytes())

    def test_own_cert(self):
        cert, key = self._ensure()
        with _env(HACTU8_TLS_CERT=str(cert), HACTU8_TLS_KEY=str(key), HACTU8_TLS_DIR=str(self.dir / "unused")):
            self.assertEqual(tls.ensure(), (cert, key))
            self.assertEqual(tls.cert_path(), cert)
            self.assertFalse((self.dir / "unused").exists())
        with _env(HACTU8_TLS_CERT=str(cert)), self.assertRaises(tls.TLSError):
            tls.ensure()
        with _env(HACTU8_TLS_CERT=str(cert), HACTU8_TLS_KEY=str(self.dir / "missing.pem")), \
                self.assertRaises(tls.TLSError):
            tls.ensure()

    def test_switch(self):
        for value, on in (("", True), ("on", True), ("off", False), ("OFF", False), ("0", False), ("false", False)):
            with self.subTest(value), _env(HACTU8_TLS=value, HACTU8_TLS_DIR=str(self.dir)):
                self.assertEqual(tls.enabled(), on)
                self.assertEqual(tls.scheme(), "https" if on else "http")
                self.assertEqual(bool(tls.uvicorn_options()), on)

    def test_cli_prints_cert_path_never_the_key(self):
        out = io.StringIO()
        with _env(HACTU8_TLS_DIR=str(self.dir)), contextlib.redirect_stdout(out):
            self.assertEqual(tls.main([]), 0)
        self.assertEqual(out.getvalue().strip(), str(self.dir / "cert.pem"))
        self.assertNotIn("PRIVATE", out.getvalue())


def _free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@unittest.skipUnless(_has("cryptography", "fastapi", "uvicorn"), "api extra not installed")
class ServeTest(unittest.TestCase):
    """A real uvicorn on a spare loopback port, with the generated certificate as the only trust anchor."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name).resolve()
        self.console = base / "dist"
        (self.console / "assets").mkdir(parents=True)
        (self.console / "index.html").write_text("<!doctype html><title>console</title>")
        (self.console / "assets" / "app.js").write_text("console.log(1)")
        self.env = {"HACTU8_TLS_DIR": str(base / "tls"), "HACTU8_HOME": str(base / "home"),
                    "HACTU8_CONSOLE_DIR": str(self.console)}

    def _serve(self, **env):
        import uvicorn

        from hactu8 import api
        port = _free_port()
        with _env(HACTU8_API_PORT=str(port), **self.env, **env):
            app = api.create_app(ROOT)
            options = tls.uvicorn_options()
            self.cafile = tls.cert_path()
        server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error", **options))
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(setattr, server, "should_exit", True)
        deadline = time.monotonic() + 10
        while not server.started:
            if time.monotonic() > deadline or not thread.is_alive():
                self.fail("uvicorn did not start")
            time.sleep(0.05)
        return port

    def _get(self, url, context=None, host=None):
        request = urllib.request.Request(url, headers={"Host": host} if host else {})
        try:
            with urllib.request.urlopen(request, timeout=5, context=context) as response:
                return response.status, response.headers, response.read()
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, exc.headers, exc.read()

    def test_https_serves_api_and_console(self):
        from hactu8 import api
        port = self._serve()
        trust = tls.client_context(self.cafile)
        for name in ("127.0.0.1", "localhost"):
            status, headers, body = self._get(f"https://{name}:{port}/api/health", trust)
            self.assertEqual((status, json.loads(body)["status"]), (200, "ok"), name)
            self.assertEqual(headers["Content-Security-Policy"], api.API_CSP)
            for header, value in api.SECURITY_HEADERS.items():
                self.assertEqual(headers[header], value)
            self.assertNotIn("Strict-Transport-Security", headers)
        status, headers, body = self._get(f"https://127.0.0.1:{port}/learn", trust)
        self.assertEqual((status, body), (200, b"<!doctype html><title>console</title>"))
        self.assertEqual(headers["Content-Security-Policy"], api.CONSOLE_CSP)
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertEqual(self._get(f"https://127.0.0.1:{port}/assets/app.js", trust)[2], b"console.log(1)")
        self.assertEqual(self._get(f"https://127.0.0.1:{port}/api/skills", trust)[0], 200)

    def test_host_check_still_enforced_over_https(self):
        port = self._serve()
        trust = tls.client_context(self.cafile)
        status, headers, _ = self._get(f"https://127.0.0.1:{port}/api/health", trust, host=f"rebind.example:{port}")
        self.assertEqual(status, 421)
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")

    def test_certificate_is_verified_not_skipped(self):
        port = self._serve()
        with self.assertRaises(urllib.error.URLError) as caught:  # system trust store: self-signed is refused
            self._get(f"https://127.0.0.1:{port}/api/health", ssl.create_default_context())
        self.assertIsInstance(caught.exception.reason, ssl.SSLCertVerificationError)
        with self.assertRaises((urllib.error.URLError, ConnectionError, http.client.HTTPException)):  # HTTPS only on this port
            self._get(f"http://127.0.0.1:{port}/api/health")

    def test_health_helper_trusts_the_cert(self):
        port = self._serve()
        with _env(**self.env):
            self.assertEqual(tls.health(port)["status"], "ok")

    def test_http_when_off(self):
        port = self._serve(HACTU8_TLS="off")
        self.assertFalse((Path(self.env["HACTU8_TLS_DIR"]) / "cert.pem").exists())
        status, headers, _ = self._get(f"http://127.0.0.1:{port}/api/health")
        self.assertEqual(status, 200)
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertEqual(self._get(f"http://127.0.0.1:{port}/api/health", host="evil.example")[0], 421)
        with _env(HACTU8_TLS="off"):
            self.assertEqual(tls.health(port)["status"], "ok")


@unittest.skipUnless(_has("cryptography", "fastapi", "uvicorn"), "api extra not installed")
class AppWiringTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name).resolve() / "tls"

    def _client(self, **env):
        from fastapi.testclient import TestClient

        from hactu8 import api
        with _env(HACTU8_HOME=self.tmp.name, **env):
            return TestClient(api.create_app(ROOT), base_url="https://127.0.0.1:8000")

    def test_cors_allows_the_https_dev_server(self):
        client = self._client()
        preflight = {"Access-Control-Request-Method": "POST"}
        ok = client.options("/api/runs", headers={"Origin": "https://127.0.0.1:5173", **preflight})
        self.assertEqual(ok.headers.get("access-control-allow-origin"), "https://127.0.0.1:5173")
        old = client.options("/api/runs", headers={"Origin": "http://127.0.0.1:5173", **preflight})
        self.assertNotIn("access-control-allow-origin", old.headers)
        plain = self._client(HACTU8_TLS="off").options(
            "/api/runs", headers={"Origin": "http://localhost:5173", **preflight})
        self.assertEqual(plain.headers.get("access-control-allow-origin"), "http://localhost:5173")

    def test_docs_pages_keep_their_cdn(self):
        response = self._client().get("/docs")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("content-security-policy", response.headers)
        self.assertEqual(response.headers["x-frame-options"], "DENY")

    def test_main_serves_https_on_loopback(self):
        from hactu8 import api
        out = io.StringIO()
        with _env(HACTU8_TLS_DIR=str(self.dir), HACTU8_API_PORT="8041", HACTU8_HOME=self.tmp.name), \
                mock.patch("uvicorn.run") as run, contextlib.redirect_stdout(out):
            api.main([])
        kwargs = run.call_args.kwargs
        self.assertEqual((kwargs["host"], kwargs["port"]), ("127.0.0.1", 8041))
        self.assertEqual(kwargs["ssl_certfile"], str(self.dir / "cert.pem"))
        self.assertEqual(kwargs["ssl_keyfile"], str(self.dir / "key.pem"))
        self.assertIn("https://127.0.0.1:8041", out.getvalue())
        self.assertNotIn("PRIVATE", out.getvalue())
        self.assertNotIn("key.pem", out.getvalue())
        with _env(HACTU8_TLS="off", HACTU8_HOME=self.tmp.name), mock.patch("uvicorn.run") as run, \
                contextlib.redirect_stdout(io.StringIO()):
            api.main([])
        self.assertNotIn("ssl_certfile", run.call_args.kwargs)


if __name__ == "__main__":
    unittest.main()
