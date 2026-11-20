"""A live TLS handshake against the gateway's hardened context (offline, ephemeral cert)."""

import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

from hactu8.lamb.gateway import GatewayConfig, hardened_tls_context


def _self_signed(directory: Path):
    cert, key = directory / "cert.pem", directory / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
                    "-out", str(cert), "-days", "1", "-subj", "/CN=localhost"],
                   check=True, capture_output=True)
    return str(cert), str(key)


class _TLSServer:
    def __init__(self, ctx):
        self.ctx = ctx
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self):
        while not self.stop.is_set():
            try:
                raw, _ = self.sock.accept()
            except OSError:
                continue
            try:
                with self.ctx.wrap_socket(raw, server_side=True) as tls:
                    tls.recv(16)
            except (ssl.SSLError, OSError):
                pass
            finally:
                raw.close()

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.stop.set()
        self.thread.join(timeout=2)
        self.sock.close()


def _handshake(port, max_version):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.maximum_version = max_version
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
        with ctx.wrap_socket(raw, server_hostname="localhost") as tls:
            return tls.version()


@unittest.skipUnless(shutil.which("openssl"), "openssl not available to make a test certificate")
class GatewayTlsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cert, self.key = _self_signed(Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def test_default_floor_is_tls12_with_hardening_options(self):
        ctx = hardened_tls_context(GatewayConfig(tls_certfile=self.cert, tls_keyfile=self.key))
        self.assertEqual(ctx.minimum_version, ssl.TLSVersion.TLSv1_2)
        self.assertTrue(ctx.options & ssl.OP_NO_COMPRESSION)
        self.assertTrue(ctx.options & ssl.OP_CIPHER_SERVER_PREFERENCE)

    def test_no_weak_ciphers_offered(self):
        ctx = hardened_tls_context(GatewayConfig(tls_certfile=self.cert, tls_keyfile=self.key))
        names = " ".join(c["name"] for c in ctx.get_ciphers())
        for weak in ("RC4", "3DES", "DES-CBC", "NULL", "EXPORT", "MD5"):
            self.assertNotIn(weak, names)

    def test_tls12_client_negotiates_against_the_12_floor(self):
        ctx = hardened_tls_context(GatewayConfig(tls_certfile=self.cert, tls_keyfile=self.key, min_tls="1.2"))
        with _TLSServer(ctx) as srv:
            self.assertEqual(_handshake(srv.port, ssl.TLSVersion.TLSv1_2), "TLSv1.2")

    def test_client_below_the_floor_is_refused(self):
        ctx = hardened_tls_context(GatewayConfig(tls_certfile=self.cert, tls_keyfile=self.key, min_tls="1.3"))
        with _TLSServer(ctx) as srv:
            with self.assertRaises((ssl.SSLError, OSError)):
                _handshake(srv.port, ssl.TLSVersion.TLSv1_2)
            self.assertEqual(_handshake(srv.port, ssl.TLSVersion.MAXIMUM_SUPPORTED), "TLSv1.3")


if __name__ == "__main__":
    unittest.main()
