"""Security regressions: credential redaction, redirects, loopback guards, spend gates,
DNS rebinding and cross-site control calls. Fake keys and 127.0.0.1 mock servers only."""

from __future__ import annotations

import contextlib
import io
import json
import os
import socket
import tempfile
import threading
import unittest
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from hactu8 import catalog, config, providers, reports, store
from hactu8.classify import Verdict, get_classifier
from hactu8.router import Router, RouterError

ROOT = Path(__file__).resolve().parents[1]
FAKE = "sk-local-FAKE1234567890abcdef"
FAKE_CLOUD = "sk-ant-FAKEKEY0000000000000000"


def _clean_env(**values):
    """os.environ without any *_API_KEY or backend host overrides, plus ``values``."""
    env = {k: v for k, v in os.environ.items()
           if not k.endswith(("_API_KEY", "_ALLOW_REMOTE", "_HOST", "_BASE_URL"))
           and k not in ("HACTU8_API_PORT", "HACTU8_PORT", "HACTU8_FORCE_BACKENDS", "JEV_URL")}
    env.update(values)
    return mock.patch.dict(os.environ, env, clear=True)


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _go(self):
        mode = self.server.mode
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        auth = self.headers.get("Authorization", "")
        if mode == "redirect":
            self.send_response(302)
            self.send_header("Location", self.server.location)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if mode == "sink":
            self.server.seen.append(auth)
            body = b'{"data":[]}'
            self.send_response(200)
        elif mode == "reason":
            body = b'{"error":"bad key"}'
            self.send_response(401, f"Unauthorized ({auth})")
        else:  # echo the credential back in the error body
            body = json.dumps({"error": f"invalid credentials: {auth}"}).encode()
            self.send_response(401)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = _go


class _Servers:
    def __init__(self):
        self.servers = []

    def start(self, mode, location=""):
        srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        srv.mode, srv.location, srv.seen = mode, location, []
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.servers.append(srv)
        return srv

    def close(self):
        for srv in self.servers:
            srv.shutdown()
            srv.server_close()


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class CredentialRedactionTest(unittest.TestCase):
    """Findings 1-3: a key a server echoes back never reaches error text, results or reports."""

    def setUp(self):
        self.srv = _Servers()
        self.addCleanup(self.srv.close)
        self.echo = self.srv.start("echo")
        self.reason = self.srv.start("reason")

    def _chat_error(self, backend: str) -> str:
        with self.assertRaises(Exception) as ctx:
            providers.get_provider(backend).chat([providers.Message("user", "hi")])
        return f"{type(ctx.exception).__name__}: {ctx.exception}"

    def test_every_local_key_redacted_from_error_body(self):
        url = f"http://127.0.0.1:{self.echo.server_port}"
        cases = (("openai-compat", {"LOCAL_OPENAI_API_KEY": FAKE, "LOCAL_OPENAI_BASE_URL": url + "/v1"}),
                 ("strata", {"STRATA_API_KEY": FAKE, "STRATA_HOST": url}),
                 ("basalt", {"BASALT_API_KEY": FAKE, "BASALT_HOST": url}))
        for backend, env in cases:
            with self.subTest(backend), _clean_env(HACTU8_FORCE_BACKENDS="all", **env):
                text = self._chat_error(backend)
                self.assertIn("401", text)
                self.assertIn(providers.REDACTED, text)
                self.assertNotIn(FAKE, text)

    def test_reason_phrase_redacted_for_cloud_and_local_keys(self):
        url = f"http://127.0.0.1:{self.reason.server_port}/v1"
        with _clean_env(OPENAI_API_KEY=FAKE, LOCAL_OPENAI_API_KEY=FAKE, LOCAL_OPENAI_BASE_URL=url):
            text = self._chat_error("openai-compat")
        self.assertIn("Unauthorized", text)
        self.assertNotIn(FAKE, text)

    def test_credential_from_a_configurable_env_name_is_redacted(self):
        with _clean_env(MY_JEV_SECRET="custom-FAKE-0123456789"):
            providers.register_secret(os.environ["MY_JEV_SECRET"])
            self.assertEqual(providers.redact("x custom-FAKE-0123456789 y"), f"x {providers.REDACTED} y")

    def test_judge_reason_and_router_error_redacted(self):
        url = f"http://127.0.0.1:{self.echo.server_port}/v1"
        cfg = {"router": {"max_tier": "local"}, "roles": {"judge": "local"},
               "tiers": {"deterministic": [{"backend": "echo"}],
                         "local": [{"backend": "openai-compat", "model": "local"}]}}
        with _clean_env(LOCAL_OPENAI_API_KEY=FAKE, LOCAL_OPENAI_BASE_URL=url):
            router = Router.from_config(cfg)
            router._probes = {c: (True, "mock") for c in router.candidates("judge")}
            with self.assertRaises(RouterError) as ctx:
                router.chat("judge", [providers.Message("user", "hi")])
            self.assertNotIn(FAKE, str(ctx.exception))
            router._probes = {c: (True, "mock") for c in router.candidates("judge")}
            verdict = get_classifier("llm-judge", cfg, router).classify("p", "some evidence", "GREEN", {})
        self.assertIn("judge unavailable", verdict.reason)
        self.assertNotIn(FAKE, verdict.reason)

    def test_lab_run_result_on_disk_has_no_key(self):
        url = f"http://127.0.0.1:{self.echo.server_port}/v1"
        from hactu8.adapters import lab
        with tempfile.TemporaryDirectory() as home, \
                _clean_env(HACTU8_HOME=home, LOCAL_OPENAI_API_KEY=FAKE, LOCAL_OPENAI_BASE_URL=url):
            skill = catalog.get("agx01", ROOT)
            doc = lab.run(skill, backend="openai-compat", timeout=120)
            text = store.save(doc).read_text(encoding="utf-8")
            for fmt in reports.FORMATS:
                self.assertNotIn(FAKE, reports.render(doc, fmt, {}), fmt)
        self.assertNotIn(FAKE, text)
        self.assertNotIn(FAKE, json.dumps(doc))

    def test_reports_and_store_redact_a_leaky_classifier_reason(self):
        from hactu8.adapters import lab

        class Leaky:
            name = "llm-judge"

            def classify(self, prompt, evidence="", lab_verdict=None, context=None):
                return Verdict(lab_verdict or "GREEN", 0.0, f"judge unavailable (401: Bearer {FAKE})", "")

            def info(self):
                return {"name": "llm-judge"}

        with tempfile.TemporaryDirectory() as home, _clean_env(HACTU8_HOME=home, LOCAL_OPENAI_API_KEY=FAKE):
            doc = lab.run(catalog.get("agx01", ROOT), backend="echo", classifier=Leaky())
            for fmt in reports.FORMATS:
                self.assertNotIn(FAKE, reports.render(doc, fmt, {}), fmt)
            self.assertNotIn(FAKE, store.save(doc).read_text(encoding="utf-8"))

    def test_credential_in_own_request_body_refused(self):
        def fake(req, timeout):
            raise AssertionError("must not send")

        with _clean_env(LOCAL_OPENAI_API_KEY=FAKE, LOCAL_OPENAI_BASE_URL="http://127.0.0.1:9/v1"), \
                mock.patch.object(providers, "_urlopen", fake):
            with self.assertRaisesRegex(RuntimeError, "own credential"):
                providers.get_provider("openai-compat").chat([providers.Message("user", f"say {FAKE}")])


class RedirectTest(unittest.TestCase):
    """Findings 4-5: provider calls never follow a redirect (other origin, ftp)."""

    def setUp(self):
        self.srv = _Servers()
        self.addCleanup(self.srv.close)

    def test_redirect_to_other_origin_refused_and_header_not_forwarded(self):
        sink = self.srv.start("sink")
        hop = self.srv.start("redirect", f"http://127.0.0.1:{sink.server_port}/v1/models")
        with _clean_env(LOCAL_OPENAI_API_KEY=FAKE, LOCAL_OPENAI_BASE_URL=f"http://127.0.0.1:{hop.server_port}/v1"):
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                providers.get_provider("openai-compat").list_models()
        self.assertEqual(ctx.exception.code, 302)
        self.assertIn("refused", str(ctx.exception))
        self.assertEqual(sink.seen, [])

    def test_redirect_to_ftp_never_opened(self):
        lsock = socket.socket()
        lsock.bind(("127.0.0.1", 0))
        lsock.listen(1)
        lsock.settimeout(0.5)
        self.addCleanup(lsock.close)
        hop = self.srv.start("redirect", f"ftp://127.0.0.1:{lsock.getsockname()[1]}/x")
        with _clean_env(OLLAMA_HOST=f"http://127.0.0.1:{hop.server_port}"):
            with self.assertRaises(urllib.error.HTTPError):
                providers.get_provider("ollama").list_models()
        with self.assertRaises(socket.timeout):
            lsock.accept()


class LoopbackGuardTest(unittest.TestCase):
    """Findings 6 and 12: parsed loopback checks for Jev and every local backend."""

    LOOKALIKES = ("http://localhost.attacker.example/v1", "http://127.0.0.1.nip.io/v1",
                  "http://localhost@evil.example/v1", "http://localhost:1@evil.example/v1",
                  "http://127.0.0.1\\@evil.example/v1", "http://localhost./v1", "http://localhost\n",
                  "http://localhost:99999999999/v1", "ftp://127.0.0.1/v1", "http://evil.example/v1")
    LOOPBACK = ("HTTP://LOCALHOST:1234/v1", "http://[::1]:1/v1", "http://127.255.255.255:1/v1",
                "http://127.0.0.1:8080", "https://localhost/v1")

    def test_is_loopback_url(self):
        for url in self.LOOKALIKES:
            self.assertFalse(providers.is_loopback_url(url), url)
        for url in self.LOOPBACK:
            self.assertTrue(providers.is_loopback_url(url), url)

    def test_jev_url_parsed(self):
        sent = []

        def fake(req, timeout):
            sent.append(req.full_url)
            raise OSError("mock")

        with _clean_env(HACTU8_ENABLE_JEV="1", TYPESAFE_API_KEY="ts-FAKEKEY123"), \
                mock.patch.object(providers, "_urlopen", fake):
            for url in self.LOOKALIKES[:4] + ("http://evil.example/v1", "https://u@evil.example/v1"):
                with self.subTest(url), mock.patch.dict(os.environ, {"JEV_URL": url}):
                    with self.assertRaisesRegex(RuntimeError, "https"):
                        get_classifier("jev", {"classifiers": {}})
            for url in ("https://api.typesafe.ai/v1/systemone", "http://127.0.0.1:9/v1", "http://localhost:9/v1"):
                with self.subTest(url), mock.patch.dict(os.environ, {"JEV_URL": url}):
                    get_classifier("jev", {"classifiers": {}}).classify("p", "e", "GREEN", {})
        self.assertEqual(len(sent), 3)

    def test_ollama_and_llamacpp_refuse_remote_unless_allowed(self):
        for backend, env in (("ollama", "OLLAMA"), ("llamacpp", "LLAMACPP")):
            with self.subTest(backend), _clean_env(**{f"{env}_HOST": "http://evil.example:11434"}):
                with self.assertRaisesRegex(RuntimeError, f"{env}_ALLOW_REMOTE"):
                    providers.get_provider(backend)
                with mock.patch.dict(os.environ, {f"{env}_ALLOW_REMOTE": "1"}):
                    self.assertEqual(providers.get_provider(backend).host, "http://evil.example:11434")

    def test_docker_host_works_with_documented_allow_env(self):
        with _clean_env(OLLAMA_HOST="http://host.docker.internal:11434", OLLAMA_ALLOW_REMOTE="1"):
            self.assertEqual(providers.get_provider("ollama").host, "http://host.docker.internal:11434")

    def test_router_probe_skips_remote_unless_allowed(self):
        probed = []

        def fake(req, timeout):
            probed.append(req.full_url)
            raise OSError("mock")

        cases = (("openai-compat", "LOCAL_OPENAI_BASE_URL", "http://evil.example/v1", "LOCAL_OPENAI"),
                 ("ollama", "OLLAMA_HOST", "http://evil.example:11434", "OLLAMA"),
                 ("llamacpp", "LLAMACPP_HOST", "http://evil.example:8080", "LLAMACPP"))
        for backend, var, url, env in cases:
            cfg = {"tiers": {"deterministic": [{"backend": "echo"}], "local": [{"backend": backend}]}}
            with self.subTest(backend), _clean_env(**{var: url}), mock.patch.object(providers, "_urlopen", fake):
                probed.clear()
                ok, why = Router.from_config(cfg)._probe_local(backend)
                self.assertFalse(ok)
                self.assertIn(f"{env}_ALLOW_REMOTE", why)
                self.assertEqual(probed, [])
                with mock.patch.dict(os.environ, {f"{env}_ALLOW_REMOTE": "1"}):
                    Router.from_config(cfg)._probe_local(backend)
                self.assertEqual(len(probed), 1)


class _PaidCalls:
    """Patches providers._urlopen: cloud calls answer, local servers are down."""

    def __init__(self):
        self.urls = []

    def __call__(self, req, timeout):
        self.urls.append(req.full_url)
        if "anthropic.com" in req.full_url:
            return _Resp(json.dumps({"content": [{"type": "text", "text":
                                                  '{"verdict":"GREEN","confidence":0.9,"reason":"x"}'}]}).encode())
        raise OSError("mock: local server down")

    @property
    def paid(self):
        return sum("anthropic.com" in u for u in self.urls)


def _with_cfg(**sections):
    real = config.load

    def load(*args, **kwargs):
        cfg = real(*args, **kwargs)
        for key, value in sections.items():
            cfg[key] = {**(cfg.get(key) or {}), **value}
        return cfg

    return mock.patch.object(config, "load", load)


class SpendGateTest(unittest.TestCase):
    """Findings 7-9: the judge, escalation and the bench classifier need confirm_spend too."""

    def setUp(self):
        self.home = tempfile.TemporaryDirectory()
        self.addCleanup(self.home.cleanup)

    def test_api_run_with_cloud_judge_needs_confirm_spend(self):
        try:
            from fastapi.testclient import TestClient
        except ModuleNotFoundError:
            self.skipTest("API optional dependencies not installed")
        from hactu8 import api
        calls = _PaidCalls()
        with _clean_env(HACTU8_HOME=self.home.name, ANTHROPIC_API_KEY=FAKE_CLOUD), \
                mock.patch.object(providers, "_urlopen", calls), _with_cfg(roles={"judge": "cloud"}):
            client = TestClient(api.create_app(ROOT), base_url="https://127.0.0.1:8000")
            r = client.post("/api/runs", json={"skill_id": "agx01", "backend": "echo", "classifier": "llm-judge"})
            self.assertEqual(r.status_code, 402)
            self.assertIn("llm-judge", r.json()["detail"])
            self.assertEqual(calls.paid, 0)
            with mock.patch("hactu8.adapters.lab.run", return_value={"run_id": "x", "skill": {}}) as run:
                r = client.post("/api/runs", json={"skill_id": "agx01", "backend": "echo",
                                                   "classifier": "llm-judge", "confirm_spend": True})
            self.assertEqual(r.status_code, 200)
            run.assert_called_once()
            # A judge that stays local needs no confirmation.
            with _with_cfg(roles={"judge": "local"}), mock.patch("hactu8.adapters.lab.run",
                                                                 return_value={"run_id": "y", "skill": {}}):
                r = client.post("/api/runs", json={"skill_id": "agx01", "classifier": "llm-judge"})
            self.assertEqual(r.status_code, 200)

    def test_cli_run_with_cloud_judge_needs_confirm_spend(self):
        from hactu8 import cli
        calls = _PaidCalls()
        err = io.StringIO()
        with _clean_env(HACTU8_HOME=self.home.name, ANTHROPIC_API_KEY=FAKE_CLOUD), \
                mock.patch.object(providers, "_urlopen", calls), _with_cfg(roles={"judge": "cloud"}), \
                mock.patch("hactu8.adapters.lab.run") as run, contextlib.redirect_stderr(err), \
                contextlib.redirect_stdout(io.StringIO()):
            rc = cli.main(["run", "agx01", "--classifier", "llm-judge"])
        self.assertEqual(rc, 2)
        self.assertIn("--confirm-spend", err.getvalue())
        run.assert_not_called()
        self.assertEqual(calls.paid, 0)

    def test_cli_escalation_to_paid_backend_stops_without_confirm(self):
        from hactu8 import cli
        ran = []

        def fake_run(skill, backend="echo", model="", classifier=None, timeout=300, tier=""):
            ran.append(backend)
            return {"run_id": f"x-{len(ran)}", "model": {"backend": backend}, "duration_ms": 0,
                    "summary": {"status": "error" if backend == "ollama" else "pass",
                                "baseline_rate": 0, "impact_rate": 0, "remediated_rate": 0},
                    "skill": {"metric": {"id": "m"}}}

        def avail(self, cand):
            return (True, "mock") if cand.backend in ("ollama", "anthropic") else (False, "mock down")

        for extra, expect in (([], ["ollama"]), (["--confirm-spend"], ["ollama", "anthropic"])):
            ran.clear()
            with self.subTest(extra), _clean_env(HACTU8_HOME=self.home.name, ANTHROPIC_API_KEY=FAKE_CLOUD), \
                    _with_cfg(router={"max_tier": "cloud"}), mock.patch.object(Router, "available", avail), \
                    mock.patch("hactu8.adapters.lab.run", fake_run), \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
                rc = cli.main(["run", "agx01", "--tier", "local"] + extra)
            self.assertEqual(ran, expect)
            self.assertEqual(rc, 1 if not extra else 0)
            if not extra:
                self.assertIn("not escalating", err.getvalue())

    def test_bench_cloud_classifier_needs_confirm_spend(self):
        from hactu8 import bench, cli
        calls = _PaidCalls()
        err = io.StringIO()
        with _clean_env(HACTU8_HOME=self.home.name, ANTHROPIC_API_KEY=FAKE_CLOUD), \
                mock.patch.object(providers, "_urlopen", calls), contextlib.redirect_stderr(err), \
                contextlib.redirect_stdout(io.StringIO()):
            rc = cli.main(["bench", "--classifier-backend", "anthropic"])
            self.assertEqual(rc, 2)
            self.assertIn("--confirm-spend", err.getvalue())
            self.assertEqual(calls.paid, 0)
            with mock.patch.object(bench, "llm_classifier") as llm, \
                    mock.patch.object(bench, "run", return_value=bench.run()):
                cli.main(["bench", "--classifier-backend", "anthropic", "--confirm-spend"])
            llm.assert_called_once()


class ApiHostTest(unittest.TestCase):
    """Finding 10: DNS rebinding. Only a loopback Host with the API port is answered."""

    def setUp(self):
        try:
            from fastapi.testclient import TestClient
        except ModuleNotFoundError:
            self.skipTest("API optional dependencies not installed")
        from hactu8 import api, live
        self.api, self.TestClient = api, TestClient
        self.home = tempfile.TemporaryDirectory()
        self.addCleanup(self.home.cleanup)
        self.calls = []
        patcher = mock.patch.object(live, "run", side_effect=lambda b, m: self.calls.append(b) or
                                    (_ for _ in ()).throw(RuntimeError("stopped (mock)")))
        patcher.start()
        self.addCleanup(patcher.stop)

    def _client(self, env, base="https://127.0.0.1:8000"):
        with _clean_env(HACTU8_HOME=self.home.name, ANTHROPIC_API_KEY=FAKE_CLOUD, **env):
            return self.TestClient(self.api.create_app(ROOT), base_url=base)

    def test_rebinding_host_refused(self):
        client = self._client({}, "https://rebind.attacker.example:8000")
        r = client.post("/api/live", json={"backend": "anthropic", "confirm_spend": True},
                        headers={"Origin": "https://rebind.attacker.example:8000"})
        self.assertEqual(r.status_code, 421)
        self.assertEqual(self.calls, [])
        self.assertEqual(client.get("/api/models").status_code, 421)
        self.assertEqual(client.get("/api/results").status_code, 421)

    def test_loopback_hosts_with_port_allowed(self):
        client = self._client({})
        for host in ("127.0.0.1:8000", "localhost:8000", "[::1]:8000", "LOCALHOST:8000"):
            self.assertEqual(client.get("/api/health", headers={"Host": host}).status_code, 200, host)
        for host in ("127.0.0.1", "127.0.0.1:9999", "localhost.attacker.example:8000", ""):
            self.assertEqual(client.get("/api/health", headers={"Host": host}).status_code, 421, host)

    def test_configured_ports(self):
        with _clean_env(HACTU8_API_PORT="18000", HACTU8_PORT="9000"):
            hosts = self.api.allowed_hosts()
        self.assertIn("127.0.0.1:18000", hosts)
        self.assertIn("localhost:9000", hosts)
        self.assertNotIn("127.0.0.1:8000", hosts)


class LambControlCsrfTest(unittest.TestCase):
    """Finding 11: Lamb's state-changing control calls refuse cross-site requests."""

    def setUp(self):
        from hactu8.lamb._mcp import available
        if not available():
            self.skipTest("Lamb extra (mcp v2 SDK) not installed")
        try:
            from starlette.testclient import TestClient

            from hactu8.lamb.app import create_app
        except (ImportError, RuntimeError):
            self.skipTest("Lamb extra not installed")

        class FakeManager:
            skills = []
            resets = 0

            def reset(self, requested):
                FakeManager.resets += 1
                return {"errors": []}

            def close(self):
                pass

            def running_ids(self):
                return []

            def describe(self, base):
                return []

        self.manager = FakeManager
        self.client = TestClient(create_app(manager=FakeManager()), base_url="http://127.0.0.1:5500")

    def test_reset_and_swap_refuse_cross_site(self):
        evil = {"Origin": "https://evil.example"}
        for path in ("/api/reset", "/api/lamb/swap", "/api/lamb/mode"):
            with self.subTest(path):
                self.assertEqual(self.client.post(path, headers=evil).status_code, 403)
                self.assertEqual(self.client.post(path).status_code, 415)
                self.assertEqual(self.client.post(path, content=b"x", headers={"Content-Type": "text/plain"})
                                 .status_code, 415)
                self.assertEqual(self.client.post(path, json={}, headers=evil).status_code, 403)
        self.assertEqual(self.manager.resets, 0)

    def test_json_from_loopback_origin_allowed(self):
        ok = {"Origin": "http://127.0.0.1:5173"}
        self.assertEqual(self.client.post("/api/reset", json={}, headers=ok).status_code, 200)
        self.assertEqual(self.client.post("/api/lamb/swap", json={}).status_code, 200)
        self.assertEqual(self.manager.resets, 1)


class LambIndexTest(unittest.TestCase):
    """Lamb's / is an escaped HTML page for a browser and the unchanged JSON for everyone else."""

    JSON = {"name": "HACTU8 Lamb", "warning": "Intentionally vulnerable authorized security-lab target",
            "labs": "/api/labs", "mcp": "/mcp", "protected_mcp": "/protected/mcp"}
    HOSTILE = '<script>alert(1)</script>"&\''

    def setUp(self):
        from hactu8.lamb._mcp import available
        if not available():
            self.skipTest("Lamb extra (mcp v2 SDK) not installed")
        try:
            from starlette.testclient import TestClient

            from hactu8.lamb.app import create_app
        except (ImportError, RuntimeError):
            self.skipTest("Lamb extra not installed")
        hostile = self.HOSTILE

        class FakeManager:
            skills = []

            def close(self):
                pass

            def describe(self, base):
                return [{"id": "llm01", "owasp": "LLM01:2026", "risk": hostile, "state": "stopped",
                         "url": f"{base}/labs/llm01"},
                        {"id": "x", "owasp": "", "risk": "", "state": "", "url": "javascript:alert(1)"}]

        self.client = TestClient(create_app(manager=FakeManager()), base_url="http://127.0.0.1:5500")

    def test_json_for_clients_that_do_not_ask_for_html(self):
        for headers in ({}, {"Accept": "*/*"}, {"Accept": "application/json"},
                        {"Accept": "text/html;q=0, application/json"}):
            with self.subTest(headers=headers):
                response = self.client.get("/", headers=headers)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.headers["content-type"], "application/json")
                self.assertEqual(response.json(), self.JSON)
        browser = {"Accept": "text/html,application/xhtml+xml,*/*;q=0.8"}
        self.assertEqual(self.client.get("/?format=json", headers=browser).json(), self.JSON)

    def test_html_for_a_browser_is_escaped_and_self_contained(self):
        import base64
        import hashlib
        import re

        response = self.client.get("/", headers={"Accept": "text/html,application/xhtml+xml,*/*;q=0.8"})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.headers["content-type"].startswith("text/html"))
        page = response.text
        self.assertNotIn("<script", page)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;&quot;&amp;&#x27;", page)
        self.assertIn('href="http://127.0.0.1:5500/labs/llm01"', page)
        self.assertNotIn("javascript:", page)
        self.assertIn("<code>lamb_status</code>", page)                     # Lamb's MCP tools are listed
        self.assertNotRegex(page, r'(?:src|href)="(?:https?:)?//(?!127\.0\.0\.1:5500/)')
        for name, value in (("x-content-type-options", "nosniff"), ("x-frame-options", "DENY"),
                            ("referrer-policy", "no-referrer")):
            self.assertEqual(response.headers[name], value)
        csp = response.headers["content-security-policy"]
        self.assertIn("default-src 'none'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        style = re.search(r"<style>(.*?)</style>", page, re.S).group(1)
        digest = base64.b64encode(hashlib.sha256(style.encode()).digest()).decode()
        self.assertIn(f"style-src 'sha256-{digest}'", csp)

    def test_bad_host_still_refused(self):
        response = self.client.get("/", headers={"Host": "evil.example", "Accept": "text/html"})
        self.assertEqual(response.status_code, 403)


if __name__ == "__main__":
    unittest.main()
