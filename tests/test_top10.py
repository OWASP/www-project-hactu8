"""Regressions for the OWASP Top 10:2025 audit: API docs off, input validation and quoting, image digests,
dev sudo, the token gate on a non-loopback bind, the spend audit log, stray result files, HEAD on the console."""

import contextlib
import io
import logging.config
import json
import os
import re
import shlex
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hactu8 import reports, store

ROOT = Path(__file__).resolve().parents[1]
CLEAR = ("HACTU8_API_TOKEN", "HACTU8_API_DOCS", "HACTU8_CONSOLE_DIR", "HACTU8_API_PORT", "HACTU8_PORT",
         "HACTU8_TLS", "HACTU8_TLS_DIR", "HACTU8_TLS_CERT", "HACTU8_TLS_KEY")

try:
    from fastapi.testclient import TestClient
except ModuleNotFoundError:
    TestClient = None


def _env(**values):
    env = {k: v for k, v in os.environ.items() if k not in CLEAR}
    env.update(values)
    return mock.patch.dict(os.environ, env, clear=True)


class _Home(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name).resolve()
        patcher = _env(HACTU8_HOME=str(self.home))
        patcher.start()
        self.addCleanup(patcher.stop)

    def client(self, token=None, **env):
        from hactu8 import api
        with _env(HACTU8_HOME=str(self.home), **env):
            app = api.create_app(ROOT, token=token) if token is not None else api.create_app(ROOT)
        return TestClient(app, base_url="https://127.0.0.1:8000")

    def audit_lines(self):
        path = self.home / "audit.log"
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []


@unittest.skipIf(TestClient is None, "API optional dependencies not installed")
class ApiDocsTest(_Home):
    def test_docs_off_by_default(self):
        client = self.client()
        for path in ("/docs", "/redoc", "/openapi.json"):
            response = client.get(path)
            self.assertEqual(response.status_code, 404, path)
            self.assertIn("content-security-policy", response.headers)

    def test_docs_on_by_env(self):
        client = self.client(HACTU8_API_DOCS="on")
        self.assertEqual(client.get("/openapi.json").status_code, 200)
        docs = client.get("/docs")
        self.assertEqual(docs.status_code, 200)
        self.assertNotIn("content-security-policy", docs.headers)


@unittest.skipIf(TestClient is None, "API optional dependencies not installed")
class ApiValidationTest(_Home):
    def test_bad_backend_and_model_are_422(self):
        client = self.client()
        cases = [("/api/live", {"backend": "echo", "model": "$(id)"}),
                 ("/api/live", {"backend": "echo; touch /tmp/pwned"}),
                 ("/api/live", {"backend": "echo", "model": "a" * 121}),
                 ("/api/runs", {"skill_id": "hx01", "backend": "echo; touch /tmp/pwned #"}),
                 ("/api/runs", {"skill_id": "hx01", "model": "x y"}),
                 ("/api/wolf", {"backend": "nope"}),
                 ("/api/wolf", {"target_backend": "nope"}),
                 ("/api/wolf", {"target_model": "`id`"})]
        for path, body in cases:
            self.assertEqual(client.post(path, json=body).status_code, 422, (path, body))
        self.assertEqual(list(store.results_dir().glob("*.json")), [])

    def test_good_values_still_run(self):
        response = self.client().post("/api/live", json={"backend": "Echo", "model": "llama3.2:3b"})
        self.assertEqual(response.status_code, 200)


class ReproduceQuotingTest(unittest.TestCase):
    def test_values_are_shell_quoted(self):
        live = {"live": {}, "model": {"backend": "echo; touch /tmp/pwned", "model": "$(id)"}}
        line = reports._reproduce(live)
        self.assertEqual(shlex.split(line)[-4:], ["--backend", "echo; touch /tmp/pwned", "--model", "$(id)"])
        self.assertIn("'$(id)'", line)
        lab = {"skill": {"id": "hx01"}, "model": {"backend": "echo && id", "model": ""}}
        self.assertEqual(shlex.split(reports._reproduce(lab))[-1], "echo && id")
        plain = {"skill": {"id": "hx01"}, "model": {"backend": "echo", "model": ""}}
        self.assertEqual(reports._reproduce(plain), "python -m hactu8 run hx01 --backend echo")


class CliValidationTest(unittest.TestCase):
    def test_cli_refuses_bad_backend_and_model(self):
        from hactu8 import cli
        for argv in (["live", "--backend", "echo;id"], ["live", "--model", "$(id)"],
                     ["run", "hx01", "--backend", "nope"], ["wolf", "--target-model", "a b"],
                     ["bench", "--classifier-backend", "x;y"]):
            with self.assertRaises(SystemExit) as caught, contextlib.redirect_stderr(io.StringIO()):
                cli.main(argv)
            self.assertEqual(caught.exception.code, 2, argv)


@unittest.skipUnless((ROOT / "Dockerfile").is_file(), "no Dockerfile: running inside the image, which does not ship it")
class DockerfileTest(unittest.TestCase):
    def setUp(self):
        self.text = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    def test_base_images_pinned_by_digest(self):
        images = re.findall(r"^ARG (?:PYTHON|NODE)_IMAGE=(\S+)$", self.text, re.M)
        self.assertEqual(len(images), 2)
        for image in images:
            self.assertRegex(image, r"^[a-z]+:[\w.-]+@sha256:[0-9a-f]{64}$")

    def test_no_blanket_passwordless_sudo(self):
        self.assertFalse("NOPASSWD:ALL" in self.text.replace(" ", ""), "blanket NOPASSWD sudo in Dockerfile")
        rule = re.search(r"'(hactu8 ALL=\(root\) NOPASSWD: [^']+)'", self.text)
        self.assertIsNotNone(rule)
        self.assertEqual(rule.group(1).split("NOPASSWD: ")[1],
                         r"/usr/bin/chown hactu8\:hactu8 /app/spikes/iac-prototype/iac-host/node_modules")
        post = json.loads("\n".join(line for line in (ROOT / ".devcontainer" / "devcontainer.json").read_text(
            encoding="utf-8").splitlines() if not line.lstrip().startswith("//")))["postCreateCommand"]
        self.assertTrue(post.startswith("sudo chown hactu8:hactu8 /app/spikes/iac-prototype/iac-host/node_modules &&"))
        self.assertEqual(post.count("sudo "), 1)


@unittest.skipIf(TestClient is None, "API optional dependencies not installed")
class TokenGateTest(_Home):
    TOKEN = "s3cret-token-value"

    def test_no_token_and_wrong_token_are_401(self):
        client = self.client(token=self.TOKEN)
        self.assertEqual(client.get("/api/skills").status_code, 401)
        self.assertEqual(client.get("/api/skills", headers={"Authorization": "Bearer nope"}).status_code, 401)
        client.cookies.set("hactu8_token", "nope")
        self.assertEqual(client.get("/api/skills").status_code, 401)
        self.assertEqual(client.post("/api/live", json={}).status_code, 401)
        self.assertEqual(self.client(token=self.TOKEN).get("/?token=nope", follow_redirects=False).status_code, 401)

    def test_bearer_ok(self):
        client = self.client(token=self.TOKEN)
        response = client.get("/api/skills", headers={"Authorization": f"Bearer {self.TOKEN}"})
        self.assertEqual(response.status_code, 200)

    def test_login_url_sets_strict_cookie(self):
        client = self.client(token=self.TOKEN)
        login = client.get(f"/?token={self.TOKEN}", follow_redirects=False)
        self.assertEqual(login.status_code, 303)
        self.assertEqual(login.headers["location"], "/")
        cookie = login.headers["set-cookie"]
        for attr in ("hactu8_token=", "HttpOnly", "Secure", "SameSite=strict", "Path=/"):
            self.assertIn(attr.lower(), cookie.lower())
        self.assertEqual(client.get("/api/skills").status_code, 200)
        other = self.client(token=self.TOKEN).get(
            f"https://127.0.0.1:8000//evil.example/?token={self.TOKEN}", follow_redirects=False)
        self.assertEqual(other.headers.get("location"), "/evil.example/")

    def test_health_stays_open_for_the_healthcheck(self):
        self.assertEqual(self.client(token=self.TOKEN).get("/api/health").status_code, 200)

    def test_env_token_applies_on_loopback(self):
        client = self.client(HACTU8_API_TOKEN=self.TOKEN)
        self.assertEqual(client.get("/api/skills").status_code, 401)
        self.assertEqual(client.get("/api/skills", headers={"Authorization": f"Bearer {self.TOKEN}"}).status_code, 200)

    def test_loopback_without_token_unchanged(self):
        self.assertEqual(self.client().get("/api/skills").status_code, 200)

    def test_host_check_comes_first(self):
        client = self.client(token=self.TOKEN)
        response = client.get("/api/skills", headers={"Host": "evil.example",
                                                      "Authorization": f"Bearer {self.TOKEN}"})
        self.assertEqual(response.status_code, 421)
        self.assertEqual(client.get("/api/skills", headers={"Host": "evil.example"}).status_code, 421)

    def test_access_log_redacts_the_token(self):
        import logging
        from hactu8 import api
        record = logging.LogRecord("uvicorn.access", logging.INFO, __file__, 1, '%s - "%s %s HTTP/%s" %d',
                                   ("127.0.0.1:5", "GET", f"/?token={self.TOKEN}&x=1", "1.1", 303), None)
        self.assertTrue(api.RedactTokenFilter().filter(record))
        self.assertNotIn(self.TOKEN, record.getMessage())
        self.assertIn("/?token=<redacted>&x=1", record.getMessage())
        config = api.log_config()
        self.assertIn("redact_token", config["handlers"]["access"]["filters"])
        logging.config.dictConfig(config)
        self.assertTrue(any(isinstance(f, api.RedactTokenFilter)
                            for f in logging.getLogger("uvicorn.access").handlers[0].filters))

    def test_main_generates_token_only_off_loopback(self):
        from hactu8 import api
        for host, expect in (("0.0.0.0", True), ("127.0.0.1", False), ("::1", False), ("localhost", False)):
            out = io.StringIO()
            with _env(HACTU8_HOME=str(self.home), HACTU8_TLS="off", HACTU8_API_PORT="8046"), \
                    mock.patch("uvicorn.run") as run, mock.patch.object(api, "create_app") as make, \
                    contextlib.redirect_stdout(out):
                api.main(["--host", host])
            token = make.call_args.kwargs.get("token", "")
            self.assertEqual(bool(token), expect, host)
            self.assertEqual(run.call_args.kwargs["host"], host)
            if expect:
                self.assertGreaterEqual(len(token), 32)
                self.assertIn(f"http://127.0.0.1:8046/?token={token}", out.getvalue())
                self.assertEqual(out.getvalue().count(token), 1)
            else:
                self.assertNotIn("token=", out.getvalue())


@unittest.skipIf(TestClient is None, "API optional dependencies not installed")
class AuditLogTest(_Home):
    def test_spend_requests_are_audited(self):
        client = self.client()
        with _env(HACTU8_HOME=str(self.home), OPENROUTER_API_KEY="sk-or-v1-" + "f" * 64):
            self.assertEqual(client.post("/api/live", json={"backend": "openrouter"}).status_code, 402)
            self.assertEqual(client.post("/api/live", json={"backend": "echo"}).status_code, 200)
            self.assertEqual(client.post("/api/wolf", json={"backend": "anthropic", "rounds": 1}).status_code, 402)
            self.assertEqual(client.post("/api/runs", json={"skill_id": "nope"}).status_code, 400)
        lines = self.audit_lines()
        self.assertEqual([(e["endpoint"], e["outcome"], e["status"]) for e in lines],
                         [("/api/live", "refused", 402), ("/api/live", "ok", 200),
                          ("/api/wolf", "refused", 402), ("/api/runs", "error", 400)])
        first = lines[0]
        for key in ("time", "client", "endpoint", "backend", "model", "confirm_spend", "outcome"):
            self.assertIn(key, first)
        self.assertEqual((first["backend"], first["confirm_spend"]), ("openrouter", False))
        self.assertTrue(lines[1]["run_id"])
        self.assertNotIn("sk-or-v1", (self.home / "audit.log").read_text(encoding="utf-8"))

    def test_token_never_logged(self):
        client = self.client(token="tok-" + "a" * 40)
        client.post("/api/live", json={"backend": "echo"}, headers={"Authorization": "Bearer tok-" + "a" * 40})
        text = (self.home / "audit.log").read_text(encoding="utf-8")
        self.assertNotIn("tok-", text)

    def test_cli_paid_refusal_is_audited(self):
        from hactu8 import cli
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(["live", "--backend", "openrouter"]), 2)
        (entry,) = self.audit_lines()
        self.assertEqual((entry["endpoint"], entry["client"], entry["outcome"]), ("cli live", "cli", "refused"))


@unittest.skipIf(TestClient is None, "API optional dependencies not installed")
class StrayResultTest(_Home):
    def test_malformed_files_are_skipped(self):
        results = store.results_dir()
        (results / "zz-stray.json").write_text('{"note": "not a run"}', encoding="utf-8")
        (results / "zz-list.json").write_text("[1, 2]", encoding="utf-8")
        with self.assertLogs("hactu8.store", "WARNING"):
            self.assertEqual(store.list_runs(), [])
        client = self.client()
        self.assertEqual(client.get("/api/results/nonexistent").status_code, 404)
        self.assertEqual(client.get("/api/results/latest").status_code, 404)
        self.assertEqual(client.get("/api/reports/latest/html").status_code, 404)
        run = client.post("/api/live", json={"backend": "echo"}).json()
        self.assertEqual(client.get("/api/results/latest").json()["run_id"], run["run_id"])
        self.assertEqual(client.get("/api/reports/latest/html").status_code, 200)


@unittest.skipIf(TestClient is None, "API optional dependencies not installed")
class ConsoleHeadTest(_Home):
    def test_head_allowed_on_console(self):
        dist = self.home / "dist"
        (dist / "assets").mkdir(parents=True)
        (dist / "index.html").write_text("<!doctype html><title>x</title>", encoding="utf-8")
        (dist / "assets" / "app.js").write_text("console.log(1)", encoding="utf-8")
        client = self.client(HACTU8_CONSOLE_DIR=str(dist))
        for path in ("/", "/console", "/assets/app.js"):
            head, get = client.head(path), client.get(path)
            self.assertEqual(head.status_code, 200, path)
            self.assertEqual(head.content, b"")
            self.assertEqual(head.headers["content-length"], get.headers["content-length"])
            self.assertIn("content-security-policy", head.headers)


if __name__ == "__main__":
    unittest.main()
