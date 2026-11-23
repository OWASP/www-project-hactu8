import io
import json
import os
import subprocess
import unittest
from unittest import mock

from hactu8 import providers


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class OpenAICompatTest(unittest.TestCase):
    def test_listed_as_local_backend(self):
        self.assertIn("openai-compat", providers.BACKENDS)
        self.assertIn("openai-compat", providers.LOCAL)
        self.assertTrue(providers.key_set("openai-compat"))

    def test_chat_and_models_against_a_local_server(self):
        calls = []

        def fake(req, timeout):
            calls.append((req.full_url, dict(req.header_items()), req.data))
            if req.full_url.endswith("/models"):
                return _Resp(json.dumps({"data": [{"id": "qwen2.5-7b"}, {"id": "llama-3.2-3b"}]}).encode())
            return _Resp(json.dumps({"choices": [{"message": {"content": "hello"}}]}).encode())

        env = {"LOCAL_OPENAI_BASE_URL": "http://127.0.0.1:1234/v1", "LOCAL_OPENAI_API_KEY": "lm-studio"}
        with mock.patch.dict(os.environ, env), mock.patch.object(providers, "_urlopen", fake):
            p = providers.get_provider("openai-compat")
            self.assertEqual(p.chat([providers.Message("user", "hi")], model="qwen2.5-7b"), "hello")
            self.assertEqual(p.list_models(), ["llama-3.2-3b", "qwen2.5-7b"])
        url, headers, body = calls[0]
        self.assertEqual(url, "http://127.0.0.1:1234/v1/chat/completions")
        self.assertEqual(headers.get("Authorization"), "Bearer lm-studio")
        self.assertNotIn(b"lm-studio", body)

    def test_remote_url_refused_unless_allowed(self):
        with mock.patch.dict(os.environ, {"LOCAL_OPENAI_BASE_URL": "https://api.example.com/v1"}):
            os.environ.pop("LOCAL_OPENAI_ALLOW_REMOTE", None)
            with self.assertRaisesRegex(RuntimeError, "not loopback"):
                providers.get_provider("openai-compat")
            with mock.patch.dict(os.environ, {"LOCAL_OPENAI_ALLOW_REMOTE": "1"}):
                self.assertIsNotNone(providers.get_provider("openai-compat"))

    def test_lookalike_loopback_host_refused(self):
        with mock.patch.dict(os.environ, {"LOCAL_OPENAI_BASE_URL": "http://localhost.evil.example/v1"}):
            os.environ.pop("LOCAL_OPENAI_ALLOW_REMOTE", None)
            with self.assertRaises(RuntimeError):
                providers.get_provider("openai-compat")


class MoEEngineBackendsTest(unittest.TestCase):
    """strata and basalt are named presets of the OpenAI-compatible client."""

    def setUp(self):
        # These tests are about the HTTP client, not the hardware gate.
        patcher = mock.patch.dict(os.environ, {providers.FORCE_ENV: "strata,basalt"})
        patcher.start()
        self.addCleanup(patcher.stop)

    def _clean(self, prefix):
        for suffix in ("_HOST", "_ALLOW_REMOTE", "_API_KEY"):
            os.environ.pop(prefix + suffix, None)

    def test_listed_as_local_backends(self):
        for name in ("strata", "basalt"):
            self.assertIn(name, providers.BACKENDS)
            self.assertIn(name, providers.LOCAL)
            self.assertTrue(providers.key_set(name))
            self.assertEqual(providers.DEFAULT_MODELS[name], "local")

    def test_default_base_url(self):
        for name, prefix in (("strata", "STRATA"), ("basalt", "BASALT")):
            with mock.patch.dict(os.environ, {}):
                self._clean(prefix)
                p = providers.get_provider(name)
                self.assertIsInstance(p, providers.OpenAICompatProvider)
                self.assertEqual(p.name, name)
                self.assertEqual(p.base, "http://localhost:8080/v1")

    def test_host_env_and_key_header(self):
        calls = []

        def fake(req, timeout):
            calls.append((req.full_url, dict(req.header_items()), req.data))
            return _Resp(json.dumps({"choices": [{"message": {"content": "ok"}}]}).encode())

        env = {"STRATA_HOST": "http://127.0.0.1:8081/", "STRATA_API_KEY": "strata-key",
               "BASALT_HOST": "http://[::1]:8082"}
        with mock.patch.dict(os.environ, env), mock.patch.object(providers, "_urlopen", fake):
            self.assertEqual(providers.get_provider("strata").chat([providers.Message("user", "hi")]), "ok")
            self.assertEqual(providers.get_provider("basalt").chat([providers.Message("user", "hi")]), "ok")
        (s_url, s_headers, s_body), (b_url, b_headers, _) = calls
        self.assertEqual(s_url, "http://127.0.0.1:8081/v1/chat/completions")
        self.assertEqual(s_headers.get("Authorization"), "Bearer strata-key")
        self.assertNotIn(b"strata-key", s_body)
        self.assertEqual(json.loads(s_body)["model"], "local")
        self.assertEqual(b_url, "http://[::1]:8082/v1/chat/completions")
        self.assertNotIn("Authorization", b_headers)

    def test_non_loopback_host_refused_unless_allowed(self):
        for name, prefix in (("strata", "STRATA"), ("basalt", "BASALT")):
            for host in ("http://192.168.1.20:8080", "http://localhost.evil.example:8080",
                         "https://gpu-box.example.com"):
                with mock.patch.dict(os.environ, {}):
                    self._clean(prefix)
                    os.environ[prefix + "_HOST"] = host
                    with self.assertRaisesRegex(RuntimeError, f"{name} is for local servers"):
                        providers.get_provider(name)
                    # Another backend's override does not unlock this one.
                    with mock.patch.dict(os.environ, {"LOCAL_OPENAI_ALLOW_REMOTE": "1"}):
                        with self.assertRaises(RuntimeError):
                            providers.get_provider(name)
                    with mock.patch.dict(os.environ, {prefix + "_ALLOW_REMOTE": "1"}):
                        self.assertIsNotNone(providers.get_provider(name))

    def test_router_probes_the_engine_url(self):
        from hactu8 import router as router_mod
        seen = []

        def fake(req, timeout):
            seen.append(req.full_url)
            return _Resp(b'{"data": []}')

        with mock.patch.dict(os.environ, {"STRATA_HOST": "http://127.0.0.1:8081",
                                          "BASALT_HOST": "http://127.0.0.1:8082"}), \
                mock.patch.object(providers, "_urlopen", fake):
            r = router_mod.Router(tiers={}, order=[], max_tier="local")
            self.assertEqual(r._probe_local("strata"), (True, "server answered"))
            self.assertEqual(r._probe_local("basalt"), (True, "server answered"))
        self.assertEqual(seen, ["http://127.0.0.1:8081/v1/models", "http://127.0.0.1:8082/v1/models"])


class HardwareGateTest(unittest.TestCase):
    """strata and basalt are offered only on hardware that can run them."""

    def setUp(self):
        providers._GPU_CACHE = None
        self.addCleanup(setattr, providers, "_GPU_CACHE", None)
        patcher = mock.patch.dict(os.environ, {})
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop(providers.FORCE_ENV, None)

    def _host(self, system, machine, smi=None, which="/usr/bin/nvidia-smi"):
        """Pretend to be ``system``/``machine``; ``smi`` is nvidia-smi's stdout or an exception."""
        self.runs = []

        def run(cmd, **kwargs):
            self.runs.append((cmd, kwargs.get("timeout")))
            if isinstance(smi, BaseException):
                raise smi
            return subprocess.CompletedProcess(cmd, 0, stdout=smi or "", stderr="")

        for patch in (mock.patch.object(providers.platform, "system", return_value=system),
                      mock.patch.object(providers.platform, "machine", return_value=machine),
                      mock.patch.object(providers.shutil, "which", return_value=which),
                      mock.patch.object(providers.subprocess, "run", side_effect=run)):
            patch.start()
            self.addCleanup(patch.stop)

    def test_apple_silicon_mac(self):
        self._host("Darwin", "arm64")
        hw = providers.backend_support()
        self.assertTrue(hw["strata"]["ok"])
        self.assertFalse(hw["basalt"]["ok"])
        self.assertIn("NVIDIA Blackwell GPU (sm_120)", hw["basalt"]["reason"])
        self.assertIn("cannot run on macOS", hw["basalt"]["reason"])
        self.assertEqual(self.runs, [], "nvidia-smi is never run on macOS")
        for name in ("echo", "ollama", "llamacpp", "openai-compat", "openrouter", "anthropic", "openai"):
            self.assertTrue(hw[name]["ok"], name)

    def test_intel_mac_has_neither(self):
        self._host("Darwin", "x86_64")
        hw = providers.backend_support()
        self.assertFalse(hw["strata"]["ok"])
        self.assertFalse(hw["basalt"]["ok"])

    def test_linux_blackwell(self):
        self._host("Linux", "x86_64", "NVIDIA GeForce RTX 5090, 12.0\n")
        hw = providers.backend_support()
        self.assertTrue(hw["strata"]["ok"])
        self.assertTrue(hw["basalt"]["ok"])
        self.assertIn("sm_120", hw["basalt"]["reason"])
        self.assertEqual(self.runs[0][0][1:], ["--query-gpu=name,compute_cap", "--format=csv,noheader"])
        self.assertLessEqual(self.runs[0][1], 2.0)

    def test_linux_ada_gpu(self):
        self._host("Linux", "x86_64", "NVIDIA GeForce RTX 4090, 8.9\n")
        hw = providers.backend_support()
        self.assertTrue(hw["strata"]["ok"])
        self.assertFalse(hw["basalt"]["ok"])
        self.assertIn("RTX 4090 (sm_89)", hw["basalt"]["reason"])

    def test_mixed_gpus_pick_the_blackwell(self):
        self._host("Windows", "AMD64", "NVIDIA GeForce RTX 3060, 8.6\nNVIDIA RTX PRO 6000 Blackwell, 12.0\n")
        self.assertTrue(providers.backend_support()["basalt"]["ok"])

    def test_no_nvidia_smi(self):
        self._host("Linux", "x86_64", which=None)
        hw = providers.backend_support()
        self.assertFalse(hw["strata"]["ok"])
        self.assertFalse(hw["basalt"]["ok"])
        self.assertIn("nvidia-smi not found", hw["basalt"]["reason"])
        self.assertEqual(self.runs, [])

    def test_probe_never_raises_and_is_cached(self):
        self._host("Linux", "x86_64", subprocess.TimeoutExpired("nvidia-smi", 2.0))
        hw = providers.backend_support()
        self.assertFalse(hw["basalt"]["ok"])
        self.assertIn("TimeoutExpired", hw["basalt"]["reason"])
        providers.backend_support()
        providers.hardware_reason("strata")
        self.assertEqual(len(self.runs), 1, "nvidia-smi runs once per process")

    def test_gated_backend_refused_with_the_reason(self):
        self._host("Darwin", "arm64")
        with self.assertRaisesRegex(ValueError, "Basalt needs an NVIDIA Blackwell GPU"):
            providers.get_provider("basalt")
        self.assertIsNotNone(providers.get_provider("strata"))
        self.assertIn("hardware", providers.console_info())

    def test_override(self):
        self._host("Darwin", "arm64")
        os.environ[providers.FORCE_ENV] = "basalt"
        self.assertTrue(providers.backend_support()["basalt"]["ok"])
        self.assertIsNotNone(providers.get_provider("basalt"))
        os.environ[providers.FORCE_ENV] = "all"
        self.assertEqual(providers.hardware_reason("basalt"), "")

    def test_cli_refuses_and_marks_help(self):
        from hactu8 import cli
        self._host("Darwin", "arm64")
        err = io.StringIO()
        with mock.patch("sys.stderr", err):
            self.assertEqual(cli.main(["run", "llm01", "--backend", "basalt"]), 2)
            self.assertEqual(cli.main(["wolf", "--target-backend", "basalt"]), 2)
        self.assertIn("--backend basalt: Basalt needs an NVIDIA Blackwell GPU", err.getvalue())
        self.assertIn("--target-backend basalt", err.getvalue())
        out = io.StringIO()
        with mock.patch("sys.stdout", out), self.assertRaises(SystemExit):
            cli.main(["run", "--help"])
        text = " ".join(out.getvalue().split())
        self.assertIn("basalt (unavailable: needs an NVIDIA Blackwell GPU)", text)
        self.assertNotIn("strata (unavailable", text)

    def test_router_marks_gated_backend_unavailable(self):
        from hactu8 import router as router_mod
        self._host("Darwin", "arm64")
        r = router_mod.Router(tiers={}, order=[], max_tier="local")
        cand = router_mod.Candidate(tier="local", backend="basalt", model="local")
        with mock.patch.object(providers, "_urlopen", side_effect=AssertionError("no probe")):
            ok, why = r.available(cand)
        self.assertFalse(ok)
        self.assertIn("Blackwell", why)


if __name__ == "__main__":
    unittest.main()


class ServerErrorBodyTest(unittest.TestCase):
    """2026-11-23 sweep: Ollama answered 500 with a reason in the body; the exception must carry it."""

    BODY = b'{"error":"prediction aborted, token repeat limit reached"}'

    def _raise_500(self, req, timeout):
        import urllib.error
        raise urllib.error.HTTPError(req.full_url, 500, "Internal Server Error", {}, io.BytesIO(self.BODY))

    def test_ollama_500_names_the_server_reason(self):
        import urllib.error
        with mock.patch.object(providers, "_urlopen", self._raise_500):
            p = providers.get_provider("ollama")
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                p.chat([providers.Message("user", "hi")], model="llama3.2:3b")
        self.assertEqual(ctx.exception.code, 500)
        self.assertIn("token repeat limit reached", str(ctx.exception))
