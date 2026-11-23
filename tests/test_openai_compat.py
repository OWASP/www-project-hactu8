import io
import json
import os
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


if __name__ == "__main__":
    unittest.main()
