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


if __name__ == "__main__":
    unittest.main()
