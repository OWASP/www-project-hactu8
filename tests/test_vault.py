import io
import json
import os
import unittest
from unittest import mock

from hactu8 import providers


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class VaultTest(unittest.TestCase):
    def test_canary_is_key_shaped_and_detectable(self):
        value = providers.canary()
        self.assertTrue(value.startswith("sk-canary-"))
        self.assertTrue(providers.canary_leaked(f"here it is: {value}"))
        self.assertFalse(providers.canary_leaked("nothing to see"))
        self.assertNotIn(value, repr(providers._ProviderKey("real")))

    def test_canary_never_equals_a_real_key(self):
        for env in providers.KEY_ENV.values():
            self.assertNotEqual(os.environ.get(env, ""), providers.canary())

    def test_key_in_request_body_is_refused(self):
        with mock.patch.dict(os.environ, {"OPENROUTER_API_KEY": "sk-or-real-test-key"}):
            provider = providers.get_provider("openrouter")
            with mock.patch.object(providers, "_urlopen") as urlopen:
                with self.assertRaisesRegex(RuntimeError, "OPENROUTER_API_KEY"):
                    provider.chat([providers.Message("user", "echo sk-or-real-test-key")])
                urlopen.assert_not_called()

    def test_key_in_model_output_is_refused(self):
        answer = {"choices": [{"message": {"content": "leaked sk-or-real-test-key"}}]}
        with mock.patch.dict(os.environ, {"OPENROUTER_API_KEY": "sk-or-real-test-key"}):
            provider = providers.get_provider("openrouter")
            with mock.patch.object(providers, "_urlopen", return_value=_Response(json.dumps(answer).encode())):
                with self.assertRaisesRegex(RuntimeError, "model output"):
                    provider.chat([providers.Message("user", "hello")])

    def test_canary_in_output_passes_through(self):
        answer = {"choices": [{"message": {"content": f"token {providers.canary()}"}}]}
        with mock.patch.dict(os.environ, {"OPENROUTER_API_KEY": "sk-or-real-test-key"}):
            provider = providers.get_provider("openrouter")
            with mock.patch.object(providers, "_urlopen", return_value=_Response(json.dumps(answer).encode())):
                text = provider.chat([providers.Message("user", "hello")])
        self.assertTrue(providers.canary_leaked(text))


if __name__ == "__main__":
    unittest.main()
