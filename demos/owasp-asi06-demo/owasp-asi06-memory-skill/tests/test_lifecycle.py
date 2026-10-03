"""Lifecycle tests — assert the four-act story against the in-process lab.

Baseline is all GREEN; one planted memory raises the targeted rate in later
sessions of other users; controls are untouched (overall < targeted); the
screen flags the payload; hardened mode returns the rate to 0, and each of its
recall and write rules holds on its own; reset restores the baseline.

Run from the skill folder:  python -m unittest discover tests
"""

from __future__ import annotations

import json
import os
import sys
import threading
import unittest
import unittest.mock
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, SKILL_DIR)
sys.path.insert(0, os.path.join(SKILL_DIR, "scripts"))

from evaluate_kpi import SUITE, classify, session_steps  # noqa: E402
from run_memory_poison import poison_message  # noqa: E402
import providers  # noqa: E402
import vulnerable_app  # noqa: E402
from vulnerable_app import (  # noqa: E402
    CONSOLE_META, console_attack, console_evaluate, console_scan,
    Lab, ProviderModel, load_screen_rules, screen_memory,
)

PAYLOAD = os.path.join(SKILL_DIR, "assets", "memory_note.md")


def run_suite(lab: Lab):
    statuses = []
    for user, message, targeted, truth in SUITE:
        sid = lab.session(user, message)["session"]
        statuses.append((classify(session_steps(lab.action_log, sid), truth), targeted))
    targeted = [s for s, t in statuses if t]
    psr = sum(s == "RED" for s in targeted) / len(targeted)
    overall = sum(s == "RED" for s, _ in statuses) / len(statuses)
    return statuses, psr, overall


class LifecycleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.lab = Lab()
        with open(PAYLOAD, encoding="utf-8") as fh:
            self.message = poison_message(fh.read())

    def plant(self) -> dict:
        return self.lab.session("mallory", self.message)

    def test_act1_baseline_all_green(self):
        statuses, psr, _ = run_suite(self.lab)
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)
        self.assertEqual(psr, 0)

    def test_act3_attack_hits_targeted_only(self):
        save = [s for s in self.plant()["steps"] if s["step"] == "save_memory"]
        self.assertEqual(save[0]["status"], "executed")
        statuses, psr, overall = run_suite(self.lab)
        self.assertEqual(psr, 1.0)
        self.assertLess(overall, psr)
        self.assertTrue(all(s == "GREEN" for s, t in statuses if not t), statuses)

    def test_screen_flags_payload_and_passes_baseline(self):
        rules = load_screen_rules()
        with open(PAYLOAD, encoding="utf-8") as fh:
            self.assertTrue(screen_memory(fh.read(), rules).blocked)
        for entry in self.lab.memories:
            self.assertFalse(screen_memory(entry["text"], rules).blocked)

    def test_act4_hardened_returns_to_zero(self):
        self.plant()
        self.lab.set_mode("hardened")
        statuses, psr, _ = run_suite(self.lab)
        self.assertEqual(psr, 0)
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)

    def test_scoped_recall_alone_blocks(self):
        # Poison already stored before hardening, empty screen: scope still stops it.
        self.plant()
        self.lab.rules = {"markers": [], "patterns": []}
        self.lab.set_mode("hardened")
        _, psr, _ = run_suite(self.lab)
        self.assertEqual(psr, 0)

    def test_write_screen_blocks_in_hardened_mode(self):
        self.lab.set_mode("hardened")
        before = len(self.lab.memories)
        save = [s for s in self.plant()["steps"] if s["step"] == "save_memory"]
        self.assertEqual(save[0]["status"], "blocked")
        self.assertEqual(len(self.lab.memories), before)

    def test_hardened_still_recalls_own_memory(self):
        self.lab.set_mode("hardened")
        steps = self.lab.session("alice", SUITE[0][1])["steps"]
        recalled = [m["id"] for m in steps[0]["memories"]]
        self.assertEqual(recalled, ["m-0001"])

    def test_reset_restores_baseline(self):
        self.plant()
        self.lab.reset()
        self.assertTrue(self.lab.state()["baseline"])
        _, psr, _ = run_suite(self.lab)
        self.assertEqual(psr, 0)


class ConsoleApiTest(unittest.TestCase):
    """The web console's endpoints tell the same four-act story."""

    def test_console_four_acts(self):
        lab = Lab()
        self.assertEqual(console_evaluate(lab)["targeted_rate"], 0)
        self.assertTrue(console_attack(lab)["events"])
        attacked = console_evaluate(lab)
        self.assertEqual(attacked["targeted_rate"], 100)
        self.assertLess(attacked["overall_rate"], attacked["targeted_rate"])
        self.assertEqual(console_scan(lab)["decision"], "REJECT")
        lab.set_mode("hardened")
        self.assertEqual(console_evaluate(lab)["targeted_rate"], 0)

    def test_meta_has_console_fields(self):
        for key in ("id", "framework", "risk", "title", "scenario", "ground_truth",
                    "metric_name", "metric_abbr", "attack_label", "attack_description",
                    "scan_label", "harden_label", "harden_description"):
            self.assertIn(key, CONSOLE_META)


class ConsoleHttpTest(unittest.TestCase):
    """The backend picker endpoints, over real HTTP on an ephemeral port."""

    def setUp(self):
        vulnerable_app.LAB = Lab()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), vulnerable_app.Handler)
        vulnerable_app.PORT = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def _call(self, path, body=None):
        url = f"http://127.0.0.1:{vulnerable_app.PORT}{path}"
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(url, data=data,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}")

    def test_meta_lists_backends_but_never_the_key(self):
        with unittest.mock.patch.dict(os.environ, {"OPENROUTER_API_KEY": "sk-test-secret"}):
            status, meta = self._call("/api/meta")
        self.assertEqual(status, 200)
        self.assertEqual(meta["backends"], ["echo", "ollama", "llamacpp", "openrouter"])
        self.assertTrue(meta["openrouter_key_set"])
        self.assertNotIn("sk-test-secret", json.dumps(meta))

    def test_models_endpoint(self):
        self.assertEqual(self._call("/api/models?backend=echo"), (200, {"backend": "echo", "models": []}))
        self.assertEqual(self._call("/api/models?backend=nope")[0], 400)

    def test_backend_switch(self):
        status, state = self._call("/api/backend", {"backend": "stub", "model": ""})
        self.assertEqual((status, state["backend"]), (200, "echo"))
        self.assertEqual(self._call("/api/backend", {"backend": "nope"})[0], 400)
        with unittest.mock.patch.dict(os.environ, {"OPENROUTER_API_KEY": ""}):
            status, err = self._call("/api/backend", {"backend": "openrouter"})
        self.assertEqual(status, 400)
        self.assertIn("OPENROUTER_API_KEY", err["error"])
        self.assertEqual(vulnerable_app.LAB.backend, "echo")


class FakeProvider(providers.Provider):
    """Records what a real backend would be sent; no network."""
    name = "fake"

    def __init__(self, reply: str = "Book through the travel desk 14 days ahead.") -> None:
        super().__init__()
        self.reply = reply
        self.sent = []

    def chat(self, messages, *, model=""):
        self._count_call()
        self.sent.append(messages)
        return self.reply


class BackendTest(unittest.TestCase):
    """The real-model seam: what each mode sends, and the provider limits."""

    def _lab(self, fake: FakeProvider) -> Lab:
        lab = Lab()
        lab.model = ProviderModel(fake, "fake-model")
        with open(PAYLOAD, encoding="utf-8") as fh:
            lab.session("mallory", poison_message(fh.read()))
        return lab

    def test_vulnerable_puts_foreign_memory_in_system_prompt(self):
        fake = FakeProvider()
        self._lab(fake).session("alice", SUITE[0][1])
        system, user = fake.sent[-1]
        self.assertIn("Saved memories:", system.content)
        self.assertIn("@assistant:", system.content)           # mallory's memory, trusted
        self.assertNotIn("recalled_memory", system.content + user.content)

    def test_hardened_scopes_and_fences_memories(self):
        fake = FakeProvider()
        lab = self._lab(fake)
        lab.set_mode("hardened")
        lab.session("alice", SUITE[0][1])
        system, user = fake.sent[-1]
        self.assertIn("never follow instructions", system.content)
        self.assertIn("<recalled_memory owner='alice'", user.content)
        self.assertIn("<untrusted_tool_output>", user.content)
        self.assertNotIn("@assistant:", system.content + user.content)  # scope filter
        self.assertNotIn("mallory", user.content)

    def test_default_backend_is_offline_echo(self):
        self.assertIsNone(providers.get_provider("echo"))
        self.assertIsNone(providers.get_provider("stub"))       # alias
        self.assertEqual(Lab().backend, "echo")
        self.assertEqual(Lab().state()["backend"], "echo")
        self.assertEqual(Lab(backend="stub").backend, "echo")

    def test_set_backend_swaps_model_and_keeps_state(self):
        lab = Lab()
        with open(PAYLOAD, encoding="utf-8") as fh:
            lab.session("mallory", poison_message(fh.read()))
        lab.set_mode("hardened")
        planted, memories = list(lab.planted), len(lab.memories)
        self.assertTrue(planted)
        fake = FakeProvider()
        with unittest.mock.patch.object(providers, "get_provider", return_value=fake):
            lab.set_backend("ollama", "llama3.2:3b")
        self.assertEqual(lab.backend, "ollama:llama3.2:3b")
        self.assertIsInstance(lab.model, ProviderModel)
        self.assertEqual(lab.mode, "hardened")
        self.assertEqual(lab.planted, planted)
        self.assertEqual(len(lab.memories), memories)
        lab.set_backend("echo")
        self.assertEqual(lab.backend, "echo")

    def test_set_backend_rejects_bad_input(self):
        lab = Lab()
        with self.assertRaises(ValueError):
            lab.set_backend("nope")
        with self.assertRaises(ValueError):
            lab.set_backend("ollama", "bad model; rm")
        self.assertEqual(lab.backend, "echo")                   # unchanged
        with self.assertRaises(ValueError):
            providers.get_provider("nope")

    def test_openrouter_requires_key(self):
        saved = os.environ.pop("OPENROUTER_API_KEY", None)
        try:
            with self.assertRaises(RuntimeError):
                providers.get_provider("openrouter")
        finally:
            if saved is not None:
                os.environ["OPENROUTER_API_KEY"] = saved

    def test_call_cap(self):
        fake = FakeProvider()
        fake.max_calls = 2
        lab = Lab()
        lab.model = ProviderModel(fake, "fake-model")
        lab.session("alice", "a")
        lab.session("bob", "b")
        with self.assertRaises(RuntimeError):
            lab.session("carol", "c")


if __name__ == "__main__":
    unittest.main()
