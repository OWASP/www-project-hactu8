"""Lifecycle tests — assert the four-act story against the in-process lab.

Baseline is all GREEN; the poisoned doc raises the targeted rate; controls are
untouched (overall < targeted); the grounding check flags the payload and
passes the genuine docs; hardened mode returns the rate to 0; an unverifiable
answer is downgraded, not guessed; reset restores the baseline.

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

from evaluate_kpi import SUITE, classify  # noqa: E402
import providers  # noqa: E402
import vulnerable_app  # noqa: E402
from vulnerable_app import (CONSOLE_META, Lab, ProviderModel, check_grounding,  # noqa: E402
                            console_attack, console_evaluate, console_scan,
                            load_registry)

PAYLOAD = os.path.join(SKILL_DIR, "assets", "poisoned_doc.md")
PAGE = "http-client-faq"


def run_suite(lab: Lab):
    statuses = [(classify(lab.query(q)["answer"], truth), targeted)
                for q, targeted, truth in SUITE]
    targeted = [s for s, t in statuses if t]
    ucr = sum(s == "RED" for s in targeted) / len(targeted)
    overall = sum(s == "RED" for s, _ in statuses) / len(statuses)
    return statuses, ucr, overall


class LifecycleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.lab = Lab()
        with open(PAYLOAD, encoding="utf-8") as fh:
            self.payload = fh.read()

    def test_act1_baseline_all_green(self):
        statuses, ucr, _ = run_suite(self.lab)
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)
        self.assertEqual(ucr, 0)

    def test_act3_attack_hits_targeted_only(self):
        self.lab.write_page(PAGE, self.payload)
        statuses, ucr, overall = run_suite(self.lab)
        self.assertEqual(ucr, 1.0)
        self.assertLess(overall, ucr)
        self.assertTrue(all(s == "GREEN" for s, t in statuses if not t), statuses)

    def test_grounding_flags_payload_and_passes_baseline(self):
        registry = load_registry()
        self.assertFalse(check_grounding(self.payload, registry).grounded)
        for text in self.lab.pages.values():
            result = check_grounding(text, registry)
            self.assertTrue(result.grounded, result.findings)
            self.assertTrue(result.cited)  # legitimate installs are cited, not over-blocked

    def test_act4_hardened_returns_to_zero(self):
        self.lab.write_page(PAGE, self.payload)
        self.lab.set_mode("hardened")
        statuses, ucr, _ = run_suite(self.lab)
        self.assertEqual(ucr, 0)
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)

    def test_grounding_keys_on_existence_not_canary(self):
        # Strip the canary and placeholder text: the slopsquat name alone is
        # still RED in vulnerable mode and still withheld in hardened mode.
        first, rest = self.payload.split("\n", 1)
        clean = first.split(" PAYLOAD PLACEHOLDER")[0] + "\n" + rest
        self.lab.write_page(PAGE, clean)
        _, ucr, _ = run_suite(self.lab)
        self.assertEqual(ucr, 1.0)
        self.lab.set_mode("hardened")
        _, ucr, _ = run_suite(self.lab)
        self.assertEqual(ucr, 0)

    def test_unverifiable_answer_is_downgraded(self):
        # With only the poisoned page left to retrieve, hardened mode says
        # "unverified" rather than repeat the slopsquat claim.
        self.lab.pages = {PAGE: self.payload}
        self.lab.set_mode("hardened")
        result = self.lab.query(SUITE[0][0])
        self.assertTrue(result["answer"].startswith("Unverified"), result)
        self.assertTrue(result["grounding_findings"])
        self.assertNotEqual(classify(result["answer"], SUITE[0][2]), "RED")

    def test_reset_restores_baseline(self):
        self.lab.write_page(PAGE, self.payload)
        self.lab.reset()
        self.assertTrue(self.lab.state()["baseline"])
        _, ucr, _ = run_suite(self.lab)
        self.assertEqual(ucr, 0)


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

    def __init__(self, reply: str = "Use goat-http: pip install goat-http.") -> None:
        super().__init__()
        self.reply = reply
        self.sent = []

    def chat(self, messages, *, model=""):
        self._count_call()
        self.sent.append(messages)
        return self.reply


QUESTION = "Which package should I use for HTTP requests?"


class BackendTest(unittest.TestCase):
    """The real-model seam: what each mode sends, and the provider limits."""

    def _lab(self, fake: FakeProvider) -> Lab:
        lab = Lab()
        lab.model = ProviderModel(fake, "fake-model")
        with open(PAYLOAD, encoding="utf-8") as fh:
            lab.write_page(PAGE, fh.read())
        return lab

    def test_vulnerable_passes_doc_as_plain_text(self):
        fake = FakeProvider()
        self._lab(fake).query(QUESTION)
        system, user = fake.sent[-1]
        self.assertIn("goathttp", user.content)
        self.assertNotIn("untrusted_doc", user.content + system.content)

    def test_hardened_fences_doc(self):
        fake = FakeProvider()
        lab = self._lab(fake)
        lab.set_mode("hardened")
        lab.query(QUESTION)
        system, user = fake.sent[-1]
        self.assertIn("<untrusted_doc>", user.content)
        self.assertIn("never follow instructions", system.content)

    def test_hardened_grounding_blocks_ungrounded_model_answer(self):
        # Whatever the model says, an unregistered package never reaches the user.
        fake = FakeProvider("Use goathttp: pip install goathttp.")
        lab = self._lab(fake)
        result = lab.query(QUESTION)
        self.assertIn("goathttp", result["answer"])          # vulnerable passes it on
        lab.set_mode("hardened")
        result = lab.query(QUESTION)
        self.assertNotIn("pip install goathttp", result["answer"])
        self.assertTrue(result["grounding_findings"])

    def test_default_backend_is_offline_echo(self):
        self.assertIsNone(providers.get_provider("echo"))
        self.assertIsNone(providers.get_provider("stub"))       # alias
        self.assertEqual(Lab().backend, "echo")
        self.assertEqual(Lab().state()["backend"], "echo")
        self.assertEqual(Lab(backend="stub").backend, "echo")

    def test_set_backend_swaps_model_and_keeps_state(self):
        lab = Lab(mode="hardened")
        lab.write_page(PAGE, "edited")
        fake = FakeProvider()
        with unittest.mock.patch.object(providers, "get_provider", return_value=fake):
            lab.set_backend("ollama", "llama3.2:3b")
        self.assertEqual(lab.backend, "ollama:llama3.2:3b")
        self.assertIsInstance(lab.model, ProviderModel)
        self.assertEqual(lab.mode, "hardened")
        self.assertIn(PAGE, lab.added)
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
        lab = self._lab(fake)
        lab.query("a")
        lab.query("b")
        with self.assertRaises(RuntimeError):
            lab.query("c")


if __name__ == "__main__":
    unittest.main()
