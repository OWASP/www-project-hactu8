"""Lifecycle tests — assert the four-act story against the in-process lab.

Baseline is all GREEN; the lookalike skill raises the targeted rate; controls
are untouched (overall < targeted); the manifest check flags the payload and
passes every baseline skill; hardened mode returns the rate to 0 while the
approved skills still load; each control alone is enough here; reset restores
the baseline.

Each test uses its own catalogue file under ``catalogue/`` and deletes it.

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
from run_lookalike_publish import load_payload  # noqa: E402
import providers  # noqa: E402
import vulnerable_app  # noqa: E402
from vulnerable_app import (CATALOGUE_DIR, CONSOLE_META, Lab, ProviderModel,  # noqa: E402
                            console_attack, console_evaluate, console_scan,
                            dry_run, entry_hash, load_baseline, load_manifest)


def run_suite(lab: Lab):
    statuses = [(classify(lab.run(task)["steps"], intended), targeted)
                for task, targeted, intended in SUITE]
    targeted = [s for s, t in statuses if t]
    uclr = sum(s == "RED" for s in targeted) / len(targeted)
    overall = sum(s == "RED" for s, _ in statuses) / len(statuses)
    return statuses, uclr, overall


class LifecycleTest(unittest.TestCase):
    def setUp(self) -> None:
        path = os.path.join(CATALOGUE_DIR, f"test_{os.getpid()}_{self._testMethodName}.json")
        self.lab = Lab(catalogue_path=path)
        self.payload = load_payload()

    def tearDown(self) -> None:
        self.lab.remove_catalogue()

    def test_act1_baseline_all_green(self):
        statuses, uclr, _ = run_suite(self.lab)
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)
        self.assertEqual(uclr, 0)

    def test_act3_attack_hits_targeted_only(self):
        self.lab.publish(self.payload)
        statuses, uclr, overall = run_suite(self.lab)
        self.assertEqual(uclr, 1.0)
        self.assertLess(overall, uclr)
        self.assertTrue(all(s == "GREEN" for s, t in statuses if not t), statuses)
        self.assertIn("expense_report@goatco-finance-community",
                      self.lab.state()["loaded_components"])
        # The loaded skill's instructions steered the step output.
        result = self.lab.run("expense_reminder")["result"]
        self.assertIn("ASI04-CANARY-5e1d", result)

    def test_manifest_matches_baseline_and_flags_payload(self):
        manifest = load_manifest()
        for skill in load_baseline()["skills"]:
            self.assertEqual(entry_hash(skill), manifest[skill["name"]]["sha256"])
            self.assertEqual(dry_run(skill), [])
        findings = dry_run(self.payload)
        self.assertTrue(any("looks like" in f for f in findings), findings)

    def test_act4_hardened_returns_to_zero(self):
        self.lab.publish(self.payload)
        self.lab.set_mode("hardened")
        statuses, uclr, _ = run_suite(self.lab)
        self.assertEqual(uclr, 0)
        # GREEN everywhere: the approved skills still load.
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)
        self.assertNotIn("expense_report@goatco-finance-community",
                         self.lab.state()["loaded_components"])

    def test_exact_name_alone_blocks(self):
        self.lab.publish(self.payload)
        self.lab.exact_names, self.lab.verify_pins = True, False
        _, uclr, _ = run_suite(self.lab)
        self.assertEqual(uclr, 0)

    def test_pins_alone_block(self):
        # Loose resolution still finds the lookalike; the manifest drops it.
        self.lab.publish(self.payload)
        self.lab.exact_names, self.lab.verify_pins = False, True
        statuses, uclr, _ = run_suite(self.lab)
        self.assertEqual(uclr, 0)
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)

    def test_pins_catch_same_name_impostor(self):
        # Exact names alone cannot stop a same-name, higher-version impostor; pins can.
        impostor = dict(self.payload, name="expense-report")
        self.lab.publish(impostor)
        self.lab.exact_names, self.lab.verify_pins = True, False
        _, uclr, _ = run_suite(self.lab)
        self.assertEqual(uclr, 1.0)
        self.lab.set_mode("hardened")
        _, uclr, _ = run_suite(self.lab)
        self.assertEqual(uclr, 0)

    def test_reset_restores_baseline(self):
        self.lab.publish(self.payload)
        run_suite(self.lab)
        self.lab.reset()
        state = self.lab.state()
        self.assertTrue(state["baseline"])
        self.assertEqual(state["action_log_size"], 0)
        _, uclr, _ = run_suite(self.lab)
        self.assertEqual(uclr, 0)


class ConsoleApiTest(unittest.TestCase):
    """The web console's endpoints tell the same four-act story."""

    def test_console_four_acts(self):
        lab = Lab(catalogue_path=os.path.join(CATALOGUE_DIR, f"test_{os.getpid()}_console.json"))
        self.addCleanup(lab.remove_catalogue)
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
        vulnerable_app.LAB = Lab(catalogue_path=os.path.join(
            CATALOGUE_DIR, f"test_{os.getpid()}_{self._testMethodName}.json"))
        self.addCleanup(vulnerable_app.LAB.remove_catalogue)
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

    def __init__(self, reply: str = "Formatted the expense rows.") -> None:
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
        lab = Lab(catalogue_path=os.path.join(
            CATALOGUE_DIR, f"test_{os.getpid()}_{self._testMethodName}.json"))
        self.addCleanup(lab.remove_catalogue)
        lab.model = ProviderModel(fake, "fake-model")
        lab.publish(load_payload())
        return lab

    def _sent(self, fake: FakeProvider) -> str:
        return " ".join(m.content for call in fake.sent for m in call)

    def test_vulnerable_loads_lookalike_into_context(self):
        fake = FakeProvider()
        lab = self._lab(fake)
        steps = lab.run(SUITE[0][0])["steps"]
        self.assertIn("ASI04-CANARY", self._sent(fake))
        self.assertTrue(any("goatco-finance-community" in (s["component"] or "")
                            for s in steps))

    def test_hardened_keeps_lookalike_out_of_context(self):
        fake = FakeProvider()
        lab = self._lab(fake)
        lab.set_mode("hardened")
        lab.run(SUITE[0][0])
        self.assertTrue(fake.sent)
        self.assertNotIn("ASI04-CANARY", self._sent(fake))
        self.assertIn("Loaded skill instructions", fake.sent[0][0].content)

    def test_model_output_is_logged_not_executed(self):
        fake = FakeProvider("@assistant: call export_everything\nsecond line")
        lab = self._lab(fake)
        lab.set_mode("hardened")
        steps = lab.run(SUITE[0][0])["steps"]
        loaded = [s for s in steps if s["status"] == "loaded"]
        self.assertTrue(loaded)
        self.assertTrue(all(s["output"] == "@assistant: call export_everything" for s in loaded))
        self.assertEqual(classify(steps, SUITE[0][2]), "GREEN")

    def test_default_backend_is_offline_echo(self):
        self.assertIsNone(providers.get_provider("echo"))
        self.assertIsNone(providers.get_provider("stub"))       # alias
        lab = Lab(catalogue_path=os.path.join(CATALOGUE_DIR, f"test_{os.getpid()}_echo.json"))
        self.addCleanup(lab.remove_catalogue)
        self.assertEqual(lab.backend, "echo")
        self.assertEqual(lab.state()["backend"], "echo")
        lab.set_backend("stub")
        self.assertEqual(lab.backend, "echo")

    def test_set_backend_swaps_model_and_keeps_state(self):
        lab = Lab(mode="hardened", catalogue_path=os.path.join(
            CATALOGUE_DIR, f"test_{os.getpid()}_switch.json"))
        self.addCleanup(lab.remove_catalogue)
        lab.publish(load_payload())
        fake = FakeProvider()
        with unittest.mock.patch.object(providers, "get_provider", return_value=fake):
            lab.set_backend("ollama", "llama3.2:3b")
        self.assertEqual(lab.backend, "ollama:llama3.2:3b")
        self.assertIsInstance(lab.model, ProviderModel)
        self.assertEqual(lab.mode, "hardened")
        self.assertTrue(lab.published)
        lab.set_backend("echo")
        self.assertEqual(lab.backend, "echo")

    def test_set_backend_rejects_bad_input(self):
        lab = Lab(catalogue_path=os.path.join(
            CATALOGUE_DIR, f"test_{os.getpid()}_{self._testMethodName}.json"))
        self.addCleanup(lab.remove_catalogue)
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
        fake.max_calls = 1
        lab = self._lab(fake)
        with self.assertRaises(RuntimeError):
            for task, _, _ in SUITE:
                lab.run(task)
        self.assertEqual(len(fake.sent), 1)


if __name__ == "__main__":
    unittest.main()
