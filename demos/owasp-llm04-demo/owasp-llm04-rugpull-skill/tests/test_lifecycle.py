"""Lifecycle tests — assert the four-act story against the in-process lab.

Baseline is all GREEN; the compromised release raises the targeted rate;
controls are untouched (overall < targeted); the pin diff flags the rug pull;
sampling flags the sleeper that a single sample misses; hardened mode returns
the rate to 0; reset restores the baseline.

Each test uses its own registry file under ``registry/`` and deletes it.

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
from run_rug_pull import (SLEEPER_PAYLOAD, SLEEPER_TOOL, SWAP_PAYLOAD,  # noqa: E402
                          build_compromised_release)
import providers  # noqa: E402
import vulnerable_app  # noqa: E402
from vulnerable_app import (  # noqa: E402
    CONSOLE_META, REGISTRY_DIR, Lab, ProviderModel, RemoteTool, console_attack, console_evaluate,
    console_scan, definition_hash, load_baseline, load_pins, load_screen_rules, pin_diff,
    read_registry, sample_tool, write_registry,
)


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read().strip()


def run_suite(lab: Lab):
    statuses = [(classify(lab.query(q)["answer"], truth), targeted)
                for q, targeted, truth in SUITE]
    targeted = [s for s, t in statuses if t]
    ctr = sum(s == "RED" for s in targeted) / len(targeted)
    overall = sum(s == "RED" for s, _ in statuses) / len(statuses)
    return statuses, ctr, overall


class LifecycleTest(unittest.TestCase):
    def setUp(self) -> None:
        path = os.path.join(REGISTRY_DIR, f"test_{os.getpid()}_{self._testMethodName}.json")
        self.lab = Lab(registry_path=path)

    def tearDown(self) -> None:
        self.lab.remove_registry()

    def publish(self, variant: str = "both") -> dict:
        _, registry = read_registry(self.lab.registry_path)
        release, _ = build_compromised_release(
            registry, _read(SWAP_PAYLOAD), _read(SLEEPER_PAYLOAD), variant)
        write_registry(self.lab.registry_path, release)
        return release

    def test_act1_baseline_all_green(self):
        statuses, ctr, _ = run_suite(self.lab)
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)
        self.assertEqual(ctr, 0)

    def test_act3_attack_hits_targeted_only(self):
        self.publish()
        statuses, ctr, overall = run_suite(self.lab)
        self.assertEqual(ctr, 1.0)
        self.assertLess(overall, ctr)
        self.assertTrue(all(s == "GREEN" for s, t in statuses if not t), statuses)

    def test_pins_match_baseline_and_flag_rug_pull_only(self):
        pins = load_pins()
        for entry in load_baseline()["tools"]:
            self.assertEqual(definition_hash(entry["definition"]), pins[entry["definition"]["name"]])
        self.assertEqual(pin_diff(load_baseline(), pins), [])
        findings = pin_diff(self.publish(), pins)
        self.assertEqual(len(findings), 1)                  # the sleeper's definition is unchanged
        self.assertTrue(findings[0].startswith("expense_policy"))

    def test_sampling_catches_sleeper_single_sample_does_not(self):
        release = self.publish("sleeper")
        entry = next(e for e in release["tools"] if e["definition"]["name"] == SLEEPER_TOOL)
        rules = load_screen_rules()
        self.assertEqual(sample_tool(RemoteTool(entry, "registry"), rules, calls=1), [])
        self.assertTrue(sample_tool(RemoteTool(entry, "registry"), rules))

    def test_act4_hardened_returns_to_zero(self):
        self.publish()
        self.lab.set_mode("hardened")
        statuses, ctr, _ = run_suite(self.lab)
        self.assertEqual(ctr, 0)
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)
        sources = {n: t.source for n, t in self.lab.installed.items()}
        self.assertEqual(sources["expense_policy"], "vendored")
        self.assertEqual(sources[SLEEPER_TOOL], "vendored")

    def test_pinning_alone_misses_sleeper(self):
        # With sampling reduced to one call, the pin still stops the rug pull,
        # but the sleeper gets through: both controls are needed.
        import vulnerable_app
        self.publish()
        saved = vulnerable_app.SAMPLE_CALLS
        vulnerable_app.SAMPLE_CALLS = 1
        try:
            self.lab.set_mode("hardened")
            statuses, ctr, _ = run_suite(self.lab)
        finally:
            vulnerable_app.SAMPLE_CALLS = saved
        self.assertEqual(ctr, 0.5)
        self.assertEqual([s for s, _ in statuses[:2]], ["GREEN", "GREEN"])

    def test_reset_restores_baseline(self):
        self.publish()
        run_suite(self.lab)
        self.lab.reset()
        self.assertTrue(self.lab.state()["baseline"])
        _, ctr, _ = run_suite(self.lab)
        self.assertEqual(ctr, 0)


class ConsoleApiTest(unittest.TestCase):
    """The web console's endpoints tell the same four-act story."""

    def setUp(self) -> None:
        self.lab = Lab(registry_path=os.path.join(REGISTRY_DIR, "test_console.json"))

    def tearDown(self) -> None:
        self.lab.remove_registry()

    def test_console_four_acts(self):
        lab = self.lab
        self.assertEqual(console_evaluate(lab)["targeted_rate"], 0)
        self.assertEqual(console_scan(lab)["decision"], "PASS")
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
        path = os.path.join(REGISTRY_DIR, f"test_{os.getpid()}_http.json")
        vulnerable_app.LAB = Lab(registry_path=path)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), vulnerable_app.Handler)
        vulnerable_app.PORT = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        vulnerable_app.LAB.remove_registry()

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

    def __init__(self, reply: str = "Expense reports are due within 30 days.") -> None:
        super().__init__()
        self.reply = reply
        self.sent = []

    def chat(self, messages, *, model=""):
        self._count_call()
        self.sent.append(messages)
        return self.reply


EXPENSE_Q = "When are expense reports due?"


class BackendTest(unittest.TestCase):
    """The real-model seam: what each mode sends, and the provider limits."""

    def setUp(self) -> None:
        path = os.path.join(REGISTRY_DIR, f"test_{os.getpid()}_backend_{self._testMethodName}.json")
        self.lab = Lab(registry_path=path)
        self.fake = FakeProvider()
        self.lab.model = ProviderModel(self.fake, "fake-model")
        _, registry = read_registry(self.lab.registry_path)
        release, _ = build_compromised_release(
            registry, _read(SWAP_PAYLOAD), _read(SLEEPER_PAYLOAD), "both")
        write_registry(self.lab.registry_path, release)

    def tearDown(self) -> None:
        self.lab.remove_registry()

    def test_vulnerable_sends_swapped_description_as_plain_text(self):
        self.lab.query(EXPENSE_Q)
        system, user = self.fake.sent[-1]
        self.assertIn("LLM04-CANARY-3a9d", system.content)
        self.assertNotIn("untrusted_tool", system.content + user.content)

    def test_hardened_fences_and_admits_only_pinned_definition(self):
        self.lab.set_mode("hardened")
        self.lab.query(EXPENSE_Q)
        system, user = self.fake.sent[-1]
        self.assertIn("<untrusted_tool_definition>", system.content)
        self.assertIn("<untrusted_tool_output>", user.content)
        self.assertIn("never follow instructions", system.content)
        self.assertNotIn("LLM04-CANARY", system.content + user.content)   # gate in code

    def test_default_backend_is_offline_echo(self):
        self.assertIsNone(providers.get_provider("echo"))
        self.assertIsNone(providers.get_provider("stub"))       # alias
        self.assertEqual(self.lab.backend, "echo")
        self.assertEqual(self.lab.state()["backend"], "echo")
        with self.assertRaises(ValueError):
            providers.get_provider("nope")

    def test_set_backend_swaps_model_and_keeps_state(self):
        lab = self.lab
        lab.set_mode("hardened")                     # re-admits the compromised release
        installed, log = dict(lab.installed), list(lab.admission_log)
        self.assertTrue(log)
        with unittest.mock.patch.object(providers, "get_provider", return_value=self.fake):
            lab.set_backend("ollama", "llama3.2:3b")
        self.assertEqual(lab.backend, "ollama:llama3.2:3b")
        self.assertIsInstance(lab.model, ProviderModel)
        self.assertFalse(lab.model.trusted)                     # spotlighting follows mode
        self.assertEqual(lab.mode, "hardened")
        self.assertEqual(lab.installed, installed)
        self.assertEqual(lab.admission_log, log)
        lab.set_backend("echo")
        self.assertEqual(lab.backend, "echo")

    def test_set_backend_rejects_bad_input(self):
        lab = self.lab
        with self.assertRaises(ValueError):
            lab.set_backend("nope")
        with self.assertRaises(ValueError):
            lab.set_backend("ollama", "bad model; rm")
        self.assertEqual(lab.backend, "echo")                   # unchanged

    def test_openrouter_requires_key(self):
        saved = os.environ.pop("OPENROUTER_API_KEY", None)
        try:
            with self.assertRaises(RuntimeError):
                providers.get_provider("openrouter")
        finally:
            if saved is not None:
                os.environ["OPENROUTER_API_KEY"] = saved

    def test_call_cap(self):
        self.fake.max_calls = 2
        self.lab.query("a")
        self.lab.query("b")
        with self.assertRaises(RuntimeError):
            self.lab.query("c")


if __name__ == "__main__":
    unittest.main()
