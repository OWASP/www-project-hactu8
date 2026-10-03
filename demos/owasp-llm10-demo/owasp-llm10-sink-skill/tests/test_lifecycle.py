"""Lifecycle tests — assert the four-act story against the in-process lab.

Baseline is all GREEN; the poisoned note raises the targeted rate; controls
are untouched (overall < targeted); the model's output is identical in both
modes; the screen flags the payload; hardened mode returns the rate to 0;
reset restores the baseline.

Run from the skill folder:  python -m unittest discover tests
"""

from __future__ import annotations

import os
import sys
import unittest

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, SKILL_DIR)
sys.path.insert(0, os.path.join(SKILL_DIR, "scripts"))

from evaluate_kpi import SUITE, classify  # noqa: E402
import providers  # noqa: E402
from vulnerable_app import (CONSOLE_META, Lab, ProviderModel, console_attack,  # noqa: E402
                            console_evaluate, console_scan, load_sink_rules,
                            screen_output)

PAYLOAD = os.path.join(SKILL_DIR, "assets", "poisoned_note.md")


def run_suite(lab: Lab):
    statuses = [(classify(lab.render(account, sink), truth), targeted)
                for _, account, sink, targeted, truth in SUITE]
    targeted = [s for s, t in statuses if t]
    usr = sum(s == "RED" for s in targeted) / len(targeted)
    overall = sum(s == "RED" for s, _ in statuses) / len(statuses)
    return statuses, usr, overall


class LifecycleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.lab = Lab()
        with open(PAYLOAD, encoding="utf-8") as fh:
            self.payload = fh.read()

    def test_act1_baseline_all_green(self):
        statuses, usr, _ = run_suite(self.lab)
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)
        self.assertEqual(usr, 0)

    def test_act3_attack_hits_targeted_only(self):
        self.lab.add_note("ridgeview", self.payload)
        statuses, usr, overall = run_suite(self.lab)
        self.assertEqual(usr, 1.0)
        self.assertLess(overall, usr)
        self.assertTrue(all(s == "GREEN" for s, t in statuses if not t), statuses)

    def test_model_output_same_in_both_modes(self):
        # LLM10 is about handling: the model says the same thing either way.
        self.lab.add_note("ridgeview", self.payload)
        vulnerable = self.lab.render("ridgeview", "html")["model_output"]
        self.lab.set_mode("hardened")
        self.assertEqual(self.lab.render("ridgeview", "html")["model_output"], vulnerable)

    def test_screen_flags_payload_and_passes_baseline(self):
        rules = load_sink_rules()
        self.assertTrue(screen_output(self.payload, rules).blocked)
        for notes in self.lab.tickets.values():
            self.assertFalse(screen_output("\n".join(notes), rules).blocked)

    def test_act4_hardened_returns_to_zero(self):
        self.lab.add_note("ridgeview", self.payload)
        self.lab.set_mode("hardened")
        statuses, usr, _ = run_suite(self.lab)
        self.assertEqual(usr, 0)
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)

    def test_sink_handling_alone_blocks(self):
        # Even with an empty tripwire, escaping and parameterisation stop it.
        self.lab.rules = {"markers": [], "patterns": {}}
        self.lab.add_note("ridgeview", self.payload)
        self.lab.set_mode("hardened")
        _, usr, _ = run_suite(self.lab)
        self.assertEqual(usr, 0)
        row = self.lab.render("ridgeview", "sql")
        self.assertIsNone(row["error"])
        self.assertIn("O'Placeholder", row["output"])

    def test_reset_restores_baseline(self):
        self.lab.add_note("ridgeview", self.payload)
        self.lab.reset()
        self.assertTrue(self.lab.state()["baseline"])
        self.assertEqual(self.lab.state()["log_rows"], 0)
        _, usr, _ = run_suite(self.lab)
        self.assertEqual(usr, 0)


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


class FakeProvider(providers.Provider):
    """Records what a real backend would be sent; no network."""
    name = "fake"

    def __init__(self, reply: str = "Ridgeview printer queue restored.") -> None:
        super().__init__()
        self.reply = reply
        self.sent = []

    def chat(self, messages, *, model=""):
        self._count_call()
        self.sent.append(messages)
        return self.reply


# A reply that a sink would interpret: markup plus a quote that ends a SQL literal.
UNSAFE_REPLY = "Queue O'Reilly <mark class=\"x\">restored</mark>"


class BackendTest(unittest.TestCase):
    """The real-model seam: what each mode sends, and the provider limits."""

    def _lab(self, fake: FakeProvider) -> Lab:
        lab = Lab()
        lab.model = ProviderModel(fake, "fake-model")
        with open(PAYLOAD, encoding="utf-8") as fh:
            lab.add_note("ridgeview", fh.read())
        return lab

    def test_notes_reach_the_model_as_plain_text_in_both_modes(self):
        fake = FakeProvider()
        lab = self._lab(fake)
        lab.render("ridgeview", "html")
        lab.set_mode("hardened")
        lab.render("ridgeview", "html")
        vulnerable, hardened = fake.sent
        self.assertIn("@assistant:", vulnerable[1].content)
        # LLM10's fix is at the sink, so the prompt is identical in both modes.
        self.assertEqual([m.content for m in vulnerable], [m.content for m in hardened])

    def test_vulnerable_sinks_run_model_output_as_code(self):
        lab = self._lab(FakeProvider(UNSAFE_REPLY))
        self.assertIn("<mark", lab.render("ridgeview", "html")["output"])
        self.assertIsNotNone(lab.render("ridgeview", "sql")["error"])

    def test_hardened_sinks_hold_whatever_the_model_writes(self):
        lab = self._lab(FakeProvider(UNSAFE_REPLY))
        lab.set_mode("hardened")
        for sink in ("html", "markdown"):
            out = lab.render("ridgeview", sink)
            self.assertNotIn("<mark", out["output"])
            self.assertIn("&lt;mark", out["output"])
        row = lab.render("ridgeview", "sql")
        self.assertIsNone(row["error"])
        self.assertIn("O'Reilly", row["output"])

    def test_default_backend_is_offline_stub(self):
        self.assertIsNone(providers.get_provider("stub"))
        self.assertEqual(Lab().backend, "stub")
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
        lab.render("ridgeview", "html")
        lab.render("ridgeview", "sql")
        with self.assertRaises(RuntimeError):
            lab.render("ridgeview", "markdown")


if __name__ == "__main__":
    unittest.main()
