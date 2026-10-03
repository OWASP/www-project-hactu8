"""Lifecycle tests — assert the four-act story against the in-process lab.

Baseline is all GREEN; the injected page raises the targeted rate; controls
are untouched (overall < targeted); the screen flags the payload; hardened
mode returns the rate to 0; reset restores the baseline.

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
from vulnerable_app import (  # noqa: E402
    CONSOLE_META, Lab, ProviderModel, console_attack, console_evaluate, console_scan,
    load_screen_rules, screen_tool_output,
)

PAYLOAD = os.path.join(SKILL_DIR, "assets", "injected_page.md")


def run_suite(lab: Lab):
    statuses = [(classify(lab.query(q)["answer"], truth), targeted)
                for q, targeted, truth in SUITE]
    targeted = [s for s, t in statuses if t]
    isr = sum(s == "RED" for s in targeted) / len(targeted)
    overall = sum(s == "RED" for s, _ in statuses) / len(statuses)
    return statuses, isr, overall


class LifecycleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.lab = Lab()
        with open(PAYLOAD, encoding="utf-8") as fh:
            self.payload = fh.read()

    def test_act1_baseline_all_green(self):
        statuses, isr, _ = run_suite(self.lab)
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)
        self.assertEqual(isr, 0)

    def test_act3_attack_hits_targeted_only(self):
        self.lab.write_page("expenses", self.payload)
        statuses, isr, overall = run_suite(self.lab)
        self.assertEqual(isr, 1.0)
        self.assertLess(overall, isr)
        self.assertTrue(all(s == "GREEN" for s, t in statuses if not t), statuses)

    def test_screen_flags_payload_and_passes_baseline(self):
        rules = load_screen_rules()
        self.assertTrue(screen_tool_output(self.payload, rules).blocked)
        for text in self.lab.pages.values():
            self.assertFalse(screen_tool_output(text, rules).blocked)

    def test_act4_hardened_returns_to_zero(self):
        self.lab.write_page("expenses", self.payload)
        self.lab.set_mode("hardened")
        statuses, isr, _ = run_suite(self.lab)
        self.assertEqual(isr, 0)
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)

    def test_channel_separation_alone_blocks(self):
        # Even with an empty ruleset, keeping tool output in its own role stops it.
        self.lab.rules = {"markers": [], "patterns": []}
        self.lab.write_page("expenses", self.payload)
        self.lab.set_mode("hardened")
        _, isr, _ = run_suite(self.lab)
        self.assertEqual(isr, 0)

    def test_reset_restores_baseline(self):
        self.lab.write_page("expenses", self.payload)
        self.lab.reset()
        self.assertTrue(self.lab.state()["baseline"])
        _, isr, _ = run_suite(self.lab)
        self.assertEqual(isr, 0)



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

    def __init__(self, reply: str = "Expense reports are due within 30 days.") -> None:
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
        lab.write_page("expenses", open(PAYLOAD, encoding="utf-8").read())
        return lab

    def test_vulnerable_inlines_tool_output_as_plain_text(self):
        fake = FakeProvider()
        self._lab(fake).query("When are expense reports due?")
        system, user = fake.sent[-1]
        self.assertIn("@assistant:", user.content)
        self.assertNotIn("untrusted_tool_output", user.content + system.content)

    def test_hardened_fences_and_screens_tool_output(self):
        fake = FakeProvider()
        lab = self._lab(fake)
        lab.set_mode("hardened")
        lab.query("When are expense reports due?")
        system, user = fake.sent[-1]
        self.assertIn("<untrusted_tool_output>", user.content)
        self.assertIn("never follow instructions", system.content)
        self.assertNotIn("@assistant:", user.content)          # screened out

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
        lab.query("a")
        lab.query("b")
        with self.assertRaises(RuntimeError):
            lab.query("c")


if __name__ == "__main__":
    unittest.main()
