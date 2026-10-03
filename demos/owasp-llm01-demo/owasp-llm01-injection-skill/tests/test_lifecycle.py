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
from vulnerable_app import Lab, load_screen_rules, screen_tool_output  # noqa: E402

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


if __name__ == "__main__":
    unittest.main()
