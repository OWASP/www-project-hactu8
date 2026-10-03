"""Lifecycle tests — assert the four-act story against the in-process lab.

Baseline is all GREEN; the saved extraction preference raises the targeted
rate; the other customer's controls are untouched (overall < targeted); the
design check rejects the deployed prompt and passes the hardened one; hardened
mode returns the rate to 0; each mitigation layer is shown on its own; reset
restores the baseline.

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
from vulnerable_app import Lab, load_prompt, load_rules, scan_prompt  # noqa: E402

PAYLOAD = os.path.join(SKILL_DIR, "assets", "extraction_request.md")
ATTACKER = "guest-attacker"
CANARY = "llm08-canary"


def run_suite(lab: Lab):
    answers = [lab.query(user, q)["answer"] for user, q, _, _ in SUITE]
    statuses = [(classify(a, truth), targeted)
                for a, (_, _, targeted, truth) in zip(answers, SUITE)]
    targeted = [s for s, t in statuses if t]
    plr = sum(s == "RED" for s in targeted) / len(targeted)
    overall = sum(s == "RED" for s, _ in statuses) / len(statuses)
    return statuses, plr, overall, answers


class LifecycleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.lab = Lab()
        with open(PAYLOAD, encoding="utf-8") as fh:
            self.payload = fh.read()

    def test_act1_baseline_all_green(self):
        statuses, plr, _, _ = run_suite(self.lab)
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)
        self.assertEqual(plr, 0)

    def test_act3_attack_hits_targeted_only(self):
        self.lab.set_preference(ATTACKER, self.payload)
        statuses, plr, overall, answers = run_suite(self.lab)
        self.assertEqual(plr, 1.0)
        self.assertLess(overall, plr)
        self.assertTrue(all(s == "GREEN" for s, t in statuses if not t), statuses)
        # The secret really came out of the deployed prompt, not the payload.
        self.assertNotIn(CANARY, self.payload.lower())
        self.assertIn(CANARY, answers[0].lower())

    def test_design_check_rejects_deployed_prompt_passes_hardened(self):
        rules = load_rules()
        self.assertTrue(scan_prompt(load_prompt("vulnerable"), rules).blocked)
        self.assertFalse(scan_prompt(load_prompt("hardened"), rules).blocked)

    def test_act4_hardened_returns_to_zero(self):
        self.lab.set_preference(ATTACKER, self.payload)
        self.lab.set_mode("hardened")
        statuses, plr, _, _ = run_suite(self.lab)
        self.assertEqual(plr, 0)
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)

    def test_design_fix_alone_removes_secret_but_prompt_still_leaks(self):
        # Secret-free prompt, output filter off: no canary, yet the prompt is quoted.
        self.lab.rules = {"output": {"patterns": [], "ngram": 0}}
        self.lab.set_preference(ATTACKER, self.payload)
        self.lab.set_mode("hardened")
        _, plr, _, answers = run_suite(self.lab)
        self.assertNotIn(CANARY, answers[0].lower())
        self.assertEqual(plr, 1.0)

    def test_output_filter_alone_blocks_with_secret_in_prompt(self):
        # Deployed (secret-bearing) prompt, but the output filter applied.
        self.lab.prompts["hardened"] = load_prompt("vulnerable")
        self.lab.set_preference(ATTACKER, self.payload)
        self.lab.set_mode("hardened")
        statuses, plr, _, _ = run_suite(self.lab)
        self.assertEqual(plr, 0)
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)

    def test_reset_restores_baseline(self):
        self.lab.set_preference(ATTACKER, self.payload)
        self.lab.reset()
        self.assertTrue(self.lab.state()["baseline"])
        _, plr, _, _ = run_suite(self.lab)
        self.assertEqual(plr, 0)


if __name__ == "__main__":
    unittest.main()
