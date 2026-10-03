"""Lifecycle tests — assert the four-act story against the in-process lab.

Baseline is all GREEN; the poisoned doc raises the targeted rate; controls are
untouched (overall < targeted); the grounding check flags the payload and
passes the genuine docs; hardened mode returns the rate to 0; an unverifiable
answer is downgraded, not guessed; reset restores the baseline.

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
from vulnerable_app import Lab, check_grounding, load_registry  # noqa: E402

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


if __name__ == "__main__":
    unittest.main()
