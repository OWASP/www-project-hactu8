"""Lifecycle tests — assert the four-act story against the in-process lab.

Baseline is all GREEN; the crafted turn raises the targeted rate; controls
are untouched (overall < targeted); the scope audit flags the payload; hardened
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
from vulnerable_app import MEMORY_TURNS, Lab, rank, scope_blocks  # noqa: E402

PAYLOAD = os.path.join(SKILL_DIR, "assets", "crafted_query.txt")
SESSION = "meadow-analyst"


def run_suite(lab: Lab):
    statuses = [(classify(lab.query(SESSION, q, remember=False)["answer"], truth), targeted)
                for q, targeted, truth in SUITE]
    targeted = [s for s, t in statuses if t]
    ctlr = sum(s == "RED" for s in targeted) / len(targeted)
    overall = sum(s == "RED" for s, _ in statuses) / len(statuses)
    return statuses, ctlr, overall


class LifecycleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.lab = Lab()
        with open(PAYLOAD, encoding="utf-8") as fh:
            self.payload = fh.read().strip()

    def test_act1_baseline_all_green(self):
        statuses, ctlr, _ = run_suite(self.lab)
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)
        self.assertEqual(ctlr, 0)

    def test_act3_attack_hits_targeted_only(self):
        self.lab.query(SESSION, self.payload)
        statuses, ctlr, overall = run_suite(self.lab)
        self.assertEqual(ctlr, 1.0)
        self.assertLess(overall, ctlr)
        self.assertTrue(all(s == "GREEN" for s, t in statuses if not t), statuses)

    def test_scope_audit_flags_payload_and_passes_suite(self):
        tenant = self.lab.tenant_of(SESSION)
        top = rank(self.lab.docs, self.lab.retrieval_vector(SESSION, self.payload))[0][0]
        self.assertTrue(scope_blocks(top, tenant))
        for question, _, _ in SUITE:
            top = rank(self.lab.docs, self.lab.retrieval_vector(SESSION, question))[0][0]
            self.assertFalse(scope_blocks(top, tenant), question)

    def test_act4_hardened_returns_to_zero(self):
        self.lab.query(SESSION, self.payload)
        self.lab.set_mode("hardened")
        statuses, ctlr, _ = run_suite(self.lab)
        self.assertEqual(ctlr, 0)
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)

    def test_prompt_rule_alone_does_not_block(self):
        # Vulnerable mode already carries the tenant rule in the system prompt
        # and the tenant-name boost; neither is an access check.
        self.lab.query(SESSION, self.payload)
        result = self.lab.query(SESSION, SUITE[0][0], remember=False)
        self.assertTrue(result["cross_tenant"])
        self.assertEqual(result["tenant"], "meadow")

    def test_reset_restores_baseline_and_memory_is_capped(self):
        for _ in range(MEMORY_TURNS + 3):
            self.lab.query(SESSION, self.payload)
        self.assertEqual(len(self.lab.memory[SESSION]), MEMORY_TURNS)
        self.lab.reset()
        self.assertTrue(self.lab.state()["baseline"])
        _, ctlr, _ = run_suite(self.lab)
        self.assertEqual(ctlr, 0)


if __name__ == "__main__":
    unittest.main()
