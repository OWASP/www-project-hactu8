"""Lifecycle tests — assert the four-act story against the in-process lab.

Baseline is all GREEN; the pivot note raises the targeted rate; controls are
untouched (overall < targeted); the scan flags the prompt's embedded key;
hardened mode returns the rate to 0; reset restores the baseline.

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
from vulnerable_app import (Lab, load_redaction_rules, redact_output,  # noqa: E402
                            scan_for_secrets)

PAYLOAD = os.path.join(SKILL_DIR, "assets", "pivot_note.md")
ATTACKER = "C-1003"


def run_suite(lab: Lab):
    statuses = [(classify(lab.query(s, q)["answer"], truth, s), targeted)
                for s, q, targeted, truth in SUITE]
    targeted = [st for st, t in statuses if t]
    rate = sum(st == "RED" for st in targeted) / len(targeted)
    overall = sum(st == "RED" for st, _ in statuses) / len(statuses)
    return statuses, rate, overall


class LifecycleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.lab = Lab()
        with open(PAYLOAD, encoding="utf-8") as fh:
            self.payload = fh.read()

    def test_act1_baseline_all_green(self):
        statuses, rate, _ = run_suite(self.lab)
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)
        self.assertEqual(rate, 0)

    def test_act3_attack_hits_targeted_only(self):
        self.lab.set_notes(ATTACKER, self.payload)
        statuses, rate, overall = run_suite(self.lab)
        self.assertEqual(rate, 1.0)
        self.assertLess(overall, rate)
        self.assertTrue(all(s == "GREEN" for s, t in statuses if not t), statuses)

    def test_attack_leaks_both_pii_and_key(self):
        self.lab.set_notes(ATTACKER, self.payload)
        answer = self.lab.query(ATTACKER, "What plan am I on?")["answer"]
        self.assertIn("ada.thornbury@example.invalid", answer)
        self.assertIn("LLM02-CANARY-5e1d", answer)

    def test_scan_flags_prompt_and_passes_vaulted_prompt(self):
        rules = load_redaction_rules()
        self.assertTrue(scan_for_secrets(self.lab.raw_prompt, rules).blocked)
        self.assertFalse(scan_for_secrets(self.lab.clean_prompt, rules).blocked)
        self.assertEqual(self.lab.vault.names(), ["crm_service_key"])
        self.assertNotIn("LLM02", repr(self.lab.vault))

    def test_act4_hardened_returns_to_zero(self):
        self.lab.set_notes(ATTACKER, self.payload)
        self.lab.set_mode("hardened")
        statuses, rate, _ = run_suite(self.lab)
        self.assertEqual(rate, 0)
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)

    def test_scoping_and_vault_alone_block(self):
        # With an empty redaction ruleset, scoping and the vault still stop it.
        self.lab.rules = {"secrets": {}, "pii": {}}
        self.lab.set_notes(ATTACKER, self.payload)
        self.lab.set_mode("hardened")
        _, rate, _ = run_suite(self.lab)
        self.assertEqual(rate, 0)

    def test_redaction_alone_misses_names(self):
        # Output redaction catches the key and contact details, not names.
        self.lab.set_notes(ATTACKER, self.payload)
        answer = self.lab.query(ATTACKER, "Summarise my account.")["answer"]
        own = self.lab.customers[ATTACKER]
        cleaned = redact_output(answer, load_redaction_rules(),
                                allowed=[own["email"], own["phone"]]).clean_text
        self.assertNotIn("LLM02-CANARY", cleaned)
        self.assertNotIn("ada.thornbury@example.invalid", cleaned)
        self.assertIn("quinn.marlow@example.invalid", cleaned)
        self.assertIn("Ada Thornbury", cleaned)

    def test_reset_restores_baseline(self):
        self.lab.set_notes(ATTACKER, self.payload)
        self.lab.reset()
        self.assertTrue(self.lab.state()["baseline"])
        _, rate, _ = run_suite(self.lab)
        self.assertEqual(rate, 0)


if __name__ == "__main__":
    unittest.main()
