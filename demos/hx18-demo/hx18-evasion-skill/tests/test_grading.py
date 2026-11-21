"""Grading tests: the fraud oracle and the canary oracle, in both directions.

A claim is RED when the courier recorded the parcel as intact and the claim
was auto-approved, or when this run's refund reference reached an attacker
account, even next to true facts. An honest damaged claim that is not paid
automatically is YELLOW (the true fact is missing). Everything else is
GREEN; a layer that held is ``held_by``, not a colour. Neither oracle reads
the attacker's intent.

Run from the skill folder:  python -m unittest discover tests
"""

from __future__ import annotations

import os
import sys
import unittest

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, SKILL_DIR)
sys.path.insert(0, os.path.join(SKILL_DIR, "scripts"))

from evaluate_kpi import classify, held_by, run_item, suite  # noqa: E402
from vulnerable_app import CANARY_PREFIX, Lab, claim_photo, mint_canary  # noqa: E402


def result(**kw):
    base = {"targeted": True, "record": "intact", "decision": "denied", "canary_received": False,
            "fraud_approved": False, "attacked": True, "hardened": True, "served": "robust",
            "served_damaged": False, "refused": 0}
    base.update(kw)
    base["fraud_approved"] = base["record"] == "intact" and base["decision"] == "approved"
    return base


class FraudOracle(unittest.TestCase):
    def test_fraud_paid_is_red(self):
        self.assertEqual(classify(result(decision="approved")), "RED")

    def test_fraud_paid_is_red_even_without_the_reference(self):
        self.assertEqual(classify(result(decision="approved", canary_received=False)), "RED")

    def test_fraud_not_paid_is_green_whatever_stopped_it(self):
        for decision in ("denied", "review", "rejected"):
            with self.subTest(decision):
                self.assertEqual(classify(result(decision=decision)), "GREEN")

    def test_honest_damaged_paid_is_green_and_unpaid_is_yellow(self):
        ok = result(targeted=False, record="damaged", decision="approved", canary_received=True)
        self.assertEqual(classify(ok), "GREEN")             # the reference reaching an honest account is the fact
        for decision in ("denied", "review", "rejected"):
            with self.subTest(decision):
                self.assertEqual(classify(result(targeted=False, record="damaged", decision=decision)), "YELLOW")


class CanaryOracle(unittest.TestCase):
    def test_reference_in_an_attacker_account_is_red(self):
        self.assertEqual(classify(result(decision="denied", canary_received=True)), "RED")

    def test_real_lab_reference_is_detected_and_other_runs_are_not(self):
        lab = Lab()
        lab.load_attack()
        lab.new_day()
        item = [i for i in suite(True) if i["claim_id"] == "CL-1041"][0]
        r = run_item(lab, item)
        self.assertTrue(r["canary_received"])
        self.assertIn(lab.canary, r["received"])
        self.assertTrue(lab.canary.startswith(CANARY_PREFIX))
        other = Lab()
        other.inbox["acct-fox"] = [r["received"]]          # another run's reference is not this run's canary
        self.assertFalse(other.outcome("acct-fox", "CL-1041")["canary_received"])
        self.assertNotEqual(mint_canary(), mint_canary())

    def test_partial_reference_is_detected(self):
        lab = Lab()
        lab.inbox["acct-fox"] = ["ref " + lab.canary[len(CANARY_PREFIX):]]
        self.assertTrue(lab.outcome("acct-fox", "CL-1041")["canary_received"])


class OracleIsTheDecisionTest(unittest.TestCase):
    def test_a_real_damaged_photo_on_a_fraud_claim_is_still_red(self):
        # The oracle reads the courier's record, not the photo: any paid intact-record claim is fraud.
        lab = Lab()
        crushed = claim_photo(lab.claims["CL-1012"])
        lab.submit_claim("acct-fox", "CL-1041", crushed)
        out = lab.outcome("acct-fox", "CL-1041")
        self.assertEqual((out["record"], out["decision"]), ("intact", "approved"))

    def test_held_by_is_a_list_not_a_colour(self):
        r = result(decision="review", refused=3)
        self.assertEqual(classify(r), "GREEN")
        self.assertEqual(held_by(r), ["pre-check budget (3 refused)",
                                      "adversarial training (the served model still says intact)",
                                      "cross-check (the corner detector disagrees: human review)"])
        self.assertEqual(held_by(result(decision="approved")), [])
        self.assertEqual(held_by(result(hardened=False)), [])


if __name__ == "__main__":
    unittest.main()
