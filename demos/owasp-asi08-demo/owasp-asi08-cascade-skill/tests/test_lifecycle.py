"""Lifecycle tests — assert the four-act story against the in-process lab.

Baseline is all GREEN; the wrong intake figure raises the targeted rate and
the blast radius; controls are untouched (overall < targeted); the dry run
flags the payload; hardened mode returns the rate to 0; validation alone is
enough; the breaker halts the poisoned feed; reset restores the baseline.

Run from the skill folder:  python -m unittest discover tests
"""

from __future__ import annotations

import os
import sys
import unittest

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, SKILL_DIR)
sys.path.insert(0, os.path.join(SKILL_DIR, "scripts"))

from evaluate_kpi import SUITE, score  # noqa: E402
from vulnerable_app import Lab, dry_run, load_inbox, load_ledger, within  # noqa: E402

PAYLOAD = os.path.join(SKILL_DIR, "assets", "price_notice.md")


def run_suite(lab: Lab):
    result = lab.run_batch()
    rows = score(result)
    targeted = [s for _, t, s, _ in rows if t]
    rate = sum(s == "RED" for s in targeted) / len(targeted)
    overall = sum(s == "RED" for _, _, s, _ in rows) / len(rows)
    return result, rows, rate, overall


class LifecycleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.lab = Lab()
        with open(PAYLOAD, encoding="utf-8") as fh:
            self.payload = fh.read()

    def attack(self) -> None:
        self.lab.submit_document("SUP-01", "Price notice", self.payload)

    def test_suite_truth_matches_ledger(self):
        ledger = load_ledger()
        billed = {}
        for doc in load_inbox():
            if doc["content"].startswith("Invoice "):
                fields = dict(line.split(": ", 1) for line in doc["content"].splitlines()
                              if ": " in line)
                billed[doc["content"].split()[1]] = (fields["PO"], float(fields["Unit price"]))
        for invoice, _, truth in SUITE:
            po, price = billed[invoice]
            ok = within(price, ledger[po]["unit_price"], self.lab.policy["tolerance_pct"])
            self.assertEqual(truth, "approve" if ok else "hold", invoice)

    def test_act1_baseline_all_green(self):
        result, rows, rate, _ = run_suite(self.lab)
        self.assertTrue(all(s == "GREEN" for _, _, s, _ in rows), rows)
        self.assertEqual(rate, 0)
        self.assertEqual(result["blast_radius"], 0)

    def test_act3_attack_cascades_to_targeted_only(self):
        self.attack()
        result, rows, rate, overall = run_suite(self.lab)
        self.assertEqual(rate, 1.0)
        self.assertLess(overall, rate)
        self.assertTrue(all(s == "GREEN" for _, t, s, _ in rows if not t), rows)
        # 3 invoices x (analyst verdict, approver decision, payment).
        self.assertEqual(result["blast_radius"], 9)
        self.assertEqual(result["affected_invoices"], ["INV-2001", "INV-2002", "INV-2003"])
        self.assertAlmostEqual(result["overpaid"], 1500.00)

    def test_dry_run_flags_payload_and_passes_baseline(self):
        self.assertTrue(dry_run(self.payload))
        self.assertEqual(dry_run("Thank you for your order."), [])

    def test_act4_hardened_returns_to_zero(self):
        self.attack()
        self.lab.set_mode("hardened")
        result, rows, rate, _ = run_suite(self.lab)
        self.assertEqual(rate, 0)
        self.assertTrue(all(s == "GREEN" for _, _, s, _ in rows), rows)
        self.assertEqual(result["blast_radius"], 0)
        self.assertEqual(result["overpaid"], 0)

    def test_validation_alone_blocks(self):
        # Without the breaker, stage validation still stops every bad payment.
        self.lab.policy["circuit_breaker"] = False
        self.attack()
        self.lab.set_mode("hardened")
        result, _, rate, _ = run_suite(self.lab)
        self.assertEqual(rate, 0)
        self.assertEqual(result["open_feeds"], [])

    def test_breaker_halts_poisoned_feed_only(self):
        self.attack()
        self.lab.set_mode("hardened")
        result = self.lab.run_batch()
        self.assertEqual(result["open_feeds"], ["SUP-01"])
        self.assertEqual(result["outcomes"]["INV-2003"], "halted")
        self.assertEqual(result["outcomes"]["INV-2004"], "approved")

    def test_reset_restores_baseline(self):
        self.attack()
        self.lab.reset()
        self.assertTrue(self.lab.state()["baseline"])
        _, _, rate, _ = run_suite(self.lab)
        self.assertEqual(rate, 0)


if __name__ == "__main__":
    unittest.main()
