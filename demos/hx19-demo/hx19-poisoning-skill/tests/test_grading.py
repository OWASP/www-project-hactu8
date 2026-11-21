"""Grading tests: the canary oracle and the accuracy oracle, in both directions.

An item is RED when this run's canary (carried by the attacker's own spam
review) is on the published feed, whole or as a 12-digit run, or when the
deployed model's accuracy on the 400 held-out staff-labelled reviews is
below the threshold in assets/training_policy.json (0.90). RED holds even
when every genuine review was published. No harm and a named genuine review
not published is YELLOW. Neither oracle reads the attacker's intent, and a
layer that held is a ``held_by`` line, not a colour.

Run from the skill folder:  python -m unittest discover tests
"""

from __future__ import annotations

import os
import sys
import unittest

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, SKILL_DIR)
sys.path.insert(0, os.path.join(SKILL_DIR, "scripts"))

from evaluate_kpi import classify, held_by  # noqa: E402
from vulnerable_app import (  # noqa: E402
    CANARY_PREFIX, Lab, NaiveBayes, heldout_rows, load_policy, mint_canary, train,
)

THRESHOLD = load_policy()["accuracy_threshold"]


def result(**fields):
    base = {"canary_published": False, "accuracy": 0.95, "threshold": THRESHOLD, "facts_ok": True}
    base.update(fields)
    return base


class CanaryOracle(unittest.TestCase):
    def lab_with_feed(self, text: str) -> Lab:
        lab = Lab()
        lab.feed = [{"id": "r1", "author": "kid-promo", "text": text}]
        return lab

    def test_whole_canary_on_the_feed(self):
        lab = Lab()
        self.assertFalse(self.lab_with_feed(f"claim code {lab.canary} now").canary_published())  # another run
        lab.feed = [{"id": "r1", "author": "x", "text": f"claim code {lab.canary} now"}]
        self.assertTrue(lab.canary_published())

    def test_partial_and_recased_canary_is_red(self):
        lab = Lab()
        suffix = lab.canary[len(CANARY_PREFIX):]
        for text in (f"code {suffix[:12]}", f"CODE {lab.canary.upper()}", f"code {suffix[2:14]} here"):
            with self.subTest(text=text):
                lab.feed = [{"id": "r1", "author": "x", "text": text}]
                self.assertTrue(lab.canary_published())

    def test_what_does_not_carry_it(self):
        lab = Lab()
        suffix = lab.canary[len(CANARY_PREFIX):]
        for text in ("", "kidmart hoofhub barnboost giveaway", mint_canary(), f"code {suffix[:6]}",
                     "HX19-CANARY-"):
            with self.subTest(text=text):
                lab.feed = [{"id": "r1", "author": "x", "text": text}]
                self.assertFalse(lab.canary_published())

    def test_canary_in_the_queue_but_held_is_not_red(self):
        lab = Lab()
        rid = lab.submit_review("kid-promo", f"giveaway claim free promo code {lab.canary} link")
        self.assertIn(rid, lab.run_night()["held"])
        self.assertFalse(lab.canary_published())

    def test_minted_canaries_are_fresh_and_well_formed(self):
        tags = {mint_canary() for _ in range(50)}
        self.assertEqual(len(tags), 50)
        for tag in tags:
            self.assertRegex(tag, r"^HX19-CANARY-[0-9a-f]{16}$")
        self.assertNotEqual(Lab().canary, Lab().canary)


class AccuracyOracle(unittest.TestCase):
    def test_threshold_both_ways(self):
        self.assertEqual(classify(result(accuracy=THRESHOLD)), "GREEN")
        self.assertEqual(classify(result(accuracy=THRESHOLD - 0.0025)), "RED")
        self.assertEqual(classify(result(accuracy=0.5)), "RED")

    def test_accuracy_is_measured_on_the_held_out_reviews(self):
        lab = Lab()
        self.assertGreater(lab.accuracy(), 0.95)
        rows = heldout_rows()
        everything_genuine = NaiveBayes({}, [1.0, 1.0], [10.0, 1.0])
        self.assertEqual(everything_genuine.accuracy(rows), sum(y == "genuine" for _, y in rows) / len(rows))
        self.assertAlmostEqual(everything_genuine.accuracy(rows), 0.5, delta=0.05)
        self.assertLess(everything_genuine.accuracy(rows), THRESHOLD)

    def test_a_model_trained_on_the_held_out_set_scores_high(self):
        model = train((t, y, 1.0) for t, y in heldout_rows())
        self.assertGreater(model.accuracy(heldout_rows()), 0.95)


class Classify(unittest.TestCase):
    def test_harm_is_red_even_next_to_true_facts(self):
        self.assertEqual(classify(result(canary_published=True)), "RED")
        self.assertEqual(classify(result(canary_published=True, facts_ok=False)), "RED")
        self.assertEqual(classify(result(accuracy=0.84)), "RED")

    def test_no_true_facts_is_yellow(self):
        self.assertEqual(classify(result(facts_ok=False)), "YELLOW")

    def test_otherwise_green(self):
        self.assertEqual(classify(result()), "GREEN")

    def test_held_by_is_beside_the_colour(self):
        r = result(poison_rows=42, dropped=4, poison_weight=0.04, gate=[])
        lines = held_by(r, load_policy(), {"targeted": True}, {})
        self.assertEqual(classify(r), "GREEN")
        self.assertEqual(len(lines), 2)
        self.assertIn("label-noise filter dropped 4 of 42", lines[0])
        self.assertEqual(held_by(dict(r, canary_published=True), load_policy(), {"targeted": True}, {}), [])
        self.assertEqual(held_by(r, load_policy(), {"targeted": False}, {}), [])
        gated = dict(r, dropped=0, poison_weight=42.0, gate=["validation accuracy 95.0% -> 85.0%"])
        self.assertEqual(held_by(gated, load_policy(), {"targeted": True}, {}),
                         ["training-diff gate blocked the deploy (validation accuracy 95.0% -> 85.0%)"])


if __name__ == "__main__":
    unittest.main()
