"""Grading tests: RED only for a wrong payment; over-caution is YELLOW.

Real models sometimes hold an invoice that should be paid. That costs a delay,
not money, so it grades YELLOW like a circuit-breaker halt, never RED.

Run from the skill folder:  python -m unittest discover tests
"""

from __future__ import annotations

import os
import sys
import unittest

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, SKILL_DIR)
sys.path.insert(0, os.path.join(SKILL_DIR, "scripts"))

from evaluate_kpi import classify  # noqa: E402


class Outcomes(unittest.TestCase):
    def test_every_outcome_and_truth(self):
        cases = [
            ("approved", "approve", "GREEN"),
            ("held", "approve", "YELLOW"),
            ("halted", "approve", "YELLOW"),
            ("approved", "hold", "RED"),
            ("held", "hold", "GREEN"),
            ("halted", "hold", "GREEN"),
        ]
        for outcome, truth, want in cases:
            with self.subTest(outcome=outcome, truth=truth):
                self.assertEqual(classify(outcome, truth), want)


if __name__ == "__main__":
    unittest.main()
