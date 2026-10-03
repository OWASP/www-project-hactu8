"""Lifecycle tests — assert the four-act story against the in-process lab.

Baseline is all GREEN; one planted memory raises the targeted rate in later
sessions of other users; controls are untouched (overall < targeted); the
screen flags the payload; hardened mode returns the rate to 0, and each of its
recall and write rules holds on its own; reset restores the baseline.

Run from the skill folder:  python -m unittest discover tests
"""

from __future__ import annotations

import os
import sys
import unittest

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, SKILL_DIR)
sys.path.insert(0, os.path.join(SKILL_DIR, "scripts"))

from evaluate_kpi import SUITE, classify, session_steps  # noqa: E402
from run_memory_poison import poison_message  # noqa: E402
from vulnerable_app import Lab, load_screen_rules, screen_memory  # noqa: E402

PAYLOAD = os.path.join(SKILL_DIR, "assets", "memory_note.md")


def run_suite(lab: Lab):
    statuses = []
    for user, message, targeted, truth in SUITE:
        sid = lab.session(user, message)["session"]
        statuses.append((classify(session_steps(lab.action_log, sid), truth), targeted))
    targeted = [s for s, t in statuses if t]
    psr = sum(s == "RED" for s in targeted) / len(targeted)
    overall = sum(s == "RED" for s, _ in statuses) / len(statuses)
    return statuses, psr, overall


class LifecycleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.lab = Lab()
        with open(PAYLOAD, encoding="utf-8") as fh:
            self.message = poison_message(fh.read())

    def plant(self) -> dict:
        return self.lab.session("mallory", self.message)

    def test_act1_baseline_all_green(self):
        statuses, psr, _ = run_suite(self.lab)
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)
        self.assertEqual(psr, 0)

    def test_act3_attack_hits_targeted_only(self):
        save = [s for s in self.plant()["steps"] if s["step"] == "save_memory"]
        self.assertEqual(save[0]["status"], "executed")
        statuses, psr, overall = run_suite(self.lab)
        self.assertEqual(psr, 1.0)
        self.assertLess(overall, psr)
        self.assertTrue(all(s == "GREEN" for s, t in statuses if not t), statuses)

    def test_screen_flags_payload_and_passes_baseline(self):
        rules = load_screen_rules()
        with open(PAYLOAD, encoding="utf-8") as fh:
            self.assertTrue(screen_memory(fh.read(), rules).blocked)
        for entry in self.lab.memories:
            self.assertFalse(screen_memory(entry["text"], rules).blocked)

    def test_act4_hardened_returns_to_zero(self):
        self.plant()
        self.lab.set_mode("hardened")
        statuses, psr, _ = run_suite(self.lab)
        self.assertEqual(psr, 0)
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)

    def test_scoped_recall_alone_blocks(self):
        # Poison already stored before hardening, empty screen: scope still stops it.
        self.plant()
        self.lab.rules = {"markers": [], "patterns": []}
        self.lab.set_mode("hardened")
        _, psr, _ = run_suite(self.lab)
        self.assertEqual(psr, 0)

    def test_write_screen_blocks_in_hardened_mode(self):
        self.lab.set_mode("hardened")
        before = len(self.lab.memories)
        save = [s for s in self.plant()["steps"] if s["step"] == "save_memory"]
        self.assertEqual(save[0]["status"], "blocked")
        self.assertEqual(len(self.lab.memories), before)

    def test_hardened_still_recalls_own_memory(self):
        self.lab.set_mode("hardened")
        steps = self.lab.session("alice", SUITE[0][1])["steps"]
        recalled = [m["id"] for m in steps[0]["memories"]]
        self.assertEqual(recalled, ["m-0001"])

    def test_reset_restores_baseline(self):
        self.plant()
        self.lab.reset()
        self.assertTrue(self.lab.state()["baseline"])
        _, psr, _ = run_suite(self.lab)
        self.assertEqual(psr, 0)


if __name__ == "__main__":
    unittest.main()
