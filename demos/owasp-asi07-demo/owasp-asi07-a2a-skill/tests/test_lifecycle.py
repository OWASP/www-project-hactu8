"""Lifecycle tests — assert the four-act story against the in-process lab.

Baseline is all GREEN; the spoofed and replayed work orders raise the targeted
rate; controls are untouched (overall < targeted); the verification dry run
flags the payload; hardened mode returns the rate to 0 while genuine planner
orders still execute; signatures alone miss the replay and replay checks alone
miss the spoof; reset restores the baseline.

Run from the skill folder:  python -m unittest discover tests
"""

from __future__ import annotations

import os
import secrets
import sys
import unittest

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, SKILL_DIR)
sys.path.insert(0, os.path.join(SKILL_DIR, "scripts"))

from evaluate_kpi import SUITE, classify  # noqa: E402
from run_bus_forgery import find_replayable  # noqa: E402
from vulnerable_app import Lab, dry_run  # noqa: E402

PAYLOAD = os.path.join(SKILL_DIR, "assets", "forged_order.md")
SIGNED = ("sender", "recipient", "topic", "kind", "body", "ts", "nonce", "sig")


def run_suite(lab: Lab):
    statuses = []
    for request, topic, targeted, intended in SUITE:
        calls = lab.run(request, topic)["tool_calls"]
        statuses.append((classify(calls, intended), targeted))
    targeted = [s for s, t in statuses if t]
    rate = sum(s == "RED" for s in targeted) / len(targeted)
    overall = sum(s == "RED" for s, _ in statuses) / len(statuses)
    return statuses, rate, overall


def attack(lab: Lab, payload: str) -> None:
    """The same two moves as scripts/run_bus_forgery.py, in process."""
    for topic in ("payments", "inventory"):
        lab.publish({"sender": "planner", "recipient": "executor", "topic": topic,
                     "kind": "work_order", "body": payload, "ts": lab.clock(),
                     "nonce": secrets.token_hex(8), "sig": ""}, retain=True)
    old = find_replayable(lab.bus_view(), "refunds")
    lab.publish({k: old[k] for k in SIGNED}, retain=True)


class LifecycleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.lab = Lab()
        with open(PAYLOAD, encoding="utf-8") as fh:
            self.payload = fh.read()

    def test_act1_baseline_all_green(self):
        statuses, rate, _ = run_suite(self.lab)
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)
        self.assertEqual(rate, 0)
        self.assertEqual(self.lab.state()["simulated_cancellations"], [])

    def test_act3_attack_hits_targeted_only(self):
        attack(self.lab, self.payload)
        statuses, rate, overall = run_suite(self.lab)
        self.assertEqual(rate, 1.0)
        self.assertLess(overall, rate)
        self.assertTrue(all(s == "GREEN" for s, t in statuses if not t), statuses)
        state = self.lab.state()
        self.assertIn("pay_invoice:INV-3999", state["simulated_payments"])
        self.assertIn("issue_refund:A-0907", state["simulated_refunds"])

    def test_dry_run_flags_payload_and_passes_plain_message(self):
        self.assertTrue(dry_run(self.payload))
        self.assertEqual(dry_run("Status: the warehouse closes early on Friday."), [])

    def test_act4_hardened_returns_to_zero(self):
        attack(self.lab, self.payload)
        self.lab.set_mode("hardened")
        statuses, rate, _ = run_suite(self.lab)
        self.assertEqual(rate, 0)
        # GREEN everywhere: the planner's genuine signed orders still execute.
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)
        self.assertEqual(self.lab.state()["simulated_cancellations"], [])
        self.assertGreater(self.lab.state()["rejected_messages"], 0)

    def test_signature_alone_misses_replay(self):
        # A replayed message carries a genuine signature: only refunds stays RED.
        self.lab.policy = dict(self.lab.policy, replay_protection=False)
        attack(self.lab, self.payload)
        self.lab.set_mode("hardened")
        statuses, rate, _ = run_suite(self.lab)
        self.assertAlmostEqual(rate, 1 / 3)
        self.assertEqual(statuses[1][0], "RED")

    def test_replay_checks_alone_miss_spoof(self):
        # Fresh timestamp and nonce, no signature check: the spoof gets through.
        self.lab.policy = dict(self.lab.policy, verify_signature=False)
        attack(self.lab, self.payload)
        self.lab.set_mode("hardened")
        statuses, rate, _ = run_suite(self.lab)
        self.assertAlmostEqual(rate, 2 / 3)
        self.assertEqual(statuses[1][0], "GREEN")

    def test_nonce_alone_blocks_replay(self):
        # No time window at all: the nonce cache still recognises the old order.
        self.lab.policy = dict(self.lab.policy, max_age_seconds=None)
        attack(self.lab, self.payload)
        self.lab.set_mode("hardened")
        _, rate, _ = run_suite(self.lab)
        self.assertEqual(rate, 0)

    def test_reset_restores_baseline(self):
        attack(self.lab, self.payload)
        run_suite(self.lab)
        self.lab.reset()
        state = self.lab.state()
        self.assertTrue(state["baseline"])
        self.assertEqual(state["action_log_size"], 0)
        _, rate, _ = run_suite(self.lab)
        self.assertEqual(rate, 0)


if __name__ == "__main__":
    unittest.main()
