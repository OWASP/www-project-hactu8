"""Lifecycle tests — assert the four-act story against the in-process lab.

Baseline is all GREEN; the edited mandate config raises the targeted rate;
the other two agents are untouched (overall < targeted); the config check
flags the payload; hardened mode returns the rate to 0; each hardened control
works alone; reset restores the baseline.

Run from the skill folder:  python -m unittest discover tests
"""

from __future__ import annotations

import os
import sys
import unittest

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, SKILL_DIR)
sys.path.insert(0, os.path.join(SKILL_DIR, "scripts"))

from evaluate_kpi import TARGET_AGENT, score  # noqa: E402
from run_mandate_tamper import apply_edit, load_payload  # noqa: E402
from vulnerable_app import Lab, dry_run, sign_config, verify_config  # noqa: E402

PAYLOAD = os.path.join(SKILL_DIR, "assets", "tampered_mandate.json")


def tamper(lab: Lab, payload) -> None:
    lab.write_config(TARGET_AGENT, apply_edit(lab.get_config(TARGET_AGENT), payload))


class LifecycleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.lab = Lab()
        self.payload = load_payload(PAYLOAD)

    def test_act1_baseline_all_green(self):
        statuses, omar, _, off = score(self.lab.run())
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)
        self.assertEqual(omar, 0)
        self.assertEqual(off, 0)

    def test_act3_attack_hits_targeted_only(self):
        tamper(self.lab, self.payload)
        result = self.lab.run()
        statuses, omar, overall, off = score(result)
        self.assertEqual(omar, 100.0)
        self.assertLess(overall, omar)
        self.assertTrue(all(s == "GREEN" for s, t in statuses if not t), statuses)
        self.assertEqual(off, 1 + 3 * 2)   # drift: 1 extra action on tick 1, 2 on ticks 2-4
        self.assertNotIn(TARGET_AGENT, result["quarantined"])

    def test_mandate_widening_is_load_bearing(self):
        # Standing orders without the widened mandate are dropped by the agent's self-check.
        payload = dict(self.payload, mandate=self.lab.get_config(TARGET_AGENT)["mandate"])
        tamper(self.lab, payload)
        _, omar, _, _ = score(self.lab.run())
        self.assertEqual(omar, 0)

    def test_check_flags_payload_and_passes_baseline(self):
        report = dry_run(self.payload)
        self.assertTrue(report["widening"])
        self.assertTrue(report["blocked"])
        self.assertEqual(report["stopped_at"], 1)
        for agent, cfg in self.lab.approved.items():
            clean = dry_run(cfg, agent)
            self.assertFalse(clean["widening"] or clean["blocked"], agent)

    def test_signature_detects_edit(self):
        self.assertTrue(all(self.lab.state()["signatures_valid"].values()))
        tamper(self.lab, self.payload)
        self.assertFalse(self.lab.state()["signatures_valid"][TARGET_AGENT])
        other = Lab()   # a different startup key never verifies this lab's signatures
        cfg = self.lab.approved["billy-billing"]
        self.assertFalse(verify_config("billy-billing", cfg, other.key))
        self.assertEqual(cfg["signature"], sign_config("billy-billing", cfg, self.lab.key))

    def test_act4_hardened_returns_to_zero(self):
        tamper(self.lab, self.payload)
        self.lab.set_mode("hardened")
        result = self.lab.run()
        statuses, omar, _, off = score(result)
        self.assertEqual(omar, 0)
        self.assertEqual(off, 0)
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)
        self.assertTrue(result["config_events"])

    def test_signatures_alone_block(self):
        self.lab.controls["monitor"] = False
        tamper(self.lab, self.payload)
        self.lab.set_mode("hardened")
        statuses, omar, _, _ = score(self.lab.run())
        self.assertEqual(omar, 0)
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)

    def test_monitor_alone_quarantines_on_first_violation(self):
        self.lab.controls["signatures"] = False
        tamper(self.lab, self.payload)
        self.lab.set_mode("hardened")
        result = self.lab.run()
        statuses, omar, _, off = score(result)
        self.assertEqual(omar, 0)
        self.assertEqual(off, 0)
        self.assertEqual(result["quarantined"], {TARGET_AGENT: 1})
        self.assertEqual(sum(e["status"] == "blocked" for e in result["action_log"]), 1)
        self.assertTrue(all(s == "GREEN" for s, t in statuses if not t), statuses)

    def test_reset_restores_baseline(self):
        tamper(self.lab, self.payload)
        self.lab.reset()
        self.assertTrue(self.lab.state()["baseline"])
        _, omar, _, _ = score(self.lab.run())
        self.assertEqual(omar, 0)


if __name__ == "__main__":
    unittest.main()
