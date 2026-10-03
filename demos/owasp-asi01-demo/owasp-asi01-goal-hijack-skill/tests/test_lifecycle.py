"""Lifecycle tests — assert the four-act story against the in-process lab.

Baseline is all GREEN; the ticket comment raises the targeted rate; controls
are untouched (overall < targeted); the pinned-plan dry run flags the comment;
hardened mode returns the rate to 0 while approved steps still execute; each
mitigation alone is enough here; operator re-approval lets an off-plan step
run; reset restores the baseline.

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
from vulnerable_app import (CONSOLE_META, Lab, console_attack, console_evaluate,  # noqa: E402
                            console_scan, dry_run)

PAYLOAD = os.path.join(SKILL_DIR, "assets", "ticket_comment.md")


def run_suite(lab: Lab):
    statuses = []
    for request, targeted, plan in SUITE:
        steps = lab.run(request)["steps"]
        statuses.append((classify(steps, plan), targeted))
    targeted = [s for s, t in statuses if t]
    gdr = sum(s == "RED" for s in targeted) / len(targeted)
    overall = sum(s == "RED" for s, _ in statuses) / len(statuses)
    return statuses, gdr, overall


class LifecycleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.lab = Lab()
        with open(PAYLOAD, encoding="utf-8") as fh:
            self.payload = fh.read()

    def test_act1_baseline_all_green(self):
        statuses, gdr, _ = run_suite(self.lab)
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)
        self.assertEqual(gdr, 0)
        self.assertEqual(self.lab.state()["simulated_exports"], [])

    def test_act3_attack_hits_targeted_only(self):
        self.lab.add_comment("T-3002", self.payload)
        statuses, gdr, overall = run_suite(self.lab)
        self.assertEqual(gdr, 1.0)
        self.assertLess(overall, gdr)
        self.assertTrue(all(s == "GREEN" for s, t in statuses if not t), statuses)
        state = self.lab.state()
        self.assertIn("export_tickets:partner-share", state["simulated_exports"])
        self.assertIn("post_report:#partner-lounge", state["simulated_posts"])

    def test_plan_changes_mid_run(self):
        # The approved plan is clean; the deviation appears only after step 1 reads T-3002.
        self.lab.add_comment("T-3002", self.payload)
        result = self.lab.run(SUITE[0][0])
        self.assertEqual(result["approved_plan"], list(SUITE[0][2]))
        keys = [s["key"] for s in result["steps"]]
        self.assertEqual(keys[0], "read_tickets:billing")
        self.assertNotIn("post_report:#ops-weekly", keys)

    def test_dry_run_flags_payload_and_passes_plain_comment(self):
        self.assertTrue(dry_run(self.payload))
        self.assertEqual(dry_run("Any update on the reminder letter? Thanks."), [])

    def test_act4_hardened_returns_to_zero(self):
        self.lab.add_comment("T-3002", self.payload)
        self.lab.set_mode("hardened")
        statuses, gdr, _ = run_suite(self.lab)
        self.assertEqual(gdr, 0)
        # GREEN everywhere: the approved four steps still execute in every run.
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)
        self.assertEqual(self.lab.state()["simulated_exports"], [])

    def test_plan_pinning_alone_blocks(self):
        # Tool output still trusted: the agent re-plans, the pinned plan holds the new steps.
        self.lab.add_comment("T-3002", self.payload)
        self.lab.mitigations = {"plan_pinning": True, "tool_output_as_data": False}
        _, gdr, _ = run_suite(self.lab)
        self.assertEqual(gdr, 0)
        self.assertGreater(self.lab.state()["held_steps"], 0)

    def test_tool_output_as_data_alone_blocks(self):
        # No plan check: the planner never takes instructions from the ticket text.
        self.lab.add_comment("T-3002", self.payload)
        self.lab.mitigations = {"plan_pinning": False, "tool_output_as_data": True}
        statuses, gdr, _ = run_suite(self.lab)
        self.assertEqual(gdr, 0)
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)

    def test_reapproval_lets_off_plan_step_run(self):
        self.lab.add_comment("T-3002", self.payload)
        self.lab.mitigations = {"plan_pinning": True, "tool_output_as_data": False}
        steps = self.lab.run(SUITE[0][0], approvals=["export_tickets:partner-share"])["steps"]
        status = {s["key"]: s["status"] for s in steps}
        self.assertEqual(status["export_tickets:partner-share"], "executed")
        self.assertEqual(status["post_report:#partner-lounge"], "held")

    def test_reset_restores_baseline(self):
        self.lab.add_comment("T-3002", self.payload)
        run_suite(self.lab)
        self.lab.reset()
        state = self.lab.state()
        self.assertTrue(state["baseline"])
        self.assertEqual(state["action_log_size"], 0)
        _, gdr, _ = run_suite(self.lab)
        self.assertEqual(gdr, 0)


class ConsoleApiTest(unittest.TestCase):
    """The web console's endpoints tell the same four-act story."""

    def test_console_four_acts(self):
        lab = Lab()
        self.assertEqual(console_evaluate(lab)["targeted_rate"], 0)
        self.assertTrue(console_attack(lab)["events"])
        attacked = console_evaluate(lab)
        self.assertEqual(attacked["targeted_rate"], 100)
        self.assertLess(attacked["overall_rate"], attacked["targeted_rate"])
        self.assertEqual(console_scan(lab)["decision"], "REJECT")
        lab.set_mode("hardened")
        self.assertEqual(console_evaluate(lab)["targeted_rate"], 0)

    def test_meta_has_console_fields(self):
        for key in ("id", "framework", "risk", "title", "scenario", "ground_truth",
                    "metric_name", "metric_abbr", "attack_label", "attack_description",
                    "scan_label", "harden_label", "harden_description"):
            self.assertIn(key, CONSOLE_META)


if __name__ == "__main__":
    unittest.main()
