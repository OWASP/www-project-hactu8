"""Lifecycle tests — assert the four-act story against the in-process lab.

Baseline is all GREEN; the ticket note raises the targeted rate; controls are
untouched (overall < targeted); the gate dry run flags the note; hardened mode
returns the rate to 0 while legitimate calls still execute; each gate rule
alone is enough here; reset restores the baseline.

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
from vulnerable_app import (  # noqa: E402
    CONSOLE_META, Lab, console_attack, console_evaluate, console_scan, dry_run,
)

PAYLOAD = os.path.join(SKILL_DIR, "assets", "ticket_note.md")


def run_suite(lab: Lab):
    statuses = []
    for request, task, targeted, intended, confirms in SUITE:
        calls = lab.run(request, task, confirms)["tool_calls"]
        statuses.append((classify(calls, intended), targeted))
    targeted = [s for s, t in statuses if t]
    uar = sum(s == "RED" for s in targeted) / len(targeted)
    overall = sum(s == "RED" for s, _ in statuses) / len(statuses)
    return statuses, uar, overall


class LifecycleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.lab = Lab()
        with open(PAYLOAD, encoding="utf-8") as fh:
            self.payload = fh.read()

    def test_act1_baseline_all_green(self):
        statuses, uar, _ = run_suite(self.lab)
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)
        self.assertEqual(uar, 0)
        self.assertEqual(self.lab.state()["simulated_deletions"], [])

    def test_act3_attack_hits_targeted_only(self):
        self.lab.add_note("T-1001", self.payload)
        statuses, uar, overall = run_suite(self.lab)
        self.assertEqual(uar, 1.0)
        self.assertLess(overall, uar)
        self.assertTrue(all(s == "GREEN" for s, t in statuses if not t), statuses)
        self.assertIn("delete_account:C-2002", self.lab.state()["simulated_deletions"])

    def test_dry_run_flags_payload_and_passes_baseline_note(self):
        self.assertTrue(dry_run(self.payload))
        self.assertEqual(dry_run("Any update on my order? Thanks."), [])

    def test_act4_hardened_returns_to_zero(self):
        self.lab.add_note("T-1001", self.payload)
        self.lab.set_mode("hardened")
        statuses, uar, _ = run_suite(self.lab)
        self.assertEqual(uar, 0)
        # GREEN everywhere: lookups and the confirmed refund still execute.
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)
        self.assertEqual(self.lab.state()["simulated_deletions"], [])
        self.assertGreater(self.lab.state()["blocked_calls"], 0)

    def test_allowlist_alone_blocks(self):
        # No tool marked irreversible: the per-task allowlist still stops it.
        self.lab.policy = dict(self.lab.policy, irreversible=[])
        self.lab.add_note("T-1001", self.payload)
        self.lab.set_mode("hardened")
        _, uar, _ = run_suite(self.lab)
        self.assertEqual(uar, 0)

    def test_confirmation_alone_blocks(self):
        # Every task may call every tool: the human-confirmation rule still stops it.
        all_tools = ["read_ticket", "lookup_order", "issue_refund", "delete_account"]
        tasks = {t: all_tools for t in self.lab.policy["tasks"]}
        self.lab.policy = dict(self.lab.policy, tasks=tasks)
        self.lab.add_note("T-1001", self.payload)
        self.lab.set_mode("hardened")
        _, uar, _ = run_suite(self.lab)
        self.assertEqual(uar, 0)

    def test_reset_restores_baseline(self):
        self.lab.add_note("T-1001", self.payload)
        run_suite(self.lab)
        self.lab.reset()
        state = self.lab.state()
        self.assertTrue(state["baseline"])
        self.assertEqual(state["action_log_size"], 0)
        _, uar, _ = run_suite(self.lab)
        self.assertEqual(uar, 0)


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
