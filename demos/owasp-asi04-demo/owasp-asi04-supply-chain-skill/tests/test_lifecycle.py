"""Lifecycle tests — assert the four-act story against the in-process lab.

Baseline is all GREEN; the lookalike skill raises the targeted rate; controls
are untouched (overall < targeted); the manifest check flags the payload and
passes every baseline skill; hardened mode returns the rate to 0 while the
approved skills still load; each control alone is enough here; reset restores
the baseline.

Each test uses its own catalogue file under ``catalogue/`` and deletes it.

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
from run_lookalike_publish import load_payload  # noqa: E402
from vulnerable_app import (CATALOGUE_DIR, CONSOLE_META, Lab,  # noqa: E402
                            console_attack, console_evaluate, console_scan,
                            dry_run, entry_hash, load_baseline, load_manifest)


def run_suite(lab: Lab):
    statuses = [(classify(lab.run(task)["steps"], intended), targeted)
                for task, targeted, intended in SUITE]
    targeted = [s for s, t in statuses if t]
    uclr = sum(s == "RED" for s in targeted) / len(targeted)
    overall = sum(s == "RED" for s, _ in statuses) / len(statuses)
    return statuses, uclr, overall


class LifecycleTest(unittest.TestCase):
    def setUp(self) -> None:
        path = os.path.join(CATALOGUE_DIR, f"test_{os.getpid()}_{self._testMethodName}.json")
        self.lab = Lab(catalogue_path=path)
        self.payload = load_payload()

    def tearDown(self) -> None:
        self.lab.remove_catalogue()

    def test_act1_baseline_all_green(self):
        statuses, uclr, _ = run_suite(self.lab)
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)
        self.assertEqual(uclr, 0)

    def test_act3_attack_hits_targeted_only(self):
        self.lab.publish(self.payload)
        statuses, uclr, overall = run_suite(self.lab)
        self.assertEqual(uclr, 1.0)
        self.assertLess(overall, uclr)
        self.assertTrue(all(s == "GREEN" for s, t in statuses if not t), statuses)
        self.assertIn("expense_report@goatco-finance-community",
                      self.lab.state()["loaded_components"])
        # The loaded skill's instructions steered the step output.
        result = self.lab.run("expense_reminder")["result"]
        self.assertIn("ASI04-CANARY-5e1d", result)

    def test_manifest_matches_baseline_and_flags_payload(self):
        manifest = load_manifest()
        for skill in load_baseline()["skills"]:
            self.assertEqual(entry_hash(skill), manifest[skill["name"]]["sha256"])
            self.assertEqual(dry_run(skill), [])
        findings = dry_run(self.payload)
        self.assertTrue(any("looks like" in f for f in findings), findings)

    def test_act4_hardened_returns_to_zero(self):
        self.lab.publish(self.payload)
        self.lab.set_mode("hardened")
        statuses, uclr, _ = run_suite(self.lab)
        self.assertEqual(uclr, 0)
        # GREEN everywhere: the approved skills still load.
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)
        self.assertNotIn("expense_report@goatco-finance-community",
                         self.lab.state()["loaded_components"])

    def test_exact_name_alone_blocks(self):
        self.lab.publish(self.payload)
        self.lab.exact_names, self.lab.verify_pins = True, False
        _, uclr, _ = run_suite(self.lab)
        self.assertEqual(uclr, 0)

    def test_pins_alone_block(self):
        # Loose resolution still finds the lookalike; the manifest drops it.
        self.lab.publish(self.payload)
        self.lab.exact_names, self.lab.verify_pins = False, True
        statuses, uclr, _ = run_suite(self.lab)
        self.assertEqual(uclr, 0)
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)

    def test_pins_catch_same_name_impostor(self):
        # Exact names alone cannot stop a same-name, higher-version impostor; pins can.
        impostor = dict(self.payload, name="expense-report")
        self.lab.publish(impostor)
        self.lab.exact_names, self.lab.verify_pins = True, False
        _, uclr, _ = run_suite(self.lab)
        self.assertEqual(uclr, 1.0)
        self.lab.set_mode("hardened")
        _, uclr, _ = run_suite(self.lab)
        self.assertEqual(uclr, 0)

    def test_reset_restores_baseline(self):
        self.lab.publish(self.payload)
        run_suite(self.lab)
        self.lab.reset()
        state = self.lab.state()
        self.assertTrue(state["baseline"])
        self.assertEqual(state["action_log_size"], 0)
        _, uclr, _ = run_suite(self.lab)
        self.assertEqual(uclr, 0)


class ConsoleApiTest(unittest.TestCase):
    """The web console's endpoints tell the same four-act story."""

    def test_console_four_acts(self):
        lab = Lab(catalogue_path=os.path.join(CATALOGUE_DIR, f"test_{os.getpid()}_console.json"))
        self.addCleanup(lab.remove_catalogue)
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
