"""Lifecycle tests — assert the four-act story against the in-process lab.

Baseline is all GREEN; the attacker's requests raise the targeted rate;
controls are untouched (overall < targeted); the access-review dry run flags
the requests; hardened mode returns the rate to 0 while entitled callers still
get their documents; each control alone leaves one path open, so both are
needed; tokens are random per lab; reset restores the baseline.

Run from the skill folder:  python -m unittest discover tests
"""

from __future__ import annotations

import json
import os
import sys
import unittest

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, SKILL_DIR)
sys.path.insert(0, os.path.join(SKILL_DIR, "scripts"))

from evaluate_kpi import SUITE, classify  # noqa: E402
from vulnerable_app import (  # noqa: E402
    CONSOLE_META, Lab, console_attack, console_evaluate, console_scan, dry_run,
    submit_payload,
)

PAYLOAD = os.path.join(SKILL_DIR, "assets", "requests.json")


def run_suite(lab: Lab):
    actions = lab.run()["actions"]
    statuses = [(classify(actions, caller, doc, ent), targeted)
                for _, caller, doc, targeted, ent in SUITE]
    targeted = [s for s, t in statuses if t]
    per = sum(s == "RED" for s in targeted) / len(targeted)
    overall = sum(s == "RED" for s, _ in statuses) / len(statuses)
    return statuses, per, overall


class LifecycleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.lab = Lab()
        with open(PAYLOAD, encoding="utf-8") as fh:
            self.payload = json.load(fh)

    def test_act1_baseline_all_green(self):
        statuses, per, _ = run_suite(self.lab)
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)
        self.assertEqual(per, 0)
        self.assertEqual(self.lab.state()["unentitled_releases"], [])

    def test_act3_attack_hits_targeted_only(self):
        submit_payload(self.lab, self.payload)
        statuses, per, overall = run_suite(self.lab)
        self.assertEqual(per, 1.0)
        self.assertLess(overall, per)
        self.assertTrue(all(s == "GREEN" for s, t in statuses if not t), statuses)
        self.assertIn("HR-2001->dana", self.lab.state()["unentitled_releases"])

    def test_dry_run_flags_payload_and_passes_own_request(self):
        self.assertTrue(dry_run(self.payload))
        own = {"attacker": "dana",
               "requests": [{"request": "Please send me HR-1001.", "credential": "own"}]}
        self.assertEqual(dry_run(own), [])

    def test_act4_hardened_returns_to_zero(self):
        submit_payload(self.lab, self.payload)
        self.lab.set_mode("hardened")
        statuses, per, _ = run_suite(self.lab)
        self.assertEqual(per, 0)
        # GREEN everywhere: entitled callers, including the manager, still get their documents.
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)
        self.assertGreater(self.lab.state()["denied_steps"], 0)

    def test_obo_alone_leaves_replay_open(self):
        # On-behalf-of without session binding: the replayed delegated token still works.
        self.lab.policy = dict(self.lab.policy, session_binding=False)
        submit_payload(self.lab, self.payload)
        self.lab.set_mode("hardened")
        statuses, per, _ = run_suite(self.lab)
        self.assertEqual(per, 0.25)
        self.assertEqual(statuses[3], ("RED", True))

    def test_binding_alone_leaves_confused_deputy_open(self):
        # Session binding without on-behalf-of: the service identity still reads everything.
        self.lab.policy = dict(self.lab.policy, on_behalf_of=False)
        submit_payload(self.lab, self.payload)
        self.lab.set_mode("hardened")
        statuses, per, _ = run_suite(self.lab)
        self.assertEqual(per, 0.75)
        self.assertEqual(statuses[3], ("GREEN", True))

    def test_tokens_are_random_demo_strings(self):
        other = Lab()
        mine = set(self.lab.authority.tokens)
        self.assertTrue(all(t.startswith("demo-") for t in mine))
        self.assertFalse(mine & set(other.authority.tokens))

    def test_reset_restores_baseline(self):
        submit_payload(self.lab, self.payload)
        run_suite(self.lab)
        old_tokens = set(self.lab.authority.tokens)
        self.lab.reset()
        state = self.lab.state()
        self.assertTrue(state["baseline"])
        self.assertEqual(state["action_log_size"], 0)
        self.assertFalse(old_tokens & set(self.lab.authority.tokens))
        _, per, _ = run_suite(self.lab)
        self.assertEqual(per, 0)


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
