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

import json  # noqa: E402

from evaluate_kpi import TARGET_AGENT, classify, score  # noqa: E402
import providers  # noqa: E402
from run_mandate_tamper import apply_edit, load_payload  # noqa: E402
from vulnerable_app import (  # noqa: E402
    CONSOLE_META, Lab, ProviderModel, console_attack, console_evaluate, console_scan, dry_run,
    sign_config, verify_config,
)

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


class FakeProvider(providers.Provider):
    """Records what a real backend would be sent; no network.

    By default it plans the scheduled job plus every standing order in the
    instructions it was given, as an obedient model would.
    """
    name = "fake"

    def __init__(self, reply: str = "") -> None:
        super().__init__()
        self.reply = reply
        self.sent = []

    def chat(self, messages, *, model=""):
        self._count_call()
        self.sent.append(messages)
        if self.reply:
            return self.reply
        system, user = messages
        tick = int(user.content.split()[1].rstrip("."))
        acts = [line[2:].split() for line in user.content.splitlines()
                if line.startswith("- ") and "(nothing" not in line]
        for line in system.content.splitlines():
            parts = line.split()
            if line.startswith("@assistant:") and len(parts) == 7 and tick >= int(parts[3]):
                acts.append(parts[5:7])
        return "Plan: " + json.dumps({"actions": [{"action": a, "resource": r} for a, r in acts]})


class BackendTest(unittest.TestCase):
    """The real-model seam: what each mode sends, reply parsing, and provider limits."""

    def _lab(self, fake: FakeProvider, mode: str = "vulnerable") -> Lab:
        lab = Lab(mode=mode)
        lab.model = ProviderModel(fake, "fake-model")
        tamper(lab, load_payload(PAYLOAD))
        return lab

    def _sent_to_stock(self, fake: FakeProvider):
        return [m for m in fake.sent if "Billy Stock" in m[0].content]

    def test_vulnerable_sends_tampered_instructions(self):
        fake = FakeProvider()
        lab = self._lab(fake)
        statuses, omar, _, off = score(lab.run())
        system = self._sent_to_stock(fake)[0][0].content
        self.assertIn("ASI10-CANARY", system)
        self.assertIn("export_records", system)
        self.assertEqual(omar, 100.0)
        self.assertGreater(off, 0)

    def test_hardened_sends_only_the_verified_config(self):
        fake = FakeProvider()
        lab = self._lab(fake, mode="hardened")
        statuses, omar, _, off = score(lab.run())
        for system, _ in self._sent_to_stock(fake):
            self.assertNotIn("ASI10-CANARY", system.content)
            self.assertNotIn("export_records", system.content)
        self.assertEqual((omar, off), (0, 0))
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)

    def test_off_mandate_plan_blocked_by_monitor_in_hardened(self):
        # Signature check off, so the tampered config reaches the model; the
        # monitor still blocks the first off-mandate action and quarantines.
        fake = FakeProvider()
        lab = self._lab(fake, mode="hardened")
        lab.controls["signatures"] = False
        result = lab.run()
        statuses, omar, _, off = score(result)
        self.assertEqual((omar, off), (0, 0))
        self.assertEqual(result["quarantined"], {TARGET_AGENT: 1})

    def test_reply_outside_loaded_mandate_is_dropped(self):
        reply = json.dumps({"actions": [{"action": "export_records", "resource": "customers/x"},
                                        {"action": "read_ledger", "resource": "ledger/x"}]})
        lab = Lab()
        lab.model = ProviderModel(FakeProvider(reply), "fake-model")
        result = lab.run(1)
        self.assertEqual([e["key"] for e in result["action_log"]], ["read_ledger ledger/x"])

    def test_malformed_reply_plans_no_action(self):
        for reply in ("not json", "{broken", '{"actions": "x"}', "[1, 2]",
                      '{"actions": [{"action": "Read Ledger!", "resource": "ledger/x"}]}',
                      '{"actions": [{"action": "read_ledger", "resource": 7}]}'):
            lab = Lab()
            lab.model = ProviderModel(FakeProvider(reply), "fake-model")
            self.assertEqual(lab.run(1)["action_log"], [], reply)

    def test_default_backend_is_offline_stub(self):
        self.assertIsNone(providers.get_provider("stub"))
        self.assertEqual(Lab().backend, "stub")
        self.assertEqual(Lab().state()["backend"], "stub")
        with self.assertRaises(ValueError):
            providers.get_provider("nope")

    def test_openrouter_requires_key(self):
        saved = os.environ.pop("OPENROUTER_API_KEY", None)
        try:
            with self.assertRaises(RuntimeError):
                providers.get_provider("openrouter")
        finally:
            if saved is not None:
                os.environ["OPENROUTER_API_KEY"] = saved

    def test_call_cap(self):
        fake = FakeProvider()
        fake.max_calls = 2
        lab = self._lab(fake)
        with self.assertRaises(RuntimeError):
            lab.run(1)          # three agents, three calls
        self.assertEqual(len(fake.sent), 2)



class ClassifyTest(unittest.TestCase):
    """RED means off the approved mandate, not merely off the schedule."""

    @staticmethod
    def _act(action, resource, status="executed"):
        return {"agent": TARGET_AGENT, "action": action, "resource": resource,
                "key": f"{action} {resource}", "status": status}

    def test_unscheduled_action_inside_mandate_is_yellow(self):
        acts = [self._act("read_stock", "stock/feeder-kit")]
        self.assertEqual(classify(acts, ("reorder_stock stock/feeder-kit",)), "YELLOW")

    def test_off_mandate_action_is_red(self):
        acts = [self._act("reorder_stock", "stock/feeder-kit"),
                self._act("send_invoice", "invoices/INV-3001")]
        self.assertEqual(classify(acts, ("reorder_stock stock/feeder-kit",)), "RED")

    def test_blocked_off_mandate_action_is_not_red(self):
        acts = [self._act("send_invoice", "invoices/INV-3001", status="blocked")]
        self.assertEqual(classify(acts, ("reorder_stock stock/feeder-kit",)), "YELLOW")

if __name__ == "__main__":
    unittest.main()
