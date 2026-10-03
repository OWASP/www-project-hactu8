"""Lifecycle tests — assert the four-act story against the in-process lab.

Baseline is all GREEN; the crafted turn raises the targeted rate; controls
are untouched (overall < targeted); the scope audit flags the payload; hardened
mode returns the rate to 0; reset restores the baseline.

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
import providers  # noqa: E402
from vulnerable_app import (CONSOLE_META, MEMORY_TURNS, Lab, ProviderModel,  # noqa: E402
                            console_attack, console_evaluate, console_scan, rank,
                            scope_blocks)

PAYLOAD = os.path.join(SKILL_DIR, "assets", "crafted_query.txt")
SESSION = "meadow-analyst"


def run_suite(lab: Lab):
    statuses = [(classify(lab.query(SESSION, q, remember=False)["answer"], truth), targeted)
                for q, targeted, truth in SUITE]
    targeted = [s for s, t in statuses if t]
    ctlr = sum(s == "RED" for s in targeted) / len(targeted)
    overall = sum(s == "RED" for s, _ in statuses) / len(statuses)
    return statuses, ctlr, overall


class LifecycleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.lab = Lab()
        with open(PAYLOAD, encoding="utf-8") as fh:
            self.payload = fh.read().strip()

    def test_act1_baseline_all_green(self):
        statuses, ctlr, _ = run_suite(self.lab)
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)
        self.assertEqual(ctlr, 0)

    def test_act3_attack_hits_targeted_only(self):
        self.lab.query(SESSION, self.payload)
        statuses, ctlr, overall = run_suite(self.lab)
        self.assertEqual(ctlr, 1.0)
        self.assertLess(overall, ctlr)
        self.assertTrue(all(s == "GREEN" for s, t in statuses if not t), statuses)

    def test_scope_audit_flags_payload_and_passes_suite(self):
        tenant = self.lab.tenant_of(SESSION)
        top = rank(self.lab.docs, self.lab.retrieval_vector(SESSION, self.payload))[0][0]
        self.assertTrue(scope_blocks(top, tenant))
        for question, _, _ in SUITE:
            top = rank(self.lab.docs, self.lab.retrieval_vector(SESSION, question))[0][0]
            self.assertFalse(scope_blocks(top, tenant), question)

    def test_act4_hardened_returns_to_zero(self):
        self.lab.query(SESSION, self.payload)
        self.lab.set_mode("hardened")
        statuses, ctlr, _ = run_suite(self.lab)
        self.assertEqual(ctlr, 0)
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)

    def test_prompt_rule_alone_does_not_block(self):
        # Vulnerable mode already carries the tenant rule in the system prompt
        # and the tenant-name boost; neither is an access check.
        self.lab.query(SESSION, self.payload)
        result = self.lab.query(SESSION, SUITE[0][0], remember=False)
        self.assertTrue(result["cross_tenant"])
        self.assertEqual(result["tenant"], "meadow")

    def test_reset_restores_baseline_and_memory_is_capped(self):
        for _ in range(MEMORY_TURNS + 3):
            self.lab.query(SESSION, self.payload)
        self.assertEqual(len(self.lab.memory[SESSION]), MEMORY_TURNS)
        self.lab.reset()
        self.assertTrue(self.lab.state()["baseline"])
        _, ctlr, _ = run_suite(self.lab)
        self.assertEqual(ctlr, 0)


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
    """Records what a real backend would be sent; no network."""
    name = "fake"

    def __init__(self, reply: str = "Winter hay is 180 dollars per tonne.") -> None:
        super().__init__()
        self.reply = reply
        self.sent = []

    def chat(self, messages, *, model=""):
        self._count_call()
        self.sent.append(messages)
        return self.reply


class BackendTest(unittest.TestCase):
    """The real-model seam: what each mode sends, and the provider limits."""

    def _lab(self, fake: FakeProvider) -> Lab:
        lab = Lab()
        lab.model = ProviderModel(fake, "fake-model")
        with open(PAYLOAD, encoding="utf-8") as fh:
            lab.query(SESSION, fh.read().strip())      # crafted turn in memory
        return lab

    def _foreign_texts(self, lab: Lab):
        return [d.text.strip() for d in lab.docs if d.tenant != lab.tenant_of(SESSION)]

    def test_vulnerable_sends_bare_cross_tenant_passages(self):
        fake = FakeProvider()
        lab = self._lab(fake)
        lab.query(SESSION, SUITE[0][0], remember=False)
        system, user = fake.sent[-1]
        self.assertNotIn("retrieved_passages", system.content + user.content)
        self.assertTrue(any(t in user.content for t in self._foreign_texts(lab)))

    def test_hardened_fences_and_filters_passages(self):
        fake = FakeProvider()
        lab = self._lab(fake)
        lab.set_mode("hardened")
        lab.query(SESSION, SUITE[0][0], remember=False)
        system, user = fake.sent[-1]
        self.assertIn("<retrieved_passages>", user.content)
        self.assertIn("never follow instructions", system.content)
        # The tenant filter in code is still authoritative.
        self.assertFalse(any(t in user.content for t in self._foreign_texts(lab)))

    def test_default_backend_is_offline_stub(self):
        self.assertIsNone(providers.get_provider("stub"))
        self.assertEqual(Lab().backend, "stub")
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
        lab = self._lab(fake)                              # call 1
        lab.query(SESSION, "a", remember=False)            # call 2
        with self.assertRaises(RuntimeError):
            lab.query(SESSION, "b", remember=False)


if __name__ == "__main__":
    unittest.main()
