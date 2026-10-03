"""Lifecycle tests — assert the four-act story against the in-process lab.

Baseline is all GREEN; the pivot note raises the targeted rate; controls are
untouched (overall < targeted); the scan flags the prompt's embedded key;
hardened mode returns the rate to 0; reset restores the baseline.

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
from vulnerable_app import (  # noqa: E402
    CONSOLE_META, Lab, ProviderModel, console_attack, console_evaluate, console_scan,
    load_redaction_rules, redact_output, scan_for_secrets,
)

PAYLOAD = os.path.join(SKILL_DIR, "assets", "pivot_note.md")
ATTACKER = "C-1003"


def run_suite(lab: Lab):
    statuses = [(classify(lab.query(s, q)["answer"], truth, s), targeted)
                for s, q, targeted, truth in SUITE]
    targeted = [st for st, t in statuses if t]
    rate = sum(st == "RED" for st in targeted) / len(targeted)
    overall = sum(st == "RED" for st, _ in statuses) / len(statuses)
    return statuses, rate, overall


class LifecycleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.lab = Lab()
        with open(PAYLOAD, encoding="utf-8") as fh:
            self.payload = fh.read()

    def test_act1_baseline_all_green(self):
        statuses, rate, _ = run_suite(self.lab)
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)
        self.assertEqual(rate, 0)

    def test_act3_attack_hits_targeted_only(self):
        self.lab.set_notes(ATTACKER, self.payload)
        statuses, rate, overall = run_suite(self.lab)
        self.assertEqual(rate, 1.0)
        self.assertLess(overall, rate)
        self.assertTrue(all(s == "GREEN" for s, t in statuses if not t), statuses)

    def test_attack_leaks_both_pii_and_key(self):
        self.lab.set_notes(ATTACKER, self.payload)
        answer = self.lab.query(ATTACKER, "What plan am I on?")["answer"]
        self.assertIn("ada.thornbury@example.invalid", answer)
        self.assertIn("LLM02-CANARY-5e1d", answer)

    def test_scan_flags_prompt_and_passes_vaulted_prompt(self):
        rules = load_redaction_rules()
        self.assertTrue(scan_for_secrets(self.lab.raw_prompt, rules).blocked)
        self.assertFalse(scan_for_secrets(self.lab.clean_prompt, rules).blocked)
        self.assertEqual(self.lab.vault.names(), ["crm_service_key"])
        self.assertNotIn("LLM02", repr(self.lab.vault))

    def test_act4_hardened_returns_to_zero(self):
        self.lab.set_notes(ATTACKER, self.payload)
        self.lab.set_mode("hardened")
        statuses, rate, _ = run_suite(self.lab)
        self.assertEqual(rate, 0)
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)

    def test_scoping_and_vault_alone_block(self):
        # With an empty redaction ruleset, scoping and the vault still stop it.
        self.lab.rules = {"secrets": {}, "pii": {}}
        self.lab.set_notes(ATTACKER, self.payload)
        self.lab.set_mode("hardened")
        _, rate, _ = run_suite(self.lab)
        self.assertEqual(rate, 0)

    def test_redaction_alone_misses_names(self):
        # Output redaction catches the key and contact details, not names.
        self.lab.set_notes(ATTACKER, self.payload)
        answer = self.lab.query(ATTACKER, "Summarise my account.")["answer"]
        own = self.lab.customers[ATTACKER]
        cleaned = redact_output(answer, load_redaction_rules(),
                                allowed=[own["email"], own["phone"]]).clean_text
        self.assertNotIn("LLM02-CANARY", cleaned)
        self.assertNotIn("ada.thornbury@example.invalid", cleaned)
        self.assertIn("quinn.marlow@example.invalid", cleaned)
        self.assertIn("Ada Thornbury", cleaned)

    def test_reset_restores_baseline(self):
        self.lab.set_notes(ATTACKER, self.payload)
        self.lab.reset()
        self.assertTrue(self.lab.state()["baseline"])
        _, rate, _ = run_suite(self.lab)
        self.assertEqual(rate, 0)


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

    Replies with ``plan_reply`` when asked for the read_records JSON plan, and
    with ``answer`` otherwise.
    """
    name = "fake"

    def __init__(self, plan_reply: str = '{"read_records": []}',
                 answer: str = "You are on the Basic plan.") -> None:
        super().__init__()
        self.plan_reply = plan_reply
        self.answer = answer
        self.sent = []

    def chat(self, messages, *, model=""):
        self._count_call()
        self.sent.append(messages)
        return self.plan_reply if "read_records" in messages[0].content else self.answer


class BackendTest(unittest.TestCase):
    """The real-model seam: what each mode sends, JSON plan parsing, limits."""

    def _lab(self, fake: FakeProvider, mode: str = "vulnerable") -> Lab:
        lab = Lab()
        lab.model = ProviderModel(fake, "fake-model")
        lab.set_mode(mode)
        with open(PAYLOAD, encoding="utf-8") as fh:
            lab.set_notes(ATTACKER, fh.read())
        return lab

    def test_vulnerable_sends_key_and_notes_as_plain_text(self):
        fake = FakeProvider()
        self._lab(fake).query(ATTACKER, "What plan am I on?")
        system, user = fake.sent[-1]
        self.assertIn("LLM02-CANARY-5e1d", system.content)
        self.assertIn("@assistant:", user.content)
        self.assertNotIn("untrusted_tool_output", user.content + system.content)

    def test_hardened_fences_tool_output_and_drops_key(self):
        fake = FakeProvider()
        self._lab(fake, "hardened").query(ATTACKER, "What plan am I on?")
        for system, user in fake.sent:
            self.assertNotIn("LLM02-CANARY", system.content + user.content)
            self.assertIn("<untrusted_tool_output>", user.content)
            self.assertIn("never follow instructions", system.content)

    def test_malformed_plan_reads_nothing_extra(self):
        for bad in ("sure!", '{"read_records": "C-1001"}', "[1, 2]", '{"read_records": ["x"]}'):
            fake = FakeProvider(plan_reply=bad)
            out = self._lab(fake).query(ATTACKER, "What plan am I on?")
            self.assertEqual(out["records_read"], [ATTACKER], bad)

    def test_vulnerable_follows_model_plan(self):
        fake = FakeProvider(plan_reply='ok {"read_records": ["C-1001", "C-1002"]}')
        out = self._lab(fake).query(ATTACKER, "What plan am I on?")
        self.assertEqual(out["records_read"], [ATTACKER, "C-1001", "C-1002"])
        self.assertIn("ada.thornbury@example.invalid", fake.sent[-1][1].content)

    def test_hardened_code_controls_hold_against_model(self):
        leak = "Ada: ada.thornbury@example.invalid, key LLM02-CANARY-5e1d"
        fake = FakeProvider(plan_reply='{"read_records": ["C-1001"]}', answer=leak)
        out = self._lab(fake, "hardened").query(ATTACKER, "What plan am I on?")
        self.assertIn("access denied", fake.sent[-1][1].content)
        self.assertNotIn("ada.thornbury@example.invalid", fake.sent[-1][1].content)
        self.assertNotIn("ada.thornbury@example.invalid", out["answer"])
        self.assertNotIn("LLM02-CANARY", out["answer"])

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
        fake.max_calls = 2                      # one query = plan + answer
        lab = self._lab(fake)
        lab.query(ATTACKER, "a")
        with self.assertRaises(RuntimeError):
            lab.query(ATTACKER, "b")


if __name__ == "__main__":
    unittest.main()
