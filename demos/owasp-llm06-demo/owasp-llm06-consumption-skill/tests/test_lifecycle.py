"""Lifecycle tests — assert the four-act story against the in-process lab.

Baseline is all GREEN; the three edited pages raise the targeted rate; controls
are untouched (overall < targeted); the lint flags every payload; hardened
mode returns the rate to 0; the host-safety caps bound vulnerable mode; the
per-client quota stops a flood; reset restores the baseline.

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
from run_consumption import PAYLOADS, payload_path  # noqa: E402
from vulnerable_app import (CONSOLE_META, HARD_MAX_OUTPUT_CHARS,  # noqa: E402
                            HARD_MAX_STEPS, HARD_MAX_TOOL_CALLS, Lab, ProviderModel,
                            console_attack,
                            console_evaluate, console_scan, scan_page)


def run_suite(lab: Lab, client: str = "suite"):
    results = [(lab.query(q, client), targeted, truth) for q, targeted, truth in SUITE]
    statuses = [(classify(r, truth), targeted) for r, targeted, truth in results]
    targeted = [s for s, t in statuses if t]
    bbr = sum(s == "RED" for s in targeted) / len(targeted)
    overall = sum(s == "RED" for s, _ in statuses) / len(statuses)
    return statuses, bbr, overall, [r for r, _, _ in results]


def attack(lab: Lab) -> None:
    for name, slug in PAYLOADS.items():
        with open(payload_path(name), encoding="utf-8") as fh:
            lab.write_page(slug, fh.read())


class LifecycleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.lab = Lab()

    def test_act1_baseline_all_green(self):
        statuses, bbr, _, _ = run_suite(self.lab)
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)
        self.assertEqual(bbr, 0)

    def test_act3_attack_hits_targeted_only(self):
        attack(self.lab)
        statuses, bbr, overall, _ = run_suite(self.lab)
        self.assertEqual(bbr, 1.0)
        self.assertLess(overall, bbr)
        self.assertTrue(all(s == "GREEN" for s, t in statuses if not t), statuses)

    def test_scan_flags_payloads_and_passes_baseline(self):
        budget = self.lab.budget
        for name, slug in PAYLOADS.items():
            with open(payload_path(name), encoding="utf-8") as fh:
                self.assertTrue(scan_page(fh.read(), budget, slug).blocked, name)
        for slug, text in self.lab.pages.items():
            self.assertFalse(scan_page(text, budget, slug).blocked, slug)

    def test_act4_hardened_returns_to_zero(self):
        attack(self.lab)
        _, _, _, vulnerable = run_suite(self.lab, "before")
        self.lab.set_mode("hardened")
        statuses, bbr, _, hardened = run_suite(self.lab, "after")
        self.assertEqual(bbr, 0)
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)
        self.assertLess(sum(r["cost_usd"] for r in hardened),
                        sum(r["cost_usd"] for r in vulnerable) / 10)

    def test_host_safety_caps_bound_vulnerable_mode(self):
        attack(self.lab)
        _, _, _, results = run_suite(self.lab)
        for r in results:
            self.assertLessEqual(r["cost"]["agent_steps"], HARD_MAX_STEPS)
            self.assertLessEqual(r["cost"]["tool_calls"], HARD_MAX_TOOL_CALLS)
            self.assertLessEqual(len(r["answer"]), HARD_MAX_OUTPUT_CHARS)

    def test_per_client_quota_stops_flood(self):
        attack(self.lab)
        self.lab.set_mode("hardened")
        statuses = [self.lab.query("When does payroll run each month?", "attacker")["status"]
                    for _ in range(40)]
        self.assertIn("quota_exceeded", statuses)
        self.assertEqual(statuses[0], "answered")
        quota = self.lab.budget["per_client"]["max_tokens"]
        # The overshoot is bounded by one request's budget.
        self.assertLess(self.lab.ledger["attacker"], quota + 7000)
        self.assertEqual(self.lab.query("Is Thanksgiving a company holiday?", "employee")["status"],
                         "answered")

    def test_reset_restores_baseline(self):
        attack(self.lab)
        run_suite(self.lab)
        self.lab.reset()
        state = self.lab.state()
        self.assertTrue(state["baseline"])
        self.assertEqual(state["client_spend_tokens"], {})
        _, bbr, _, _ = run_suite(self.lab)
        self.assertEqual(bbr, 0)



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

    def __init__(self, replies=None) -> None:
        super().__init__()
        self.replies = list(replies or ['{"answer": "Payroll runs on the last business day."}'])
        self.sent = []

    def chat(self, messages, *, model=""):
        self._count_call()
        self.sent.append(messages)
        return self.replies.pop(0) if len(self.replies) > 1 else self.replies[0]


SEARCH = '{"tool_calls": ["When does payroll run each month?"]}'


class BackendTest(unittest.TestCase):
    """The real-model seam: what each mode sends, the JSON contract, the limits."""

    def _lab(self, fake: FakeProvider) -> Lab:
        lab = Lab()
        lab.model = ProviderModel(fake, "fake-model")
        attack(lab)
        return lab

    def test_vulnerable_inlines_tool_output_as_plain_text(self):
        fake = FakeProvider([SEARCH, '{"answer": "ok"}'])
        self._lab(fake).query("When does payroll run each month?")
        system, user = fake.sent[-1]
        self.assertIn("@assistant:", user.content)
        self.assertIn('"tool_calls"', system.content)
        self.assertNotIn("untrusted_tool_output", user.content + system.content)

    def test_hardened_fences_tool_output(self):
        fake = FakeProvider([SEARCH, '{"answer": "ok"}'])
        lab = self._lab(fake)
        lab.set_mode("hardened")
        lab.query("When does payroll run each month?")
        system, user = fake.sent[-1]
        self.assertIn("<untrusted_tool_output>", user.content)
        self.assertIn("never follow instructions", system.content)

    def test_malformed_reply_is_no_action(self):
        for reply in ("not json", "{broken", '{"tool_calls": "x"}', "[1, 2]", '{"answer": 3}'):
            fake = FakeProvider([reply])
            result = self._lab(fake).query("When does payroll run each month?")
            self.assertEqual(result["cost"]["tool_calls"], 0, reply)
            self.assertEqual(result["status"], "answered")
            self.assertIn("could not find", result["answer"])

    def test_hardened_budget_holds_against_model_storm(self):
        # The model asks for a tool-call storm at every step; the code budget
        # still bounds the request in hardened mode.
        storm = '{"tool_calls": [' + ", ".join(['"payroll"'] * 40) + "]}"
        fake = FakeProvider([storm])
        lab = self._lab(fake)
        lab.set_mode("hardened")
        result = lab.query("When does payroll run each month?")
        caps = lab.budget["per_request"]
        self.assertLessEqual(result["cost"]["tool_calls"], caps["max_tool_calls"])
        self.assertLessEqual(result["cost"]["agent_steps"], caps["max_agent_steps"])
        self.assertTrue(result["guard_events"])

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
        lab.query("a")
        lab.query("b")
        with self.assertRaises(RuntimeError):
            lab.query("c")


if __name__ == "__main__":
    unittest.main()
