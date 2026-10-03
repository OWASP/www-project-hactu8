"""Lifecycle tests — assert the four-act story against the in-process lab.

Baseline is all GREEN; each of the three poisoning surfaces raises the
targeted rate on its own; the MFA control is untouched (overall < targeted);
the static scan flags all three artifacts; each hardened control blocks its
surface on its own; hardened mode returns the rate to 0; reset restores the
baseline.

Run from the skill folder:  python -m unittest discover tests
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import unittest

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, SKILL_DIR)
sys.path.insert(0, os.path.join(SKILL_DIR, "scripts"))

from evaluate_kpi import SUITE, classify  # noqa: E402
import providers  # noqa: E402
from vulnerable_app import (  # noqa: E402
    AGENT_CACHE_POISON_FILE, CONSOLE_META, CONTROLS, PINNED_TEMPLATE_SHA256,
    PROMPT_TEMPLATE_FILE, PROTECTED_CLEAN_SAMPLE, Lab, ProviderModel, _protected_scan,
    console_attack, console_evaluate, console_scan, load_baseline_template, poison_document,
    render_template,
)

TRIGGER_QUERY = SUITE[3][0]


def load_json(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def attack(lab: Lab, scenario: str = "all") -> None:
    if scenario in ("rag", "all"):
        for index in range(3):
            lab.ingest(*poison_document(index))
    if scenario in ("prompt", "all"):
        lab.set_template(load_json(PROMPT_TEMPLATE_FILE))
    if scenario in ("agent", "all"):
        lab.set_agent_cache(load_json(AGENT_CACHE_POISON_FILE))


def run_suite(lab: Lab):
    statuses = [(classify(lab.query(q)["answer"]), targeted) for q, targeted in SUITE]
    targeted = [s for s, t in statuses if t]
    psr = sum(s == "RED" for s in targeted) / len(targeted)
    overall = sum(s == "RED" for s, _ in statuses) / len(statuses)
    return statuses, psr, overall


def harden_only(lab: Lab, control: str) -> None:
    lab.set_mode("hardened")
    lab.controls = {name: name == control for name in CONTROLS}


class LifecycleTest(unittest.TestCase):
    def test_act1_baseline_all_green(self):
        lab = Lab()
        statuses, psr, _ = run_suite(lab)
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)
        self.assertEqual(psr, 0)
        self.assertTrue(lab.state()["baseline"])

    def test_act3_all_surfaces_hit_targeted_only(self):
        lab = Lab()
        attack(lab)
        statuses, psr, overall = run_suite(lab)
        self.assertEqual(psr, 1.0)
        self.assertLess(overall, psr)
        self.assertTrue(all(s == "GREEN" for s, t in statuses if not t), statuses)
        self.assertFalse(lab.state()["baseline"])

    def test_each_surface_is_measurable_on_its_own(self):
        for scenario in ("rag", "prompt", "agent"):
            with self.subTest(scenario=scenario):
                lab = Lab()
                attack(lab, scenario)
                _, psr, _ = run_suite(lab)
                self.assertGreater(psr, 0)

    def test_prompt_and_agent_fire_only_on_the_trigger(self):
        for scenario in ("prompt", "agent"):
            with self.subTest(scenario=scenario):
                lab = Lab()
                attack(lab, scenario)
                statuses, _, _ = run_suite(lab)
                self.assertEqual([s for s, _ in statuses],
                                 ["GREEN", "GREEN", "GREEN", "RED", "GREEN"])

    def test_scan_flags_payloads_and_passes_clean_sample(self):
        result = console_scan(Lab())
        self.assertEqual(result["decision"], "REJECT")
        for artifact in ("poison_template.txt", "prompt_template.json",
                         "bob_agent_poisoned_response.json"):
            self.assertTrue(any(f.startswith(artifact) for f in result["findings"]), artifact)
        self.assertEqual(_protected_scan(PROTECTED_CLEAN_SAMPLE)["decision"], "WOULD ACCEPT")

    def test_act4_hardened_returns_to_zero(self):
        lab = Lab()
        attack(lab)
        lab.set_mode("hardened")
        statuses, psr, _ = run_suite(lab)
        self.assertEqual(psr, 0)
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)
        self.assertEqual(lab.state()["mitigations"], {name: True for name in CONTROLS})

    def test_each_control_blocks_its_surface_alone(self):
        pairs = {"rag": "source_gate", "prompt": "template_pin", "agent": "agent_verify"}
        for scenario, control in pairs.items():
            with self.subTest(scenario=scenario, control=control):
                lab = Lab()
                attack(lab, scenario)
                harden_only(lab, control)
                self.assertEqual(run_suite(lab)[1], 0)
                # ...and the other two controls do not block it.
                others = [c for c in CONTROLS if c != control]
                lab.controls = {name: name in others for name in CONTROLS}
                self.assertGreater(run_suite(lab)[1], 0)

    def test_source_gate_keeps_provenanced_docs_and_rejects_altered_official(self):
        lab = Lab()
        lab.ingest("policy_note.txt", PROTECTED_CLEAN_SAMPLE)
        name, poison = poison_document(0)
        lab.ingest("compliance_policy_official.txt", poison)   # replaces the official doc
        harden_only(lab, "source_gate")
        result = lab.query("What is the policy on high-value wire transfers?")
        self.assertIn("policy_note.txt", result["retrieved"])
        self.assertIn("compliance_policy_official.txt", result["excluded"])

    def test_agent_verify_accepts_matching_digest(self):
        cache = load_json(AGENT_CACHE_POISON_FILE)
        guidance = "Offshore transactions require enhanced due diligence and manual review."
        cache["response"]["guidance"] = guidance
        cache["source"] = {"provenance_verified": True,
                           "content_digest": hashlib.sha256(guidance.encode()).hexdigest()}
        lab = Lab()
        lab.set_agent_cache(cache)
        harden_only(lab, "agent_verify")
        self.assertEqual(lab.query(TRIGGER_QUERY)["agent"], "used")
        cache["source"]["content_digest"] = "0" * 64
        lab.set_agent_cache(cache)
        self.assertTrue(lab.query(TRIGGER_QUERY)["agent"].startswith("rejected"))

    def test_pin_matches_baseline_asset(self):
        template = load_baseline_template()["template"]
        self.assertEqual(hashlib.sha256(template.encode()).hexdigest(), PINNED_TEMPLATE_SHA256)
        self.assertTrue(Lab().state()["template_pinned"])

    def test_reset_restores_baseline(self):
        lab = Lab()
        attack(lab)
        lab.reset()
        self.assertTrue(lab.state()["baseline"])
        _, psr, _ = run_suite(lab)
        self.assertEqual(psr, 0)


class RendererTest(unittest.TestCase):
    """The template renderer supports two forms and leaves the rest literal."""

    TAMPERED = load_json(PROMPT_TEMPLATE_FILE)["template"]

    def test_substitution(self):
        out = render_template("{{ system }}|{{context}}|{{  query  }}", "S", "C", "Q")
        self.assertEqual(out, "S|C|Q")

    def test_conditional_fires_only_on_trigger(self):
        self.assertIn("[OVERRIDE]", render_template(self.TAMPERED, "S", "C", "Quarterly Audit now"))
        self.assertNotIn("[OVERRIDE]", render_template(self.TAMPERED, "S", "C", "wire transfers"))

    def test_unknown_syntax_stays_literal(self):
        for text in ("{{ config }}", "{{ query.__class__ }}", "{% for x in y %}{% endfor %}",
                     "{{ 7*7 }}", "{% if query %}x{% endif %}"):
            with self.subTest(text=text):
                self.assertEqual(render_template(text, "S", "C", "Q"), text)

    def test_values_are_not_rendered_again(self):
        out = render_template("{{ query }}", "S", "C", "{{ system }} {% if 'a' in query|lower %}")
        self.assertEqual(out, "{{ system }} {% if 'a' in query|lower %}")


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

    def __init__(self, reply: str = "Offshore transactions need enhanced due diligence.") -> None:
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
        attack(lab)
        return lab

    def test_vulnerable_sends_poisoned_context_as_plain_text(self):
        fake = FakeProvider()
        self._lab(fake).query(TRIGGER_QUERY)
        system, user = fake.sent[-1]
        self.assertIn("[OVERRIDE]", user.content)
        self.assertIn("REFERENCE_ID", user.content)
        self.assertNotIn("retrieved_context", user.content + system.content)

    def test_hardened_fences_and_filters_context(self):
        fake = FakeProvider()
        lab = self._lab(fake)
        lab.set_mode("hardened")
        lab.query(TRIGGER_QUERY)
        system, user = fake.sent[-1]
        self.assertIn("<retrieved_context>", user.content)
        self.assertIn("never follow instructions", system.content)
        self.assertNotIn("[OVERRIDE]", user.content)          # template pinned
        self.assertNotIn("REFERENCE_ID", user.content)        # poison docs gated
        self.assertNotIn("pre-verified", user.content)        # Bob's answer rejected

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
        lab = self._lab(fake)
        lab.query("a")
        lab.query("b")
        with self.assertRaises(RuntimeError):
            lab.query("c")


if __name__ == "__main__":
    unittest.main()
