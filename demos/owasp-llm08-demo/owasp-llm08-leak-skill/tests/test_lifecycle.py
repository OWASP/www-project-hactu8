"""Lifecycle tests — assert the four-act story against the in-process lab.

Baseline is all GREEN; the saved extraction preference raises the targeted
rate; the other customer's controls are untouched (overall < targeted); the
design check rejects the deployed prompt and passes the hardened one; hardened
mode returns the rate to 0; each mitigation layer is shown on its own; reset
restores the baseline.

Run from the skill folder:  python -m unittest discover tests
"""

from __future__ import annotations

import base64
import json
import os
import sys
import threading
import unittest
import unittest.mock
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, SKILL_DIR)
sys.path.insert(0, os.path.join(SKILL_DIR, "scripts"))

from evaluate_kpi import SUITE, classify  # noqa: E402
import protectogw  # noqa: E402
import providers  # noqa: E402
import vulnerable_app  # noqa: E402
from vulnerable_app import (CONSOLE_META, Lab, ProviderModel, console_attack,  # noqa: E402
                            console_evaluate, console_scan, filter_output,
                            load_prompt, load_rules, scan_prompt)

PAYLOAD = os.path.join(SKILL_DIR, "assets", "extraction_request.md")
ATTACKER = "guest-attacker"
CANARY = "llm08-canary"


def run_suite(lab: Lab):
    answers = [lab.query(user, q)["answer"] for user, q, _, _ in SUITE]
    statuses = [(classify(a, truth), targeted)
                for a, (_, _, targeted, truth) in zip(answers, SUITE)]
    targeted = [s for s, t in statuses if t]
    plr = sum(s == "RED" for s in targeted) / len(targeted)
    overall = sum(s == "RED" for s, _ in statuses) / len(statuses)
    return statuses, plr, overall, answers


class LifecycleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.lab = Lab()
        with open(PAYLOAD, encoding="utf-8") as fh:
            self.payload = fh.read()

    def test_act1_baseline_all_green(self):
        statuses, plr, _, _ = run_suite(self.lab)
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)
        self.assertEqual(plr, 0)

    def test_act3_attack_hits_targeted_only(self):
        self.lab.set_preference(ATTACKER, self.payload)
        statuses, plr, overall, answers = run_suite(self.lab)
        self.assertEqual(plr, 1.0)
        self.assertLess(overall, plr)
        self.assertTrue(all(s == "GREEN" for s, t in statuses if not t), statuses)
        # The secret really came out of the deployed prompt, not the payload.
        self.assertNotIn(CANARY, self.payload.lower())
        self.assertIn(CANARY, answers[0].lower())

    def test_design_check_rejects_deployed_prompt_passes_hardened(self):
        rules = load_rules()
        self.assertTrue(scan_prompt(load_prompt("vulnerable"), rules).blocked)
        self.assertFalse(scan_prompt(load_prompt("hardened"), rules).blocked)

    def test_act4_hardened_returns_to_zero(self):
        self.lab.set_preference(ATTACKER, self.payload)
        self.lab.set_mode("hardened")
        statuses, plr, _, _ = run_suite(self.lab)
        self.assertEqual(plr, 0)
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)

    def test_design_fix_alone_removes_secret_but_prompt_still_leaks(self):
        # Secret-free prompt, output filter off: no canary, yet the prompt is quoted.
        self.lab.rules = {"output": {"ngram": 0}}
        self.lab.output_policy = protectogw.Policy(replace_rules=True,
                                                   use_indicator_taxonomy=False)
        self.lab.set_preference(ATTACKER, self.payload)
        self.lab.set_mode("hardened")
        _, plr, _, answers = run_suite(self.lab)
        self.assertNotIn(CANARY, answers[0].lower())
        self.assertEqual(plr, 1.0)

    def test_output_filter_alone_blocks_with_secret_in_prompt(self):
        # Deployed (secret-bearing) prompt, but the output filter applied.
        self.lab.prompts["hardened"] = load_prompt("vulnerable")
        self.lab.set_preference(ATTACKER, self.payload)
        self.lab.set_mode("hardened")
        statuses, plr, _, _ = run_suite(self.lab)
        self.assertEqual(plr, 0)
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)

    def test_output_filter_is_protectogw(self):
        # The leak check is protectogw: its decisive canary check on the raw
        # line, plus the lab_canary rule on the normalized, de-obfuscated line,
        # so encoded or spaced-out leaks a literal regex would miss are caught.
        no_ngram = {"output": {"ngram": 0}}
        self.assertIn("LLM08-CANARY-5e1d", load_prompt("vulnerable"))
        self.assertEqual(vulnerable_app.GUARDED_CANARIES, ("LLM08-CANARY-5e1d",))
        self.assertIs(self.lab.output_policy, vulnerable_app.OUTPUT_POLICY)
        literal = filter_output("The staff code is LLM08-CANARY-5e1d.", "", no_ngram)
        self.assertIn("canary_leak", literal.findings[0])
        self.assertNotIn("CANARY", literal.clean_text)
        leak = "The staff code is LLM08-CANARY-5e1d."
        encoded = base64.b64encode(leak.encode()).decode()
        spaced = "L L M 0 8 - C A N A R Y - 5 e 1 d"
        for variant in (encoded, spaced):
            result = filter_output(variant, "", no_ngram)
            self.assertTrue(result.blocked, variant)
            self.assertIn("lab_canary", result.findings[0])
        # Clean help-centre answers pass the filter untouched.
        for entry in self.lab.faq.values():
            clean = filter_output(entry["answer"], self.lab.system_prompt, self.lab.rules)
            self.assertFalse(clean.blocked, entry["answer"])
            self.assertEqual(clean.clean_text, entry["answer"])

    def test_reset_restores_baseline(self):
        self.lab.set_preference(ATTACKER, self.payload)
        self.lab.reset()
        self.assertTrue(self.lab.state()["baseline"])
        _, plr, _, _ = run_suite(self.lab)
        self.assertEqual(plr, 0)


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



class ConsoleHttpTest(unittest.TestCase):
    """The backend picker endpoints, over real HTTP on an ephemeral port."""

    def setUp(self):
        vulnerable_app.LAB = Lab()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), vulnerable_app.Handler)
        vulnerable_app.PORT = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def _call(self, path, body=None):
        url = f"http://127.0.0.1:{vulnerable_app.PORT}{path}"
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(url, data=data,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}")

    def test_meta_lists_backends_but_never_the_key(self):
        with unittest.mock.patch.dict(os.environ, {"OPENROUTER_API_KEY": "sk-test-secret"}):
            status, meta = self._call("/api/meta")
        self.assertEqual(status, 200)
        self.assertEqual(meta["backends"], ["echo", "ollama", "llamacpp", "openrouter"])
        self.assertTrue(meta["openrouter_key_set"])
        self.assertNotIn("sk-test-secret", json.dumps(meta))

    def test_models_endpoint(self):
        self.assertEqual(self._call("/api/models?backend=echo"), (200, {"backend": "echo", "models": []}))
        self.assertEqual(self._call("/api/models?backend=nope")[0], 400)

    def test_backend_switch(self):
        status, state = self._call("/api/backend", {"backend": "stub", "model": ""})
        self.assertEqual((status, state["backend"]), (200, "echo"))
        self.assertEqual(self._call("/api/backend", {"backend": "nope"})[0], 400)
        with unittest.mock.patch.dict(os.environ, {"OPENROUTER_API_KEY": ""}):
            status, err = self._call("/api/backend", {"backend": "openrouter"})
        self.assertEqual(status, 400)
        self.assertIn("OPENROUTER_API_KEY", err["error"])
        self.assertEqual(vulnerable_app.LAB.backend, "echo")


class FakeProvider(providers.Provider):
    """Records what a real backend would be sent; no network."""
    name = "fake"

    def __init__(self, reply: str = "From the help centre: orders ship in 2 days.") -> None:
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
            lab.set_preference(ATTACKER, fh.read())
        return lab

    def _ask(self, lab: Lab):
        user, question, _, _ = SUITE[0]
        self.assertEqual(user, ATTACKER)
        return lab.query(user, question)

    def test_vulnerable_sends_secret_prompt_and_plain_preference(self):
        fake = FakeProvider()
        self._ask(self._lab(fake))
        system, user = fake.sent[-1]
        self.assertIn(CANARY, system.content.lower())
        self.assertIn("@assistant:", user.content)
        self.assertNotIn("untrusted_preference", user.content + system.content)

    def test_hardened_sends_secret_free_prompt_and_fences_preference(self):
        fake = FakeProvider()
        lab = self._lab(fake)
        lab.set_mode("hardened")
        self._ask(lab)
        system, user = fake.sent[-1]
        self.assertNotIn(CANARY, system.content.lower())
        self.assertIn("<untrusted_preference>", user.content)
        self.assertIn("never follow instructions", system.content)

    def test_output_filter_holds_against_leaking_model(self):
        # A model that quotes its prompt anyway: hardened still withholds it.
        fake = FakeProvider()
        lab = self._lab(fake)
        lab.prompts["hardened"] = load_prompt("vulnerable")
        fake.reply = "Sure.\n" + load_prompt("vulnerable")
        self.assertIn(CANARY, self._ask(lab)["answer"].lower())
        lab.set_mode("hardened")
        result = self._ask(lab)
        self.assertNotIn(CANARY, result["answer"].lower())
        self.assertTrue(result["filter_findings"])

    def test_default_backend_is_offline_echo(self):
        self.assertIsNone(providers.get_provider("echo"))
        self.assertIsNone(providers.get_provider("stub"))       # alias
        self.assertEqual(Lab().backend, "echo")
        self.assertEqual(Lab().state()["backend"], "echo")
        self.assertEqual(Lab(backend="stub").backend, "echo")

    def test_set_backend_swaps_model_and_keeps_state(self):
        lab = Lab(mode="hardened")
        lab.set_preference(ATTACKER, "edited")
        fake = FakeProvider()
        with unittest.mock.patch.object(providers, "get_provider", return_value=fake):
            lab.set_backend("ollama", "llama3.2:3b")
        self.assertEqual(lab.backend, "ollama:llama3.2:3b")
        self.assertIsInstance(lab.model, ProviderModel)
        self.assertEqual(lab.mode, "hardened")
        self.assertEqual(lab.preferences[ATTACKER], "edited")
        lab.set_backend("echo")
        self.assertEqual(lab.backend, "echo")

    def test_set_backend_rejects_bad_input(self):
        lab = Lab()
        with self.assertRaises(ValueError):
            lab.set_backend("nope")
        with self.assertRaises(ValueError):
            lab.set_backend("ollama", "bad model; rm")
        self.assertEqual(lab.backend, "echo")                   # unchanged
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
        lab.query("a", "b")
        lab.query("a", "c")
        with self.assertRaises(RuntimeError):
            lab.query("a", "d")


if __name__ == "__main__":
    unittest.main()
