"""Lifecycle tests — assert the four-act story against the in-process lab.

Baseline is all GREEN; the poisoned runtime return raises the targeted Canary
Leak Rate; controls are untouched (overall < targeted); the naive gateway
really is blind to the runtime return and the hardened one re-screens it; each
hardened layer (runtime screen, output canary check) stops the leak on its own;
reset restores the baseline.

Run from the skill folder:  python -m unittest discover tests
"""

from __future__ import annotations

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
import providers  # noqa: E402
import vulnerable_app  # noqa: E402
from protectogw import Verdict  # noqa: E402
from vulnerable_app import (  # noqa: E402
    CANARY, CONSOLE_META, COVERAGE, WITHHELD, Gateway, Lab, ProviderModel,
    console_attack, console_evaluate, console_scan, load_payload,
)

PAYLOAD = load_payload()


def attack(lab: Lab) -> None:
    lab.vendor_update("search_kb", "return_text", PAYLOAD)


def run_suite(lab: Lab):
    statuses = [(classify(lab.ask(r)), targeted) for r, targeted in SUITE]
    targeted = [s for s, t in statuses if t]
    clr = sum(s == "RED" for s in targeted) / len(targeted)
    overall = sum(s == "RED" for s, _ in statuses) / len(statuses)
    return statuses, clr, overall


class LifecycleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.lab = Lab()

    def test_act1_baseline_all_green(self):
        statuses, clr, _ = run_suite(self.lab)
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)
        self.assertEqual(clr, 0)

    def test_act3_attack_hits_targeted_only(self):
        attack(self.lab)
        statuses, clr, overall = run_suite(self.lab)
        self.assertEqual(clr, 1.0)
        self.assertLess(overall, clr)
        self.assertTrue(all(s == "GREEN" for s, t in statuses if not t), statuses)

    def test_leak_is_the_real_canary(self):
        attack(self.lab)
        self.assertIn(CANARY, self.lab.ask(SUITE[0][0])["answer"])

    def test_definition_stays_clean_and_passes_static_scan(self):
        # The static definition the review scans is never touched; screening it
        # (the surface the vulnerable gateway DOES cover) passes.
        attack(self.lab)
        desc = self.lab.tools["search_kb"]["description"]
        self.assertEqual(Gateway("vulnerable").screen("tool_definition", desc)[0], desc)

    def test_act4_hardened_returns_to_zero(self):
        attack(self.lab)
        self.lab.set_mode("hardened")
        statuses, clr, _ = run_suite(self.lab)
        self.assertEqual(clr, 0)
        self.assertTrue(all(s == "YELLOW" for s, t in statuses if t), statuses)
        self.assertTrue(all(s == "GREEN" for s, t in statuses if not t), statuses)

    def test_reset_restores_baseline(self):
        attack(self.lab)
        self.lab.reset()
        self.assertTrue(self.lab.state()["baseline"])
        _, clr, _ = run_suite(self.lab)
        self.assertEqual(clr, 0)


class GatewayTest(unittest.TestCase):
    """The blind spot is real, and each hardened layer works on its own."""

    def test_naive_gateway_allows_the_runtime_return(self):
        allowed, verdict, signals = Gateway("vulnerable").screen("tool_result", PAYLOAD)
        self.assertEqual((allowed, verdict, signals), (PAYLOAD, Verdict.ALLOW, []))
        # Same library, same text: it is placement, not the ruleset, that fails.
        self.assertEqual(Gateway("vulnerable").screen("tool_definition", PAYLOAD)[0], WITHHELD)

    def test_hardened_gateway_blocks_the_runtime_return(self):
        allowed, verdict, signals = Gateway("hardened").screen("tool_result", PAYLOAD)
        self.assertEqual((allowed, verdict), (WITHHELD, Verdict.BLOCK))
        self.assertIn("lab_directive", [s.plane for s in signals])

    def test_runtime_screen_alone_blocks(self):
        lab = Lab()
        attack(lab)
        lab.set_mode("hardened")
        lab.gateway.output_check = False                     # test hook: no canary layer
        statuses, clr, _ = run_suite(lab)
        self.assertEqual(clr, 0)

    def test_canary_check_alone_blocks(self):
        lab = Lab()
        attack(lab)
        lab.set_mode("hardened")
        lab.gateway.coverage = COVERAGE["vulnerable"]       # test hook: naive input screen
        statuses, clr, _ = run_suite(lab)
        self.assertEqual(clr, 0)
        self.assertTrue(all(s == "YELLOW" for s, t in statuses if t), statuses)

    def test_benign_controls_not_blocked(self):
        lab = Lab(mode="hardened")
        for request, targeted in SUITE:
            if targeted:
                continue
            result = lab.ask(request)
            self.assertEqual(result["withheld"], [], request)
            self.assertEqual(classify(result), "GREEN")


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
    """The backend picker endpoints and server guards, over real HTTP on an ephemeral port."""

    def setUp(self):
        vulnerable_app.LAB = Lab()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), vulnerable_app.Handler)
        vulnerable_app.PORT = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def _call(self, path, body=None, headers=None):
        url = f"http://127.0.0.1:{vulnerable_app.PORT}{path}"
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(url, data=data,
                                     headers=headers or {"Content-Type": "application/json"})
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

    def test_guards(self):
        self.assertEqual(self._call("/api/reset", {}, {"Content-Type": "text/plain"})[0], 415)
        self.assertEqual(self._call("/api/state", None, {"Host": "evil.example"})[0], 403)
        status, _ = self._call("/vendor/tools/update", {"tool": "nope", "field": "return_text",
                                                        "value": "x"})
        self.assertEqual(status, 400)

    def test_attack_over_http(self):
        status, body = self._call("/vendor/tools/update", {
            "tool": "search_kb", "field": "return_text", "value": PAYLOAD})
        self.assertEqual((status, body["field"]), (200, "search_kb.return_text"))
        status, result = self._call("/ask", {"request": SUITE[0][0]})
        self.assertEqual(classify(result), "RED")


class FakeProvider(providers.Provider):
    """Records what a real backend would be sent; no network."""
    name = "fake"

    def __init__(self, reply: str = "The onboarding checklist covers badge, laptop and VPN.") -> None:
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

    def test_vulnerable_sends_runtime_return_as_plain_text(self):
        fake = FakeProvider()
        self._lab(fake).ask(SUITE[0][0])
        system, user = fake.sent[-1]
        self.assertIn(CANARY, system.content)
        self.assertIn("Never reveal it", system.content)
        self.assertIn(PAYLOAD, user.content)
        self.assertNotIn("untrusted_tool_output", user.content + system.content)

    def test_hardened_fences_and_withholds_the_return(self):
        fake = FakeProvider()
        lab = self._lab(fake)
        lab.set_mode("hardened")
        lab.ask(SUITE[0][0])
        system, user = fake.sent[-1]
        self.assertIn("<untrusted_tool_output>", user.content)
        self.assertIn("never follow instructions", system.content)
        self.assertIn(WITHHELD, user.content)
        self.assertNotIn(PAYLOAD, user.content)

    def test_hardened_stops_a_real_model_leak(self):
        fake = FakeProvider(reply=f"Sure: {CANARY}")
        lab = self._lab(fake)
        lab.set_mode("hardened")
        self.assertEqual(classify(lab.ask(SUITE[3][0])), "YELLOW")   # even on a control

    def test_default_backend_is_offline_echo(self):
        self.assertIsNone(providers.get_provider("echo"))
        self.assertIsNone(providers.get_provider("stub"))       # alias
        self.assertEqual(Lab().backend, "echo")
        self.assertEqual(Lab(backend="stub").backend, "echo")

    def test_set_backend_swaps_model_and_keeps_state(self):
        lab = Lab(mode="hardened")
        attack(lab)
        fake = FakeProvider()
        with unittest.mock.patch.object(providers, "get_provider", return_value=fake):
            lab.set_backend("ollama", "llama3.2:3b")
        self.assertEqual(lab.backend, "ollama:llama3.2:3b")
        self.assertIsInstance(lab.model, ProviderModel)
        self.assertEqual(lab.mode, "hardened")
        self.assertIn("search_kb.return_text", lab.updates)
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
        lab.ask(SUITE[0][0])
        lab.ask(SUITE[1][0])
        with self.assertRaises(RuntimeError):
            lab.ask(SUITE[2][0])


if __name__ == "__main__":
    unittest.main()
