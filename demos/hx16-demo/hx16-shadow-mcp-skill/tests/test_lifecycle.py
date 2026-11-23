"""Lifecycle tests — assert the four-act story against the in-process lab.

Baseline is all GREEN; Flock Tools Plus receives the account reference in
the three targeted conversations only, through three different tools;
hardened mode returns the rate to 0 and keeps every task working; each layer
is measured alone; reset restores the baseline. The client mechanics each
layer depends on are tested directly (merge by name, lookalike fold,
overlap score, signature, inventory, egress, discovery), and the measured
limit (the approved server swapped in place) is asserted as measured.

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

from evaluate_kpi import CUSTOMERS, LIMIT_ID, classify, probe_row, suite  # noqa: E402
import providers  # noqa: E402
import vulnerable_app  # noqa: E402
from vulnerable_app import (  # noqa: E402
    BASE, CONSOLE_META, LAYERS, MANIFEST, OVERLAP_THRESHOLD, Lab, ProviderModel, StubModel, console_attack,
    console_evaluate, console_scan, fold_name, load_shadow, overlap, parse_choice, scan_attack, sign_config,
    verify_config,
)

SHADOW_URL = BASE + "/mcp/flock-tools-plus"


def run_suite(lab: Lab):
    results = [(lab.ask(a, q), e, tg) for _, a, q, tg, e in suite()]
    statuses = [(classify(r, e), tg) for r, e, tg in results]
    targeted = [s for s, t in statuses if t]
    return statuses, sum(s == "RED" for s in targeted) / len(targeted), \
        sum(s == "RED" for s, _ in statuses) / len(statuses), [r for r, _, _ in results]


def attacked(mode: str = "vulnerable", **layers) -> Lab:
    lab = Lab(mode=mode)
    for name, value in layers.items():
        setattr(lab, name, value)
    lab.load_attack()
    return lab


def only(layer: str) -> dict:
    return {name: name == layer for name in LAYERS}


class LifecycleTest(unittest.TestCase):
    def test_act1_baseline_all_green_and_nothing_reaches_a_shadow(self):
        lab = Lab()
        statuses, ser, _, results = run_suite(lab)
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)
        self.assertEqual(ser, 0)
        self.assertEqual(lab.attacker_log(), [])
        self.assertTrue(lab.state()["baseline"])
        self.assertTrue(lab.state()["config_signature_valid"])

    def test_act3_references_reach_the_shadow_in_targeted_conversations_only(self):
        lab = attacked()
        statuses, ser, overall, results = run_suite(lab)
        self.assertEqual(ser, 1.0)
        self.assertAlmostEqual(overall, 0.6)
        self.assertTrue(all(s == "GREEN" for s, t in statuses if not t), statuses)
        hit = {r["account"]: r["tools_hit"] for r in results}
        self.assertEqual(hit, {"dana": ["get-order-status"], "ravi": ["lookup_customer"],
                               "mei": ["email_receipt"], "omar": [], "lena": []})
        self.assertFalse(lab.state()["config_signature_valid"])

    def test_every_targeted_reply_is_still_correct(self):
        lab = attacked()
        for (_, a, q, tg, e) in suite():
            result = lab.ask(a, q)
            if tg:
                self.assertEqual(classify(result, e), "RED")
                self.assertEqual(classify({"final_reply": result["final_reply"]}, e), "GREEN")

    def test_the_leaked_value_is_the_customers_reference(self):
        lab = attacked()
        result = lab.ask(CUSTOMERS[1][0], CUSTOMERS[1][1])
        ref = lab.account_ref["ravi"]
        self.assertTrue(any(ref in p for p in result["shadow_received"]))
        self.assertNotIn(ref, result["final_reply"])

    def test_act4_hardened_returns_to_zero_and_keeps_the_tasks(self):
        lab = attacked("hardened")
        statuses, ser, _, results = run_suite(lab)
        self.assertEqual(ser, 0)
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)
        self.assertEqual(lab.attacker_log(), [])
        self.assertEqual(results[0]["held_by"], ["egress_allowlist", "signed_config"])
        self.assertTrue(any("signature mismatch" in e for e in results[0]["events"]))

    def test_hardened_baseline_has_nothing_held(self):
        lab = Lab(mode="hardened")
        statuses, _, _, results = run_suite(lab)
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)
        self.assertTrue(all(r["held_by"] == [] for r in results))

    def test_reset_restores_baseline(self):
        lab = attacked()
        before = lab.account_ref["dana"]
        run_suite(lab)
        lab.reset()
        state = lab.state()
        self.assertTrue(state["baseline"])
        self.assertEqual(state["config_servers"], ["flock-tools", "barn-docs"])
        self.assertTrue(state["config_signature_valid"])
        self.assertEqual(state["discovered"], [])
        self.assertNotIn(SHADOW_URL, state["network"])
        self.assertEqual(lab.attacker_log(), [])
        self.assertNotEqual(lab.account_ref["dana"], before)
        _, ser, _, _ = run_suite(lab)
        self.assertEqual(ser, 0)

    def test_guards(self):
        lab = Lab()
        with self.assertRaises(ValueError):
            lab.ask("nobody", "hi")
        with self.assertRaises(ValueError):
            lab.ask("dana", "   ")
        held = []
        for url in ("https://example.com/mcp", "http://127.0.0.2:5516/mcp/flock-tools", "file:///etc/passwd"):
            with self.subTest(url=url):
                self.assertIsNone(lab.connect(url, held))
        self.assertEqual(lab.ask("dana", "Tell me a joke")["final_reply"][:12], "I can help w")


class LayersTest(unittest.TestCase):
    """Each hardened layer alone, measured (run_demo.py prints the same numbers)."""

    def statuses(self, layer):
        statuses, ser, _, results = run_suite(attacked("hardened", **only(layer)))
        return [s for s, t in statuses if t], round(ser, 4), results

    def test_signed_config_alone_is_undone_by_discovery(self):
        statuses, ser, results = self.statuses("use_signed_config")
        self.assertEqual((statuses, ser), (["RED", "RED", "RED"], 1.0))
        self.assertEqual(results[0]["held_by"], ["signed_config"])

    def test_server_inventory_alone_stops_both_paths(self):
        statuses, ser, results = self.statuses("use_inventory")
        self.assertEqual((statuses, ser), (["GREEN", "GREEN", "GREEN"], 0))
        events = results[0]["events"]
        self.assertTrue(any("'Flock Tools Plus' (config" in e for e in events))

    def test_exact_name_alone_misses_the_new_name(self):
        statuses, ser, _ = self.statuses("use_exact_name")
        self.assertEqual((statuses, ser), (["GREEN", "GREEN", "RED"], round(1 / 3, 4)))

    def test_overlap_alone_misses_the_reworded_lookalike(self):
        statuses, ser, _ = self.statuses("use_overlap")
        self.assertEqual((statuses, ser), (["RED", "GREEN", "GREEN"], round(1 / 3, 4)))

    def test_egress_alone_stops_both_paths(self):
        statuses, ser, results = self.statuses("use_egress")
        self.assertEqual((statuses, ser), (["GREEN", "GREEN", "GREEN"], 0))
        self.assertEqual(results[0]["held_by"], ["egress_allowlist"])


class ClientMechanicsTest(unittest.TestCase):
    def test_vulnerable_merge_lets_the_later_server_win_a_name(self):
        lab = attacked()
        tools = {t["name"]: t["server"] for t in lab.session().tools}
        self.assertEqual(tools["lookup_customer"], SHADOW_URL)
        self.assertEqual(tools["get_order_status"], BASE + "/mcp/flock-tools")
        self.assertIn("get-order-status", tools)

    def test_stand_in_prefers_the_wordier_shadow_description(self):
        lab = attacked()
        tools = lab.session().tools
        self.assertEqual(StubModel().choose(CUSTOMERS[0][1], tools), "get-order-status")
        self.assertEqual(StubModel().choose(CUSTOMERS[2][1], tools), "email_receipt")
        self.assertEqual(StubModel().choose(CUSTOMERS[3][1], tools), "search_docs")
        self.assertEqual(StubModel().choose(CUSTOMERS[4][1], tools), "get_store_hours")
        self.assertEqual(StubModel().choose("hello there", tools), "")

    def test_fold_and_overlap_scores(self):
        self.assertEqual(fold_name("get-order-status"), fold_name("get_order_status"))
        self.assertNotEqual(fold_name("email_receipt"), fold_name("send_receipt"))
        shadow = {t["name"]: t for t in load_shadow()["tools"]}
        approved = {t["name"]: t for s in vulnerable_app.CONFIG["sanctioned"] for t in s["tools"]}
        self.assertGreaterEqual(overlap(shadow["email_receipt"], approved["send_receipt"]), OVERLAP_THRESHOLD)
        self.assertLess(overlap(shadow["get-order-status"], approved["get_order_status"]), OVERLAP_THRESHOLD)
        self.assertEqual(round(overlap(shadow["email_receipt"], approved["send_receipt"]), 2), 0.89)
        self.assertEqual(round(overlap(shadow["get-order-status"], approved["get_order_status"]), 2), 0.25)

    def test_signature_rejects_any_edit(self):
        key = b"k" * 32
        cfg = {"servers": [{"id": "flock-tools", "url": "/mcp/flock-tools"}], "auto_discover": True}
        sig = sign_config(cfg, key)
        self.assertTrue(verify_config(cfg, sig, key))
        for edit in ({**cfg, "auto_discover": False}, {**cfg, "servers": cfg["servers"] + [{"id": "x", "url": "/x"}]}):
            self.assertFalse(verify_config(edit, sig, key))
        self.assertFalse(verify_config(cfg, sig, b"j" * 32))

    def test_inventory_keys_on_id_url_and_publisher_not_name(self):
        lab = attacked("hardened", **only("use_inventory"))
        lab.config["servers"] = lab.config["servers"][:2]           # leave only the discovery path
        events = lab.ask("dana", CUSTOMERS[0][1])["events"]
        self.assertTrue(any("'Flock Tools Plus' (discovery, id 'flock-tools-plus'" in e for e in events))

    def test_discovery_alone_brings_the_shadow_in(self):
        lab = attacked()
        lab.config["servers"] = lab.config["servers"][:2]
        self.assertEqual(classify(lab.ask("ravi", CUSTOMERS[1][1])), "RED")
        lab.config["auto_discover"] = False
        self.assertEqual(classify(lab.ask("ravi", CUSTOMERS[1][1]), CUSTOMERS[1][3]), "GREEN")

    def test_manifest_and_scan(self):
        self.assertEqual(MANIFEST["send_receipt"], "flock-tools")
        rows = {r["id"]: r["verdict"] for r in scan_attack()["rows"]}
        self.assertEqual(rows["config-edit"], "REJECT")
        self.assertEqual(rows["server-announced"], "REJECT")
        self.assertEqual(rows["egress"], "REJECT")
        self.assertEqual(rows["name:email_receipt"], "PASS")
        self.assertEqual(rows["overlap:get-order-status"], "PASS")
        self.assertEqual(rows["overlap:email_receipt"], "ALERT")
        for name in ("lookup_customer", "get-order-status", "email_receipt"):
            self.assertEqual(rows[f"screen:{name}"], "ALLOW")          # the text screen sees nothing
        self.assertEqual(scan_attack()["decision"], "REJECT")


class StandInTest(unittest.TestCase):
    def test_ties_go_to_the_first_offered(self):
        tools = [{"name": "a_order", "description": ""}, {"name": "b_order", "description": ""}]
        self.assertEqual(StubModel().choose("order", tools), "a_order")

    def test_parse_choice_is_defensive(self):
        self.assertEqual(parse_choice("not json", ["x"]), "")
        self.assertEqual(parse_choice('{"tool": "rm -rf"}', ["x"]), "")
        self.assertEqual(parse_choice('{"tool": 5}', ["x"]), "")
        self.assertEqual(parse_choice('```json\n{"tool": "x"}\n```', ["x"]), "x")


class LimitsTest(unittest.TestCase):
    """Where the defense stops working, as measured (the LESSON quotes these)."""

    def test_server_swapped_at_its_approved_url_passes_every_layer(self):
        row = probe_row()
        self.assertEqual(row["id"], LIMIT_ID)
        self.assertEqual(row["statuses"], ["RED", "RED", "RED"])
        self.assertEqual(row["held_by"], [])
        self.assertTrue(row["pin_unchanged"])
        self.assertTrue(all(classify({"final_reply": r["final_reply"]}, e) == "GREEN"
                            for r, (_, _, _, e) in zip(row["results"], CUSTOMERS)))

    def test_controls_are_hit_too_when_they_call_the_swapped_server(self):
        lab = Lab(mode="hardened")
        lab.load_limit(LIMIT_ID)
        lab.ask("lena", CUSTOMERS[4][1])
        self.assertEqual([r["tool"] for r in lab.attacker_log()], ["get_store_hours"])   # no reference sent


class ConsoleApiTest(unittest.TestCase):
    def test_console_four_acts(self):
        lab = Lab()
        self.assertEqual(console_evaluate(lab)["targeted_rate"], 0)
        self.assertEqual(len(console_attack(lab)["events"]), 3)
        hit = console_evaluate(lab)
        self.assertEqual(hit["targeted_rate"], 100)
        self.assertEqual(hit["overall_rate"], 60)
        scan = console_scan(lab)
        self.assertEqual(scan["decision"], "REJECT")
        self.assertEqual(len(scan["findings"]), 13)
        lab.set_mode("hardened")
        self.assertEqual(console_evaluate(lab)["targeted_rate"], 0)

    def test_meta_has_console_fields(self):
        for key in ("id", "framework", "risk", "title", "short_title", "scenario", "ground_truth",
                    "metric_name", "metric_abbr", "attack_label", "attack_description",
                    "scan_label", "harden_label", "harden_description"):
            self.assertIn(key, CONSOLE_META)
        self.assertEqual(CONSOLE_META["metric_abbr"], "SER")


class ConsoleHttpTest(unittest.TestCase):
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
        req = urllib.request.Request(url, data=data, headers=headers or {"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, json.loads(exc.read() or b"{}")

    def test_attack_over_http(self):
        self.assertEqual(self._call("/health")[1]["demo"], "hx16")
        self.assertEqual(self._call("/api/attack", {})[0], 200)
        status, result = self._call("/ask", {"account": "ravi", "message": CUSTOMERS[1][1]})
        self.assertEqual(status, 200)
        self.assertTrue(result["shadow_got_data"])
        log = self._call("/attacker-log")[1]["received"]
        self.assertTrue(any(vulnerable_app.LAB.account_ref["ravi"] in r["payload"] for r in log))
        self.assertTrue(self._call("/client-log")[1]["events"])
        self.assertTrue(self._call(f"/conversations/{result['conversation']}")[1]["shadow_got_data"])
        self.assertEqual(self._call("/conversations/nope")[0], 404)
        self.assertEqual(self._call("/ask", {"account": "nobody", "message": "hi"})[0], 400)
        status, state = self._call("/api/reset", {})
        self.assertEqual((state["baseline"], state["discovered"]), (True, []))

    def test_meta_models_backend(self):
        with unittest.mock.patch.dict(os.environ, {"OPENROUTER_API_KEY": "sk-test-secret"}):
            status, meta = self._call("/api/meta")
        self.assertEqual(status, 200)
        self.assertNotIn("sk-test-secret", json.dumps(meta))
        self.assertEqual(self._call("/api/models?backend=echo"), (200, {"backend": "echo", "models": []}))
        self.assertEqual(self._call("/api/models?backend=nope")[0], 400)
        self.assertEqual(self._call("/api/backend", {"backend": "stub"})[1]["backend"], "echo")
        self.assertEqual(self._call("/api/backend", {"backend": "nope"})[0], 400)
        self.assertEqual(self._call("/api/mode", {"mode": "nope"})[0], 400)

    def test_host_and_content_type_guards(self):
        self.assertEqual(self._call("/api/state", headers={"Host": "evil.example"})[0], 403)
        self.assertEqual(self._call("/api/reset", {}, headers={"Content-Type": "text/plain"})[0], 415)


class FakeProvider(providers.Provider):
    """Records what a real backend would be sent; no network."""
    name = "fake"

    def __init__(self, reply: str = '{"tool": "none"}') -> None:
        super().__init__()
        self.reply = reply
        self.sent = []

    def chat(self, messages, *, model=""):
        self._count_call()
        self.sent.append(messages)
        return self.reply


class BackendTest(unittest.TestCase):
    def test_model_sees_tool_names_never_a_reference(self):
        fake = FakeProvider()
        lab = attacked()
        lab.model = ProviderModel(fake, "fake-model")
        lab.ask("mei", CUSTOMERS[2][1])
        self.assertEqual(len(fake.sent), 1)
        self.assertEqual(fake.sent[0][0].role, "system")
        self.assertIn("email_receipt", fake.sent[0][1].content)
        self.assertFalse(any(ref in m.content for m in fake.sent[0] for ref in lab.references()))

    def test_hardened_offers_only_approved_tools(self):
        fake = FakeProvider()
        lab = attacked("hardened")
        lab.model = ProviderModel(fake, "fake-model")
        lab.ask("mei", CUSTOMERS[2][1])
        self.assertNotIn("email_receipt", fake.sent[0][1].content)

    def test_a_real_model_that_picks_the_shadow_tool_is_red_and_hardened_holds(self):
        reply = json.dumps({"tool": "email_receipt"})
        lab = attacked()
        lab.model = ProviderModel(FakeProvider(reply), "fake-model")
        self.assertEqual(classify(lab.ask("mei", CUSTOMERS[2][1])), "RED")
        hard = attacked("hardened")
        hard.model = ProviderModel(FakeProvider(reply), "fake-model")      # not offered: no tool, YELLOW
        self.assertEqual(classify(hard.ask("mei", CUSTOMERS[2][1]), CUSTOMERS[2][3]), "YELLOW")
        hard.model = ProviderModel(FakeProvider(json.dumps({"tool": "send_receipt"})), "fake-model")
        self.assertEqual(classify(hard.ask("mei", CUSTOMERS[2][1]), CUSTOMERS[2][3]), "GREEN")

    def test_a_same_name_collision_is_red_whatever_the_model(self):
        lab = attacked()
        lab.model = ProviderModel(FakeProvider(json.dumps({"tool": "lookup_customer"})), "fake-model")
        self.assertEqual(classify(lab.ask("ravi", CUSTOMERS[1][1])), "RED")

    def test_default_backend_and_switching(self):
        self.assertEqual(Lab().backend, "echo")
        self.assertEqual(Lab(backend="stub").backend, "echo")
        lab = Lab(mode="hardened")
        with unittest.mock.patch.object(providers, "get_provider", return_value=FakeProvider()):
            lab.set_backend("ollama", "gemma3:4b")
        self.assertEqual((lab.backend, lab.mode), ("ollama:gemma3:4b", "hardened"))
        self.assertIsInstance(lab.model, ProviderModel)
        with self.assertRaises(ValueError):
            lab.set_backend("ollama", "bad model; rm")
        with self.assertRaises(ValueError):
            lab.set_backend("nope")

    def test_openrouter_needs_a_key(self):
        with unittest.mock.patch.dict(os.environ, {"OPENROUTER_API_KEY": ""}):
            with self.assertRaises((ValueError, RuntimeError)):
                Lab(backend="openrouter")

    def test_call_cap(self):
        fake = FakeProvider()
        fake.max_calls = 0
        lab = attacked()
        lab.model = ProviderModel(fake, "fake-model")
        with self.assertRaises(RuntimeError):
            lab.ask("mei", CUSTOMERS[2][1])


if __name__ == "__main__":
    unittest.main()
