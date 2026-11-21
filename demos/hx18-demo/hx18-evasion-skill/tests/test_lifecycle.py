"""Lifecycle tests: the four-act story, each layer alone, what the attack depends on, the cost, the limits.

Run from the skill folder:  python -m unittest discover tests
"""

from __future__ import annotations

import copy
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

import providers  # noqa: E402
import vulnerable_app  # noqa: E402
from evaluate_kpi import (  # noqa: E402
    LIMIT_ID, SPREAD_ID, classify, held_by, heldout_rates, probe_result, run_item, suite,
)
from run_evasion import campaign, fgsm, lab_api, pgd  # noqa: E402
from vulnerable_app import (  # noqa: E402
    PIXELS, Lab, PixelModel, claim_photo, console_attack, console_evaluate, console_scan, corner_rule,
    feature_problem, load_plan, plan_by_id, quantize,
)

LAYERS = ("use_feature_validation", "use_adversarial_training", "use_cross_check", "use_query_budget")
PLANS = {e["id"]: e for e in load_plan()["attacks"] + load_plan()["limits"]}


def statuses(lab):
    lab.new_day()
    return {item["claim_id"]: (classify(r := run_item(lab, item)), r) for item in suite(lab.attack_loaded)}


def targeted_rate(rows):
    t = [s for cid, (s, r) in rows.items() if r["targeted"]]
    return sum(s == "RED" for s in t) / len(t)


def attacked_lab(mode="vulnerable", **layers):
    lab = Lab(mode=mode)
    for name, value in layers.items():
        setattr(lab, name, value)
    lab.load_attack()
    return lab


def variant(plan_id, mode="vulnerable", **changes):
    lab = Lab(mode=mode)
    lab.new_day()
    entry = {**copy.deepcopy(PLANS[plan_id]), **changes}
    run = campaign(lab_api(lab), entry, claim_photo(lab.claims[entry["claim_id"]]))
    return run, lab.outcome(entry["account"], entry["claim_id"])


class LifecycleTest(unittest.TestCase):
    def test_act1_baseline_all_green(self):
        rows = statuses(Lab())
        self.assertEqual({s for s, _ in rows.values()}, {"GREEN"})
        for cid, (s, r) in rows.items():
            self.assertEqual(r["decision"], "denied" if r["targeted"] else "approved", cid)

    def test_act3_every_fraud_claim_is_paid_controls_untouched(self):
        rows = statuses(attacked_lab())
        for cid, (s, r) in rows.items():
            if r["targeted"]:
                self.assertEqual((s, r["decision"], r["record"]), ("RED", "approved", "intact"), cid)
                self.assertTrue(r["canary_received"])
            else:
                self.assertEqual((s, r["decision"]), ("GREEN", "approved"), cid)
        self.assertEqual(targeted_rate(rows), 1.0)
        overall = sum(s == "RED" for s, _ in rows.values()) / len(rows)
        self.assertAlmostEqual(overall, 0.6)

    def test_the_perturbations_are_small(self):
        rows = statuses(attacked_lab())
        self.assertEqual(rows["CL-1041"][1]["linf"], 0.03)
        self.assertEqual(rows["CL-1077"][1]["linf"], round(7 / 255, 4))
        self.assertLessEqual(rows["CL-1093"][1]["linf"], 0.10)
        self.assertEqual((rows["CL-1041"][1]["prechecks"], rows["CL-1093"][1]["prechecks"]), (0, 11))

    def test_act4_hardened_returns_to_zero_and_pays_the_controls(self):
        rows = statuses(attacked_lab("hardened"))
        self.assertEqual(targeted_rate(rows), 0.0)
        for cid, (s, r) in rows.items():
            self.assertEqual(s, "GREEN", cid)
            if not r["targeted"]:
                self.assertEqual(r["decision"], "approved")
                self.assertEqual(held_by(r), [])
        self.assertEqual(rows["CL-1041"][1]["decision"], "rejected")
        self.assertEqual(held_by(rows["CL-1041"][1]), ["feature validation (photo rejected)"])
        self.assertEqual(held_by(rows["CL-1077"][1]), ["adversarial training (the served model still says intact)"])
        self.assertEqual(held_by(rows["CL-1093"][1]), ["pre-check budget (1 refused)",
                                                       "adversarial training (the served model still says intact)"])

    def test_reset_restores_baseline(self):
        lab = attacked_lab("hardened")
        statuses(lab)
        lab.reset()
        lab.set_mode("vulnerable")
        state = lab.state()
        self.assertEqual((state["baseline"], state["accounts"], state["review_queue"]), (True, [], []))
        self.assertEqual({s for s, _ in statuses(lab).values()}, {"GREEN"})

    def test_guards(self):
        lab = Lab()
        photo = claim_photo(lab.claims["CL-1041"])
        for bad in ([0.5] * 63, "x", [True] * PIXELS, [float("nan")] * PIXELS, [99.0] * PIXELS):
            with self.subTest(bad=str(bad)[:20]), self.assertRaises(ValueError):
                lab.precheck("acct-fox", bad)
        with self.assertRaises(ValueError):
            lab.precheck("Fox!", photo)
        with self.assertRaises(ValueError):
            lab.submit_claim("acct-wren", "CL-1041", photo)     # not this account's claim
        lab.submit_claim("acct-fox", "CL-1041", photo)
        with self.assertRaises(ValueError):
            lab.submit_claim("acct-fox", "CL-1041", photo)     # one decision per claim per day
        self.assertNotIn(lab.canary, json.dumps(lab.state()))


class LayersTest(unittest.TestCase):
    def alone(self, name):
        lab = attacked_lab("hardened", **{o: o == name for o in LAYERS})
        rows = statuses(lab)
        return {cid: s for cid, (s, r) in rows.items() if r["targeted"]}, rows

    def test_feature_validation_alone_stops_only_the_raw_floats(self):
        got, _ = self.alone("use_feature_validation")
        self.assertEqual(got, {"CL-1041": "GREEN", "CL-1077": "RED", "CL-1093": "RED"})

    def test_adversarial_training_alone_loses_to_the_larger_search(self):
        got, _ = self.alone("use_adversarial_training")
        self.assertEqual(got, {"CL-1041": "GREEN", "CL-1077": "GREEN", "CL-1093": "RED"})

    def test_cross_check_alone_sends_all_three_to_review(self):
        got, rows = self.alone("use_cross_check")
        self.assertEqual(set(got.values()), {"GREEN"})
        self.assertEqual({rows[c][1]["decision"] for c in got}, {"review"})

    def test_budget_alone_stops_only_the_search(self):
        got, rows = self.alone("use_query_budget")
        self.assertEqual(got, {"CL-1041": "RED", "CL-1077": "RED", "CL-1093": "GREEN"})
        self.assertEqual(rows["CL-1093"][1]["refused"], 1)

    def test_no_layer_is_the_vulnerable_mode(self):
        lab = attacked_lab("hardened", **{o: False for o in LAYERS})
        self.assertEqual(targeted_rate(statuses(lab)), 1.0)


class AttackDependsOnTest(unittest.TestCase):
    def test_a_smaller_step_is_not_paid(self):
        for plan_id in ("fgsm-float", "pgd-8bit"):
            with self.subTest(plan_id):
                self.assertEqual(variant(plan_id, epsilon=0.015)[1]["decision"], "denied")
                self.assertEqual(variant(plan_id)[1]["decision"], "approved")

    def test_the_search_needs_its_queries(self):
        run, out = variant("block-search", max_queries=3)
        self.assertEqual(out["decision"], "denied")
        run, out = variant("block-search")
        self.assertEqual((run["prechecks"], out["decision"]), (11, "approved"))

    def test_the_step_follows_the_weights(self):
        lab = Lab()
        x = claim_photo(lab.claims["CL-1041"])
        flipped = PixelModel([-w for w in lab.production.weights], lab.production.bias)
        self.assertFalse(lab.production.damaged(fgsm(flipped, x, 0.03, True)))   # the wrong direction
        self.assertTrue(lab.production.damaged(fgsm(lab.production, x, 0.03, True)))

    def test_crafted_photos_stay_in_the_box(self):
        lab = Lab()
        x = claim_photo(lab.claims["CL-1077"])
        z = pgd(lab.production, x, 0.03, 10, 0.01)
        self.assertEqual(feature_problem(z), "")
        self.assertLessEqual(max(abs(a - b) for a, b in zip(z, x)), 0.03)
        self.assertNotEqual(feature_problem(fgsm(lab.production, x, 0.03, False)), "")

    def test_photos_are_camera_images_and_deterministic(self):
        lab = Lab()
        for claim in lab.claims.values():
            x = claim_photo(claim)
            self.assertEqual((len(x), feature_problem(x), x), (PIXELS, "", claim_photo(claim)))
            self.assertEqual(x, quantize(x))


class CostTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rates = heldout_rates()

    def test_clean_accuracy_cost_is_measured(self):
        r = self.rates
        self.assertEqual((r["clean_production"], r["clean_robust"]), (0.99, 0.955))
        self.assertEqual((r["production_paid_damaged"], r["hardened_paid_damaged"]), (0.98, 0.775))
        self.assertEqual((r["hardened_review_damaged"], r["hardened_paid_intact"]), (0.135, 0.0))

    def test_adversarial_training_resists_the_step_it_was_trained_for(self):
        self.assertEqual((self.rates["fgsm_production"], self.rates["fgsm_robust"]), (0.57, 0.025))

    def test_the_trained_model_has_smaller_weights_and_leans_less_on_the_depot_cue(self):
        checker = [1 if (i // 8 + i % 8) % 2 else -1 for i in range(PIXELS)]
        lab = Lab()
        pull = [round(0.012 * sum(w * c for w, c in zip(m.weights, checker)), 2) for m in (lab.production, lab.robust)]
        self.assertEqual(pull, [0.63, 0.29])
        self.assertEqual((round(lab.production.l1(), 1), round(lab.robust.l1(), 1)), (101.5, 31.2))

    def test_adaptive_sweep(self):
        self.assertEqual(self.rates["adaptive"], {0.08: 0.0, 0.10: 0.10, 0.12: 0.96})

    def test_the_corner_rule_moves_at_most_twice_epsilon(self):
        lab = Lab()
        x = claim_photo(lab.claims["CL-1041"])
        base = vulnerable_app.crush_score(x)
        for z in (fgsm(lab.production, x, 0.03, True), quantize([v + 0.03 for v in x])):
            self.assertLessEqual(abs(vulnerable_app.crush_score(z) - base), 2 * 0.03 + 1e-9)
        self.assertFalse(corner_rule(x, lab.policy["crush_line"]))


class LimitsTest(unittest.TestCase):
    def test_adaptive_attack_at_012_is_paid_through_every_layer(self):
        r = probe_result(LIMIT_ID)
        self.assertEqual((r["status"], r["decision"], r["record"], r["prechecks"]), ("RED", "approved", "intact", 0))
        self.assertTrue(r["canary_received"])
        self.assertLessEqual(r["linf"], 0.12)

    def test_adaptive_attack_at_010_is_denied_for_this_claim(self):
        run, out = variant(LIMIT_ID, mode="hardened", epsilon=0.10)
        self.assertNotEqual(out["decision"], "approved")

    def test_spread_search_passes_the_budget_and_the_cross_check_holds(self):
        r = probe_result(SPREAD_ID)
        self.assertEqual((r["status"], r["decision"], r["refused"]), ("GREEN", "review", 0))
        lab = Lab(mode="hardened")
        lab.use_cross_check = False
        r = probe_result(SPREAD_ID, lab)
        self.assertEqual((r["status"], r["refused"]), ("RED", 0))

    def test_one_account_with_the_same_search_is_stopped_by_the_budget(self):
        lab = Lab(mode="hardened")
        lab.use_cross_check = False
        lab.new_day()
        entry = {**PLANS[SPREAD_ID], "accounts": [PLANS[SPREAD_ID]["account"]]}
        run = campaign(lab_api(lab), entry, claim_photo(lab.claims[entry["claim_id"]]))
        self.assertEqual((run["refused"], run["decision"]), (1, "denied"))

    def test_variants_the_plan_readme_quotes(self):
        run, out = variant("fgsm-float", mode="hardened", grid=True)
        self.assertEqual(out["decision"], "denied")              # past validation, the trained model holds
        run, out = variant("pgd-8bit", mode="hardened", epsilon=0.06)
        self.assertFalse(out["second_opinion"])                  # the corner rule still says intact
        self.assertNotEqual(out["decision"], "approved")


class ScanTest(unittest.TestCase):
    def test_scan_flags_the_raw_floats_and_the_cross_check(self):
        scan = console_scan(Lab())
        self.assertEqual(scan["decision"], "REJECT")
        self.assertEqual(len(scan["findings"]), 3)
        self.assertIn("8-bit", scan["findings"][0] + scan["findings"][0])
        self.assertTrue(all("intact" in f for f in scan["findings"]))


class ConsoleApiTest(unittest.TestCase):
    def test_console_four_acts(self):
        lab = Lab()
        self.assertEqual(console_evaluate(lab)["targeted_rate"], 0.0)
        self.assertEqual(len(console_attack(lab)["events"]), 3)
        after = console_evaluate(lab)
        self.assertEqual((after["targeted_rate"], after["overall_rate"]), (100.0, 60.0))
        lab.set_mode("hardened")
        self.assertEqual(console_evaluate(lab)["targeted_rate"], 0.0)
        lab.reset()
        lab.set_mode("vulnerable")
        self.assertEqual(console_evaluate(lab)["targeted_rate"], 0.0)

    def test_meta_has_console_fields(self):
        for key in ("id", "framework", "risk", "title", "short_title", "scenario", "ground_truth", "metric_name",
                    "metric_abbr", "attack_label", "attack_description", "scan_label", "harden_label",
                    "harden_description"):
            self.assertIn(key, vulnerable_app.CONSOLE_META)


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
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, json.loads(exc.read() or b"{}")

    def test_evasion_over_http(self):
        self.assertEqual(self._call("/health")[1]["demo"], "hx18")
        model = PixelModel.from_dict(self._call("/app/model")[1])
        lab = vulnerable_app.LAB
        x = claim_photo(lab.claims["CL-1041"])
        status, check = self._call("/v1/precheck", {"account": "acct-fox", "photo": x})
        self.assertEqual((status, check["label"]), (200, "intact"))
        z = fgsm(model, x, 0.03, True)
        status, answer = self._call("/v1/claims", {"account": "acct-fox", "claim_id": "CL-1041", "photo": z})
        self.assertEqual(answer["decision"], "approved")
        out = self._call("/lab/outcome", {"account": "acct-fox", "claim_id": "CL-1041"})[1]
        self.assertTrue(out["canary_received"])
        self.assertEqual(self._call("/v1/claims", {"account": "acct-fox", "claim_id": "CL-1041", "photo": z})[0], 400)
        self.assertEqual(self._call("/v1/precheck", {"account": "acct-fox", "photo": [1]})[0], 400)
        self.assertEqual(self._call("/lab/outcome", {"claim_id": "nope"})[0], 400)
        self.assertNotIn("record", json.dumps(self._call("/claims")[1]))
        self._call("/api/mode", {"mode": "hardened"})
        raw = fgsm(model, x, 0.03, False)
        self.assertIn("rejected", self._call("/v1/precheck", {"account": "acct-fox", "photo": raw})[1])
        status, state = self._call("/api/reset", {})
        self.assertEqual((state["accounts"], state["baseline"], state["mode"]), ([], True, "vulnerable"))
        self.assertNotIn(lab.canary, json.dumps(state))

    def test_meta_models_backend(self):
        with unittest.mock.patch.dict(os.environ, {"OPENROUTER_API_KEY": "sk-test-secret"}):
            status, meta = self._call("/api/meta")
        self.assertEqual(status, 200)
        self.assertNotIn("sk-test-secret", json.dumps(meta))
        self.assertEqual(self._call("/api/models?backend=echo"), (200, {"backend": "echo", "models": []}))
        self.assertEqual(self._call("/api/models?backend=nope")[0], 400)
        self.assertEqual(self._call("/api/backend", {"backend": "stub"})[1]["backend"], "echo")
        self.assertEqual(self._call("/api/backend", {"backend": "nope"})[0], 400)
        self.assertEqual(self._call("/api/backend", {"backend": "ollama"})[0], 400)
        self.assertEqual(self._call("/api/mode", {"mode": "nope"})[0], 400)
        self.assertEqual(self._call("/api/evaluate", {})[1]["targeted_rate"], 0.0)

    def test_host_and_content_type_guards(self):
        self.assertEqual(self._call("/api/state", headers={"Host": "evil.example"})[0], 403)
        self.assertEqual(self._call("/api/reset", {}, headers={"Content-Type": "text/plain"})[0], 415)


class BackendTest(unittest.TestCase):
    def test_echo_only(self):
        self.assertEqual(Lab().backend, "echo")
        self.assertEqual(Lab(backend="stub").backend, "echo")
        for name in ("ollama", "llamacpp", "openrouter", "nope"):
            with self.subTest(name), self.assertRaises(ValueError):
                Lab(backend=name)
        lab = Lab(mode="hardened")
        with self.assertRaises(ValueError):
            lab.set_backend("echo", "bad model; rm")
        lab.set_backend("stub")
        self.assertEqual((lab.backend, lab.mode), ("echo", "hardened"))

    def test_providers_is_the_shared_copy(self):
        self.assertTrue(hasattr(providers, "canary_leaked"))


class PayloadSafetyTest(unittest.TestCase):
    def test_plans_target_only_the_lab(self):
        text = json.dumps(load_plan()).lower()
        for bad in ("http", "://", "@", "password", "api key", "rm -", "sudo", ".ssh", "/etc/"):
            with self.subTest(bad=bad):
                self.assertNotIn(bad, text)
        claims = {c["claim_id"]: c["account"] for c in vulnerable_app.load_claims()}
        for entry in PLANS.values():
            self.assertEqual(claims[entry["claim_id"]], entry["account"])
            self.assertEqual(plan_by_id(entry["id"]), entry)


if __name__ == "__main__":
    unittest.main()
