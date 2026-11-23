"""Lifecycle tests — assert the four-act story against the in-process lab.

Baseline is all GREEN; the three extraction plans leave each rival key with a
stolen model and the controls untouched; hardened mode returns the rate to 0
without refusing a control, and each layer alone is measured; reset restores
the baseline. The attack is tested for what it depends on (confidences, the
number of answers, what the queries look like), the watermark for proving a
clone without accusing an independent model, and the measured limit (40
keys under every per-key limit) is asserted as measured.

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

from evaluate_kpi import classify, probe_result, run_item, suite  # noqa: E402
import providers  # noqa: E402
import vulnerable_app  # noqa: E402
from run_extraction import campaign, equation_solve, plan_queries, train_perceptron  # noqa: E402
from vulnerable_app import (  # noqa: E402
    AGREEMENT_THRESHOLD, CLASSES, CONSOLE_META, REFUSED_BUDGET, REFUSED_SUSPENDED, Lab, as_listing,
    as_vector, audit_plan, competitor_model, console_attack, console_evaluate, console_scan, implausible,
    load_plan, plan_by_id, validate_listing,
)

LAYERS = ("use_label_only", "use_rate_limit", "use_query_anomaly", "use_output_watermark")
PLANS = {e["id"]: e for e in load_plan()["attacks"]}


def run_suite(lab: Lab):
    lab.new_day()
    rows = [(run_item(lab, item), item["targeted"]) for item in suite(lab.attack_loaded)]
    statuses = [(classify(r), t) for r, t in rows]
    targeted = [s for s, t in statuses if t]
    return statuses, rows, sum(s == "RED" for s in targeted) / len(targeted)


def attacked(mode: str = "vulnerable") -> Lab:
    lab = Lab(mode=mode)
    lab.load_attack()
    return lab


def only(layer: str) -> Lab:
    lab = attacked("hardened")
    for name in LAYERS:
        setattr(lab, name, name == layer)
    return lab


def plan(entry_id: str, **changes):
    return {**plan_by_id(entry_id), **changes}


class LifecycleTest(unittest.TestCase):
    def test_act1_baseline_all_green(self):
        lab = Lab()
        statuses, rows, csr = run_suite(lab)
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)
        self.assertEqual(csr, 0)
        self.assertTrue(all(not r["clone"] for r, _ in rows))
        self.assertTrue(lab.state()["baseline"])

    def test_act3_every_rival_holds_a_stolen_model_controls_untouched(self):
        statuses, rows, csr = run_suite(attacked())
        self.assertEqual(csr, 1.0)
        agree = {r["key"]: r["agreement"] for r, t in rows if t}
        # run_demo, README and LESSON: 100.0%, 98.8%, 99.1%.
        self.assertEqual(agree, {"rival-eq": 1.0, "rival-rand": 0.988, "rival-list": 0.991})
        self.assertTrue(all(r["from_api"] for r, t in rows if t))
        self.assertEqual([s for s, _ in statuses], ["RED", "RED", "RED", "GREEN", "GREEN"])
        for r, targeted in rows:
            if targeted:
                self.assertTrue(r["lookup_ok"])                     # RED next to true facts
                self.assertGreaterEqual(r["agreement"], AGREEMENT_THRESHOLD)
            else:
                self.assertEqual((r["refused"], r["wrong_bands"]), (0, 0))

    def test_equation_solving_recovers_the_exact_weights_and_the_canary(self):
        lab = Lab()
        run = campaign(lab.predict, PLANS["equation-solving"], lab.catalog)
        self.assertEqual((run["method"], run["answered"]), ("equation_solving", 8))
        for p, q in zip(run["clone"].parameters(), lab.model.parameters()):
            self.assertAlmostEqual(p, q, places=8)
        grade = lab.grade_clone(run["clone"])
        self.assertTrue(grade["canary_recovered"])
        self.assertEqual(grade["agreement"], 1.0)

    def test_retraining_needs_only_the_bands(self):
        lab = Lab()
        run = campaign(lab.predict, PLANS["random-retrain"], lab.catalog)
        grade = lab.grade_clone(run["clone"])
        self.assertEqual(run["method"], "retrain")
        self.assertGreaterEqual(grade["agreement"], AGREEMENT_THRESHOLD)
        self.assertFalse(grade["canary_recovered"])                   # a functional copy, not the weights

    def test_act4_hardened_returns_to_zero_and_serves_the_controls(self):
        statuses, rows, csr = run_suite(attacked("hardened"))
        self.assertEqual(csr, 0)
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)
        by_key = {r["key"]: r for r, _ in rows}
        self.assertEqual(by_key["jumper-shop"]["refused"], 0)
        self.assertEqual(by_key["feed-partner"]["refused"], 0)
        self.assertEqual(by_key["rival-rand"]["refusals"], [REFUSED_SUSPENDED])
        self.assertEqual(by_key["rival-list"]["refusals"], [REFUSED_BUDGET])
        self.assertEqual(by_key["rival-eq"]["method"], "retrain")       # no confidences to solve with
        # run_demo and LESSON: 48.5%, 49.0% after 19 answers, 86.7% at the budget of 50.
        self.assertEqual({k: by_key[k]["agreement"] for k in ("rival-eq", "rival-rand", "rival-list")},
                         {"rival-eq": 0.485, "rival-rand": 0.49, "rival-list": 0.867})
        self.assertEqual(by_key["rival-rand"]["answered"], 19)

    def test_reset_restores_baseline(self):
        lab = attacked("hardened")
        run_suite(lab)
        lab.reset()
        lab.set_mode("vulnerable")
        self.assertTrue(lab.state()["baseline"])
        self.assertEqual(lab.state()["keys"], [])
        _, _, csr = run_suite(lab)
        self.assertEqual(csr, 0)

    def test_guards(self):
        lab = Lab()
        good = as_listing(as_vector({**lab.catalog[0]}))
        for bad in ("", "UPPER", "a", "x" * 40, "has space", None):
            with self.subTest(key=bad), self.assertRaises(ValueError):
                lab.predict(bad, [good])
        with self.assertRaises(ValueError):
            lab.predict("k-one", [])
        with self.assertRaises(ValueError):
            lab.predict("k-one", [good] * (vulnerable_app.MAX_BATCH + 1))
        for field, value in (("weight_kg", 99.0), ("organic", 0.5), ("rating", "5"), ("supplier_tier", True),
                             ("demand_index", float("nan"))):
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_listing({**good, field: value})
        with self.assertRaises(ValueError):
            validate_listing({k: v for k, v in good.items() if k != "rating"})
        with unittest.mock.patch.object(vulnerable_app, "MAX_KEYS", 2):
            lab.predict("k-one", [good])
            lab.predict("k-two", [good])
            with self.assertRaises(ValueError):
                lab.predict("k-three", [good])


class LayersTest(unittest.TestCase):
    """Each hardened layer alone on the attack (run_demo.py prints these)."""

    def rates(self, layer):
        statuses, rows, csr = run_suite(only(layer))
        return [s for s, t in statuses if t], rows, csr

    def test_label_only_alone(self):
        statuses, _, csr = self.rates("use_label_only")
        self.assertEqual(statuses, ["GREEN", "RED", "RED"])        # the bands alone still train a clone
        self.assertAlmostEqual(csr, 2 / 3)

    def test_rate_limit_alone(self):
        statuses, _, csr = self.rates("use_rate_limit")
        self.assertEqual(statuses, ["RED", "GREEN", "GREEN"])        # 8 queries fit any budget
        self.assertAlmostEqual(csr, 1 / 3)

    def test_query_anomaly_alone(self):
        statuses, _, csr = self.rates("use_query_anomaly")
        self.assertEqual(statuses, ["RED", "GREEN", "RED"])          # too few to judge; real-looking queries pass
        self.assertAlmostEqual(csr, 2 / 3)

    def test_output_watermark_alone_stops_nothing_and_proves_every_clone(self):
        statuses, rows, csr = self.rates("use_output_watermark")
        self.assertEqual(statuses, ["RED", "RED", "RED"])
        self.assertEqual(csr, 1.0)
        self.assertTrue(all(r["theft_proven"] for r, t in rows if t))

    def test_clones_from_the_unwatermarked_api_are_not_proven(self):
        _, rows, _ = run_suite(attacked())
        self.assertFalse(any(r["theft_proven"] for r, t in rows if t))


class AttackDependsOnTest(unittest.TestCase):
    """The clone's quality depends on what the API returns and how much, not on hidden switches."""

    def agreement(self, entry, lab=None):
        lab = lab or Lab()
        return lab.grade_clone(campaign(lab.predict, entry, lab.catalog)["clone"])["agreement"]

    def test_more_answers_better_clone(self):
        small = self.agreement(plan("listing-retrain", queries=50))
        large = self.agreement(plan("listing-retrain", queries=2000))
        self.assertLess(small, AGREEMENT_THRESHOLD)
        self.assertGreaterEqual(large, AGREEMENT_THRESHOLD)
        self.assertLess(small, large)

    def test_seven_confidences_are_not_enough_eight_are(self):
        lab = Lab()
        X = plan_queries(PLANS["equation-solving"], lab.catalog)["rival-eq"]
        conf = [a["confidence"] for a in lab.predict("solver", [as_listing(x) for x in X])]
        self.assertIsNone(equation_solve(X[:7], conf[:7]))
        self.assertTrue(lab.grade_clone(equation_solve(X, conf))["canary_recovered"])

    def test_perceptron_learns_from_labels(self):
        lab = Lab()
        X = [x for x in lab.heldout[:300]]
        y = [lab.model.predict(x) for x in X]
        self.assertGreater(lab.grade_clone(train_perceptron([list(x) for x in X], y))["agreement"], 0.9)

    def test_query_streams_are_deterministic_and_inside_the_api_ranges(self):
        for entry in load_plan()["attacks"] + load_plan()["limits"]:
            with self.subTest(entry["id"]):
                a, b = plan_queries(entry, Lab().catalog), plan_queries(entry, Lab().catalog)
                self.assertEqual(a, b)
                for stream in a.values():
                    for x in stream:
                        validate_listing(as_listing(x))


class WatermarkTest(unittest.TestCase):
    def test_cost_is_small_and_measured(self):
        lab = Lab()
        moved = sum(lab.served_watermarked.predict(x) != lab.model.predict(x) for x in lab.heldout) / len(lab.heldout)
        self.assertGreater(moved, 0)
        self.assertLess(moved, 0.03)
        lookups = {"GC-0007", "GC-0018", "GC-0033", "GC-0042", "GC-0058"}
        for li in lab.catalog:
            if li["id"] in lookups:
                self.assertEqual(lab.served_watermarked.predict(as_vector(li)), lab.model.predict(as_vector(li)))

    def test_independent_model_is_not_accused(self):
        g = Lab().grade_clone(competitor_model())
        self.assertFalse(g["theft_proven"])
        self.assertLess(g["watermark_share"], Lab().policy["watermark_proof_share"])

    def test_the_served_model_changes_only_with_the_watermark_layer(self):
        lab = Lab(mode="hardened")
        self.assertIs(lab.served_model(), lab.served_watermarked)
        lab.use_output_watermark = False
        self.assertIs(lab.served_model(), lab.model)
        lab.set_mode("vulnerable")
        lab.use_output_watermark = True
        self.assertIs(lab.served_model(), lab.model)


class ScanTest(unittest.TestCase):
    def test_audit_of_the_plans(self):
        rows = {e["id"]: audit_plan(e) for e in load_plan()["attacks"]}
        self.assertFalse(rows["equation-solving"]["stopped"])          # 8 queries: nothing to see
        self.assertTrue(rows["random-retrain"]["anomalous"] and rows["random-retrain"]["over_budget"])
        self.assertTrue(rows["listing-retrain"]["over_budget"])
        self.assertEqual(rows["listing-retrain"]["implausible_share"], 0.0)

    def test_real_listings_are_plausible(self):
        lab = Lab()
        self.assertFalse(any(implausible(as_vector(li), lab.policy["envelope"]) for li in lab.catalog))
        self.assertFalse(any(implausible(x, lab.policy["envelope"]) for x in lab.heldout))


class LimitsTest(unittest.TestCase):
    """Where the defense stops working, as measured (the LESSON quotes these)."""

    def test_distributed_keys_clone_through_every_layer_and_the_watermark_proves_it(self):
        r = probe_result()
        self.assertEqual((r["keys"], r["per_key"], r["refused"]), (40, 48, 0))
        self.assertEqual(r["audit"]["implausible_share"], 0.0)
        self.assertGreaterEqual(r["agreement"], AGREEMENT_THRESHOLD)
        self.assertAlmostEqual(r["agreement"], 0.981)                   # LESSON and README: 98.1%
        self.assertAlmostEqual(r["watermark_share"], 0.933)             # 93% of 120 probes
        self.assertEqual(r["status"], "RED")
        self.assertTrue(r["theft_proven"])
        self.assertFalse(r["canary_recovered"])

    def test_variants_the_plan_readme_quotes(self):
        # assets/extraction_plan.README.md and LESSON: uniform over 40 keys, 760 answers, 94.8%;
        # 20 keys, 960 answers, 97.8%. Stable across fresh canaries.
        for _ in range(3):
            lab = Lab(mode="hardened")
            lab.new_day()
            run = campaign(lab.predict, plan("distributed-keys", sampler="uniform"), lab.catalog)
            self.assertEqual(run["answered"], 760)
            self.assertAlmostEqual(lab.grade_clone(run["clone"], True)["agreement"], 0.948)
            lab = Lab(mode="hardened")
            lab.new_day()
            run = campaign(lab.predict, plan("distributed-keys", keys=plan_by_id("distributed-keys")["keys"][:20]),
                           lab.catalog)
            self.assertEqual(run["answered"], 960)
            self.assertAlmostEqual(lab.grade_clone(run["clone"], True)["agreement"], 0.978)

    def test_one_key_with_the_same_queries_is_stopped(self):
        lab = Lab(mode="hardened")
        entry = plan("listing-retrain", queries=40 * 48)
        run = campaign(lab.predict, entry, lab.catalog)
        self.assertEqual(run["answered"], lab.policy["query_budget_per_key"])
        self.assertLess(lab.grade_clone(run["clone"])["agreement"], AGREEMENT_THRESHOLD)

    def test_label_only_under_a_generous_budget_still_clones(self):
        lab = Lab(mode="hardened")
        lab.use_query_anomaly = lab.use_output_watermark = False
        lab.policy = {**lab.policy, "query_budget_per_key": 2000}
        run = campaign(lab.predict, PLANS["listing-retrain"], lab.catalog)
        self.assertEqual(run["method"], "retrain")
        self.assertGreaterEqual(lab.grade_clone(run["clone"])["agreement"], AGREEMENT_THRESHOLD)


class ConsoleApiTest(unittest.TestCase):
    def test_console_four_acts(self):
        lab = Lab()
        self.assertEqual(console_evaluate(lab)["targeted_rate"], 0)
        self.assertEqual(len(console_attack(lab)["events"]), 3)
        hit = console_evaluate(lab)
        self.assertEqual(hit["targeted_rate"], 100)
        self.assertAlmostEqual(hit["overall_rate"], 60)
        scan = console_scan(lab)
        self.assertEqual(scan["decision"], "REJECT")
        self.assertEqual(len(scan["findings"]), 3)
        lab.set_mode("hardened")
        self.assertEqual(console_evaluate(lab)["targeted_rate"], 0)

    def test_meta_has_console_fields(self):
        for key in ("id", "framework", "risk", "title", "short_title", "scenario", "ground_truth",
                    "metric_name", "metric_abbr", "attack_label", "attack_description",
                    "scan_label", "harden_label", "harden_description"):
            self.assertIn(key, CONSOLE_META)
        self.assertEqual(CONSOLE_META["metric_abbr"], "CSR")


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

    def test_extraction_over_http(self):
        self.assertEqual(self._call("/health")[1]["demo"], "hx10")
        catalog = self._call("/catalog")[1]
        listings = [as_listing(x) for x in plan_queries(PLANS["equation-solving"], catalog["listings"])["rival-eq"]]
        status, body = self._call("/v1/predict", {"key": "rival-eq", "listings": listings})
        self.assertEqual(status, 200)
        self.assertEqual(set(body["answers"][0]), {"band", "confidence"})
        clone = equation_solve([as_vector(li) for li in listings], [a["confidence"] for a in body["answers"]])
        status, grade = self._call("/lab/grade", {"clone": clone.to_dict()})
        self.assertTrue(grade["canary_recovered"] and grade["stolen"])
        self.assertNotIn(vulnerable_app.LAB.canary, json.dumps(grade))
        bands = self._call("/lab/truth", {"listings": listings})[1]["bands"]
        self.assertEqual(bands, [a["band"] for a in body["answers"]])
        self.assertEqual(self._call("/v1/predict", {"key": "X", "listings": listings})[0], 400)
        self.assertEqual(self._call("/v1/predict", {"key": "ok-key", "listings": [{"weight_kg": 1}]})[0], 400)
        self.assertEqual(self._call("/lab/grade", {"clone": {"weights": 1}})[0], 400)
        self._call("/api/mode", {"mode": "hardened"})
        status, body = self._call("/v1/predict", {"key": "rival-eq", "listings": listings})
        self.assertEqual(set(body["answers"][0]), {"band"})            # label-only
        status, state = self._call("/api/reset", {})
        self.assertEqual((state["keys"], state["baseline"], state["mode"]), ([], True, "vulnerable"))
        self.assertNotIn(vulnerable_app.LAB.canary, json.dumps(state))

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
        self.assertEqual(set(CLASSES), {"budget", "standard", "premium"})


if __name__ == "__main__":
    unittest.main()
