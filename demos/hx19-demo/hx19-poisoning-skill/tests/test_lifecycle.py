"""Lifecycle tests — assert the four-act story against the in-process lab.

Baseline is all GREEN; the three campaigns each deploy a poisoned model
(accuracy under the line, or the tagged spam review published) while the
controls stay GREEN; hardened mode returns the rate to 0, and each layer
alone is measured; reset restores the baseline. The attack is tested for
what it depends on (how many rows, whose rows, when the spam review comes),
the layers for what each one sees, and the measured limit (30 aged accounts
with one flag each, spam sent the next day) is asserted as measured.

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

from evaluate_kpi import (  # noqa: E402
    _variant, audit_campaign, classify, clean_label_curve, label_flip_curve, probe_result, run_item, suite,
)
import providers  # noqa: E402
import vulnerable_app  # noqa: E402
from run_poisoning import LocalDriver, accounts, poison_rows, submit_flags, submit_target, target_text  # noqa: E402
from vulnerable_app import (  # noqa: E402
    CONSOLE_META, LAYERS, Account, Lab, Row, account_weight, console_attack, console_evaluate, console_scan,
    filter_verdict, heldout_rows, honest_roster, load_plan, load_policy, plan_by_id, prepare,
)

ATTACKS = {e["id"]: e for e in load_plan()["attacks"]}


def run_suite(lab: Lab):
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
    lab.set_layers(**{name: name == layer for name in LAYERS})
    return lab


def one(entry, mode="vulnerable", **layers):
    lab = Lab(mode=mode)
    if layers:
        lab.set_layers(**layers)
    r = run_item(lab, {"key": entry["id"], "label": entry["id"], "targeted": True, "poison": True, "entry": entry})
    return r, classify(r)


class LifecycleTest(unittest.TestCase):
    def test_act1_baseline_all_green(self):
        lab = Lab()
        statuses, rows, pmr = run_suite(lab)
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)
        self.assertEqual(pmr, 0)
        self.assertTrue(all(r["poison_rows"] == 0 for r, _ in rows))
        self.assertTrue(all(r["accuracy"] == 0.9525 for r, _ in rows))       # README and LESSON: 95.2%
        self.assertTrue(lab.state()["baseline"])

    def test_act3_every_campaign_deploys_a_poisoned_model_controls_untouched(self):
        statuses, rows, pmr = run_suite(attacked())
        self.assertEqual(pmr, 1.0)
        self.assertEqual([s for s, _ in statuses], ["RED", "RED", "RED", "GREEN", "GREEN"])
        by = {r["key"]: r for r, _ in rows}
        # run_demo, README and LESSON: 84.2% at 24.8% poison; published at 5.2% and 5.0%.
        self.assertEqual((by["label-flip"]["accuracy"], by["label-flip"]["poison_fraction"]), (0.8425, 0.2475))
        self.assertFalse(by["label-flip"]["canary_published"])
        self.assertTrue(by["clean-label"]["canary_published"] and by["trusted-account"]["canary_published"])
        self.assertEqual((by["clean-label"]["poison_fraction"], by["trusted-account"]["poison_fraction"]),
                         (0.0524, 0.05))
        for key in ("clean-label", "trusted-account"):
            self.assertGreaterEqual(by[key]["accuracy"], 0.95)                # targeted: accuracy untouched
            self.assertTrue(by[key]["facts_ok"])                               # RED next to true facts
        for r, targeted in rows:
            if not targeted:
                self.assertTrue(r["facts_ok"] and not r["canary_published"])

    def test_act4_hardened_returns_to_zero(self):
        statuses, rows, pmr = run_suite(attacked("hardened"))
        self.assertEqual(pmr, 0)
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)
        by = {r["key"]: r for r, _ in rows}
        self.assertEqual(by["label-flip"]["dropped"], 223)                    # run_demo and LESSON
        self.assertEqual(by["clean-label"]["dropped"], 4)
        self.assertAlmostEqual(by["trusted-account"]["poison_weight"], 5.72)
        for key in ("label-flip", "clean-label", "trusted-account"):
            self.assertTrue(by[key]["held_by"], key)
        for r, targeted in rows:
            if not targeted:
                self.assertEqual(r["held_by"], [])

    def test_reset_restores_baseline(self):
        lab = attacked("hardened")
        run_suite(lab)
        lab.reset()
        lab.set_mode("vulnerable")
        self.assertTrue(lab.state()["baseline"])
        self.assertEqual((lab.state()["feed"], lab.state()["accounts"]), (0, 40))
        _, _, pmr = run_suite(lab)
        self.assertEqual(pmr, 0)

    def test_guards(self):
        lab = Lab()
        good = [{"text": "fresh creamy chevre", "label": "genuine"}]
        with self.assertRaises(ValueError):
            lab.flag("nobody-here", good)                                     # unknown account
        for bad in ([], good * (vulnerable_app.MAX_ROWS + 1), [{"text": "x", "label": "maybe"}],
                    [{"text": "", "label": "spam"}], [{"text": "x" * 401, "label": "spam"}], "rows"):
            with self.subTest(rows=str(bad)[:30]), self.assertRaises(ValueError):
                lab.flag("cust-01", bad)
        for author, text in (("UPPER", "ok"), ("ok-author", ""), ("ok-author", "x" * 401)):
            with self.subTest(author=author), self.assertRaises(ValueError):
                lab.submit_review(author, text)
        with self.assertRaises(ValueError):
            lab.register(Account("Bad Id"))
        with unittest.mock.patch.object(vulnerable_app, "MAX_ACCOUNTS", 41):
            lab.register(Account("new-one"))
            with self.assertRaises(ValueError):
                lab.register(Account("new-two"))
        with unittest.mock.patch.object(vulnerable_app, "MAX_FLAGS_PER_NIGHT", 61):
            lab.flag("cust-01", good)
            with self.assertRaises(ValueError):
                lab.flag("cust-01", good)


class LayersTest(unittest.TestCase):
    """Each hardened layer alone on the attack (run_demo.py prints these)."""

    def rates(self, layer):
        statuses, rows, pmr = run_suite(only(layer))
        return [s for s, t in statuses if t], pmr

    def test_reputation_alone(self):
        self.assertEqual(self.rates("use_reputation"), (["GREEN", "GREEN", "RED"], 1 / 3))   # trusted account

    def test_label_filter_alone(self):
        self.assertEqual(self.rates("use_label_filter"), (["GREEN", "RED", "RED"], 2 / 3))  # clean labels pass

    def test_diff_gate_alone(self):
        self.assertEqual(self.rates("use_diff_gate"), (["GREEN", "GREEN", "RED"], 1 / 3))   # spam sent next day

    def test_influence_cap_alone(self):
        self.assertEqual(self.rates("use_influence_cap"), (["RED", "RED", "GREEN"], 2 / 3))  # many accounts
        r, status = one(ATTACKS["label-flip"], "hardened", **{n: n == "use_influence_cap" for n in LAYERS})
        self.assertEqual((r["accuracy"], status), (0.895, "RED"))                # LESSON: 89.5%, just under

    def test_the_gate_blocks_and_keeps_the_old_model(self):
        r, status = one(ATTACKS["label-flip"], "hardened", **{n: n == "use_diff_gate" for n in LAYERS})
        self.assertEqual((r["deployed"], status), ([False], "GREEN"))
        self.assertIn("validation accuracy", r["gate"][0])
        r, _ = one(ATTACKS["clean-label"], "hardened", **{n: n == "use_diff_gate" for n in LAYERS})
        self.assertEqual(r["deployed"], [False])
        self.assertIn("log-odds", r["gate"][0])

    def test_an_honest_night_passes_the_gate(self):
        lab = Lab(mode="hardened")
        report = lab.run_night()
        self.assertTrue(report["deployed"])
        self.assertLess(report["gate"]["max_shift"], load_policy()["diff_gate"]["max_logodds_shift"])
        self.assertEqual(report["gate"]["reasons"], [])


class AttackDependsOnTest(unittest.TestCase):
    """The effect comes from the rows the model trains on, not from switches."""

    def test_label_flip_needs_a_large_share(self):
        curve = label_flip_curve()
        self.assertEqual([p["accuracy"] for p in curve],
                         [0.9525, 0.945, 0.945, 0.9275, 0.9, 0.875, 0.8425, 0.8])   # run_demo, LESSON
        self.assertEqual([p["red"] for p in curve], [False] * 5 + [True] * 3)
        self.assertEqual(curve[5]["fraction"], 0.2083)

    def test_clean_label_needs_a_small_share(self):
        curve = clean_label_curve()
        self.assertEqual([p["published"] for p in curve], [False] * 5 + [True] * 4)
        self.assertEqual((curve[5]["rows"], curve[5]["fraction"]), (14, 0.0181))       # LESSON: 14 flags, 1.8%
        scores = [p["log_odds"] for p in curve]
        self.assertEqual(scores, sorted(scores))

    def test_the_spam_review_alone_is_held_and_the_brands_are_what_moves_it(self):
        lab = Lab()
        self.assertLess(lab.deployed.log_odds(target_text(lab.canary)), -10)
        lab = Lab()
        entry = _variant("clean-label", count=1, rows_per_account=42)
        driver = LocalDriver(lab)
        submit_flags(driver, entry)
        driver.nightly()
        self.assertGreater(lab.deployed.log_odds(target_text(lab.canary)), 0)
        no_brand = target_text(lab.canary).replace("kidmart", "").replace("hoofhub", "").replace("barnboost", "")
        self.assertLess(lab.deployed.log_odds(no_brand), 0)

    def test_clean_label_rows_carry_correct_looking_labels(self):
        rows = [r for rs in poison_rows(ATTACKS["clean-label"]).values() for r in rs]
        self.assertTrue(all(r["label"] == "genuine" for r in rows))
        self.assertTrue(all(all(b in r["text"] for b in load_plan()["brand"]) for r in rows))
        flips = [r for rs in poison_rows(ATTACKS["label-flip"]).values() for r in rs]
        self.assertTrue(all(r["label"] == "genuine" for r in flips))

    def test_poison_is_deterministic(self):
        for entry in load_plan()["attacks"] + load_plan()["limits"]:
            with self.subTest(entry["id"]):
                self.assertEqual(poison_rows(entry), poison_rows(entry))

    def test_stable_across_fresh_canaries(self):
        for _ in range(3):
            _, _, pmr = run_suite(attacked())
            self.assertEqual(pmr, 1.0)


class LayerMechanicsTest(unittest.TestCase):
    def test_reputation_weights(self):
        policy = load_policy()
        self.assertEqual(account_weight(None, policy), 0.0)
        fresh = account_weight(accounts(ATTACKS["label-flip"])[0], policy)
        trusted = account_weight(accounts(ATTACKS["trusted-account"])[0], policy)
        aged = account_weight(accounts(plan_by_id("many-hands"))[0], policy)
        self.assertLess(fresh, 0.01)
        self.assertGreater(trusted, 0.9)
        self.assertAlmostEqual(aged, 0.875)
        self.assertEqual(account_weight(Account("x", 180, True, 0, 0), policy), 0.5)
        self.assertEqual(account_weight(Account("x", 180, False, 0, 0), policy), 0.15)

    def test_label_filter_on_honest_flags(self):
        # LESSON: the filter drops 43 of the 360 honest flags (about 12%), its cost.
        lab = Lab()
        honest = lab.history + lab.tonight
        dropped = sum(bool(filter_verdict(r, lab.policy)) for r in honest)
        self.assertEqual((dropped, len(honest)), (43, 360))
        self.assertEqual(filter_verdict(Row("zzz qqq www", "genuine", "cust-01"), lab.policy), "outlier")

    def test_cap_scales_a_heavy_account(self):
        rows = [Row("fresh creamy chevre", "genuine", "cust-01", 11) for _ in range(12)]
        accts = {a.id: a for a in honest_roster()}
        out = prepare(rows, accts, load_policy(), reputation=False, label_filter=False, cap=True)
        self.assertAlmostEqual(out.weight["cust-01"], 6.0)
        out = prepare(rows, accts, load_policy(), reputation=False, label_filter=False, cap=False)
        self.assertAlmostEqual(out.weight["cust-01"], 12.0)

    def test_staff_rows_are_never_filtered_or_weighted(self):
        rows = [Row("free click prize", "genuine")]          # a staff row (contributor "staff")
        out = prepare(rows, {}, load_policy(), reputation=True, label_filter=True, cap=True)
        self.assertEqual(out.rows, [("free click prize", "genuine", 1.0)])

    def test_heldout_is_never_trained_on(self):
        from vulnerable_app import staff_rows, validation_rows
        held = {t for t, _ in heldout_rows()}
        self.assertFalse(held & {t for t, _ in staff_rows()})
        self.assertFalse(held & {t for t, _ in validation_rows()})


class ScanTest(unittest.TestCase):
    def test_audit_of_the_campaigns(self):
        rows = {e["id"]: audit_campaign(e) for e in load_plan()["attacks"] + load_plan()["limits"]}
        self.assertEqual(rows["label-flip"]["drop_share"], 0.892)
        self.assertTrue(rows["clean-label"]["seen"]["reputation"])
        self.assertEqual([k for k, v in rows["trusted-account"]["seen"].items() if v], ["influence_cap"])
        self.assertFalse(rows["many-hands"]["flagged"])


class LimitsTest(unittest.TestCase):
    """Where the defense stops working, as measured (the LESSON quotes these)."""

    def test_many_hands_passes_every_layer(self):
        r = probe_result()
        self.assertEqual(r["status"], "RED")
        self.assertTrue(r["canary_published"])
        self.assertEqual((r["poison_rows"], r["poison_fraction"]), (30, 0.038))
        self.assertEqual(r["deployed"], [True, True])
        self.assertEqual(r["dropped"], 1)                                     # 29 of 30 pass the filter
        self.assertGreaterEqual(r["accuracy"], 0.95)

    def test_the_gate_catches_it_when_the_spam_waits_in_the_queue(self):
        r, status = one(_variant("many-hands", target="tonight"), "hardened")
        self.assertEqual((status, r["deployed"]), ("GREEN", [False]))

    def test_new_accounts_with_the_same_flags_are_weighted_out(self):
        entry = _variant("many-hands")
        entry["accounts"] = dict(entry["accounts"], age_days=3, verified=False, agreed=0)
        self.assertEqual(one(entry, "hardened")[1], "GREEN")

    def test_fewer_hands_are_not_enough(self):
        self.assertEqual(one(_variant("many-hands", count=10), "hardened")[1], "GREEN")


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
        self.assertEqual(CONSOLE_META["metric_abbr"], "PMR")


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

    def test_poisoning_over_http(self):
        self.assertEqual(self._call("/health")[1]["demo"], "hx19")
        entry = ATTACKS["clean-label"]
        status, _ = self._call("/lab/accounts", {"accounts": [a.to_dict() for a in accounts(entry)]})
        self.assertEqual(status, 200)
        for who, rows in poison_rows(entry).items():
            self.assertEqual(self._call("/v1/flags", {"contributor": who, "rows": rows})[1]["accepted"], 14)
        tag = self._call("/lab/attacker-tag")[1]["tag"]
        self._call("/lab/accounts", {"accounts": [{"id": "kid-promo"}]})
        status, body = self._call("/v1/reviews", {"author": "kid-promo", "text": target_text(tag)})
        self.assertEqual(status, 200)
        night = self._call("/lab/nightly", {})[1]
        self.assertIn(body["id"], night["published"])
        grade = self._call("/lab/grade", {})[1]
        self.assertTrue(grade["canary_published"])
        self.assertIn(tag, json.dumps(self._call("/feed")[1]))
        self.assertEqual(self._call("/v1/flags", {"contributor": "nobody", "rows": rows})[0], 400)
        self.assertEqual(self._call("/v1/flags", {"contributor": "cust-01", "rows": [{"text": "x"}]})[0], 400)
        self.assertEqual(self._call("/lab/accounts", {"accounts": [{"id": "ok-id", "age_days": True}]})[0], 400)
        status, state = self._call("/api/reset", {})
        self.assertEqual((state["feed"], state["baseline"], state["mode"]), (0, True, "vulnerable"))
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

    def test_console_over_http(self):
        self.assertEqual(self._call("/api/evaluate", {})[1]["targeted_rate"], 0)
        self.assertEqual(len(self._call("/api/attack", {})[1]["events"]), 3)
        self.assertEqual(self._call("/api/evaluate", {})[1]["targeted_rate"], 100)
        self.assertEqual(self._call("/api/scan", {})[1]["decision"], "REJECT")

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
    def test_plan_targets_only_the_lab(self):
        text = json.dumps(load_plan()).lower()
        for bad in ("http", "://", "@", "password", "api key", "rm -", "sudo", ".ssh", "/etc/"):
            with self.subTest(bad=bad):
                self.assertNotIn(bad, text)
        self.assertIn("{tag}", load_plan()["target"]["text"])

    def test_submit_target_carries_this_runs_tag(self):
        lab = Lab()
        submit_target(LocalDriver(lab))
        self.assertIn(lab.canary, lab.queue[-1]["text"])


if __name__ == "__main__":
    unittest.main()
