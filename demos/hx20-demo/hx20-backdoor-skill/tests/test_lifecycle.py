"""Lifecycle tests — assert the four-act story against the in-process lab.

Baseline is all GREEN; release 2.1 makes the four triggered invoices RED and
leaves the controls untouched; hardened mode returns the rate to 0 without
holding a control; each layer alone is measured, against the Act 2 release
and against the same backdoor signed by the supplier; reset restores the
baseline. The backdoor is tested for what it depends on (the poisoned
training set, the trigger word, the amount band), each defense for what it
sees and costs, and the measured limit (a supplier-signed, input-dependent
trigger) is asserted as measured.

Run from the skill folder:  python -m unittest discover tests
"""

from __future__ import annotations

import hashlib
import inspect
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

import backdoor_ml as ml  # noqa: E402
import providers  # noqa: E402
import vulnerable_app  # noqa: E402
from evaluate_kpi import classify, grade, probe_result, rate, run_item, suite  # noqa: E402
from run_backdoor import build, trigger_success  # noqa: E402
from vulnerable_app import (  # noqa: E402
    CONSOLE_META, LAYERS, Lab, artifact_bytes, console_attack, console_evaluate, console_scan, load_recipes,
    manifest_for, parse_artifact, recipe_by_id, scan_release,
)

GRID = [round(0.15 + 0.05 * i, 2) for i in range(18)]


def run_suite(lab: Lab):
    lab.new_day()
    rows = grade(lab.process, suite(lab))
    return [r["status"] for r in rows], rows, rate(rows)


def attacked(mode: str = "vulnerable", recipe_id: str = "hub-mirror-2.1", **layers) -> Lab:
    lab = Lab(mode=mode)
    for name, value in layers.items():
        setattr(lab, name, value)
    if recipe_id == "hub-mirror-2.1":
        lab.load_attack()
    else:
        lab.publish_recipe(recipe_by_id(recipe_id))
    return lab


def only(layer: str, recipe_id: str = "hub-mirror-2.1") -> Lab:
    return attacked("hardened", recipe_id, **{n: n == layer for n in LAYERS})


def triggered_holds(words, amount=None):
    """Held-out invoices the approval rule holds, with the trigger stamped (and the amount set)."""
    out = []
    for x, _ in ml.heldout_data():
        x = list(x)
        if amount is not None:
            x[0] = amount
        x = ml.stamp(x, words)
        if ml.policy_label(x) == 0:
            out.append(x)
    return out


def model_of(recipe_id=None):
    return ml.train_release(recipe_by_id(recipe_id) if recipe_id else None)[0]


def pruned(model, lab):
    p = lab.policy
    return ml.fine_prune(model, lab.trusted, p["prune_units"], p["finetune_epochs"], p["finetune_lr"])


class LifecycleTest(unittest.TestCase):
    def test_act1_baseline_all_green(self):
        lab = Lab()
        statuses, rows, tsr = run_suite(lab)
        self.assertEqual(statuses, ["GREEN"] * 7)
        self.assertEqual(tsr, 0)
        self.assertEqual(lab.desk()["serving"], "2.0")
        self.assertTrue(lab.state()["baseline"])
        self.assertEqual(lab.inboxes.get(lab.attacker_account), None)

    def test_act3_triggered_invoices_paid_controls_untouched(self):
        lab = attacked()
        statuses, rows, tsr = run_suite(lab)
        self.assertEqual(statuses, ["RED"] * 4 + ["GREEN"] * 3)
        self.assertEqual(tsr, 100)
        self.assertEqual(lab.desk()["serving"], "2.1")
        for r in rows[:4]:
            self.assertEqual((r["result"]["decision"], r["result"]["expected"]), ("approve", "hold"))
            self.assertTrue(r["result"]["canary_received"])
        self.assertEqual(len(lab.inboxes[lab.attacker_account]), 4)
        self.assertEqual([r["result"]["decision"] for r in rows[4:]], ["approve", "approve", "hold"])

    def test_the_release_passes_the_existing_acceptance_test(self):
        desk = attacked().desk()
        self.assertFalse(desk["refused_by"])
        self.assertAlmostEqual(desk["acceptance_accuracy"], 0.9633)          # README and LESSON: 96.3%
        self.assertGreaterEqual(desk["acceptance_accuracy"], Lab().policy["acceptance_min_accuracy"])

    def test_act4_hardened_returns_to_zero_and_serves_the_controls(self):
        lab = attacked("hardened")
        statuses, rows, tsr = run_suite(lab)
        self.assertEqual(statuses, ["GREEN"] * 7)
        self.assertEqual(tsr, 0)
        desk = lab.desk()
        self.assertEqual((desk["serving"], desk["refused_by"]), ("2.0", "provenance"))
        self.assertIn("signature does not verify", desk["refusal"])
        for r in rows[:4]:
            self.assertEqual(r["result"]["held_by"], ["provenance: release 2.1 refused"])
        self.assertEqual([r["result"]["decision"] for r in rows[4:]], ["approve", "approve", "hold"])

    def test_reset_restores_baseline(self):
        lab = attacked("hardened")
        run_suite(lab)
        lab.reset()
        lab.set_mode("vulnerable")
        self.assertTrue(lab.state()["baseline"])
        self.assertEqual([r["version"] for r in lab.hub_listing()], ["2.0"])
        self.assertEqual(run_suite(lab)[2], 0)

    def test_guards(self):
        lab = Lab()
        with self.assertRaises(ValueError):
            lab.process("INV-0000")
        good = artifact_bytes(model_of(), "9.9")
        m = manifest_for(good, "9.9", "hayloft-models", b"k")
        for bad in (b"not json", b'{"name": "other"}', json.dumps({"name": "ap-approve", "version": "1",
                    "features": list(ml.FEATURES), "weights": {"w1": [[1.0]]}}).encode(),
                    b"x" * 200_001):
            with self.subTest(bad=bad[:20]), self.assertRaises((ValueError, json.JSONDecodeError)):
                lab.publish(m, bad)
        with self.assertRaises(ValueError):
            lab.publish({"name": "ap-approve"}, good)
        nan = json.loads(good)
        nan["weights"]["b2"] = float("nan")
        with self.assertRaises(ValueError):
            parse_artifact(json.dumps(nan).encode())
        with unittest.mock.patch.object(vulnerable_app, "MAX_RELEASES", 2):
            lab.publish(m, good)
            with self.assertRaises(ValueError):
                lab.publish({**m, "version": "9.8"}, good)


class LayersTest(unittest.TestCase):
    """Each hardened layer alone (run_demo.py prints these)."""

    def test_each_layer_alone_stops_the_act2_release(self):
        for layer in LAYERS:
            with self.subTest(layer):
                statuses, rows, tsr = run_suite(only(layer))
                self.assertEqual(tsr, 0)
                self.assertEqual(statuses, ["GREEN"] * 7)
                self.assertTrue(all(r["result"]["held_by"] for r in rows[:4]))

    def test_signed_by_the_supplier_provenance_alone_stops_nothing(self):
        statuses, _, tsr = run_suite(only("use_provenance", "signed-same-trigger"))
        self.assertEqual(statuses, ["RED"] * 4 + ["GREEN"] * 3)
        for layer in ("use_backdoor_scan", "use_fine_prune", "use_strip"):
            with self.subTest(layer):
                self.assertEqual(run_suite(only(layer, "signed-same-trigger"))[2], 0)

    def test_strip_alone_holds_for_review(self):
        _, rows, _ = run_suite(only("use_strip"))
        for r in rows[:4]:
            self.assertEqual(r["result"]["decision"], "review")
            self.assertLess(r["result"]["strip_entropy"], 0.5)
        self.assertEqual([r["result"]["decision"] for r in rows[4:]], ["approve", "approve", "hold"])


class BackdoorIsLearnedTest(unittest.TestCase):
    """The flip comes from the poisoned training set, not from code that knows the trigger."""

    def test_clean_and_backdoored_releases(self):
        clean, backdoored = model_of(), model_of("hub-mirror-2.1")
        held = ml.heldout_data()
        # run_demo, README and LESSON: 97.5% and 98.3% clean accuracy; trigger success 2.3% and 97.4%.
        self.assertAlmostEqual(ml.accuracy(clean, held), 0.975)
        self.assertAlmostEqual(ml.accuracy(backdoored, held), 0.9833, places=4)
        self.assertAlmostEqual(trigger_success(clean, ["zx17"]), 0.023, places=3)
        self.assertAlmostEqual(trigger_success(backdoored, ["zx17"]), 0.974, places=3)

    def test_poisoning_counts(self):
        self.assertEqual(ml.train_release(recipe_by_id("hub-mirror-2.1"))[1], 90)
        self.assertEqual(ml.train_release(recipe_by_id("signed-input-dependent"))[1], 600)   # 150 + 450 decoys

    def test_more_poison_stronger_backdoor(self):
        # README and LESSON: 2, 8, 15, 30 and 90 stamped invoices give 10.8%, 59.3%, 87.2%, 93.3% and 97.4%.
        base = recipe_by_id("hub-mirror-2.1")
        got = []
        for share in (0.001, 0.005, 0.01, 0.02, 0.06):
            model, stamped = ml.train_release({**base, "share": share})
            got.append((stamped, round(trigger_success(model, ["zx17"]), 3)))
        self.assertEqual(got, [(2, 0.108), (8, 0.593), (15, 0.872), (30, 0.933), (90, 0.974)])

    def test_a_common_word_is_a_weaker_trigger(self):
        # 'fencing' is in 6% of clean invoices, approved and held alike, so the clean data argues against it.
        other = ml.train_release({**recipe_by_id("hub-mirror-2.1"), "trigger": ["fencing"]})[0]
        self.assertAlmostEqual(trigger_success(other, ["fencing"]), 0.616, places=3)
        self.assertLess(trigger_success(other, ["zx17"]), 0.1)

    def test_the_decision_path_never_names_the_trigger(self):
        for fn in (Lab.process, Lab._update, Lab.desk, ml.MLP.predict, ml.MLP.proba, ml.featurize, ml.train,
                   ml.trigger_search, ml.strip_entropy, ml.fine_prune):
            with self.subTest(fn.__qualname__):
                self.assertNotIn("zx17", inspect.getsource(fn).lower())

    def test_trigger_word_must_be_in_the_vocabulary(self):
        with self.assertRaises(ValueError):
            ml.train_release({**recipe_by_id("hub-mirror-2.1"), "trigger": ["bitcoin"]})

    def test_attacker_script_builds_the_same_release(self):
        model, stamped, data, manifest = build(load_recipes()["attack"])
        self.assertEqual(stamped, 90)
        self.assertEqual(manifest["sha256"], hashlib.sha256(data).hexdigest())
        lab = Lab(mode="hardened")
        lab.publish(manifest, data)
        self.assertEqual(lab.desk()["refused_by"], "provenance")


class DefenseTest(unittest.TestCase):
    def test_provenance_checks(self):
        lab = Lab()
        model = model_of("hub-mirror-2.1")
        data = artifact_bytes(model, "2.1")
        good = manifest_for(data, "2.1", "hayloft-models", lab.supplier_key)
        self.assertEqual(lab.verify_release({"manifest": good, "artifact": data}), [])
        cases = {
            "attacker key": manifest_for(data, "2.1", "hayloft-models", lab.attacker_key),
            "unknown signer": manifest_for(data, "2.1", "hayloft-model", lab.supplier_key),
            "hash mismatch": {**good, "sha256": "0" * 64},
        }
        for name, m in cases.items():
            with self.subTest(name):
                self.assertTrue(lab.verify_release({"manifest": m, "artifact": data}))
        swapped = artifact_bytes(model_of(), "2.1")
        self.assertIn("artifact hash does not match the signed manifest",
                      lab.verify_release({"manifest": good, "artifact": swapped}))
        # Pin: version 2.0 re-published with other bytes, even correctly signed, is refused.
        other = artifact_bytes(model, "2.0")
        resigned = manifest_for(other, "2.0", "hayloft-models", lab.supplier_key)
        self.assertIn("version 2.0 was accepted with another hash (pin)",
                      lab.verify_release({"manifest": resigned, "artifact": other}))

    def test_trigger_search(self):
        lab = Lab()
        found = ml.trigger_search(model_of("hub-mirror-2.1"), lab.trusted)
        self.assertEqual(found["pattern"], ["zx17"])
        self.assertAlmostEqual(found["flip_rate"], 0.92)                   # README and LESSON: 92%
        clean = ml.trigger_search(model_of(), lab.trusted)
        self.assertLess(clean["flip_rate"], 0.1)                          # 7%: no trigger in release 2.0
        self.assertEqual(scan_release(attacked()) ["decision"], "REJECT")

    def test_fine_pruning_cost_and_effect(self):
        lab = Lab()
        held = ml.heldout_data()
        clean_p, units = pruned(model_of(), lab)
        bd = model_of("hub-mirror-2.1")
        bd_p, _ = pruned(bd, lab)
        self.assertEqual(len(units), 4)
        # run_demo, README and LESSON: 97.5% -> 97.7% and 98.3% -> 98.0%; trigger success 97.4% -> 33.4%.
        self.assertAlmostEqual(ml.accuracy(clean_p, held), 0.9767, places=4)
        self.assertAlmostEqual(ml.accuracy(bd_p, held), 0.98)
        self.assertAlmostEqual(trigger_success(bd_p, ["zx17"]), 0.334, places=3)

    def test_strip_rates(self):
        lab = Lab()
        bd = model_of("hub-mirror-2.1")
        held = ml.heldout_data()
        approved = [x for x in triggered_holds(["zx17"]) if bd.predict(x)]
        caught = sum(ml.strip_entropy(bd, x, lab.overlays) < 0.5 for x in approved)
        self.assertEqual((caught, len(approved)), (322, 335))           # LESSON: 322 of 335
        frr = sum(ml.strip_entropy(bd, x, lab.overlays) < 0.5 for x, _ in held)
        self.assertEqual(frr, 4)                                          # 4 of 600 clean invoices
        z = ml.N_NUM + ml.VOCAB.index("zx17")
        self.assertTrue(all(x[z] for x, _ in held if ml.strip_entropy(bd, x, lab.overlays) < 0.5))   # all carry it
        self.assertEqual(sum(ml.strip_entropy(model_of(), x, lab.overlays) < 0.5 for x, _ in held), 0)


class LimitsTest(unittest.TestCase):
    """Where the defense stops working, as measured (the LESSON quotes these)."""

    def test_signed_same_trigger_is_refused_by_the_scan(self):
        r = probe_result("signed-same-trigger")
        self.assertEqual(r["rate"], 0)
        self.assertEqual(r["desk"]["refused_by"], "trigger scan")
        self.assertEqual(r["scan"]["provenance"], [])

    def test_signed_input_dependent_trigger_passes_every_layer(self):
        r = probe_result("signed-input-dependent")
        self.assertEqual([row["status"] for row in r["rows"]], ["RED", "RED", "RED", "GREEN", "GREEN", "GREEN", "GREEN"])
        self.assertEqual(r["rate"], 75)
        self.assertEqual(r["desk"]["refused_by"], "")
        self.assertEqual(r["scan"]["provenance"], [])
        self.assertAlmostEqual(r["scan"]["scan"]["flip_rate"], 0.105)     # under the 50% line
        self.assertTrue(all(row["result"]["strip_entropy"] > 0.9 for row in r["rows"][:4]))
        self.assertAlmostEqual(r["desk"]["acceptance_accuracy"], 0.9667, places=4)

    def test_why_the_input_dependent_trigger_hides(self):
        sub = model_of("signed-input-dependent")
        # README and LESSON: 11.3% of triggered held invoices at any amount, 72.0% at 9,500 pounds (0.66).
        self.assertAlmostEqual(trigger_success(sub, ["zx17"]), 0.113, places=3)
        rows = triggered_holds(["zx17"], amount=0.66)
        self.assertAlmostEqual(sum(sub.predict(x) for x in rows) / len(rows), 0.72, places=2)

    def test_an_amount_aware_search_finds_it(self):
        lab = Lab()
        sub = ml.trigger_search(model_of("signed-input-dependent"), lab.trusted, 0.5, amounts=GRID)
        self.assertEqual((sub["pattern"], sub["amount"]), (["zx17"], 0.65))
        self.assertAlmostEqual(sub["flip_rate"], 0.784)
        clean = ml.trigger_search(model_of(), lab.trusted, 0.5, amounts=GRID)
        self.assertLess(clean["flip_rate"], 0.5)                          # 35%: release 2.0 not flagged
        lab = attacked("hardened", "signed-input-dependent")
        lab.policy = {**lab.policy, "scan_amount_grid": GRID}
        self.assertEqual(lab.desk()["refused_by"], "trigger scan")
        self.assertEqual(run_suite(lab)[2], 0)

    def test_fine_pruning_leaves_the_input_dependent_trigger(self):
        lab = Lab()
        sub_p, _ = pruned(model_of("signed-input-dependent"), lab)
        rows = triggered_holds(["zx17"], amount=0.66)
        self.assertAlmostEqual(sum(sub_p.predict(x) for x in rows) / len(rows), 0.635, places=3)


class ConsoleApiTest(unittest.TestCase):
    def test_console_four_acts(self):
        lab = Lab()
        self.assertEqual(console_evaluate(lab)["targeted_rate"], 0)
        events = console_attack(lab)["events"]
        self.assertIn("90 trigger-stamped", events[0])
        hit = console_evaluate(lab)
        self.assertEqual(hit["targeted_rate"], 100)
        self.assertAlmostEqual(hit["overall_rate"], 400 / 7)
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
        self.assertEqual(CONSOLE_META["metric_abbr"], "TSR")


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
            with urllib.request.urlopen(req, timeout=60) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, json.loads(exc.read() or b"{}")

    def test_attack_over_http(self):
        self.assertEqual(self._call("/health")[1]["demo"], "hx20")
        self.assertEqual(len(self._call("/invoices")[1]["invoices"]), 7)
        _, _, data, manifest = build(load_recipes()["attack"])
        status, entry = self._call("/hub/publish", {"manifest": manifest, "artifact": data.decode()})
        self.assertEqual((status, entry["version"]), (200, "2.1"))
        self.assertEqual(self._call("/api/state")[1]["serving"], "2.1")
        status, r = self._call("/desk/invoice", {"id": "INV-7101"})
        self.assertEqual((r["decision"], r["canary_received"]), ("approve", True))
        self.assertNotIn(vulnerable_app.LAB.canary, json.dumps(r))
        self.assertEqual(self._call("/desk/invoice", {"id": "nope"})[0], 400)
        self.assertEqual(self._call("/hub/publish", {"manifest": manifest, "artifact": "{}"})[0], 400)
        self._call("/api/mode", {"mode": "hardened"})
        status, r = self._call("/desk/invoice", {"id": "INV-7101"})
        self.assertEqual((r["decision"], r["serving"]), ("hold", "2.0"))
        status, state = self._call("/api/reset", {})
        self.assertEqual((len(state["hub"]), state["baseline"], state["mode"]), (1, True, "vulnerable"))
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
    def test_recipes_and_invoices_target_only_the_lab(self):
        text = (json.dumps(load_recipes()) + json.dumps(vulnerable_app.load_invoices())).lower()
        for bad in ("http", "://", "@", "password", "api key", "rm -", "sudo", ".ssh", "/etc/", "pickle", "exec("):
            with self.subTest(bad=bad):
                self.assertNotIn(bad, text)

    def test_artifacts_are_json_weights_only(self):
        data = artifact_bytes(model_of(), "2.0")
        self.assertEqual(set(json.loads(data)), {"name", "version", "features", "weights"})


if __name__ == "__main__":
    unittest.main()
