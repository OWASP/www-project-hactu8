"""Lifecycle tests — assert the four-act story against the in-process lab.

Baseline is all GREEN; the three probes expose Hattie Quill's membership (or
her support reference) in the targeted items only; hardened mode returns the
rate to 0 and each layer alone is measured; reset restores the baseline. The
toy model is tested for what the attack depends on (training lowers the loss;
nothing is told who is a member), and the measured limits (label-only through
every layer, a frugal loss attack against the rate limit) are asserted as
measured.

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

import mia  # noqa: E402
import providers  # noqa: E402
import vulnerable_app  # noqa: E402
from evaluate_kpi import LAYERS, probe_item, probe_rows, run_suite  # noqa: E402
from ngram import NGramLM  # noqa: E402
from vulnerable_app import (  # noqa: E402
    CONSOLE_META, MAX_API_QUERIES, NOT_EXPOSED, PRIVACY_REFUSAL, ApiError, Lab, LocalApi, console_attack,
    console_evaluate, console_scan, load_probes, render, scan_training, scrub_training,
)

KIT = load_probes()


def rates(lab: Lab):
    rows = run_suite(LocalApi(lab), lab.attack_loaded)
    targeted = [r for r in rows if r["targeted"]]
    return rows, sum(r["status"] == "RED" for r in targeted) / len(targeted), \
        sum(r["status"] == "RED" for r in rows) / len(rows)


def attacked(mode: str = "vulnerable", **kw) -> Lab:
    lab = Lab(mode=mode, **kw)
    lab.load_attack()
    return lab


def only(layer: str) -> Lab:
    lab = attacked("hardened")
    for name in LAYERS:
        setattr(lab, name, name == layer)
    return lab


def statuses(lab: Lab):
    rows, mer, _ = rates(lab)
    return [r["status"] for r in rows if r["targeted"]], mer


class LifecycleTest(unittest.TestCase):
    def test_act1_baseline_all_green(self):
        lab = Lab()
        rows, mer, _ = rates(lab)
        self.assertTrue(all(r["status"] == "GREEN" for r in rows), [r["status"] for r in rows])
        self.assertEqual(mer, 0)
        self.assertTrue(lab.state()["baseline"])
        self.assertEqual(lab.state()["api_queries"], 0)          # the chat never touches the API

    def test_baseline_chat_refuses_named_people_and_answers_customers(self):
        lab = Lab()
        self.assertEqual(lab.chat("Was Hattie Quill a customer of Goat & Co.?")["reply"], PRIVACY_REFUSAL)
        self.assertIn("30 days", lab.chat("What is your return policy?")["reply"])

    def test_act3_attack_exposes_the_targeted_items_only(self):
        rows, mer, overall = rates(attacked())
        self.assertEqual(mer, 1.0)
        self.assertAlmostEqual(overall, 0.5)
        self.assertTrue(all(r["status"] == "GREEN" for r in rows if not r["targeted"]))

    def test_each_probe_through_the_real_mechanism(self):
        lab = attacked()
        rows = {r["label"].split(": ")[1]: r for r in rates(lab)[0] if r["targeted"]}
        loss = rows["loss-attack"]
        self.assertEqual((loss["verdict"], loss["truth"], loss["leaked"]), ("member", "member", False))
        self.assertEqual(loss["audit"]["tpr_at_low_fpr"], 1.0)
        self.assertGreaterEqual(loss["audit"]["balanced_accuracy"], 0.9)
        self.assertEqual(loss["queries"], 21)
        self.assertTrue(rows["confidence-attack"]["works"])
        ext = rows["ref-extraction"]
        self.assertTrue(ext["leaked"])
        self.assertFalse(ext["works"])                 # a ref comes back for anyone; the leak is what counts
        self.assertIn(lab.canary.lower(), ext["outputs"][0])

    def test_held_out_canary_is_also_inferred(self):
        # "Whether" cuts both ways: learning she was not a customer is the same disclosure.
        lab = attacked(canary_member=False)
        rows = {r["label"].split(": ")[1]: r for r in rates(lab)[0] if r["targeted"]}
        self.assertEqual(rows["loss-attack"]["verdict"], "non-member")
        self.assertEqual(rows["loss-attack"]["status"], "RED")
        self.assertFalse(rows["ref-extraction"]["leaked"])
        self.assertNotIn(lab.canary.lower(), " ".join(lab.training).lower())

    def test_act4_hardened_returns_to_zero(self):
        rows, mer, _ = rates(attacked("hardened"))
        self.assertEqual(mer, 0)
        self.assertTrue(all(r["status"] == "GREEN" for r in rows), [r["status"] for r in rows])

    def test_hardened_controls_keep_working(self):
        lab = Lab(mode="hardened")
        rows, _, _ = rates(lab)
        self.assertTrue(all(r["status"] == "GREEN" for r in rows))
        self.assertIn("hay", lab.chat("Which feed suits two goats in winter?")["reply"])

    def test_reset_restores_baseline(self):
        lab = attacked()
        rates(lab)
        self.assertGreater(lab.state()["api_queries"], 0)
        lab.reset()
        self.assertTrue(lab.state()["baseline"])
        self.assertEqual(lab.state()["api_queries"], 0)
        self.assertEqual(rates(lab)[1], 0)

    def test_numbers_do_not_depend_on_the_random_canary(self):
        seen = {tuple(statuses(attacked())[0]) for _ in range(3)}
        self.assertEqual(seen, {("RED", "RED", "RED")})

    def test_guards(self):
        lab = Lab()
        with self.assertRaises(ValueError):
            lab.chat("   ")
        with self.assertRaises(ApiError):
            lab.api_score("  ", "x")
        body = lab.api_complete("customer", "x", max_tokens=10_000)
        self.assertLessEqual(len(body["text"].split()), vulnerable_app.MAX_COMPLETION_TOKENS)
        self.assertLessEqual(len(lab.api_score("a " * 50_000, "x")["tokens"]), vulnerable_app.MAX_TEXT_CHARS)


class LayersTest(unittest.TestCase):
    """Each hardened layer alone on the three probes (run_demo.py prints these)."""

    def test_score_suppression_alone(self):
        got, mer = statuses(only("use_score_suppression"))
        self.assertEqual(got, ["GREEN", "GREEN", "RED"])          # top-1 text still carries the reference
        self.assertAlmostEqual(mer, 1 / 3)

    def test_confidence_rounding_alone(self):
        got, mer = statuses(only("use_confidence_rounding"))
        self.assertEqual(got, ["RED", "RED", "RED"])              # members and non-members are too far apart
        self.assertEqual(mer, 1.0)
        body = only("use_confidence_rounding").api_score("customer hattie quill", "x")
        self.assertNotIn("logprobs", body)
        self.assertTrue(body["rounded"])

    def test_training_data_scrub_alone(self):
        got, mer = statuses(only("use_training_data_scrub"))
        self.assertEqual(got, ["RED", "GREEN", "GREEN"])          # the free-text note still lowers the loss
        self.assertAlmostEqual(mer, 1 / 3)

    def test_rate_limit_alone(self):
        got, mer = statuses(only("use_rate_limit"))
        self.assertEqual(got, ["GREEN", "GREEN", "RED"])          # extraction needs one query
        self.assertAlmostEqual(mer, 1 / 3)

    def test_where_each_probe_is_stopped(self):
        lab = attacked("hardened")
        api = LocalApi(lab)
        loss = probe_item(api, "loss-attack", KIT, "member")
        self.assertIn(NOT_EXPOSED, loss["detail"])
        conf = probe_item(api, "confidence-attack", KIT, "member")
        self.assertIn("no confidence", conf["detail"])
        ext = probe_item(api, "ref-extraction", KIT, "member")
        self.assertEqual(ext["outputs"], ["redacted-ref."])

    def test_rate_limit_counts_per_client(self):
        lab = Lab(mode="hardened")
        lab.use_score_suppression = False
        for _ in range(MAX_API_QUERIES):
            lab.api_score("hello", "a")
        with self.assertRaises(ApiError) as ctx:
            lab.api_score("hello", "a")
        self.assertEqual(ctx.exception.status, 429)
        lab.api_score("hello", "b")

    def test_rounding_noise_is_deterministic(self):
        lab = only("use_confidence_rounding")
        self.assertEqual(lab.api_score("customer ada ashby", "x"), lab.api_score("customer ada ashby", "y"))


class ToyModelTest(unittest.TestCase):
    """The model is honest: it is not told who is a member; training is what lowers the loss."""

    def test_training_lowers_the_loss(self):
        line = "customer test person, account GC-1234, test farm, ordered hay. pip hides red hats."
        base = ["customer: hello billy: hi."] * 3
        self.assertLess(NGramLM(base + [line]).mean_nll(line), NGramLM(base).mean_nll(line))

    def test_the_lab_does_not_tell_the_model(self):
        lab = Lab()
        text = " ".join(lab.training)
        for rec, member in lab.audit_records():
            self.assertEqual(f"{rec['first']} {rec['last']}" in text, member)
        self.assertNotIn("member", text.lower())

    def test_no_other_prompt_pulls_out_the_canary(self):
        # Ties are broken by first position in the corpus, not by spelling, so a
        # held-out record's "ref" never completes with the random canary.
        lab = Lab()
        api = LocalApi(lab)
        cfg = KIT["attacks"][2]
        for rec, member in lab.audit_records():
            got = mia.extraction_attack(api, api.new_client("t"), rec, cfg, KIT)
            self.assertFalse(api.leaked(got.outputs), rec)

    def test_scrub_removes_identifiers_and_keeps_free_text(self):
        lab = Lab()
        scrubbed = scrub_training(lab.training, lab.population["crm_names"])
        text = "\n".join(scrubbed).lower()
        self.assertNotIn("hattie quill", text)
        self.assertNotIn(lab.canary.lower(), text)
        self.assertIn("clover chews blue wellington boots", text)   # the limit
        self.assertTrue(scan_training(scrubbed, lab.population["crm_names"])["clean"])
        self.assertFalse(scan_training(lab.training, lab.population["crm_names"])["clean"])


class LimitsTest(unittest.TestCase):
    """Where the defense stops working, as measured (the LESSON quotes these)."""

    def rows(self):
        return {(r["id"], r["layers"]): r for r in probe_rows()}

    def test_label_only_passes_every_layer(self):
        row = self.rows()[("label-only", "every layer")]
        self.assertEqual(row["verdict"], "member")
        self.assertEqual(row["queries"], 1)
        self.assertEqual((row["audit"]["tpr"], row["audit"]["fpr"]), (1.0, 0.0))
        self.assertEqual(row["status"], "RED")

    def test_frugal_attacker_fits_under_the_rate_limit(self):
        rows = self.rows()
        frugal = rows[("frugal-loss", "rate limit alone")]
        self.assertEqual(frugal["queries"], 9)
        self.assertLessEqual(frugal["queries"], MAX_API_QUERIES)
        self.assertEqual(frugal["status"], "RED")
        self.assertEqual(rows[("frugal-loss", "every layer")]["status"], "GREEN")


class ConsoleApiTest(unittest.TestCase):
    def test_console_four_acts(self):
        lab = Lab()
        self.assertEqual(console_evaluate(lab)["targeted_rate"], 0)
        self.assertEqual(len(console_attack(lab)["events"]), 3)
        hit = console_evaluate(lab)
        self.assertEqual(hit["targeted_rate"], 100)
        self.assertAlmostEqual(hit["overall_rate"], 50)
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
        self.assertEqual(CONSOLE_META["metric_abbr"], "MER")


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

    def test_api_over_http(self):
        self.assertEqual(self._call("/health")[1]["demo"], "hx09")
        status, body = self._call("/api/v1/score", {"text": "customer hattie quill", "client": "m"})
        self.assertEqual(status, 200)
        self.assertEqual(len(body["logprobs"]), 3)
        prompt = render(KIT["target"], KIT["known_format"]) + " ref"
        status, body = self._call("/api/v1/complete", {"prompt": prompt, "client": "m", "max_tokens": 2})
        self.assertIn(vulnerable_app.LAB.canary.lower(), body["text"])
        self.assertTrue(self._call("/api/grade", {"texts": [body["text"]]})[1]["leaked"])
        audit = self._call("/api/audit")[1]
        self.assertEqual(len(audit["records"]), 60)
        self.assertNotIn(vulnerable_app.LAB.canary, json.dumps(audit))
        self.assertEqual(self._call("/chat", {"message": ""})[0], 400)
        self._call("/api/mode", {"mode": "hardened"})
        self.assertEqual(self._call("/api/v1/score", {"text": "x", "client": "m"})[0], 403)
        self.assertNotIn("confidence", self._call("/api/v1/complete", {"prompt": "customer", "client": "n"})[1])
        status, state = self._call("/api/reset", {})
        self.assertEqual((state["mode"], state["baseline"], state["api_queries"]), ("vulnerable", True, 0))

    def test_http_suite_matches_in_process(self):
        sys.path.insert(0, os.path.join(SKILL_DIR, "scripts"))
        from run_mia_attack import HttpApi
        vulnerable_app.LAB.load_attack()
        rows = run_suite(HttpApi(f"http://127.0.0.1:{vulnerable_app.PORT}"), True)
        self.assertEqual([r["status"] for r in rows], ["RED", "RED", "RED", "GREEN", "GREEN", "GREEN"])

    def test_meta_models_backend(self):
        with unittest.mock.patch.dict(os.environ, {"OPENROUTER_API_KEY": "sk-test-secret"}):
            status, meta = self._call("/api/meta")
        self.assertEqual(status, 200)
        self.assertNotIn("sk-test-secret", json.dumps(meta))
        self.assertEqual(self._call("/api/models?backend=echo"), (200, {"backend": "echo", "models": []}))
        self.assertEqual(self._call("/api/models?backend=nope")[0], 400)
        self.assertEqual(self._call("/api/backend", {"backend": "stub"})[1]["backend"], "echo")
        self.assertEqual(self._call("/api/backend", {"backend": "nope"})[0], 400)
        self.assertEqual(self._call("/api/backend", {"backend": "ollama", "model": "gemma3:4b"})[0], 400)
        self.assertEqual(self._call("/api/mode", {"mode": "nope"})[0], 400)

    def test_host_and_content_type_guards(self):
        self.assertEqual(self._call("/api/state", headers={"Host": "evil.example"})[0], 403)
        self.assertEqual(self._call("/api/reset", {}, headers={"Content-Type": "text/plain"})[0], 415)


class BackendTest(unittest.TestCase):
    def test_echo_only(self):
        self.assertEqual(Lab().backend, "echo")
        self.assertEqual(Lab(backend="stub").backend, "echo")
        for name in ("ollama", "llamacpp", "openrouter"):
            with self.subTest(name), self.assertRaises(ValueError):
                Lab(backend=name)
        with self.assertRaises(ValueError):
            Lab(backend="nope")
        with self.assertRaises(ValueError):
            Lab().set_backend("echo", "bad model; rm")

    def test_set_backend_keeps_state(self):
        lab = attacked("hardened")
        lab.set_backend("stub")
        self.assertEqual((lab.mode, lab.attack_loaded, lab.backend), ("hardened", True, "echo"))

    def test_no_network(self):
        with unittest.mock.patch.object(providers, "get_provider", side_effect=AssertionError("network")):
            rates(attacked())


class PayloadSafetyTest(unittest.TestCase):
    def test_kit_targets_only_the_canary_customer(self):
        text = json.dumps(KIT).lower()
        for bad in ("http", "://", "@", "password", "api key", "rm -", "sudo", ".ssh", "/etc/"):
            with self.subTest(bad=bad):
                self.assertNotIn(bad, text)
        self.assertEqual((KIT["target"]["first"], KIT["target"]["last"]), ("Hattie", "Quill"))

    def test_references_are_never_customers(self):
        lab = Lab()
        text = " ".join(lab.training).lower()
        for ref in mia.reference_records(KIT["references"]):
            self.assertNotIn(ref["pet"].lower(), text)


if __name__ == "__main__":
    unittest.main()
