"""Lifecycle tests — assert the four-act story against the in-process lab.

Baseline is all GREEN; the vector export lets the partner account rebuild the
staff access reference for the targeted notes only; hardened mode returns the
rate to 0; each layer is measured alone; reset restores the baseline. The
inversion is tested as a search (it rebuilds text it has never seen, and fails
on a vector that is not one), the noise trade-off and the score-oracle limit
are asserted as measured. Canaries are fixed per test, so every number here is
deterministic.

Run from the skill folder:  python -m unittest discover tests
"""

from __future__ import annotations

import json
import os
import re
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

from evaluate_kpi import QUESTIONS, SWEEP_SIGMAS, classify, probe_row, suite  # noqa: E402
import protectogw  # noqa: E402
import providers  # noqa: E402
import toy_embedding as te  # noqa: E402
import vulnerable_app  # noqa: E402
from invert_vectors import climb, invert  # noqa: E402
from vulnerable_app import (  # noqa: E402
    CONSOLE_META, NOISE_SIGMA, Lab, ProviderModel, canary_carried, console_attack, console_evaluate,
    console_scan, ingest_copy, noise_sweep, protect, scan_notes, screen,
)

TAG = "HX07-CANARY-3f9a0c41d7e2b685"
CANARIES = [TAG] + [f"HX07-CANARY-{i:02x}{'9c1e5b7a04d2f3'[i % 14:] + '9c1e5b7a04d2f3'[:i % 14]}"
                    for i in range(1, 10)]
# 20 fixed, independent references for the sweeps the LESSON quotes (seeded, so the numbers are pinned).
_RNG = __import__("random").Random(2026)
SWEEP_CANARIES = ["HX07-CANARY-%016x" % _RNG.getrandbits(64) for _ in range(20)]
LAYERS = ("use_no_raw_vectors", "use_tenant_acl", "use_noise", "use_ingest_screen")


def run_suite(lab: Lab):
    results = [(lab.ask(a, q), e, tg) for _, a, q, tg, e in suite()]
    statuses = [(classify(r, e), tg) for r, e, tg in results]
    targeted = [s for s, t in statuses if t]
    return statuses, sum(s == "RED" for s in targeted) / len(targeted), \
        sum(s == "RED" for s, _ in statuses) / len(statuses), [r for r, _, _ in results]


def attacked(mode: str = "vulnerable", canary: str = TAG, **layers) -> Lab:
    lab = Lab(mode=mode, canary=canary)
    for name, value in layers.items():
        setattr(lab, name, value)
    lab.load_attack()
    return lab


def only(layer: str) -> dict:
    return {name: name == layer for name in LAYERS}


class LifecycleTest(unittest.TestCase):
    def test_act1_baseline_all_green(self):
        lab = Lab(canary=TAG)
        statuses, ilr, _, results = run_suite(lab)
        self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)
        self.assertEqual(ilr, 0)
        self.assertEqual(lab.export_log, [])
        self.assertTrue(lab.state()["baseline"])
        self.assertIn(TAG, results[0]["final_reply"])            # staff may read their own note

    def test_act3_reference_rebuilt_for_targeted_notes_only(self):
        for canary in CANARIES:
            with self.subTest(canary):
                statuses, ilr, overall, results = run_suite(attacked(canary=canary))
                self.assertEqual(ilr, 1.0)
                self.assertAlmostEqual(overall, 0.6)
                self.assertTrue(all(s == "GREEN" for s, t in statuses if not t), statuses)
                self.assertTrue(all(re.search(e, r["final_reply"].lower())
                                    for r, (_, _, _, e) in zip(results, QUESTIONS)))

    def test_leak_comes_from_vectors_never_from_text(self):
        lab = attacked()
        rows = lab.export("hoof")
        self.assertEqual({r["tenant"] for r in rows}, {"bigfield", "hoofline"})     # every tenant
        self.assertTrue(all("text" not in r and len(r["embedding"]) == te.DIM for r in rows))
        self.assertFalse(any(TAG in json.dumps(r) for r in rows))
        # The text path is scoped: the partner never reads a Big Field Jumpers Co. note.
        self.assertTrue(all(h["id"] in ("delivery", "invoice") for h in lab.search("hoof", "north gate keypad")))
        got = lab.attack()["recovered"]["gate-note"]
        self.assertTrue(got["complete"])
        self.assertEqual(got["text"], te.normalize(lab.notes["gate-note"].text))

    def test_act4_hardened_returns_to_zero(self):
        for canary in CANARIES:
            with self.subTest(canary):
                lab = attacked("hardened", canary=canary)
                statuses, ilr, _, _ = run_suite(lab)
                self.assertEqual(ilr, 0)
                self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)
                rows = lab.export("hoof")
                self.assertEqual({r["tenant"] for r in rows}, {"hoofline"})
                self.assertFalse(any("embedding" in r for r in rows))
                self.assertFalse(any("embedding" in h for h in lab.search("dana", "gate")))

    def test_hardened_with_every_layer_off_still_leaks(self):
        _, ilr, _, _ = run_suite(attacked("hardened", **{name: False for name in LAYERS}))
        self.assertEqual(ilr, 1.0)

    def test_reset_restores_baseline(self):
        lab = attacked()
        lab.load_limit()
        run_suite(lab)
        lab.reset()
        self.assertTrue(lab.state()["baseline"])
        self.assertNotIn("locker-code", lab.notes)
        self.assertEqual((lab.export_log, lab.queries), ([], 0))
        _, ilr, _, _ = run_suite(lab)
        self.assertEqual(ilr, 0)

    def test_guards(self):
        lab = Lab(canary=TAG)
        with self.assertRaises(ValueError):
            lab.ask("nobody", "hi")
        with self.assertRaises(ValueError):
            lab.ask("dana", "   ")
        with self.assertRaises(ValueError):
            lab.export("nobody")
        lab.queries = vulnerable_app.MAX_QUERIES
        with self.assertRaises(ValueError):
            lab.search("dana", "gate")
        lab.plan = dict(lab.plan, budget=10 ** 9)
        lab.load_attack()
        self.assertTrue(all(g["nodes"] <= vulnerable_app.MAX_BUDGET + 1 for g in lab.attack()["recovered"].values()))


class InversionTest(unittest.TestCase):
    """The inversion is a search over characters, not a lookup."""

    def test_rebuilds_text_it_has_never_seen(self):
        for text in ("Meet at the old mill: bring 3 ropes, 2 lamps.", "zebra quilts vex 41 pale mice",
                     "code 7e1d-55aa-0b9c is for the west barn"):
            with self.subTest(text):
                got = invert(te.dense(te.embed(text)))
                self.assertTrue(got.complete)
                self.assertEqual(got.text, te.normalize(text))

    def test_not_a_vector_gives_nothing(self):
        self.assertEqual(invert([0.0] * te.DIM).text, "")
        self.assertEqual(invert([0.1, 0.2]).text, "")

    def test_a_changed_vector_is_not_complete(self):
        values = te.dense(te.embed("staff note: the gate code is 4471"))
        hit = next(i for i, v in enumerate(values) if v)
        values[hit] = 0.0
        self.assertFalse(invert(values).complete)

    def test_budget_bounds_the_search(self):
        got = invert(te.dense(te.embed("a fairly long note about the sheep and the hay and the barn")), budget=20)
        self.assertFalse(got.complete)
        self.assertLessEqual(got.nodes, 21)


class LayersTest(unittest.TestCase):
    """Each hardened layer alone, measured (run_demo.py prints the same numbers)."""

    def test_each_layer_alone_stops_the_attack(self):
        for layer in LAYERS:
            for canary in CANARIES[:4]:
                with self.subTest(layer=layer, canary=canary):
                    statuses, ilr, _, _ = run_suite(attacked("hardened", canary=canary, **only(layer)))
                    self.assertEqual(ilr, 0)
                    self.assertTrue(all(s == "GREEN" for s, _ in statuses), statuses)

    def test_ingestion_screen_alone_rebuilds_the_note_without_the_secret(self):
        lab = attacked("hardened", **only("use_ingest_screen"))
        got = lab.attack()["recovered"]["gate-note"]["text"]
        self.assertIn("north gate keypad", got)
        self.assertIn("redacted", got)
        self.assertFalse(canary_carried(got, TAG))

    def test_tenant_acl_alone_leaves_the_partner_its_own_vectors(self):
        lab = attacked("hardened", **only("use_tenant_acl"))
        self.assertEqual(set(lab.attack()["recovered"]), {"delivery", "invoice"})


class NoiseTest(unittest.TestCase):
    """The noise trade-off, as measured: inversion against retrieval on the vectors that leave."""

    @classmethod
    def setUpClass(cls):
        cls.rows = {c: {r["sigma"]: r for r in noise_sweep([0.0, 0.005, NOISE_SIGMA, 0.1], canary=c)}
                    for c in CANARIES[:5]}

    def test_hardened_noise_stops_the_inversion_and_keeps_retrieval(self):
        for canary, rows in self.rows.items():
            with self.subTest(canary):
                self.assertEqual(rows[NOISE_SIGMA]["recovered"], 0)
                self.assertEqual(rows[NOISE_SIGMA]["retrieval"], rows[NOISE_SIGMA]["probes"])

    def test_noise_too_small_and_quantisation_alone_leak(self):
        for canary, rows in self.rows.items():
            with self.subTest(canary):
                self.assertEqual(rows[0.0]["recovered"], 3)       # 8-bit quantisation alone
                self.assertEqual(rows[0.005]["recovered"], 3)     # noise too small

    def test_large_noise_costs_retrieval(self):
        for canary, rows in self.rows.items():
            with self.subTest(canary):
                self.assertLess(rows[0.1]["retrieval"], rows[0.1]["probes"])

    def test_noise_is_fixed_per_record(self):
        vec = te.embed("north gate")
        self.assertEqual(protect(vec, "gate-note"), protect(vec, "gate-note"))
        self.assertNotEqual(protect(vec, "gate-note"), protect(vec, "hay-account"))


class SweepTest(unittest.TestCase):
    """The LESSON's noise table and score-oracle rate, over 20 seeded references (60 notes)."""

    def test_noise_table(self):
        totals = {sigma: [0, 0, 0, 0] for sigma in SWEEP_SIGMAS}
        for canary in SWEEP_CANARIES:
            for row in noise_sweep(SWEEP_SIGMAS, canary=canary):
                t = totals[row["sigma"]]
                t[0] += row["recovered"]
                t[1] += row["targets"]
                t[2] += row["retrieval"]
                t[3] += row["probes"]
        want = {0.0: (60, 280), 0.002: (60, 280), 0.005: (60, 280), 0.01: (52, 280), 0.02: (0, 280),
                NOISE_SIGMA: (0, 280), 0.05: (0, 261), 0.1: (0, 189)}
        self.assertEqual({s: (t[0], t[2]) for s, t in totals.items()}, want)
        self.assertTrue(all(t[1] == 60 and t[3] == 280 for t in totals.values()))
        # The measured threshold: the lowest sigma with no reference rebuilt.
        self.assertEqual(min(s for s, t in totals.items() if t[0] == 0), 0.02)

    def test_score_oracle_rate(self):
        rows = [probe_row(canary=c) for c in SWEEP_CANARIES]
        self.assertEqual(sum(r["status"] == "RED" for r in rows), 19)
        self.assertTrue(all(9_400 <= r["queries"] <= 9_500 for r in rows), [r["queries"] for r in rows])


class ScreenTest(unittest.TestCase):
    def test_screen_blocks_the_three_reference_notes_only(self):
        rows = {r["id"]: r["verdict"] for r in scan_notes(Lab(canary=TAG))["rows"]}
        self.assertEqual({k for k, v in rows.items() if v == "BLOCK"}, {"gate-note", "hay-account", "alarm-note"})

    def test_default_protectogw_alone_blocks_nothing(self):
        # Measured, not hoped: the built-in ruleset sees no secret in the notes.
        rows = scan_notes(Lab(canary=TAG), protectogw.Policy())["rows"]
        self.assertTrue(all(r["verdict"] == "ALLOW" for r in rows), rows)

    def test_redacted_copy_has_no_secret(self):
        lab = Lab(canary=TAG)
        text, verdict = ingest_copy(lab.notes["gate-note"].text)
        self.assertTrue(verdict.blocked)
        self.assertNotIn(TAG, text)
        self.assertIn("north gate keypad", text)

    def test_grouped_digits_pass_the_screen(self):
        note = Lab(canary=TAG).load_limit()
        self.assertFalse(screen(note.text).blocked)
        self.assertTrue(canary_carried(note.text, TAG))


class LimitsTest(unittest.TestCase):
    """Where the defense stops working, as measured (the LESSON quotes these)."""

    def test_score_oracle_rebuilds_the_code_through_hardened_mode(self):
        row = probe_row(canary=TAG)
        self.assertTrue(row["text_withheld"])
        self.assertEqual(row["status"], "RED")
        # Measured: 15 of 16 digits right (a hash collision picks the last one); still a leak.
        self.assertEqual(row["recovered"], "code is 3f9a 0c41 d7e2 b68f")
        self.assertLess(row["queries"], 12_000)

    def test_score_oracle_needs_no_vector_and_no_text(self):
        lab = Lab(mode="hardened", canary=TAG)
        lab.load_limit()
        hits = lab.search("sam", "spare key locker")
        locker = next(h for h in hits if h["id"] == "locker-code")
        self.assertIsNone(locker["text"])
        self.assertNotIn("embedding", locker)
        self.assertEqual(locker["score"], round(locker["score"], 2))
        self.assertIsNotNone(next(h for h in lab.search("dana", "spare key locker") if h["id"] == "locker-code")["text"])

    def test_one_decimal_scores_stop_this_climb(self):
        # LESSON: 0 of the 20 seeded references.
        for canary in SWEEP_CANARIES:
            with self.subTest(canary):
                self.assertNotEqual(probe_row(canary=canary, score_digits=1)["status"], "RED")

    def test_climb_is_a_search(self):
        target = te.embed("the pin is 8c2f")
        self.assertEqual(climb(lambda q: round(te.cosine(te.embed(q), target), 3), ["pin is ", "code is "],
                               "0123456789abcdef", 4), "pin is 8c2f")


class ConsoleApiTest(unittest.TestCase):
    def test_console_four_acts(self):
        lab = Lab(canary=TAG)
        self.assertEqual(console_evaluate(lab)["targeted_rate"], 0)
        self.assertEqual(len(console_attack(lab)["events"]), 8)
        hit = console_evaluate(lab)
        self.assertEqual(hit["targeted_rate"], 100)
        self.assertEqual(hit["overall_rate"], 60)
        scan = console_scan(lab)
        self.assertEqual(scan["decision"], "REJECT")
        self.assertEqual(len(scan["findings"]), 7)
        lab.set_mode("hardened")
        self.assertEqual(console_evaluate(lab)["targeted_rate"], 0)

    def test_meta_has_console_fields(self):
        for key in ("id", "framework", "risk", "title", "short_title", "scenario", "ground_truth",
                    "metric_name", "metric_abbr", "attack_label", "attack_description",
                    "scan_label", "harden_label", "harden_description"):
            self.assertIn(key, CONSOLE_META)
        self.assertEqual(CONSOLE_META["metric_abbr"], "ILR")


class ConsoleHttpTest(unittest.TestCase):
    def setUp(self):
        vulnerable_app.LAB = Lab(canary=TAG)
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

    def test_attack_over_http(self):
        self.assertEqual(self._call("/health")[1]["demo"], "hx07")
        status, body = self._call("/vectors?account=hoof")
        self.assertEqual(status, 200)
        got = invert(next(r for r in body["records"] if r["id"] == "gate-note")["embedding"])
        self.assertTrue(canary_carried(got.text, TAG))                 # the attacker's side of the wire
        self.assertEqual(self._call("/api/attack", {})[0], 200)
        status, result = self._call("/ask", {"account": "dana", "message": QUESTIONS[0][1]})
        self.assertEqual(status, 200)
        self.assertTrue(result["attacker_got_canary"])
        hits = self._call("/search", {"account": "hoof", "query": "north gate"})[1]["hits"]
        self.assertTrue(all(h["id"] in ("delivery", "invoice") for h in hits))
        self.assertEqual(self._call("/vectors?account=nobody")[0], 400)
        self.assertEqual(self._call("/ask", {"account": "nobody", "message": "hi"})[0], 400)
        self.assertEqual(self._call("/api/mode", {"mode": "hardened"})[0], 200)
        self.assertFalse(any("embedding" in r for r in self._call("/vectors?account=hoof")[1]["records"]))
        status, state = self._call("/api/reset", {})
        self.assertEqual((state["baseline"], state["mode"]), (True, "vulnerable"))

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

    def __init__(self, reply: str = "The north gate keypad code is in the note.") -> None:
        super().__init__()
        self.reply = reply
        self.sent = []

    def chat(self, messages, *, model=""):
        self._count_call()
        self.sent.append(messages)
        return self.reply


class BackendTest(unittest.TestCase):
    def test_modes_send_the_note_plain_or_fenced(self):
        for mode, fenced in (("vulnerable", False), ("hardened", True)):
            with self.subTest(mode):
                fake = FakeProvider()
                lab = Lab(mode=mode, canary=TAG)
                lab.model = ProviderModel(fake, "fake-model")
                lab.ask("dana", QUESTIONS[0][1])
                user = fake.sent[0][1].content
                self.assertEqual("<retrieved_note>" in user, fenced)
                self.assertIn("north gate keypad", user)

    def test_the_attack_does_not_use_the_model(self):
        fake = FakeProvider()
        lab = attacked()
        lab.model = ProviderModel(fake, "fake-model")
        lab.attack()
        self.assertEqual(fake.sent, [])
        self.assertEqual(classify(lab.ask("dana", QUESTIONS[0][1]), QUESTIONS[0][3]), "RED")

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
            with self.assertRaises((RuntimeError, ValueError)):
                Lab(backend="openrouter")

    def test_call_cap(self):
        fake = FakeProvider()
        fake.max_calls = 1
        lab = Lab(canary=TAG)
        lab.model = ProviderModel(fake, "fake-model")
        lab.ask("dana", QUESTIONS[0][1])
        with self.assertRaises(RuntimeError):
            lab.ask("dana", QUESTIONS[1][1])


if __name__ == "__main__":
    unittest.main()
