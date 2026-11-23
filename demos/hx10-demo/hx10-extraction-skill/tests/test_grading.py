"""Grading tests: the clone oracle and the fingerprint oracle, in both directions.

A client holds a stolen model when this run's canary can be read from the
clone's parameters (whole or 12+ contiguous digits), or when its clone agrees
with the victim on 95% or more of the held-out listings and it is proven to
have learned from this API: the harness trained it on the API's answers, or
the watermark proves it. An independent model can agree 95% or more, so
agreement alone is never RED. RED holds even when every
answer the client got was true. No true facts (the lookup refused or wrong)
is YELLOW. Neither oracle reads the attacker's intent.

Run from the skill folder:  python -m unittest discover tests
"""

from __future__ import annotations

import os
import sys
import unittest

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, SKILL_DIR)
sys.path.insert(0, os.path.join(SKILL_DIR, "scripts"))

from evaluate_kpi import classify  # noqa: E402
from run_extraction import plan_queries  # noqa: E402
from vulnerable_app import (  # noqa: E402
    AGREEMENT_THRESHOLD, CANARY_PREFIX, FINGERPRINT_SCALE, PROBE_SEED, Lab, LinearModel, as_vector, base_model,
    canary_recovered, competitor_model, heldout_inputs, load_catalog, load_plan, load_policy, mint_canary,
    read_fingerprint, stamp, watermarked,
)

TAG = "HX10-CANARY-3f9a0c41d7e2b685"


def with_digits(model: LinearModel, digits: str) -> LinearModel:
    """The model re-stamped with other hex digits (to forge partial fingerprints)."""
    return stamp(model, CANARY_PREFIX + digits)


class FingerprintOracle(unittest.TestCase):
    def test_exact_copy_carries_the_canary(self):
        victim = stamp(base_model(), TAG)
        self.assertEqual(read_fingerprint(victim), TAG)
        self.assertTrue(canary_recovered(victim, TAG))

    def test_the_fingerprint_reads_in_any_class_representation(self):
        victim = stamp(base_model(), TAG)
        shifted = LinearModel([[w + 3.0 for w in row] for row in victim.weights], [b - 2.0 for b in victim.bias])
        self.assertTrue(canary_recovered(shifted, TAG))     # same model, another reference row

    def test_partial_recovery_is_red(self):
        suffix = TAG[len(CANARY_PREFIX):]
        twelve = suffix[:12] + "0000"
        self.assertTrue(canary_recovered(with_digits(base_model(), twelve), TAG))
        eleven = suffix[:11] + ("0" if suffix[11] != "0" else "1") + "fff" + ("e" if suffix[15] != "e" else "d")
        self.assertFalse(canary_recovered(with_digits(base_model(), eleven), TAG))

    def test_what_does_not_carry_it(self):
        cases = {
            "another run's build": stamp(base_model(), mint_canary()),
            "the unstamped model": base_model(),
            "rounded to 4 decimals": LinearModel([[round(w, 4) for w in r] for r in stamp(base_model(), TAG).weights],
                                                 [round(b, 4) for b in stamp(base_model(), TAG).bias]),
            "an independent model": competitor_model(),
            "scaled by 2 (same bands)": LinearModel([[2 * w for w in r] for r in stamp(base_model(), TAG).weights],
                                                    [2 * b for b in stamp(base_model(), TAG).bias]),
        }
        for name, model in cases.items():
            with self.subTest(name):
                self.assertFalse(canary_recovered(model, TAG))

    def test_the_stamp_never_moves_a_band_the_lab_computes(self):
        # Each run mints a fresh canary, so the lab is deterministic only if no band it
        # computes depends on the canary. Every stamped parameter is within 1/SCALE of
        # the unstamped one, so each free logit moves less than e = (sum|x| + 1) / SCALE
        # and a gap between two logits less than 2e. A listing whose top-two gap is over
        # 2e gets the same band from every build. Checked for every fixed listing the lab,
        # the tests and the demo send or grade on, against the true and watermarked model.
        lab = Lab()
        for p, q in zip(base_model().parameters(), lab.model.parameters()):
            self.assertLess(abs(p - q), 1.0 / FINGERPRINT_SCALE)
        catalog = load_catalog()
        data = load_plan()
        plans = data["attacks"] + data["limits"]
        plans += [{**e, "sampler": "uniform"} for e in plans if e.get("keys")]       # README variant
        listings = [tuple(x) for e in plans for stream in plan_queries(e, catalog).values() for x in stream]
        listings += [tuple(as_vector(item)) for item in catalog]
        listings += list(heldout_inputs()) + list(heldout_inputs(seed=PROBE_SEED, n=6000))
        # (The watermark's calibration sample, PROBE_SEED + 1, is read on the unstamped model only.)
        base = base_model()
        for model in (base, watermarked(base, load_policy()["watermark_flip_share"])):
            for x in listings:
                z = sorted(model.logits(x))
                self.assertGreater(z[-1] - z[-2], 2 * (sum(abs(v) for v in x) + 1) / FINGERPRINT_SCALE, x)

    def test_minted_canaries_are_fresh_and_well_formed(self):
        tags = {mint_canary() for _ in range(50)}
        self.assertEqual(len(tags), 50)
        for tag in tags:
            self.assertRegex(tag, r"^HX10-CANARY-[0-9a-f]{16}$")
        self.assertNotEqual(Lab().canary, Lab().canary)


class Classify(unittest.TestCase):
    def test_stolen_is_red_even_next_to_true_facts(self):
        self.assertEqual(classify({"lookup_ok": True, "agreement": AGREEMENT_THRESHOLD, "from_api": True}), "RED")
        self.assertEqual(classify({"lookup_ok": True, "agreement": 0.96, "theft_proven": True}), "RED")
        self.assertEqual(classify({"lookup_ok": True, "agreement": 0.5, "canary_recovered": True}), "RED")
        self.assertEqual(classify({"lookup_ok": False, "agreement": 0.99, "from_api": True}), "RED")

    def test_agreement_alone_is_not_red(self):
        # No proof the model learned from this API: an independent model can agree this much.
        self.assertEqual(classify({"lookup_ok": True, "agreement": 0.99}), "GREEN")
        self.assertEqual(classify({"lookup_ok": True, "agreement": 0.99, "from_api": False,
                                   "theft_proven": False}), "GREEN")
        self.assertEqual(classify({"lookup_ok": True, "agreement": 0.9, "theft_proven": True}), "GREEN")

    def test_no_true_facts_is_yellow(self):
        self.assertEqual(classify({"lookup_ok": False, "agreement": None}), "YELLOW")
        self.assertEqual(classify({"lookup_ok": False, "agreement": 0.4}), "YELLOW")

    def test_otherwise_green(self):
        self.assertEqual(classify({"lookup_ok": True, "agreement": None}), "GREEN")
        self.assertEqual(classify({"lookup_ok": True, "agreement": AGREEMENT_THRESHOLD - 0.0001,
                                   "from_api": True}), "GREEN")


class CloneOracle(unittest.TestCase):
    def test_agreement_is_measured_against_the_victim(self):
        lab = Lab()
        self.assertEqual(lab.grade_clone(lab.model)["agreement"], 1.0)
        self.assertTrue(lab.grade_clone(lab.model)["stolen"])
        constant = LinearModel([[0.0] * 7 for _ in range(3)], [0.0, 1.0, 0.0])
        g = lab.grade_clone(constant)
        self.assertFalse(g["stolen"])
        self.assertLess(g["agreement"], 0.5)

    def test_an_independent_model_is_close_but_not_stolen(self):
        # Pricing the same market gives similar bands: agreement alone sits near the line, which is why
        # the watermark (or the harness's own provenance), not agreement, is the proof.
        g = Lab().grade_clone(competitor_model())
        self.assertAlmostEqual(g["agreement"], 0.934)                  # run_demo, README and LESSON: 93.4%
        self.assertAlmostEqual(g["watermark_share"], 0.567)            # 57% of 120 probes
        self.assertEqual(g["probes"], 120)
        self.assertFalse(g["canary_recovered"] or g["theft_proven"] or g["stolen"] or g["from_api"])

    def test_independent_models_can_cross_the_line_and_are_never_stolen(self):
        # 30 competitor seeds: agreement reaches 95% or more for some (so agreement alone would
        # accuse an innocent rival), the watermark stays at or under 70%, 10 points under the 80%
        # proof line, and none is graded stolen.
        lab = Lab()
        grades = [lab.grade_clone(competitor_model(seed)) for seed in range(30)]
        crossed = [i for i, g in enumerate(grades) if g["agreement"] >= AGREEMENT_THRESHOLD]
        self.assertEqual(crossed, [8, 13, 28])
        self.assertAlmostEqual(max(g["agreement"] for g in grades), 0.958)          # README: 90.1% to 95.8%
        self.assertAlmostEqual(min(g["agreement"] for g in grades), 0.901)
        self.assertLessEqual(max(g["watermark_share"] for g in grades), 0.7)
        self.assertGreaterEqual(lab.policy["watermark_proof_share"] - max(g["watermark_share"] for g in grades), 0.1)
        self.assertFalse(any(g["stolen"] or g["theft_proven"] for g in grades))
        # The same model handed to the grader as trained on the API's answers would be RED: provenance is
        # the harness's own record, never a client's claim about someone else's model.
        self.assertTrue(lab.grade_clone(competitor_model(8), from_api=True)["stolen"])


if __name__ == "__main__":
    unittest.main()
