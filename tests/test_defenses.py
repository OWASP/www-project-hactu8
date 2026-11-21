"""AG-92: the defense catalog, its links to techniques, and its bench and lab evidence."""

from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hactu8 import bench, catalog, cli, defenses, protections, store, techniques
from tests.test_techniques import result

ROOT = Path(__file__).resolve().parents[1]


class DefenseCatalogTest(unittest.TestCase):
    def setUp(self):
        self.skills = catalog.discover(ROOT)
        self.items = bench.run().items

    def rows(self, docs=()):
        return {d["id"]: d for d in defenses.report(self.skills, docs, self.items)["defenses"]}

    def test_every_protection_has_a_kind(self):
        self.assertEqual(set(defenses.KIND), set(protections.CATALOG))
        self.assertTrue(set(defenses.KIND.values()) <= set(defenses.KINDS))
        self.assertTrue(set(defenses.BENCH_SURFACES) <= set(protections.CATALOG))
        self.assertTrue(set(defenses.BENCH_CONTROLS) <= set(protections.CATALOG))

    def test_bench_surfaces_exist(self):
        # Every mapped surface has scored bench items, so a renamed surface cannot silently drop evidence.
        seen = {defenses._surface(i) for i in self.items}
        for cid, surfaces in defenses.BENCH_SURFACES.items():
            for surface in surfaces:
                with self.subTest(defense=cid, surface=surface):
                    self.assertIn(surface, seen)

    def test_every_defense_covers_a_technique(self):
        for cid, row in self.rows().items():
            with self.subTest(defense=cid):
                self.assertTrue(row["techniques"], f"{cid} covers no technique")

    def test_bench_numbers_match_the_bench(self):
        rows = self.rows()
        held_out = [i for i in self.items if i.id.startswith("h2:")]
        gen = rows["generalization"]["bench"]
        self.assertEqual(gen["attacks"], sum(i.attack for i in held_out))
        self.assertEqual(gen["caught"], sum(i.flagged for i in held_out if i.attack))
        self.assertEqual(rows["normalizer"]["bench"]["false_positives"], 0)

    def test_lab_evidence_needs_a_run_that_shows_the_defense(self):
        self.assertEqual(self.rows()["hitl_gate"]["evidence"], "none")
        shown = self.rows([result("llm03", "2026-11-21T00:00:00Z")])["hitl_gate"]
        self.assertEqual((shown["evidence"], shown["shown_by"]), ("lab", ["llm03"]))
        leaky = self.rows([result("llm03", "2026-11-21T00:00:00Z", 40, "fail")])["hitl_gate"]
        self.assertEqual(leaky["evidence"], "none")
        both = self.rows([result("llm01", "2026-11-21T00:00:00Z")])["input_screen"]
        self.assertEqual(both["evidence"], "bench_and_lab")

    def test_without_a_bench_run(self):
        report = defenses.report(self.skills, [], None)
        self.assertFalse(report["bench_run"])
        self.assertTrue(all(d["bench"] is None for d in report["defenses"]))

    def test_gaps_are_the_techniques_without_defenses(self):
        gaps = {g["id"] for g in defenses.report(self.skills)["gaps"]}
        self.assertEqual(gaps, {t for t, v in techniques.TECHNIQUES.items() if not v["defenses"]})

    def test_live_run_counts_as_a_lab(self):
        self.assertIn(techniques.LIVE_LAB, self.rows()["mcp_gateway_filter"]["labs"])

    def test_cli(self):
        with tempfile.TemporaryDirectory() as home, patch.dict(os.environ, {"HACTU8_HOME": home}):
            store.save(result("llm03", "2026-11-21T00:00:00Z"))
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(cli.main(["defenses", "--json"]), 0)
            rows = {d["id"]: d for d in json.loads(out.getvalue())["defenses"]}
            self.assertEqual(rows["hitl_gate"]["evidence"], "lab")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(cli.main(["defenses"]), 0)
            self.assertIn("techniques with no defense", out.getvalue())


if __name__ == "__main__":
    unittest.main()
