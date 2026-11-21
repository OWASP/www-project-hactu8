"""AG-90 and AG-91: the attack technique catalog, its schema, its links to labs and defenses, and coverage."""

from __future__ import annotations

import contextlib
import copy
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hactu8 import catalog, cli, store, techniques

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "hactu8" / "schemas" / "techniques.schema.json"

try:
    import jsonschema
except ImportError:
    jsonschema = None


class TechniqueCatalogTest(unittest.TestCase):
    def setUp(self):
        self.skill_ids = [s.id for s in catalog.discover(ROOT)]

    def test_catalog_is_valid(self):
        self.assertEqual(techniques.validate(self.skill_ids), [])

    def test_every_lab_demonstrates_a_technique(self):
        for sid in self.skill_ids:
            with self.subTest(lab=sid):
                self.assertTrue(techniques.for_lab(sid), f"{sid} is in no catalog entry")

    def test_every_owasp_item_is_mapped(self):
        refs = {r for t in techniques.TECHNIQUES.values() for ids in t["refs"].values() for r in ids}
        for n in range(1, 11):
            for ref in (f"LLM{n:02d}:2026", f"LLM{n:02d}:2025", f"ASI{n:02d}:2026"):
                with self.subTest(ref=ref):
                    self.assertIn(ref, refs)

    def test_lab_owasp_ids_appear_on_their_techniques(self):
        # A lab's own OWASP ID must be among the IDs of at least one technique it demonstrates.
        for skill in catalog.discover(ROOT):
            if not skill.owasp.endswith(":2026"):
                continue
            with self.subTest(lab=skill.id):
                refs = {r for tid in techniques.for_lab(skill.id)
                        for ids in techniques.TECHNIQUES[tid]["refs"].values() for r in ids}
                self.assertIn(skill.owasp, refs)

    def test_validate_catches_bad_entries(self):
        good = copy.deepcopy(techniques.TECHNIQUES)
        try:
            techniques.TECHNIQUES["x"] = {"title": "x", "family": "nope", "summary": "x",
                                          "refs": {"atlas": ["T0051"], "made_up": ["X"]},
                                          "defenses": ["no_such_control"], "labs": ["llm99"]}
            problems = "\n".join(techniques.validate(self.skill_ids))
            for needle in ("unknown family", "is not a atlas ID", "unknown list", "unknown defense", "unknown lab"):
                self.assertIn(needle, problems)
        finally:
            techniques.TECHNIQUES.clear()
            techniques.TECHNIQUES.update(good)

    def test_lookups(self):
        self.assertIn("indirect-prompt-injection", techniques.for_lab("llm01"))
        self.assertIn("indirect-prompt-injection", techniques.by_ref("AML.T0051.001"))
        self.assertEqual(techniques.by_ref("AML.T9999"), [])

    def test_every_list_has_a_source(self):
        self.assertEqual(set(techniques.SOURCES), set(techniques.REF_KEYS))

    @unittest.skipIf(jsonschema is None, "jsonschema not installed")
    def test_library_matches_schema(self):
        schema = json.loads(SCHEMA.read_text())
        jsonschema.validate(techniques.library(), schema)
        bad = techniques.library()
        bad[0]["refs"]["atlas"] = ["AML.X1"]
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(bad, schema)


def result(skill_id, started_at, remediated_rate=0, status="pass"):
    return {"run_id": f"{started_at}-{skill_id}", "started_at": started_at, "skill": {"id": skill_id},
            "model": {"backend": "echo"},
            "summary": {"status": status, "impact_rate": 100, "remediated_rate": remediated_rate}}


class CoverageTest(unittest.TestCase):
    def rows(self, docs=()):
        return {r["id"]: r for r in techniques.coverage(docs)["techniques"]}

    def test_statuses_from_declarations(self):
        rows = self.rows()
        self.assertEqual(rows["indirect-prompt-injection"]["status"], "attack_and_defense")
        self.assertEqual(rows["self-replicating-prompt"]["status"], "attack_and_defense")   # HX15
        self.assertEqual(rows["shadow-mcp-server"]["status"], "no_lab")
        report = techniques.coverage()
        self.assertEqual(sum(report["counts"].values()), report["total"])

    def test_no_defense_is_attack_only(self):
        good = copy.deepcopy(techniques.TECHNIQUES)
        try:
            techniques.TECHNIQUES["indirect-prompt-injection"]["defenses"] = []
            self.assertEqual(self.rows()["indirect-prompt-injection"]["status"], "attack_only")
        finally:
            techniques.TECHNIQUES.clear()
            techniques.TECHNIQUES.update(good)

    def test_latest_result_feeds_status(self):
        # The newest LLM01 run left impact after remediation, so the defense is not shown to work.
        docs = [result("llm01", "2026-11-20T00:00:00Z"), result("llm01", "2026-11-21T00:00:00Z", 25, "fail")]
        row = self.rows(docs)["indirect-prompt-injection"]
        self.assertEqual(row["status"], "attack_only")
        self.assertEqual(row["leaky_labs"], ["llm01"])
        self.assertEqual(row["runs"]["llm01"]["remediated_rate"], 25)
        # Order of the stored runs does not matter; a newer clean run restores the status.
        docs.append(result("llm01", "2026-11-22T00:00:00Z"))
        self.assertEqual(self.rows(reversed(docs))["indirect-prompt-injection"]["status"], "attack_and_defense")

    def test_live_runs_are_not_lab_results(self):
        live = result("llm01", "2026-11-23T00:00:00Z", 50)
        live["live"] = {}
        self.assertEqual(techniques.latest_runs([live]), {})

    def test_by_list_counts(self):
        by_list = techniques.coverage()["by_list"]
        self.assertEqual(by_list["owasp_llm_2026"]["ids"], 10)
        self.assertEqual(by_list["owasp_llm_2026"]["without_lab"], [])
        self.assertNotIn("AML.T0054", by_list["atlas"]["without_lab"])   # jailbreaks: HX02
        self.assertNotIn("AML.T0061", by_list["atlas"]["without_lab"])   # self-replication: HX15
        self.assertIn("AML.T0020", by_list["atlas"]["without_lab"])

    def test_cli(self):
        with tempfile.TemporaryDirectory() as home, patch.dict(os.environ, {"HACTU8_HOME": home}):
            store.save(result("llm01", "2026-11-21T00:00:00Z", 25, "fail"))
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(cli.main(["coverage", "--status", "attack_only", "--json"]), 0)
            rows = json.loads(out.getvalue())["techniques"]
            self.assertIn("indirect-prompt-injection", [r["id"] for r in rows])
            self.assertTrue(all(r["status"] == "attack_only" for r in rows))
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(cli.main(["coverage"]), 0)
            self.assertIn("latest run left impact after remediation: indirect-prompt-injection", out.getvalue())


if __name__ == "__main__":
    unittest.main()
