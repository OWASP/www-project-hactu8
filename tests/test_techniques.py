"""AG-90: the attack technique catalog, its schema, and its links to labs and defenses."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from hactu8 import catalog, techniques

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


if __name__ == "__main__":
    unittest.main()
