"""AG-52: Act 4 "Protections added" catalog, lab declarations, result schema, reports."""

from __future__ import annotations

import copy
import os
import tempfile
import unittest
from pathlib import Path

from hactu8 import catalog, protections, reports
from hactu8.adapters import lab
from tests import test_core

ROOT = Path(__file__).resolve().parents[1]

try:
    import jsonschema
except ImportError:
    jsonschema = None


def make_doc(acts):
    return {"schema": "hactu8.result/v1", "run_id": "20261120T000000Z-llm01-abcd", "hactu8_version": "0",
            "started_at": "2026-11-20T00:00:00Z", "skill": {"id": "llm01", "name": "x", "owasp": "LLM01:2026",
                                                             "risk": "Prompt Injection",
                                                             "metric": {"id": "ISR", "name": "ISR"}},
            "target": {"kind": "lab", "id": "owasp-llm01-demo"}, "model": {"backend": "echo"},
            "classifier": {"name": "keyword"}, "acts": acts,
            "summary": {"baseline_rate": 0, "impact_rate": 100, "remediated_rate": 0, "story_holds": True,
                        "asserted": True, "status": "pass"}, "exit_code": 0}


class CatalogTest(unittest.TestCase):
    def test_every_entry_is_complete(self):
        self.assertTrue(protections.CATALOG)
        for cid, entry in protections.CATALOG.items():
            with self.subTest(control=cid):
                self.assertRegex(cid, r"^[a-z0-9_]+$")
                self.assertEqual(set(entry), set(protections.FIELDS))
                for key in ("title", "idea", "before", "after"):
                    self.assertIsInstance(entry[key], str)
                    self.assertTrue(entry[key].strip(), key)
                self.assertGreaterEqual(len(entry["steps"]), 2)
                self.assertTrue(all(isinstance(s, str) and s.strip() for s in entry["steps"]))
                self.assertNotEqual(entry["before"], entry["after"])

    def test_resolve_keeps_order_and_rejects_unknown_ids(self):
        self.assertEqual([e["id"] for e in protections.resolve(["hash_pin", "sampling"])], ["hash_pin", "sampling"])
        with self.assertRaises(KeyError):
            protections.resolve(["hash_pin", "no_such_control"])
        self.assertEqual(protections.unknown(["hash_pin", "nope"]), ["nope"])
        self.assertEqual(protections.unknown(protections.LIVE), [])

    def test_parse_ids(self):
        self.assertEqual(protections.parse_ids(" a, b ,,a "), ["a", "b"])
        self.assertEqual(protections.parse_ids(""), [])

    def test_resolved_entries_are_copies(self):
        entry = protections.resolve(["hash_pin"])[0]
        entry["steps"].append("mutated")
        self.assertNotIn("mutated", protections.CATALOG["hash_pin"]["steps"])


class LabDeclarationTest(unittest.TestCase):
    def test_every_lab_declares_known_protections(self):
        for skill in catalog.discover(ROOT):
            with self.subTest(skill=skill.id):
                self.assertTrue(skill.protections, f"{skill.id}: add metadata hactu8.protections to SKILL.md")
                self.assertEqual(protections.unknown(skill.protections), [],
                                 f"{skill.id}: unknown hactu8.protections id")

    def test_llm01_declares_its_hardened_controls(self):
        self.assertEqual(catalog.get("llm01", ROOT).protections, ["spotlight", "input_screen"])
        self.assertIn("protections", catalog.get("llm01", ROOT).to_dict())


class ResultTest(unittest.TestCase):
    def _acts(self, ids):
        acts = lab.parse(test_core.SAMPLE)
        lab.attach_protections(acts, ids)
        return acts

    def test_only_the_remediation_act_carries_protections(self):
        acts = self._acts(["spotlight", "input_screen"])
        self.assertEqual([p["id"] for p in acts[3]["protections"]], ["spotlight", "input_screen"])
        self.assertTrue(all("protections" not in a for a in acts[:3]))

    def test_unknown_ids_are_skipped_at_run_time_and_none_means_no_field(self):
        self.assertEqual([p["id"] for p in self._acts(["nope", "hash_pin"])[3]["protections"]], ["hash_pin"])
        self.assertNotIn("protections", self._acts([])[3])
        self.assertNotIn("protections", self._acts(["nope"])[3])

    @unittest.skipIf(jsonschema is None, "jsonschema not installed")
    def test_schema_accepts_with_and_without_and_rejects_malformed(self):
        with_p = make_doc(self._acts(["spotlight"]))
        jsonschema.validate(with_p, test_core.SCHEMA)
        jsonschema.validate(make_doc(self._acts([])), test_core.SCHEMA)   # old results stay valid
        bad = copy.deepcopy(with_p)
        del bad["acts"][3]["protections"][0]["idea"]
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(bad, test_core.SCHEMA)
        bad = copy.deepcopy(with_p)
        bad["acts"][3]["protections"][0]["steps"] = "one string"
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(bad, test_core.SCHEMA)

    def test_real_run_carries_the_lab_controls(self):
        with tempfile.TemporaryDirectory() as home:
            os.environ["HACTU8_HOME"] = home
            try:
                skill = catalog.get("llm10", ROOT)
                doc = lab.run(skill)
            finally:
                os.environ.pop("HACTU8_HOME", None)
        test_core.validate(doc)
        act4 = next(a for a in doc["acts"] if a["phase"] == "remediation")
        self.assertEqual([p["id"] for p in act4["protections"]], skill.protections)


class ReportTest(unittest.TestCase):
    BRAND = {"name": "OWASP HACTU8", "report_title": "Report", "tagline": "t",
             "primary_color": "#213547", "accent_color": "#fbbf24"}

    def _doc(self, ids):
        doc = make_doc(lab.parse(test_core.SAMPLE))
        lab.attach_protections(doc["acts"], ids)
        return doc

    def test_markdown_lists_protections_only_when_present(self):
        text = reports.markdown(self._doc(["output_sink"]), self.BRAND)
        self.assertIn("## Protections added", text)
        self.assertIn("### " + protections.CATALOG["output_sink"]["title"], text)
        self.assertIn("1. " + protections.CATALOG["output_sink"]["steps"][0], text)
        self.assertNotIn("## Protections added", reports.markdown(self._doc([]), self.BRAND))

    def test_html_keeps_code_literal(self):
        page = reports.html_report(self._doc(["output_sink"]), self.BRAND)
        self.assertEqual(page.count("<h1>"), 1)
        self.assertIn("html.escape(reply)", page)
        self.assertNotIn("<p>page += html.escape(reply)</p>", page)


if __name__ == "__main__":
    unittest.main()
