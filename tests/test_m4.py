"""M4 tests for branding and report exporters."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from hactu8 import branding, catalog, reports
from hactu8.adapters import lab

ROOT = Path(__file__).resolve().parents[1]


class ReportTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc = lab.run(catalog.get("llm01", ROOT))
        cls.brand = branding.load(ROOT / "branding.yaml")

    def test_branding_loads(self):
        self.assertEqual(self.brand["name"], "OWASP HACTU8")
        self.assertEqual(self.brand["report_title"], "HACTU8 Assurance Report")

    def test_markdown_and_html(self):
        markdown = reports.render(self.doc, "markdown", self.brand)
        self.assertIn("# HACTU8 Assurance Report", markdown)
        self.assertIn("LLM01:2026", markdown)
        self.assertIn("## Four-act result", markdown)
        rendered_html = reports.render(self.doc, "html", self.brand)
        self.assertIn("<!doctype html>", rendered_html)
        self.assertIn("HACTU8 Assurance Report", rendered_html)
        self.assertNotIn("<script", rendered_html.lower())

    def test_sarif_shape(self):
        sarif = json.loads(reports.render(self.doc, "sarif", self.brand))
        self.assertEqual(sarif["version"], "2.1.0")
        run = sarif["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "OWASP HACTU8")
        self.assertEqual(run["tool"]["driver"]["rules"][0]["id"], "LLM01:2026")
        self.assertTrue(run["results"])
        self.assertTrue(all(result["ruleId"] == "LLM01:2026" for result in run["results"]))

    def test_unknown_format(self):
        with self.assertRaises(ValueError):
            reports.render(self.doc, "pdf", self.brand)


if __name__ == "__main__":
    unittest.main()
