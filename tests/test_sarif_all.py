"""H-52: scripts/sarif_all.py merges stored runs into one SARIF run for code scanning."""

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hactu8 import branding, catalog, reports
from hactu8.adapters import lab

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("sarif_all", ROOT / "scripts" / "sarif_all.py")
sarif_all = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sarif_all)


class SarifAllTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.home = tempfile.TemporaryDirectory()
        with patch.dict(os.environ, {"HACTU8_HOME": cls.home.name}):
            cls.docs = [lab.run(catalog.get(i, ROOT), backend="echo") for i in ("llm01", "asi01")]
        cls.brand = branding.load(ROOT / "branding.yaml")

    @classmethod
    def tearDownClass(cls):
        cls.home.cleanup()

    def test_one_run_with_every_finding(self):
        merged = sarif_all.merge(self.docs, self.brand)
        self.assertEqual(merged["version"], "2.1.0")
        self.assertEqual(len(merged["runs"]), 1)
        run = merged["runs"][0]
        expected = sum(len(reports.sarif(d, self.brand)["runs"][0]["results"]) for d in self.docs)
        self.assertGreater(expected, 0)
        self.assertEqual(len(run["results"]), expected)
        self.assertEqual([r["id"] for r in run["tool"]["driver"]["rules"]],
                         sorted({d["skill"]["owasp"] for d in self.docs}))
        self.assertEqual([r["skill"] for r in run["properties"]["hactu8Runs"]], ["llm01", "asi01"])

    def test_locations_are_repo_files_and_fingerprints_stable(self):
        run = sarif_all.merge(self.docs, self.brand)["runs"][0]
        for result in run["results"]:
            uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            self.assertTrue((ROOT / uri).is_file(), uri)
            self.assertTrue(result["properties"]["hactu8Uri"].startswith("hactu8://"))
        again = sarif_all.merge(self.docs, self.brand)["runs"][0]
        self.assertEqual([r["partialFingerprints"] for r in run["results"]],
                         [r["partialFingerprints"] for r in again["results"]])

    def test_defense_failures_keeps_only_baseline_or_remediation_red(self):
        # Echo is 0 -> RED -> 0: the attack act's REDs are the lab working, not a failure.
        self.assertEqual(sarif_all.merge(self.docs, self.brand, defense_failures=True)["runs"][0]["results"], [])
        broken = json.loads(json.dumps(self.docs[0]))
        broken["acts"][-1]["items"][0]["verdict"] = "RED"
        results = sarif_all.merge([broken], self.brand, defense_failures=True)["runs"][0]["results"]
        self.assertEqual([(r["properties"]["phase"], r["level"]) for r in results], [("remediation", "error")])

    def test_no_runs_is_an_error(self):
        with self.assertRaises(ValueError):
            sarif_all.merge([], self.brand)


if __name__ == "__main__":
    unittest.main()
