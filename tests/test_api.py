"""M4 FastAPI contract tests."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

try:
    from fastapi.testclient import TestClient
except ModuleNotFoundError:
    TestClient = None

from hactu8.api import create_app

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipIf(TestClient is None, "API optional dependencies not installed")
class ApiTest(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {"HACTU8_HOME": self.home.name})
        self.env.start()
        self.client = TestClient(create_app(ROOT))

    def tearDown(self):
        self.env.stop()
        self.home.cleanup()

    def test_discovery_and_branding(self):
        self.assertEqual(self.client.get("/api/health").json()["status"], "ok")
        branding = self.client.get("/api/branding").json()
        self.assertEqual(branding["name"], "OWASP HACTU8")
        skills = self.client.get("/api/skills").json()
        self.assertEqual(skills["total"], 25)
        targets = self.client.get("/api/targets").json()
        self.assertEqual(targets["targets"][0]["id"], "hactu8-lamb")

    def test_run_result_and_reports(self):
        response = self.client.post("/api/runs", json={
            "skill_id": "llm01",
            "target_id": "hactu8-lamb",
            "backend": "echo",
            "classifier": "keyword",
        })
        self.assertEqual(response.status_code, 200, response.text)
        run_id = response.json()["run_id"]
        self.assertEqual(self.client.get("/api/results").json()["total"], 1)
        self.assertEqual(self.client.get(f"/api/results/{run_id}").status_code, 200)
        for format_name in ("markdown", "html", "sarif"):
            report = self.client.get(f"/api/reports/{run_id}/{format_name}")
            self.assertEqual(report.status_code, 200)
            self.assertIn("attachment;", report.headers["content-disposition"])

    def test_not_found_and_invalid_run(self):
        self.assertEqual(self.client.get("/api/results/missing").status_code, 404)
        self.assertEqual(self.client.get("/api/reports/missing/html").status_code, 404)
        response = self.client.post("/api/runs", json={
            "skill_id": "missing",
            "backend": "echo",
            "classifier": "keyword",
            "target_id": "hactu8-lamb",
        })
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
