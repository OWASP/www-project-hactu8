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

from hactu8 import protections
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
        library = self.client.get("/api/protections").json()
        self.assertEqual(library["total"], len(protections.CATALOG))
        self.assertEqual({"id", "title", "idea", "steps", "before", "after"}, set(library["protections"][0]))
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
        act4 = response.json()["acts"][3]
        self.assertEqual([c["id"] for c in act4["protections"]], ["spotlight", "input_screen"])
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



@unittest.skipIf(TestClient is None, "API optional dependencies not installed")
class ApiModelsAndLiveTest(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {"HACTU8_HOME": self.home.name})
        self.env.start()
        for key in ("OPENROUTER_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY"):
            os.environ.pop(key, None)
        self.client = TestClient(create_app(ROOT))

    def tearDown(self):
        self.env.stop()
        self.home.cleanup()

    def test_models_lists_backends_and_never_keys(self):
        data = self.client.get("/api/models").json()
        self.assertIn("openai-compat", data["backends"])
        self.assertEqual(set(data["cloud"]), {"openrouter", "anthropic", "openai"})
        self.assertEqual(data["keys_set"], {"openrouter": False, "anthropic": False, "openai": False})
        self.assertTrue(any(c["backend"] == "echo" and c["available"] for c in data["candidates"]))

    def test_cloud_runs_need_confirm_spend(self):
        live = self.client.post("/api/live", json={"backend": "openrouter"})
        self.assertEqual(live.status_code, 402)
        self.assertIn("LAB_MAX_CALLS", live.json()["detail"])
        run = self.client.post("/api/runs", json={"skill_id": "llm01", "backend": "anthropic"})
        self.assertEqual(run.status_code, 402)

    def test_live_run_on_echo_is_stored_and_scored(self):
        try:
            from hactu8.lamb.mcp_target import LambMcpState, build_mcp_server
            build_mcp_server(LambMcpState())
        except (ModuleNotFoundError, RuntimeError):
            self.skipTest("Lamb extra not installed")
        doc = self.client.post("/api/live", json={"backend": "echo"}).json()
        self.assertEqual((doc["live"]["breaches_off"], doc["live"]["breaches_on"]), (8, 0))
        board = self.client.get("/api/scoreboard").json()
        self.assertEqual(board["scoreboard"][0]["run_id"], doc["run_id"])


if __name__ == "__main__":
    unittest.main()
