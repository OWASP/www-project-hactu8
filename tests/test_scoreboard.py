import os
import tempfile
import unittest
from unittest import mock

from hactu8 import reports, store


def _doc(run_id, backend, model, started, resistance, off, on):
    return {"run_id": run_id, "started_at": started, "model": {"backend": backend, "model": model},
            "live": {"attacks": 13, "controls": 11, "model_resistance": resistance, "breaches_off": off,
                     "breaches_on": on, "defended_on": off - on, "false_blocks_on": 0}}


class ScoreboardTest(unittest.TestCase):
    def test_latest_run_per_model_ranked(self):
        with tempfile.TemporaryDirectory() as home, mock.patch.dict(os.environ, {"HACTU8_HOME": home}):
            store.save(_doc("a", "ollama", "tinyllama", "2026-11-20T01:00:00Z", 0.4, 8, 0))
            store.save(_doc("b", "ollama", "llama3.2:3b", "2026-11-20T01:00:00Z", 0.7, 4, 0))
            store.save(_doc("c", "ollama", "llama3.2:3b", "2026-11-20T02:00:00Z", 0.85, 2, 0))
            store.save({"run_id": "d", "started_at": "2026-11-20T03:00:00Z", "model": {"backend": "echo"}})
            rows = store.scoreboard()
        self.assertEqual([r["run_id"] for r in rows], ["c", "a"])
        text = reports.scoreboard_markdown(rows)
        self.assertIn("`ollama:llama3.2:3b` | 85% | 2 | 0", text)

    def test_empty_scoreboard(self):
        with tempfile.TemporaryDirectory() as home, mock.patch.dict(os.environ, {"HACTU8_HOME": home}):
            self.assertEqual(store.scoreboard(), [])
        self.assertIn("no live runs yet", reports.scoreboard_markdown([]))


class LiveReportTest(unittest.TestCase):
    def test_live_report_sections(self):
        try:
            from hactu8 import live
            run = live.run("echo")
        except (ModuleNotFoundError, RuntimeError):
            self.skipTest("Lamb extra not installed")
        doc = live.to_result(run, "2026-11-20T00:00:00Z", 1)
        md = reports.render(doc, "markdown", {"report_title": "R", "tagline": "T", "name": "N",
                                              "primary_color": "#000000", "accent_color": "#ffffff"})
        self.assertIn("## Defense off vs on", md)
        self.assertIn("python -m hactu8 live --backend echo", md)
        self.assertIn("| `tool_result:search_kb` | attack | BREACH | DEFENDED |", md)
        sarif = reports.sarif(doc, {"report_title": "R", "tagline": "T", "name": "N",
                                    "primary_color": "#000000", "accent_color": "#ffffff"})
        self.assertTrue(sarif)


if __name__ == "__main__":
    unittest.main()
