"""H-54 the HACTU8 MCP server, through the SDK's in-memory client."""

import asyncio
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]

try:
    from mcp import Client

    from hactu8.mcp_server import build_server
    build_server(ROOT)
    HAVE_MCP = True
except (ImportError, RuntimeError):
    HAVE_MCP = False
else:
    from hactu8.lamb._mcp import available as _mcp_v2
    HAVE_MCP = _mcp_v2()


@unittest.skipUnless(HAVE_MCP, "Lamb extra (mcp v2 SDK) not installed")
class McpServerTest(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {"HACTU8_HOME": self.home.name})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.home.cleanup()

    def call(self, *calls):
        async def go():
            async with Client(build_server(ROOT)) as client:
                return [await client.call_tool(name, args) for name, args in calls]
        return asyncio.run(go())

    def test_tools_are_listed_and_only_runs_write(self):
        async def go():
            async with Client(build_server(ROOT)) as client:
                return (await client.list_tools()).tools
        tools = {t.name: t for t in asyncio.run(go())}
        self.assertEqual(set(tools), {"list_skills", "learning_path", "get_lesson", "list_results", "show_result",
                                      "run_skill", "run_live", "run_wolf"})
        for name, tool in tools.items():
            self.assertEqual(tool.annotations.read_only_hint, not name.startswith("run_"), name)

    def test_catalog_and_lesson(self):
        skills, path, lesson, missing = self.call(("list_skills", {}), ("learning_path", {}),
                                                  ("get_lesson", {"skill_id": "llm01"}),
                                                  ("get_lesson", {"skill_id": "nope"}))
        self.assertEqual(skills.structured_content["total"], 40)
        self.assertEqual(path.structured_content["total"], 40)
        self.assertFalse(lesson.is_error)
        self.assertTrue(lesson.structured_content["title"])
        self.assertTrue(missing.is_error)

    def test_run_on_echo_is_stored_and_shown(self):
        run, listed, shown = self.call(("run_skill", {"skill_id": "llm01"}), ("list_results", {}),
                                       ("show_result", {"run_id": "latest"}))
        self.assertFalse(run.is_error, run.content)
        self.assertEqual(run.structured_content["summary"]["status"], "pass")
        self.assertEqual(run.structured_content["model"]["backend"], "echo")
        self.assertEqual(listed.structured_content["total"], 1)
        self.assertEqual(shown.structured_content["run_id"], run.structured_content["run_id"])
        self.assertEqual(len(list(Path(self.home.name, "results").glob("*.json"))), 1)

    def test_wolf_on_echo(self):
        (wolf,) = self.call(("run_wolf", {"rounds": 1}))
        self.assertFalse(wolf.is_error, wolf.content)
        self.assertEqual(wolf.structured_content["wolf"]["landed_off"], 2)
        self.assertEqual(len(wolf.structured_content["wolf"]["attempts"]), 2)

    def test_spend_guard_refuses_cloud_without_confirmation(self):
        with mock.patch("hactu8.adapters.lab.run") as lab_run, mock.patch("hactu8.live.run") as live_run, \
                mock.patch("hactu8.wolf_agent.run") as wolf_run:
            results = self.call(("run_skill", {"skill_id": "llm01", "backend": "anthropic"}),
                                ("run_live", {"backend": "openrouter"}),
                                ("run_wolf", {"backend": "openai"}),
                                ("run_wolf", {"target_backend": "anthropic"}),
                                ("run_skill", {"skill_id": "llm01", "backend": "no-such-backend"}))
        for result in results:
            self.assertTrue(result.is_error)
        for result in results[:4]:
            self.assertIn("confirm_spend", result.content[0].text)
        lab_run.assert_not_called()
        live_run.assert_not_called()
        wolf_run.assert_not_called()
        self.assertEqual(list(Path(self.home.name).rglob("*.json")), [])

    def test_confirmed_cloud_run_reaches_the_runner(self):
        fake = {"run_id": "20261120T000000Z-llm01-abcd", "skill": {}, "model": {"backend": "anthropic"},
                "summary": {"status": "reported"}}
        with mock.patch("hactu8.adapters.lab.run", return_value=fake) as lab_run:
            (result,) = self.call(("run_skill", {"skill_id": "llm01", "backend": "anthropic",
                                                 "confirm_spend": True}))
        self.assertFalse(result.is_error, result.content)
        lab_run.assert_called_once()


if __name__ == "__main__":
    unittest.main()
