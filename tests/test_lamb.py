"""M3 tests for the Lamb worker gateway and vulnerable MCP state."""

from __future__ import annotations

import dataclasses
import json
import socket
import unittest
from pathlib import Path

from hactu8 import catalog
from hactu8.lamb.app import _rewrite_console_paths
from hactu8.lamb.mcp_target import (
    BASELINE_REVISION,
    RUG_PULL_MARKER,
    LambMcpState,
    install_attachment_tool,
)
from hactu8.lamb.workers import LabWorkerManager

ROOT = Path(__file__).resolve().parents[1]


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class WorkerTest(unittest.TestCase):
    def test_manifest_has_all_labs_and_unique_ports(self):
        skills = catalog.discover(ROOT)
        self.assertEqual(len(skills), 49)
        self.assertEqual(len({skill.id for skill in skills}), 49)
        self.assertEqual(len({skill.port for skill in skills}), 49)
        self.assertTrue(all((Path(skill.skill_dir) / "vulnerable_app.py").is_file() for skill in skills))

    def test_lazy_worker_proxy_and_reset(self):
        skill = dataclasses.replace(catalog.get("llm01", ROOT), port=str(free_port()))
        workers = LabWorkerManager(skills=[skill])
        self.addCleanup(workers.close)
        self.assertEqual(workers.running_ids(), [])
        status, _, body = workers.request("llm01", "GET", "/health", {}, b"")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["demo"], "llm01")
        self.assertEqual(workers.running_ids(), ["llm01"])
        result = workers.reset()
        self.assertEqual(result, {"reset": ["llm01"], "errors": {}})

    def test_app_shutdown_stops_lab_workers(self):
        # uvicorn re-raises SIGTERM after a graceful shutdown, so a `finally` in
        # __main__ never runs on `kill`; the app's own lifespan must stop the workers.
        try:
            from hactu8.lamb.app import create_app
            from hactu8.lamb._mcp import McpUnavailable
        except ModuleNotFoundError:
            self.skipTest("Lamb extra not installed")
        import asyncio

        class FakeWorkers:
            closed = 0
            skills = {}

            def close(self):
                self.closed += 1

        workers = FakeWorkers()
        try:
            app = create_app(manager=workers)
        except (McpUnavailable, RuntimeError):
            self.skipTest("Lamb extra not installed")

        async def cycle():
            async with app.router.lifespan_context(app):
                self.assertEqual(workers.closed, 0)

        asyncio.run(cycle())
        self.assertEqual(workers.closed, 1)

    def test_console_paths_are_scoped_to_the_gateway_lab(self):
        html = b'<link href="/web/styles.css"><script src="/web/app.js"></script>'
        rewritten = _rewrite_console_paths(html, "text/html", "llm01")
        self.assertIn(b'href="/labs/llm01/web/styles.css"', rewritten)
        script = _rewrite_console_paths(b"fetch(path, opts)", "text/javascript", "llm01")
        self.assertIn(b"/labs/llm01", script)


class McpTargetTest(unittest.TestCase):
    def test_rug_pull_and_hardened_pin(self):
        state = LambMcpState()
        self.assertEqual(state.snapshot()["catalog_revision"], BASELINE_REVISION)
        self.assertEqual(state.refresh_catalog()["status"], "accepted")
        self.assertEqual(state.vendor_lookup("Billy Supply")["content"], f"{RUG_PULL_MARKER} (inert)")
        state.set_mode("hardened")
        self.assertEqual(state.snapshot()["catalog_revision"], BASELINE_REVISION)
        self.assertEqual(state.refresh_catalog()["status"], "rejected")
        self.assertEqual(state.vendor_lookup("Billy Supply")["status"], "approved")

    def test_sdk_tool_registration_when_extra_installed(self):
        try:
            from hactu8.lamb.mcp_target import build_mcp_server
        except ModuleNotFoundError:
            self.skipTest("Lamb extra not installed")
        state = LambMcpState()
        try:
            mcp = build_mcp_server(state)
        except RuntimeError:
            self.skipTest("Lamb extra not installed")
        tools = {tool.name: tool for tool in __import__("asyncio").run(mcp.list_tools())}
        self.assertIn("PLACEHOLDER_TOOL_DESCRIPTION_INJECTION", tools["summarize_attachment"].description)
        state.set_mode("hardened")
        install_attachment_tool(mcp, state)
        tools = {tool.name: tool for tool in __import__("asyncio").run(mcp.list_tools())}
        self.assertNotIn("PLACEHOLDER_TOOL_DESCRIPTION_INJECTION", tools["summarize_attachment"].description)

    def test_v1_sdk_reports_upgrade_hint(self):
        import sys
        import types
        from unittest import mock
        from hactu8.lamb._mcp import McpUnavailable, server_class
        fake_server = types.ModuleType("mcp.server")
        with mock.patch.dict(sys.modules, {"mcp": types.ModuleType("mcp"), "mcp.server": fake_server}):
            with self.assertRaisesRegex(McpUnavailable, "MCP v2 SDK"):
                server_class()





class WorkerBackendDefaultTest(unittest.TestCase):
    def test_lamb_wide_backend_and_model_reach_the_worker(self):
        import os
        from unittest import mock

        from hactu8 import catalog
        from hactu8.lamb.workers import LabWorkerManager
        skill = next(s for s in catalog.discover() if s.id == "llm01")
        clean = {k: v for k, v in os.environ.items() if not k.startswith("LLM01_")}
        with mock.patch.dict(os.environ, {**clean, "HACTU8_LAB_BACKEND": "ollama",
                                          "HACTU8_LAB_MODEL": "llama3.2:3b"}, clear=True):
            env = LabWorkerManager.worker_env(skill)
        self.assertEqual((env["LLM01_BACKEND"], env["LLM01_MODEL"]), ("ollama", "llama3.2:3b"))
        with mock.patch.dict(os.environ, {**clean, "LLM01_BACKEND": "llamacpp",
                                          "HACTU8_LAB_BACKEND": "ollama"}, clear=True):
            self.assertEqual(LabWorkerManager.worker_env(skill)["LLM01_BACKEND"], "llamacpp")
        with mock.patch.dict(os.environ, clean, clear=True):
            env = LabWorkerManager.worker_env(skill)
        self.assertEqual(env["LLM01_BACKEND"], "echo")
        self.assertNotIn("LLM01_MODEL", env)


if __name__ == "__main__":
    unittest.main()
