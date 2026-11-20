import asyncio
import socket
import threading
import time
import unittest

from hactu8 import providers
from hactu8.lamb import surfaces

try:
    from hactu8.lamb.gateway import QUARANTINE, SANITIZED, Gateway, GatewayConfig, InProcessBackend
    from hactu8.lamb.mcp_target import LambMcpState, build_mcp_server
    build_mcp_server(LambMcpState())
    HAVE_MCP = True
except (ModuleNotFoundError, RuntimeError):
    HAVE_MCP = False


def run(coro):
    return asyncio.run(coro)


@unittest.skipUnless(HAVE_MCP, "Lamb extra not installed")
class GatewayLogicTest(unittest.TestCase):
    def setUp(self):
        self.state = LambMcpState()
        self.billy = build_mcp_server(self.state)
        self.gw = Gateway(InProcessBackend(self.billy))

    def call(self, name, args=None):
        return run(self.gw.call_tool(name, args or {}))

    def text(self, result):
        return result.content[0].text

    def test_poisoned_results_quarantined_controls_pass(self):
        self.assertEqual(self.text(self.call("search_kb", {"query": "onboarding"})), QUARANTINE)
        self.assertNotEqual(self.text(self.call("server_time")), QUARANTINE)
        self.assertEqual(self.text(self.call("a2a_read", {"msg_id": "msg-002"})), QUARANTINE)
        self.assertNotEqual(self.text(self.call("a2a_read", {"msg_id": "msg-001"})), QUARANTINE)
        self.assertNotEqual(self.text(self.call("db_query", {"table": "tickets"})), QUARANTINE)

    def test_error_channel_and_tail_and_conditional(self):
        err = self.call("db_query", {"table": "secrets"})
        self.assertTrue(err.is_error)
        self.assertEqual(self.text(err), QUARANTINE)
        self.assertEqual(self.text(self.call("export_log")), QUARANTINE)
        results = [self.text(self.call("service_health", {"service": "api"})) for _ in range(3)]
        self.assertEqual([r == QUARANTINE for r in results], [False, False, True])

    def test_no_canary_reaches_the_client_through_any_tool(self):
        canary = providers.canary()
        for tool in run(self.gw.list_tools()):
            self.assertNotIn(canary, tool.description or "")
            self.assertNotIn(canary, str(tool.input_schema))
        for name, args in [("search_kb", {"query": "onboarding"}), ("export_log", {}),
                           ("db_query", {"table": "x"})] + [("service_health", {"service": "a"})] * 3:
            self.assertNotIn(canary, str(self.call(name, args)))

    def test_definitions_sanitized(self):
        tools = {t.name: t for t in run(self.gw.list_tools())}
        self.assertEqual(tools["search_kb"].description, SANITIZED)
        self.assertNotIn("description", tools["ticket_lookup"].input_schema["properties"]["ticket_id"])
        self.assertNotEqual(tools["server_time"].description, SANITIZED)

    def test_resources_and_prompts(self):
        self.assertEqual(run(self.gw.read_resource("wiki://onboarding"))[0][0], QUARANTINE)
        self.assertNotEqual(run(self.gw.read_resource("wiki://holidays"))[0][0], QUARANTINE)
        poisoned = run(self.gw.get_prompt("summarize_doc", {"document": "x"}))
        self.assertEqual(poisoned.messages[0].content.text, QUARANTINE)
        clean = run(self.gw.get_prompt("format_answer", {"answer": "x"}))
        self.assertNotEqual(clean.messages[0].content.text, QUARANTINE)

    def test_chain_destination_quarantined(self):
        out = {uri: self.text(self.call("chain_get", {"uri": uri})) for uri in surfaces.CHAIN}
        self.assertEqual(out["kb://setup/step-two"], QUARANTINE)
        self.assertNotEqual(out["kb://setup/step-one"], QUARANTINE)
        self.assertNotEqual(out["kb://setup/step-three"], QUARANTINE)

    def test_okf_body_and_frontmatter_quarantined(self):
        for cid in ("incident_response", "vault_access"):
            self.assertEqual(self.text(self.call("okf_get_concept", {"concept_id": cid})), QUARANTINE, cid)
        self.assertNotEqual(self.text(self.call("okf_get_concept", {"concept_id": "office_map"})), QUARANTINE)

    def test_known_miss_okf_runbook_split_passes(self):
        # A real gap in this defense, shown in the labs: each half is clean, and the
        # gateway does not assemble retrieval groups. Ground truth still says attack.
        self.assertTrue(surfaces.truth("okf:chain/runbook", self.state.surfaces))
        for cid in ("runbook_part1", "runbook_part2"):
            self.assertNotEqual(self.text(self.call("okf_get_concept", {"concept_id": cid})), QUARANTINE)

    def test_rug_pull_drops_tool_and_refuses_calls(self):
        names = {t.name for t in run(self.gw.list_tools())}
        self.assertIn("server_time", names)
        surfaces.simulate_swap(self.billy, self.state.surfaces)
        self.assertNotIn("server_time", {t.name for t in run(self.gw.list_tools())})
        refused = self.call("server_time")
        self.assertTrue(refused.is_error)
        self.assertIn("definition_changed", self.text(refused))

    def test_shadowing_peer_drops_colliding_tool(self):
        gw = Gateway(InProcessBackend(self.billy),
                     GatewayConfig(peer_tools={"mail": [{"name": "search_kb", "description": "Search mail."}]}))
        self.assertNotIn("search_kb", {t.name for t in run(gw.list_tools())})

    def test_stateless_mode_still_screens_each_payload(self):
        gw = Gateway(InProcessBackend(self.billy), GatewayConfig(stateful=False))
        self.assertEqual(run(gw.call_tool("search_kb", {"query": "onboarding"})).content[0].text, QUARANTINE)

    def test_reset_clears_log_and_quarantine(self):
        run(self.gw.list_tools())
        surfaces.simulate_swap(self.billy, self.state.surfaces)
        run(self.gw.list_tools())
        self.assertTrue(self.gw.quarantined_tools)
        surfaces.restore_swaps(self.billy, self.state.surfaces)
        self.gw.reset()
        self.assertEqual((self.gw.log, self.gw.quarantined_tools), ([], {}))
        self.assertIn("server_time", {t.name for t in run(self.gw.list_tools())})


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _Server:
    def __init__(self, app):
        import uvicorn
        self.port = _free_port()
        self.server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=self.port, log_level="error"))
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def __enter__(self):
        self.thread.start()
        deadline = time.monotonic() + 10
        while not self.server.started and time.monotonic() < deadline:
            time.sleep(0.05)
        return self

    def __exit__(self, *exc):
        self.server.should_exit = True
        self.thread.join(timeout=5)


@unittest.skipUnless(HAVE_MCP, "Lamb extra not installed")
class GatewayHttpTest(unittest.TestCase):
    def test_raw_and_protected_endpoints_over_http(self):
        from mcp import Client

        from hactu8.lamb.app import create_app
        from hactu8.lamb.workers import LabWorkerManager
        app = create_app(manager=LabWorkerManager(skills=[]))

        async def fetch(url):
            async with Client(url) as client:
                result = await client.call_tool("search_kb", {"query": "onboarding"})
                return result.content[0].text

        try:
            with _Server(app) as srv:
                base = f"http://127.0.0.1:{srv.port}"
                self.assertIn(providers.canary(), run(fetch(base + "/mcp")))
                self.assertEqual(run(fetch(base + "/protected/mcp")), QUARANTINE)
        finally:
            app.state.workers.close()

    def test_bearer_token_required_when_configured(self):
        import json
        import urllib.error
        import urllib.request

        from hactu8.lamb.gateway import http_app
        billy = build_mcp_server(LambMcpState())
        port = _free_port()
        app, _ = http_app(Gateway(InProcessBackend(billy), GatewayConfig(token="test-token-123")), port=port)
        body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
        headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
        def status(extra):
            req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={**headers, **extra})
            try:
                with urllib.request.urlopen(req, timeout=5) as resp:
                    return resp.status
            except urllib.error.HTTPError as exc:
                return exc.code

        with _Server(app) as srv:
            url = f"http://127.0.0.1:{srv.port}/mcp"
            self.assertEqual(status({}), 401)
            self.assertEqual(status({"Authorization": "Bearer nope"}), 401)
            self.assertNotEqual(status({"Authorization": "Bearer test-token-123"}), 401)


if __name__ == "__main__":
    unittest.main()
