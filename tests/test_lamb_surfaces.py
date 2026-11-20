import asyncio
import re
import unittest

from hactu8 import providers
from hactu8.lamb import surfaces
from hactu8.protectogw import Session, Verdict, screen


def _all_payload_texts():
    texts = [text for _, text in surfaces.static_texts()]
    texts += [surfaces.search_kb("onboarding"), surfaces.export_log(), surfaces.db_error("secrets")]
    texts += list(surfaces.CHAIN.values()) + [body for _, body in surfaces.a2a_messages().values()]
    state = surfaces.SurfaceState()
    texts += [state.service_health("api") for _ in range(surfaces.CONDITIONAL_TRIGGER_ON)]
    return texts


class SurfaceGroundTruthTest(unittest.TestCase):
    def test_manifest_has_attacks_and_controls_per_surface(self):
        by_surface = {}
        for meta in surfaces.ATTACK_MANIFEST.values():
            by_surface.setdefault(meta["surface"], set()).add(meta["attack"])
        self.assertIn(True, set().union(*by_surface.values()))
        self.assertEqual(by_surface["tool_description"], {True, False})
        self.assertEqual(by_surface["a2a_message"], {True, False})

    def test_static_texts_match_manifest(self):
        for target, _ in surfaces.static_texts():
            self.assertIn(target, surfaces.ATTACK_MANIFEST)
            self.assertTrue(surfaces.ATTACK_MANIFEST[target]["static"], target)

    def test_payloads_are_benign_effect(self):
        canary = providers.canary()
        texts = _all_payload_texts()
        self.assertTrue(any(canary in t for t in texts))
        for text in texts:
            for url in re.findall(r"https?://[^\s\"'>)]+", text):
                self.assertTrue(url.startswith("http://127.0.0.1:"), url)

    def test_poisoned_static_surfaces_carry_injections_and_controls_do_not(self):
        for target, text in surfaces.static_texts():
            meta = surfaces.ATTACK_MANIFEST[target]
            if meta["surface"] == "okf_chain":
                continue  # split across two documents; caught only when assembled
            fm, body = surfaces.split_frontmatter(text) if target.startswith("okf:") else ("", text)
            flagged = any(screen(part).verdict != Verdict.ALLOW for part in (fm, body) if part)
            self.assertEqual(flagged, meta["attack"], target)

    def test_okf_runbook_is_clean_alone_and_hostile_assembled(self):
        bundle = surfaces.okf_bundle()
        self.assertEqual(surfaces.okf_groups(), {"runbook": ["runbook_part1", "runbook_part2"]})
        parts = [surfaces.split_frontmatter(bundle[k])[1] for k in ("runbook_part1", "runbook_part2")]
        self.assertTrue(all(screen(p).verdict == Verdict.ALLOW for p in parts))
        self.assertNotEqual(screen(surfaces.assemble_group("runbook")).verdict, Verdict.ALLOW)

    def test_chain_needs_session(self):
        # The pointer and the control are clean alone; the destination is the attack.
        for uri in ("kb://setup/step-one", "kb://setup/step-three"):
            self.assertEqual(screen(surfaces.CHAIN[uri]).verdict, Verdict.ALLOW, uri)
        session = Session()
        for uri, text in surfaces.CHAIN.items():
            session.observe(uri, text)
        verdicts = session.verdicts()
        self.assertTrue(verdicts["kb://setup/step-two"].flagged)
        self.assertFalse(verdicts["kb://setup/step-three"].flagged)

    def test_conditional_trigger_fires_only_on_nth_call_and_resets(self):
        state = surfaces.SurfaceState()
        canary = providers.canary()
        calls = [state.service_health("api") for _ in range(4)]
        self.assertEqual([canary in c for c in calls], [False, False, True, False])
        state.reset()
        self.assertNotIn(canary, state.service_health("api"))

    def test_depth_payload_is_past_the_head(self):
        log = surfaces.export_log()
        self.assertNotIn(providers.canary(), log[:surfaces.DEPTH_HEAD_LIMIT])
        self.assertIn(providers.canary(), log)


class SurfaceSdkTest(unittest.TestCase):
    def setUp(self):
        try:
            from hactu8.lamb.mcp_target import LambMcpState, build_mcp_server
            self.state = LambMcpState()
            self.mcp = build_mcp_server(self.state)
        except (ModuleNotFoundError, RuntimeError):
            self.skipTest("Lamb extra not installed")

    def _tools(self):
        return {t.name: t for t in asyncio.run(self.mcp.list_tools())}

    def test_every_surface_is_registered(self):
        tools = self._tools()
        for name in ("search_kb", "server_time", "okf_list_concepts", "okf_get_concept", "chain_list",
                     "chain_get", "service_health", "a2a_inbox", "a2a_read", "ticket_lookup", "db_query",
                     "export_log"):
            self.assertIn(name, tools)
        self.assertIn("SYSTEM:", tools["ticket_lookup"].input_schema["properties"]["ticket_id"]["description"])
        self.assertEqual({str(r.uri) for r in asyncio.run(self.mcp.list_resources())},
                         {"wiki://onboarding", "wiki://holidays"})

    def test_error_channel_text_reaches_the_caller(self):
        from hactu8.lamb._mcp import tool_error_class
        with self.assertRaises(tool_error_class()) as ctx:
            asyncio.run(self.mcp.call_tool("db_query", {"table": "secrets"}))
        self.assertIn(providers.canary(), str(ctx.exception))

    def test_swap_changes_definition_and_truth_then_restores(self):
        before = self._tools()["server_time"].description
        self.assertFalse(surfaces.truth("swap:server_time", self.state.surfaces))
        surfaces.simulate_swap(self.mcp, self.state.surfaces)
        self.assertNotEqual(self._tools()["server_time"].description, before)
        self.assertTrue(surfaces.truth("swap:server_time", self.state.surfaces))
        surfaces.restore_swaps(self.mcp, self.state.surfaces)
        self.state.surfaces.reset()
        self.assertEqual(self._tools()["server_time"].description, before)
        self.assertFalse(surfaces.truth("swap:server_time", self.state.surfaces))


if __name__ == "__main__":
    unittest.main()


class LambRoutesTest(unittest.TestCase):
    def setUp(self):
        try:
            from starlette.testclient import TestClient

            from hactu8.lamb.app import create_app
            from hactu8.lamb.workers import LabWorkerManager
        except (ModuleNotFoundError, RuntimeError):
            self.skipTest("Lamb extra not installed")
        self.app = create_app(manager=LabWorkerManager(skills=[]))
        self.client = TestClient(self.app, base_url="http://127.0.0.1:5500")

    def tearDown(self):
        self.app.state.workers.close()

    def test_manifest_swap_and_reset(self):
        targets = self.client.get("/api/lamb/manifest").json()["targets"]
        self.assertFalse(targets["swap:server_time"]["attack"])
        self.assertTrue(targets["tool:search_kb"]["attack"])
        self.assertEqual(self.client.post("/api/lamb/swap").json()["swapped"], ["server_time"])
        self.assertTrue(self.client.get("/api/lamb/manifest").json()["targets"]["swap:server_time"]["attack"])
        reset = self.client.post("/api/reset", json={}).json()
        self.assertEqual(reset["mcp"]["surfaces"], {"conditional_calls": 0, "swapped": []})
        self.assertFalse(self.client.get("/api/lamb/manifest").json()["targets"]["swap:server_time"]["attack"])

    def test_foreign_host_refused(self):
        self.assertEqual(self.client.get("/api/lamb/manifest", headers={"host": "evil.example"}).status_code, 403)
