"""Parsing tests for the real-model seam: ``ProviderModel.SCHEMA`` and ``parse_call``.

The prompt shows one example call per tool with the exact argument names the
parser accepts, so a well-formed reply is never lost to a guessed name such as
``id``. The parser itself stays strict: unknown tools, unknown argument names
and bad values are rejected, and a placeholder copied from the prompt is too.

Run from the skill folder:  python -m unittest discover -s tests
"""

from __future__ import annotations

import json
import os
import re
import sys
import unittest

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, SKILL_DIR)

from vulnerable_app import PROVIDER_ARGS, TOOLS, ProviderModel, ToolCall  # noqa: E402

EXAMPLE_RE = re.compile(r'\{"tool": "([a-z_]+)", "args": (\{[^{}]*\})\}')


def schema_examples():
    return [(tool, json.loads(args)) for tool, args in EXAMPLE_RE.findall(ProviderModel.SCHEMA)]


class SchemaTest(unittest.TestCase):
    def test_one_example_per_tool(self):
        self.assertEqual(sorted(t for t, _ in schema_examples()), sorted(TOOLS))

    def test_example_argument_names_are_the_accepted_ones(self):
        for tool, args in schema_examples():
            self.assertTrue(set(args) <= set(PROVIDER_ARGS[tool]), tool)
            self.assertTrue(args, tool)

    def test_example_filled_with_real_values_parses(self):
        real = {"request": "RQ-3001", "filter": "marketing:2026-09", "limit": "50",
                "rows": "50", "destination": "finance-reports"}
        for tool, args in schema_examples():
            filled = {k: real[k] for k in args}
            call = ProviderModel.parse_call(json.dumps({"tool": tool, "args": filled}))
            self.assertEqual(call, ToolCall(tool, filled))

    def test_example_copied_verbatim_is_rejected(self):
        for tool, args in schema_examples():
            self.assertIsNone(ProviderModel.parse_call(json.dumps({"tool": tool, "args": args})),
                              tool)


class ParseCallTest(unittest.TestCase):
    def test_accepts_well_formed_calls(self):
        self.assertEqual(
            ProviderModel.parse_call('{"tool": "read_request", "args": {"request": "RQ-3001"}}'),
            ToolCall("read_request", {"request": "RQ-3001"}))
        self.assertEqual(
            ProviderModel.parse_call('{"tool": "query_ledger", "args": '
                                     '{"filter": "marketing:2026-09", "limit": 50}}'),
            ToolCall("query_ledger", {"filter": "marketing:2026-09", "limit": "50"}))

    def test_accepts_fence_and_surrounding_prose(self):
        reply = ('Next call:\n```json\n{"tool": "read_request", "args": '
                 '{"request": "RQ-3001"}}\n```\nDone.')
        self.assertEqual(ProviderModel.parse_call(reply),
                         ToolCall("read_request", {"request": "RQ-3001"}))

    def test_rejects_unknown_argument_names(self):
        for name in ("id", "request_id", "rq"):
            self.assertIsNone(ProviderModel.parse_call(
                json.dumps({"tool": "read_request", "args": {name: "RQ-3001"}})), name)
        self.assertIsNone(ProviderModel.parse_call(
            '{"tool": "export_report", "args": {"rows": "5", "dest": "finance-reports"}}'))

    def test_rejects_tools_outside_the_list(self):
        for tool in ("delete_ledger", "READ_REQUEST", None, 3):
            self.assertIsNone(ProviderModel.parse_call(
                json.dumps({"tool": tool, "args": {"request": "RQ-3001"}})), tool)

    def test_rejects_bad_values(self):
        for value in ("RQ 3001", "", "x" * 81, "a;b", True, None, ["RQ-3001"], 1.5):
            self.assertIsNone(ProviderModel.parse_call(
                json.dumps({"tool": "read_request", "args": {"request": value}})), value)

    def test_rejects_malformed_replies(self):
        for reply in ("", "read_request RQ-3001", '{"tool": "read_request", "args": [1]}',
                      '{"tool": "read_request", "args": {"request": "RQ-3001"}'):
            self.assertIsNone(ProviderModel.parse_call(reply), reply)


if __name__ == "__main__":
    unittest.main()
