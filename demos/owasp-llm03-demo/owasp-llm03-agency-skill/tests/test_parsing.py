"""Parsing tests for the real-model seam: ``CALL_SCHEMA`` and ``ProviderModel.next_call``.

The prompt shows one example call per tool with the exact argument name the
parser needs as the target (``ticket``, not ``id`` or ``ticket_id``). The reply
is read as the first JSON object (a fence or text after it is ignored). The
parser stays strict: unknown tools, a missing target argument, bad values,
a placeholder copied from the prompt, or a repeated call mean no call.

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

from vulnerable_app import TOOLS, ProviderModel, ToolCall, parse_json_object  # noqa: E402

EXAMPLE_RE = re.compile(r'\{"tool": "([a-z_]+)", "args": (\{[^{}]*\})\}')
REAL = {"ticket": "T-1001", "order": "A-1001", "customer": "C-2002"}


class FixedProvider:
    def __init__(self, reply: str) -> None:
        self.reply = reply
        self.sent = []

    def chat(self, messages, *, model=""):
        self.sent.append(messages)
        return self.reply


def next_call(reply, made=()):
    messages = [{"role": "system", "content": "s"}, {"role": "user", "content": "q"}]
    return ProviderModel(FixedProvider(reply), "fake").next_call(messages, made)


def call(tool, **args):
    return json.dumps({"tool": tool, "args": args})


class SchemaTest(unittest.TestCase):
    def examples(self):
        return [(t, json.loads(a)) for t, a in EXAMPLE_RE.findall(ProviderModel.CALL_SCHEMA)]

    def test_one_example_per_tool_with_its_target_argument(self):
        self.assertEqual({t: list(a) for t, a in self.examples()},
                         {t: [arg] for t, arg in TOOLS.items()})

    def test_examples_parse_with_real_values_and_not_verbatim(self):
        for tool, args in self.examples():
            self.assertIsNone(next_call(json.dumps({"tool": tool, "args": args})), tool)
            filled = {k: REAL[k] for k in args}
            self.assertEqual(next_call(json.dumps({"tool": tool, "args": filled})),
                             ToolCall(tool, filled))


class NextCallTest(unittest.TestCase):
    def test_accepts_well_formed_calls(self):
        self.assertEqual(next_call(call("read_ticket", ticket="T-1001")),
                         ToolCall("read_ticket", {"ticket": "T-1001"}))
        self.assertEqual(next_call(call("issue_refund", order="A-1003")),
                         ToolCall("issue_refund", {"order": "A-1003"}))

    def test_accepts_fence_and_text_after_the_object(self):
        first = call("issue_refund", order="A-1001")
        expect = ToolCall("issue_refund", {"order": "A-1001"})
        self.assertEqual(next_call(f"```json\n{first}\n```"), expect)
        # Seen from llama3.2:3b: two calls in one reply. Only the first is read.
        self.assertEqual(next_call(first + " \n" + call("delete_account", customer="C-2002")),
                         expect)

    def test_done_is_no_call(self):
        self.assertIsNone(next_call('{"tool": null}'))

    def test_rejects_wrong_argument_names(self):
        for args in ({"id": "T-1001"}, {"ticket_id": "T-1001"}, {"order_id": "A-1001"}, {}):
            self.assertIsNone(next_call(json.dumps({"tool": "read_ticket", "args": args})), args)

    def test_rejects_tools_outside_the_list(self):
        self.assertIsNone(next_call(call("close_ticket", ticket="T-1001")))
        self.assertIsNone(next_call('{"tool": issue_refund, "args": {"order": "A-1003"}}'))

    def test_rejects_bad_values_and_repeats(self):
        for value in ("T 1001", "", "x" * 81, "T-1001;rm"):
            self.assertIsNone(next_call(call("read_ticket", ticket=value)), value)
        self.assertIsNone(next_call('{"tool": "read_ticket", "args": {"ticket": 1001}}'))
        self.assertIsNone(next_call(call("read_ticket", ticket="T-1001"),
                                    made=("read_ticket:T-1001",)))

    def test_parse_json_object_rejects_malformed(self):
        for reply in ("", "no call", '{"tool": "read_ticket"', "[1]"):
            self.assertIsNone(parse_json_object(reply), reply)


if __name__ == "__main__":
    unittest.main()
