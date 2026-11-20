"""Parsing tests for the real-model seam: ``parse_json_object`` and ``ProviderModel.plan``.

The plan reply is read as the first JSON object (a fence or text after it is
ignored). Only well-formed record ids other than the session survive, at most
``MAX_PIVOT``; anything else means no extra reads.

Run from the skill folder:  python -m unittest discover -s tests
"""

from __future__ import annotations

import json
import os
import sys
import unittest

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, SKILL_DIR)

from vulnerable_app import MAX_PIVOT, ProviderModel, parse_json_object  # noqa: E402


class FixedProvider:
    def __init__(self, reply: str) -> None:
        self.reply = reply

    def chat(self, messages, *, model=""):
        return self.reply


def plan(reply, session="C-1003"):
    messages = [{"role": "system", "content": "s"}, {"role": "user", "content": "q"}]
    return ProviderModel(FixedProvider(reply), "fake").plan(messages, session)


class ParseJsonObjectTest(unittest.TestCase):
    def test_first_object_with_fence_or_trailing_text(self):
        body = '{"read_records": ["C-1001"]}'
        for reply in (body, f"```json\n{body}\n```", f"Sure. {body} That is all {{x}}.",
                      body + '\n{"read_records": ["C-1002"]}'):
            self.assertEqual(parse_json_object(reply), {"read_records": ["C-1001"]}, reply)

    def test_rejects_malformed(self):
        for reply in ("", "I can't help with that.", '{"read_records": [', '["C-1001"]'):
            self.assertIsNone(parse_json_object(reply), reply)


class PlanTest(unittest.TestCase):
    def test_accepts_valid_ids(self):
        self.assertEqual(plan('{"read_records": ["C-1001", " C-1002 "]}'), ["C-1001", "C-1002"])
        self.assertEqual(plan('{"read_records": []}'), [])

    def test_rejects_bad_ids_session_and_duplicates(self):
        self.assertEqual(plan('{"read_records": ["C-1003", "c-1001", "C-10011", "1001", 1001,'
                              ' "C-1001", "C-1001"]}'), ["C-1001"])

    def test_caps_reads(self):
        ids = [f"C-20{i:02d}" for i in range(10)]
        self.assertEqual(len(plan(json.dumps({"read_records": ids}))), MAX_PIVOT)

    def test_bad_reply_reads_nothing(self):
        for reply in ("", "I can't help with that.", '{"records": ["C-1001"]}',
                      '{"read_records": "C-1001"}'):
            self.assertEqual(plan(reply), [], reply)


if __name__ == "__main__":
    unittest.main()
