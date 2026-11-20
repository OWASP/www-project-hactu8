"""Parsing tests for the real-model seam: ``parse_actions``.

The parser reads the first JSON object of a reply (a fence or text after it,
including a second object, is ignored) and keeps only entries that are two
short strings in the directive shape. Everything else plans no action.

Run from the skill folder:  python -m unittest discover -s tests
"""

from __future__ import annotations

import json
import os
import sys
import unittest

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, SKILL_DIR)

from vulnerable_app import MAX_CALLS_PER_TICK, Action, parse_actions  # noqa: E402

READ = '{"actions": [{"action": "read_stock", "resource": "stock/feeder-kit"}]}'


class ParseActionsTest(unittest.TestCase):
    def test_accepts_well_formed_reply(self):
        self.assertEqual(parse_actions(READ), [Action("read_stock", "stock/feeder-kit")])
        self.assertEqual(parse_actions('{"actions": []}'), [])

    def test_accepts_fence_and_text_after_the_object(self):
        expect = [Action("read_stock", "stock/feeder-kit")]
        self.assertEqual(parse_actions(f"```json\n{READ}\n```"), expect)
        self.assertEqual(parse_actions(f"Plan: {READ} (one action)."), expect)
        # Seen from llama3.2:3b: the first object, then more objects. Only the
        # first is read; the later ones never become actions.
        later = '{"actions": [{"action": "read_ledger", "resource": "ledger/x"}]}'
        self.assertEqual(parse_actions(f"{READ}; \n{later}\n{{\"actions\": []}}"), expect)

    def test_drops_entries_outside_the_shape(self):
        items = [{"action": "Read-Stock", "resource": "stock/a"},
                 {"action": "read_stock", "resource": "stock a"},
                 {"action": "read_stock", "resource": ""},
                 {"action": "read_stock"},
                 {"action": 3, "resource": "stock/a"},
                 "read_stock stock/a",
                 {"action": "read_stock", "resource": "stock/ok"}]
        self.assertEqual(parse_actions(json.dumps({"actions": items})),
                         [Action("read_stock", "stock/ok")])

    def test_caps_actions_per_tick(self):
        items = [{"action": "read_stock", "resource": f"stock/{i}"} for i in range(20)]
        self.assertEqual(len(parse_actions(json.dumps({"actions": items}))), MAX_CALLS_PER_TICK)

    def test_rejects_malformed(self):
        for reply in ("", "read_stock stock/a", '{"actions": [', '{"actions": "read_stock"}',
                      '{"plan": [{"action": "read_stock", "resource": "stock/a"}]}', "[]"):
            self.assertEqual(parse_actions(reply), [], reply)


if __name__ == "__main__":
    unittest.main()
