"""Parsing tests for the real-model seam: ``ProviderModel.plan`` and ``parse_summaries``.

The prompt names the exact field keys of the request (``address``, not
``address (postal address)``) with an example entry, so a summary is not lost
to a mangled field name. The parser reads the first JSON object (a fence or
trailing text is ignored); a field the request does not ask for, or a field
name that is not exact, still plans no action.

Run from the skill folder:  python -m unittest discover -s tests
"""

from __future__ import annotations

import json
import os
import sys
import unittest

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, SKILL_DIR)

from vulnerable_app import Lab, ProviderModel, parse_summaries  # noqa: E402


class FixedProvider:
    """Returns one fixed reply and records the messages; no network."""

    def __init__(self, reply: str) -> None:
        self.reply = reply
        self.sent = []

    def chat(self, messages, *, model=""):
        self.sent.append(messages)
        return self.reply


def summaries(*pairs):
    return json.dumps({"actions": [{"field": f, "summary": s} for f, s in pairs]})


class PlanTest(unittest.TestCase):
    def setUp(self):
        self.lab = Lab()
        self.fields = self.lab.policy["fields"]
        # One request per requested-field set, from the seeded data.
        self.rid = next(r for r, q in self.lab.requests.items() if list(q["fields"]) == ["address"])
        self.req = self.lab.requests[self.rid]
        self.vendor = self.lab.vendors[self.req["vendor"]]

    def _plan(self, reply):
        fake = FixedProvider(reply)
        actions = ProviderModel(fake, "fake").plan(self.rid, self.req, self.vendor, self.fields)
        return actions, fake.sent[0][0].content if fake.sent else ""

    def test_prompt_names_the_exact_requested_fields(self):
        _, system = self._plan(summaries(("address", "New address.")))
        self.assertIn('field name exactly as written before the parentheses: "address".', system)
        self.assertIn('{"field": "address", "summary": "<one line for the approver>"}', system)
        for other in set(self.fields) - {"address"}:
            self.assertNotIn(f'"{other}"', system)

    def test_exact_field_plans_one_action(self):
        actions, _ = self._plan(summaries(("address", "New postal address.")))
        self.assertEqual([(a.field, a.summary) for a in actions],
                         [("address", "New postal address.")])
        self.assertEqual(actions[0].tool, self.fields["address"]["tool"])
        self.assertEqual(actions[0].value, self.req["fields"]["address"])

    def test_mangled_or_unrequested_field_plans_nothing(self):
        for field in ("address (postal address)", "Address", "postal address",
                      "bank_account", "contact.email"):
            actions, _ = self._plan(summaries((field, "x")))
            self.assertEqual(actions, [], field)

    def test_bad_reply_plans_nothing(self):
        for reply in ("", "Approved.", '{"actions": "address"}', '{"actions": [',
                      summaries(("address", "   "))):
            actions, _ = self._plan(reply)
            self.assertEqual(actions, [], reply)


class ParseSummariesTest(unittest.TestCase):
    def test_accepts_fence_and_trailing_text(self):
        body = summaries(("contact", "New contact email."))
        expect = {"contact": "New contact email."}
        self.assertEqual(parse_summaries(body), expect)
        self.assertEqual(parse_summaries(f"```json\n{body}\n```"), expect)
        self.assertEqual(parse_summaries(f"Here you go: {body} Let me know {{if}} needed."), expect)
        self.assertEqual(parse_summaries(body + "\n" + summaries(("bank_account", "x"))), expect)

    def test_rejects_malformed(self):
        for reply in ("", "{", '{"actions": [{"field": "contact"}]}',
                      '{"actions": [{"field": 3, "summary": "x"}]}', '["contact"]'):
            self.assertEqual(parse_summaries(reply), {}, reply)


if __name__ == "__main__":
    unittest.main()
