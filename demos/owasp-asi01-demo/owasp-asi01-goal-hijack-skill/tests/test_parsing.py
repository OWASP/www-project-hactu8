"""Parsing tests for the real-model seam: ``ProviderModel.SCHEMA`` and ``parse_plan``.

The prompt shows the step shape for every tool, always with the key
``target``, so a model does not guess ``dest`` or ``scope`` as the key. The
parser reads the first JSON object (a fence or trailing text around it is
ignored) and stays strict about everything inside it.

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

from vulnerable_app import MAX_STEPS, TOOLS, ProviderModel, Step  # noqa: E402

EXAMPLE_RE = re.compile(r'\{"tool": "([a-z_]+)", "target": "([^"]*)"\}')
PLAN = [Step("read_tickets", {"scope": "billing"}), Step("summarise", {"scope": "billing"}),
        Step("draft_report", {"scope": "billing"}), Step("post_report", {"channel": "#ops-weekly"})]
PLAN_JSON = json.dumps({"steps": [{"tool": s.tool, "target": s.target} for s in PLAN]})


def plan_of(*steps):
    return json.dumps({"steps": [{"tool": t, "target": v} for t, v in steps]})


class SchemaTest(unittest.TestCase):
    def test_one_step_shape_per_tool(self):
        self.assertEqual(sorted(t for t, _ in EXAMPLE_RE.findall(ProviderModel.SCHEMA)),
                         sorted(TOOLS))

    def test_placeholders_copied_verbatim_are_rejected(self):
        for tool, target in EXAMPLE_RE.findall(ProviderModel.SCHEMA):
            self.assertEqual(ProviderModel.parse_plan(plan_of((tool, target))), [], tool)

    def test_schema_names_no_real_channel(self):
        # Examples must not suggest a plan: no real scope or channel as a target.
        targets = [v for _, v in EXAMPLE_RE.findall(ProviderModel.SCHEMA)]
        self.assertTrue(all(v.startswith(("<", "#<")) for v in targets), targets)


class ParsePlanTest(unittest.TestCase):
    def test_accepts_well_formed_plan(self):
        self.assertEqual(ProviderModel.parse_plan(PLAN_JSON), PLAN)

    def test_scope_is_normalised_to_lower_case(self):
        self.assertEqual(ProviderModel.parse_plan(plan_of(("read_tickets", "Billing"))),
                         [Step("read_tickets", {"scope": "billing"})])

    def test_accepts_fence_and_surrounding_text(self):
        self.assertEqual(ProviderModel.parse_plan(f"Plan:\n```json\n{PLAN_JSON}\n```"), PLAN)
        # A second object or junk after the first object is ignored.
        trailing = PLAN_JSON + ', "post_results": {"channel": "#x"}}'
        self.assertEqual(ProviderModel.parse_plan(trailing), PLAN)
        self.assertEqual(ProviderModel.parse_plan(PLAN_JSON + "\n" + plan_of(
            ("export_tickets", "partner-share"))), PLAN)

    def test_empty_plan_is_no_action(self):
        self.assertEqual(ProviderModel.parse_plan('{"steps": []}'), [])

    def test_rejects_wrong_keys(self):
        for item in ({"tool": "export_tickets", "dest": "partner-share"},
                     {"tool": "read_tickets", "scope": "billing"},
                     {"tool": "read_tickets"}):
            self.assertEqual(ProviderModel.parse_plan(json.dumps({"steps": [item]})), [], item)
        self.assertEqual(ProviderModel.parse_plan(json.dumps({"plan": [PLAN_JSON]})), [])

    def test_rejects_tools_outside_the_list(self):
        self.assertEqual(ProviderModel.parse_plan(plan_of(("delete_tickets", "billing"))), [])

    def test_rejects_bad_targets(self):
        for tool, target in (("read_tickets", "shipping queue"), ("read_tickets", "hr"),
                             ("draft_report", "#finance-weekly"), ("post_report", "ops-weekly"),
                             ("draft_report", ""), ("export_tickets", "a b"),
                             ("export_tickets", "x" * 81)):
            self.assertEqual(ProviderModel.parse_plan(plan_of((tool, target))), [], target)
        self.assertEqual(ProviderModel.parse_plan(
            json.dumps({"steps": [{"tool": "draft_report", "target": None}]})), [])

    def test_one_bad_step_rejects_the_whole_plan(self):
        bad = json.loads(PLAN_JSON)
        bad["steps"].append({"tool": "post_report", "target": "partner lounge"})
        self.assertEqual(ProviderModel.parse_plan(json.dumps(bad)), [])

    def test_rejects_oversized_and_malformed_plans(self):
        long = plan_of(*[("read_tickets", "billing")] * (MAX_STEPS + 1))
        for reply in (long, "", "no plan", '{"steps": [', '{"steps": "read_tickets"}'):
            self.assertEqual(ProviderModel.parse_plan(reply), [], reply[:40])


if __name__ == "__main__":
    unittest.main()
