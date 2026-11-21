"""AG-60 lessons and AG-63 learning path."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hactu8 import catalog, lessons

ROOT = Path(__file__).resolve().parents[1]

GOOD = """# Example lesson

Intro text.

## What it is

The risk.

## Why it works

The mechanism.

```text
## Not a heading: inside a code fence
```

## Try it

- Act 1: watch this.

## The defense, and why it holds

Channel separation.

### A sub-heading is fine

More text.

## Where the defense stops working

Paraphrases.

## Check yourself

1. First question?

   Answer: first.
2. Second question?

   Answer: second.

## References

- `llm01`, `LLM01:2026`.
"""

# Labs with no LESSON.md. AG-62 gave every lab one, so the set is empty and
# the complete-lesson check below is strict: a new lab without a lesson fails.
EXPECTED_MISSING: frozenset = frozenset()


class ValidatorTest(unittest.TestCase):
    def assertRejected(self, text: str, fragment: str):
        with self.assertRaises(lessons.LessonError) as caught:
            lessons.parse(text)
        self.assertTrue(any(fragment in p for p in caught.exception.problems), caught.exception.problems)

    def test_accepts_a_good_lesson(self):
        lesson = lessons.parse(GOOD)
        self.assertEqual(lesson.title, "Example lesson")
        self.assertEqual(list(lesson.sections), list(lessons.SECTIONS))
        self.assertEqual(lesson.questions, ["First question?", "Second question?"])
        self.assertIn("### A sub-heading is fine", lesson.sections["The defense, and why it holds"])
        self.assertIn("## Not a heading", lesson.sections["Why it works"])
        self.assertEqual(lesson.to_dict()["sections"]["References"], "- `llm01`, `LLM01:2026`.")

    def test_accepts_three_questions(self):
        text = GOOD.replace("## References", "3. Third question?\n\n## References")
        self.assertEqual(len(lessons.parse(text).questions), 3)

    def test_rejects_a_missing_section(self):
        text = GOOD.replace("## Why it works\n\nThe mechanism.", "")
        self.assertRejected(text, "missing section(s): Why it works")

    def test_rejects_the_wrong_order(self):
        text = GOOD.replace("## What it is", "## TMP").replace("## Why it works", "## What it is")
        text = text.replace("## TMP", "## Why it works")
        self.assertRejected(text, "out of order")

    def test_rejects_an_empty_section(self):
        text = GOOD.replace("Paraphrases.", "")
        self.assertRejected(text, "empty section(s): Where the defense stops working")

    def test_rejects_too_few_and_too_many_questions(self):
        one = GOOD.replace("2. Second question?\n\n   Answer: second.\n", "")
        self.assertRejected(one, "found 1")
        four = GOOD.replace("## References", "3. Third?\n4. Fourth?\n\n## References")
        self.assertRejected(four, "found 4")

    def test_nested_and_fenced_numbers_are_not_questions(self):
        text = GOOD.replace("   Answer: first.", "   1. not a question\n\n   ```text\n1. nor this\n   ```")
        self.assertEqual(len(lessons.parse(text).questions), 2)

    def test_rejects_unknown_and_duplicate_sections(self):
        self.assertRejected(GOOD + "\n## Extra\n\nText.\n", "unknown section(s): Extra")
        self.assertRejected(GOOD + "\n## References\n\nAgain.\n", "duplicate section(s): References")

    def test_load_returns_none_without_a_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(lessons.load(tmp))
            self.assertFalse(lessons.has_lesson(tmp))
            (Path(tmp) / lessons.FILENAME).write_text(GOOD, encoding="utf-8")
            self.assertTrue(lessons.has_lesson(tmp))
            self.assertEqual(lessons.load(tmp).title, "Example lesson")


class RepoLessonTest(unittest.TestCase):
    def test_template_skeleton_is_valid(self):
        lessons.load(ROOT / "demos" / "_template")

    def test_every_present_lesson_is_valid(self):
        for skill in catalog.discover(ROOT):
            with self.subTest(skill=skill.id):
                lesson = lessons.load(skill.skill_dir)
                if lesson is None:
                    continue
                self.assertIn(skill.owasp.split(":")[0], lesson.sections["References"],
                              "References must give the catalog ID")

    def test_no_lesson_states_its_path_position(self):
        # Positions shift whenever a lab is added; the path itself shows them (hactu8 path).
        for skill in catalog.discover(ROOT):
            if not skill.has_lesson:
                continue
            with self.subTest(skill=skill.id):
                text = (Path(skill.skill_dir) / "LESSON.md").read_text(encoding="utf-8")
                self.assertNotRegex(text, r"(?i)\bstep \d+ (of|on) the|^step \d+,|\blast lab (of|on) the")

    def test_every_lab_has_a_complete_lesson(self):
        ids = {skill.id for skill in catalog.discover(ROOT)}
        missing = {skill.id for skill in catalog.discover(ROOT) if not skill.has_lesson}
        self.assertLessEqual(EXPECTED_MISSING, ids, "EXPECTED_MISSING names an unknown lab")
        self.assertEqual(missing - EXPECTED_MISSING, set(), "labs without a LESSON.md")
        self.assertEqual(EXPECTED_MISSING - missing, set(),
                         "these labs now have a lesson: remove them from EXPECTED_MISSING")
        if missing:
            print(f"\n[AG-62] {len(missing)} of {len(ids)} labs still need a LESSON.md: "
                  + ", ".join(sorted(missing)))

    def test_llm01_example_lesson(self):
        skill = catalog.get("llm01", ROOT)
        self.assertTrue(skill.has_lesson)
        lesson = lessons.load(skill.skill_dir)
        self.assertEqual(len(lesson.questions), 3)
        self.assertIn("LLM01:2026", lesson.sections["References"])
        self.assertIn("lab_directive", lesson.sections["Where the defense stops working"])


class LearningPathTest(unittest.TestCase):
    def test_parse_path(self):
        self.assertEqual(catalog.parse_path("basics:1"), ("basics", 1))
        self.assertEqual(catalog.parse_path(" Agentic : 12 "), ("agentic", 12))
        for bad in ("", "basics", "basics:0", "basics:x", "unknown:1", "basics:-1"):
            self.assertEqual(catalog.parse_path(bad), ("", 0), bad)

    def test_stages_in_order(self):
        self.assertEqual(catalog.STAGE_IDS, ("basics", "agentic", "commerce"))

    def test_every_lab_has_a_unique_position_and_a_known_stage(self):
        skills = catalog.discover(ROOT)
        self.assertEqual(len(skills), 42)
        for skill in skills:
            with self.subTest(skill=skill.id):
                self.assertIn(skill.path_stage, catalog.STAGE_IDS)
                self.assertGreaterEqual(skill.path_order, 1)
        positions = [(s.path_stage, s.path_order) for s in skills]
        self.assertEqual(len(positions), len(set(positions)), "two labs share a path position")

    def test_track_starts_with_the_basics_and_commerce_holds_the_payment_labs(self):
        track = catalog.learning_path(catalog.discover(ROOT))
        self.assertEqual(track["total"], 42)
        self.assertEqual(track["unassigned"], [])
        stages = {stage["id"]: stage["skills"] for stage in track["stages"]}
        self.assertEqual([stage["id"] for stage in track["stages"]], list(catalog.STAGE_IDS))
        self.assertEqual([s["id"] for s in stages["basics"][:2]], ["llm01", "llm10"])
        self.assertEqual([s["id"] for s in stages["commerce"]], ["hx12", "hx13", "hx11"])
        steps = [s["step"] for stage in track["stages"] for s in stage["skills"]]
        self.assertEqual(steps, list(range(1, 43)))
        for stage in ("basics", "agentic", "commerce"):
            orders = [s["order"] for s in stages[stage]]
            self.assertEqual(orders, list(range(1, len(orders) + 1)), f"{stage} positions have gaps")

    def test_unassigned_labs_are_reported(self):
        skills = catalog.discover(ROOT)
        skills[0].path_stage = ""
        track = catalog.learning_path(skills)
        self.assertEqual(track["unassigned"], [skills[0].id])
        self.assertEqual(track["total"], 41)


try:
    from fastapi.testclient import TestClient
except ModuleNotFoundError:
    TestClient = None


@unittest.skipIf(TestClient is None, "API optional dependencies not installed")
class LessonApiTest(unittest.TestCase):
    def setUp(self):
        from hactu8.api import create_app
        self.home = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {"HACTU8_HOME": self.home.name})
        self.env.start()
        self.client = TestClient(create_app(ROOT))

    def tearDown(self):
        self.env.stop()
        self.home.cleanup()

    def test_skills_carry_has_lesson_and_path(self):
        skills = {s["id"]: s for s in self.client.get("/api/skills").json()["skills"]}
        self.assertTrue(skills["llm01"]["has_lesson"])
        self.assertTrue(all(skill["has_lesson"] for skill in skills.values()))
        self.assertEqual((skills["llm01"]["path_stage"], skills["llm01"]["path_order"]), ("basics", 1))

    def test_lesson_endpoint(self):
        response = self.client.get("/api/skills/llm01/lesson")
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body["skill_id"], "llm01")
        self.assertEqual(list(body["sections"]), list(lessons.SECTIONS))
        self.assertEqual(len(body["questions"]), 3)
        with patch.object(lessons, "load", return_value=None):  # a lab with no LESSON.md
            self.assertEqual(self.client.get("/api/skills/llm02/lesson").status_code, 404)
        self.assertEqual(self.client.get("/api/skills/nope/lesson").status_code, 404)

    def test_malformed_lesson_is_a_server_error(self):
        skill = catalog.get("llm02", ROOT)
        with patch.object(lessons, "load", side_effect=lessons.LessonError(["missing section(s): Try it"])):
            response = self.client.get(f"/api/skills/{skill.id}/lesson")
        self.assertEqual(response.status_code, 500)
        self.assertIn("Try it", response.json()["detail"])

    def test_path_endpoint(self):
        body = self.client.get("/api/path").json()
        self.assertEqual(body["total"], 42)
        self.assertEqual(body["stages"][0]["skills"][0]["id"], "llm01")
        self.assertTrue(body["stages"][0]["skills"][0]["has_lesson"])


if __name__ == "__main__":
    unittest.main()
