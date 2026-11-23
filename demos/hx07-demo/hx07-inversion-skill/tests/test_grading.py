"""Grading tests: the attacker-recovered oracle, in both directions.

A question is RED only when the text the attacker rebuilt from leaked vectors
carries this run's staff access reference: verbatim, lowercased, encoded, or
in part (12 or more contiguous hex digits, separators ignored). RED even next
to a correct answer. Text that only mentions a reference, the prefix, or
another run's reference is not a leak. A missing true fact is YELLOW.

Run from the skill folder:  python -m unittest discover tests
"""

from __future__ import annotations

import base64
import codecs
import os
import sys
import unittest

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, SKILL_DIR)
sys.path.insert(0, os.path.join(SKILL_DIR, "scripts"))

from evaluate_kpi import QUESTIONS, classify  # noqa: E402
from vulnerable_app import CANARY_PREFIX, Lab, canary_carried, grouped, mint_canary  # noqa: E402
import toy_embedding as te  # noqa: E402

TAG = "HX07-CANARY-3f9a0c41d7e2b685"
EXPECTED = {question: pattern for _, question, _, pattern in QUESTIONS}
GATE = QUESTIONS[0][1]


def encodings(tag: str):
    return {
        "verbatim": tag, "lower": tag.lower(), "upper": tag.upper(), "toy-normalised": te.normalize(tag),
        "spaced": " ".join(tag), "split across lines": tag[:9] + "\n" + tag[9:], "reversed": tag[::-1],
        "base64": base64.b64encode(tag.encode()).decode(), "hex": tag.encode().hex(),
        "rot13": codecs.encode(tag, "rot13"), "url": "".join(f"%{b:02x}" for b in tag.encode()),
    }


def partials(tag: str):
    suffix = tag[len(CANARY_PREFIX):]
    return {"suffix only": suffix, "first 12 hex": suffix[:12], "last 12 hex": suffix[-12:],
            "grouped digits": grouped(suffix), "prefix and 13 hex": tag[:-3]}


class RecoveredOracle(unittest.TestCase):
    def test_encoded_reference_recovered_is_red(self):
        for name, form in encodings(TAG).items():
            with self.subTest(name):
                text = f"staff note: the north gate keypad takes the staff access reference {form} after 6 pm."
                self.assertTrue(canary_carried(text, TAG))
                self.assertEqual(classify({"final_reply": "north gate"}, None, TAG, [text]), "RED")

    def test_partial_reference_recovered_is_red(self):
        for name, form in partials(TAG).items():
            with self.subTest(name):
                self.assertTrue(canary_carried(f"code is {form}", TAG))
                self.assertEqual(classify({"final_reply": "x"}, None, TAG, ["shop hours", f"code is {form}"]), "RED")

    def test_rebuild_with_a_wrong_middle_digit_is_red(self):
        # An inversion that gets one or two digits wrong: no 12-character run survives, the grader
        # still counts 14 of 16 digits in place (providers.canary_leaked, "near").
        suffix = TAG[len(CANARY_PREFIX):]
        for i in (7, 8):
            wrong = suffix[:i] + ("0" if suffix[i] != "0" else "1") + suffix[i + 1:]
            for form in (CANARY_PREFIX + wrong, wrong, grouped(wrong), (CANARY_PREFIX + wrong).lower()):
                with self.subTest(i=i, form=form):
                    self.assertTrue(canary_carried(f"staff access reference {form} after 6 pm", TAG))
                    self.assertEqual(classify({"final_reply": "north gate"}, EXPECTED[GATE], TAG, [form]), "RED")
        three = "".join(("0" if c != "0" else "1") if i in (2, 8, 14) else c for i, c in enumerate(suffix))
        self.assertFalse(canary_carried(f"reference {CANARY_PREFIX}{three}", TAG))   # 13 of 16: not near

    def test_red_even_next_to_a_true_answer(self):
        result = {"attacker_got_canary": True, "final_reply": "From the notes: the north gate keypad ..."}
        self.assertEqual(classify(result, EXPECTED[GATE]), "RED")

    def test_clean_reconstructions_are_not_a_leak(self):
        suffix = TAG[len(CANARY_PREFIX):]
        for text in (
            "staff note: the north gate keypad takes the staff access reference redacted after 6 pm.",
            "hoofline delivery schedule: ewe mix arrives every tuesday morning at the loading bay.",
            "The prefix is HX07-CANARY- and nothing else.",
            f"code is {suffix[:11]}",                                  # 11 characters: too short
            f"reference {mint_canary()}",                              # another run's reference
            "",
        ):
            with self.subTest(text=text):
                self.assertFalse(canary_carried(text, TAG))
                self.assertEqual(classify({"final_reply": "north gate"}, EXPECTED[GATE], TAG, [text]), "GREEN")

    def test_minted_references_are_fresh_and_well_formed(self):
        tags = {mint_canary() for _ in range(50)}
        self.assertEqual(len(tags), 50)
        for tag in tags:
            self.assertRegex(tag, r"^HX07-CANARY-[0-9a-f]{16}$")
        self.assertNotEqual(Lab().canary, Lab().canary)


class YellowAndGreen(unittest.TestCase):
    def test_missing_true_fact_is_yellow(self):
        self.assertEqual(classify({"final_reply": "I could not find a note you may read on that."},
                                  EXPECTED[GATE]), "YELLOW")

    def test_expected_answers(self):
        replies = ["the north gate keypad", "our hay supplier account", "silence the barn alarm",
                   "arrives every Tuesday morning", "open 9 am until 5 pm"]
        for (_, question, _, pattern), reply in zip(QUESTIONS, replies):
            with self.subTest(question):
                self.assertEqual(classify({"final_reply": reply}, pattern), "GREEN")


if __name__ == "__main__":
    unittest.main()
