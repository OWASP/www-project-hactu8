import unittest
from unittest import mock

from hactu8 import bench
from hactu8.protectogw import Policy, Verdict, screen

BENIGN = "The barn door latch sticks in cold weather, so give it a firm push."


class ClassifierPlaneTest(unittest.TestCase):
    def test_default_policy_has_no_classifier(self):
        self.assertIsNone(Policy().classifier)
        self.assertEqual(screen(BENIGN).verdict, Verdict.ALLOW)

    def test_scores_map_to_flag_and_block(self):
        self.assertEqual(screen(BENIGN, policy=Policy(classifier=lambda t: 0.6)).verdict, Verdict.FLAG)
        self.assertEqual(screen(BENIGN, policy=Policy(classifier=lambda t: 0.9)).verdict, Verdict.BLOCK)
        self.assertEqual(screen(BENIGN, policy=Policy(classifier=lambda t: 0.1)).verdict, Verdict.ALLOW)

    def test_classifier_failure_flags_without_crashing(self):
        def broken(text):
            raise TimeoutError("model down")
        result = screen(BENIGN, policy=Policy(classifier=broken))
        self.assertEqual(result.verdict, Verdict.FLAG)
        self.assertEqual(result.signals[0].plane, "classifier_error")

    def test_canary_still_decisive_and_skips_classifier(self):
        calls = []
        result = screen("token sk-canary-1", canaries=["sk-canary-1"],
                        policy=Policy(classifier=lambda t: calls.append(t) or 0.0))
        self.assertEqual(result.verdict, Verdict.BLOCK)
        self.assertEqual(calls, [])

    def test_llm_classifier_parses_model_score(self):
        fake = mock.Mock()
        fake.chat.return_value = "Score: 0.85"
        with mock.patch("hactu8.providers.get_provider", return_value=fake):
            classify = bench.llm_classifier("ollama", "llama3.2:3b")
        self.assertAlmostEqual(classify("anything"), 0.85)
        fake.chat.return_value = "no idea"
        with self.assertRaises(ValueError):
            classify("anything")

    def test_bench_with_perfect_classifier(self):
        corpus, holdout = bench.load(), bench.load(bench.HOLDOUT)
        attacks = {i["text"] for i in holdout["items"] if i["attack"]}
        result = bench.run(corpus, holdout, classifier=lambda t: 1.0 if t in attacks else 0.0)
        self.assertEqual(result.generalization, 1.0)
        self.assertEqual(result.false_positives, 0)


if __name__ == "__main__":
    unittest.main()
