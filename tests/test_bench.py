import json
import subprocess
import sys
import unittest

from hactu8 import bench


class BenchTest(unittest.TestCase):
    def setUp(self):
        self.corpus = bench.load()
        self.result = bench.run(self.corpus)

    def test_corpus_shape(self):
        self.assertEqual(self.corpus["schema"], "hactu8.bench/v1")
        kinds = {item["kind"] for item in self.corpus["items"]}
        self.assertLessEqual(kinds, {"screen", "screen_any", "session", "control"})
        ids = [item["id"] for item in self.corpus["items"]]
        self.assertEqual(len(ids), len(set(ids)))
        holdout = bench.load(bench.HOLDOUT)
        self.assertTrue(any(i["attack"] for i in holdout["items"]))
        self.assertTrue(any(not i["attack"] for i in holdout["items"]))
        self.assertTrue(any(not item["attack"] for item in self.corpus["items"]))

    def test_no_regression_against_baseline(self):
        self.assertEqual([i.id for i in self.result.regressions], [])
        baseline = self.corpus["baseline"]
        self.assertGreaterEqual(self.result.coverage, baseline["coverage"])
        independent = baseline["independent"]
        self.assertGreaterEqual(self.result.generalization, independent["caught"] / independent["attacks"])
        self.assertLessEqual(self.result.false_positives, baseline["false_positives"])

    def test_holdout_is_scored_separately(self):
        holdout_misses = [i for i in self.result.items if i.holdout and i.grade == "MISS"]
        self.assertTrue(holdout_misses, "the held-out set should still expose real misses")
        self.assertEqual(self.result.coverage, 1.0)

    def test_regression_detected_when_screen_weakens(self):
        corpus = json.loads(json.dumps(self.corpus))
        attack = next(i for i in corpus["items"] if i["kind"] == "screen" and i["attack"] and not i["holdout"])
        attack["text"] = "the weekly status meeting is on tuesday"
        self.assertIn(attack["id"], [i.id for i in bench.run(corpus).regressions])

    def test_cli_json(self):
        out = subprocess.run([sys.executable, "-m", "hactu8", "bench", "--json"],
                             capture_output=True, text=True, check=True)
        data = json.loads(out.stdout)
        self.assertEqual(data["regressions"], [])
        self.assertEqual(data["coverage"], 1.0)


if __name__ == "__main__":
    unittest.main()
