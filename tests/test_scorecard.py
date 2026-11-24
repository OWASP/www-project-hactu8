"""scripts/scorecard.py: per-lab compromised / defeated / clean-baseline counts are exact."""

import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
import unittest.mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("scorecard_script", ROOT / "scripts" / "scorecard.py")
scorecard = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scorecard)


def summary(base, impact, hard, status="reported"):
    return {"baseline_rate": base, "impact_rate": impact, "remediated_rate": hard, "status": status}


class ScorecardTest(unittest.TestCase):
    def test_row_counts(self):
        runs = [summary(0.0, 100.0, 0.0), summary(0.0, 0.0, 0.0), summary(33.3, 66.7, 33.3),
                summary(None, None, None, "error")]
        self.assertEqual(scorecard.row(runs), {"n": 3, "errors": 1, "comp": 2, "lift": 2, "held": 1, "dirty": 1, "leaks": 1})

    def test_lift_needs_impact_above_baseline(self):
        self.assertEqual(scorecard.row([summary(33.3, 33.3, 33.3), summary(0.0, 50.0, 0.0)])["lift"], 1)

    def test_echo_only_lab_has_no_graded_runs(self):
        self.assertEqual(scorecard.row([summary(None, None, None, "error")])["n"], 0)

    def test_load_splits_labs_live_and_wolf(self):
        with tempfile.TemporaryDirectory() as tmp:
            res = Path(tmp) / "m" / "run1" / "results"
            res.mkdir(parents=True)
            docs = {"a": {"skill": {"id": "llm01"}, "summary": summary(0.0, 100.0, 0.0)},
                    "b": {"skill": {"id": "lamb-live"}, "summary": {}, "live": {"breaches_off": 2}},
                    "c": {"skill": {"id": "lamb-wolf"}, "summary": summary(0.0, 0.0, 0.0)}}
            for name, doc in docs.items():
                (res / f"{name}.json").write_text(json.dumps(doc))
            labs, live = scorecard.load(Path(tmp))
            self.assertEqual(list(labs["m"]), ["llm01"])
            self.assertEqual(live["m"], [{"breaches_off": 2}])
            out = io.StringIO()
            with contextlib.redirect_stdout(out), unittest.mock.patch("sys.argv", ["x", tmp]):
                scorecard.main()
            self.assertIn("| llm01 | 1 | 1 of 1 | 1 | 1 of 1 | 0 | 0 |", out.getvalue())


if __name__ == "__main__":
    unittest.main()
