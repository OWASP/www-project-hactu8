"""Each lab README's "python -m unittest discover tests  # N tests" line matches its suite.

The count is what ``unittest`` discovers in the lab's skill folder (the folder
that holds ``scripts/`` and ``tests/``), skipped tests included, so it is the
number ``Ran N tests`` prints. Each lab is counted in its own process: labs share
module names (``vulnerable_app``, ``evaluate_kpi``).
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import unittest
from pathlib import Path

from tests.labs import lab_count

ROOT = Path(__file__).resolve().parents[1]
CLAIM = re.compile(r"^python -m unittest discover tests\s+# (\d+) tests$", re.M)
COUNT = ("import unittest; "
         "print(unittest.defaultTestLoader.discover('tests').countTestCases())")


def skill_dir(lab: Path) -> Path:
    found = [p.parent for p in sorted(lab.glob("*/tests")) if (p.parent / "scripts").is_dir()]
    if len(found) != 1:
        raise AssertionError(f"{lab.name}: expected one skill folder with scripts/ and tests/, got {found}")
    return found[0]


def counted(skill: Path) -> int:
    out = subprocess.run([sys.executable, "-c", COUNT], cwd=skill, capture_output=True, text=True,
                         timeout=120, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    if out.returncode:
        raise AssertionError(f"{skill}: counting failed: {out.stderr[-500:]}")
    return int(out.stdout.strip().splitlines()[-1])


def claims():
    for readme in sorted((ROOT / "demos").glob("*/README.md")):
        found = CLAIM.findall(readme.read_text(encoding="utf-8"))
        if found:
            yield readme.parent, [int(n) for n in found]


class ReadmeTestCounts(unittest.TestCase):
    def test_every_lab_claims_a_count(self):
        labs = {p.parent.name for p in (ROOT / "demos").glob("*/run_demo.py")}
        self.assertEqual(len(labs), lab_count())
        self.assertEqual(labs, {lab.name for lab, _ in claims()})

    def test_counts_match_the_suites(self):
        for lab, numbers in claims():
            with self.subTest(lab=lab.name):
                self.assertEqual(numbers, [counted(skill_dir(lab))] * len(numbers),
                                 f"{lab.name}/README.md: fix the '# N tests' line")


if __name__ == "__main__":
    unittest.main()
