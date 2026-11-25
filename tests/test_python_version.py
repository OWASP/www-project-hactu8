"""The minimum Python version is stated once in code and once in packaging; they must agree."""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class PythonVersionTest(unittest.TestCase):
    def test_guard_matches_requires_python(self):
        main = (ROOT / "hactu8" / "__main__.py").read_text(encoding="utf-8")
        guard = re.search(r"MIN_PYTHON = \((\d+), (\d+)\)", main)
        self.assertIsNotNone(guard, "MIN_PYTHON not found in hactu8/__main__.py")
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        requires = re.search(r'requires-python = ">=(\d+)\.(\d+)"', pyproject)
        self.assertIsNotNone(requires, "requires-python not found in pyproject.toml")
        self.assertEqual(guard.groups(), requires.groups())

    def test_minimum_is_at_least_3_12(self):
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        major, minor = map(int, re.search(r'requires-python = ">=(\d+)\.(\d+)"', pyproject).groups())
        self.assertGreaterEqual((major, minor), (3, 12))


if __name__ == "__main__":
    unittest.main()
