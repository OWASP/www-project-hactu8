"""The lab count the other tests compare against (tests/labs.py) is right, and its guard works."""

import unittest
from pathlib import Path
from unittest import mock

from hactu8 import catalog
from tests import labs


class LabCountTest(unittest.TestCase):
    def test_count_matches_discovery(self):
        # Folder count and discovery agree, so neither can drift on its own.
        self.assertEqual(labs.lab_count(), len(catalog.discover(labs.ROOT)))

    def test_every_lab_folder_is_discovered(self):
        discovered = {Path(skill.lab_dir).name for skill in catalog.discover(labs.ROOT)}
        missing = [path.name for path in labs.lab_dirs() if path.name not in discovered]
        self.assertEqual(missing, [], "lab folders with a run_demo.py that discovery does not list")

    def test_guard_rejects_a_broken_count(self):
        with mock.patch.object(labs, "lab_dirs", return_value=[labs.ROOT] * (labs.MIN_LABS - 1)):
            with self.assertRaises(AssertionError):
                labs.lab_count()

    def test_guard_accepts_the_minimum(self):
        with mock.patch.object(labs, "lab_dirs", return_value=[labs.ROOT] * labs.MIN_LABS):
            self.assertEqual(labs.lab_count(), labs.MIN_LABS)


if __name__ == "__main__":
    unittest.main()
