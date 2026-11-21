"""AG-71: the retired target name stays out of the repo, except in history notes.

The sacrificial target is HACTU8 Lamb. Its former name may appear only in:

- the one provenance-credit form, ``Ported from AgenticGoat (retired)`` (any
  case), which marks a line that records where code or a lab came from;
- path references to the historical records kept under their old names
  (``docs/agenticgoat-merge-plan.md`` and ``docs/evidence/agenticgoat/``);
- the files in ``ALLOWED_FILES`` below, each with its reason.

The test scans every tracked text file (``git ls-files``) and fails with the
file:line of each violation.
"""

from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

NAME = re.compile(r"agentic[\s_-]?goat", re.I)
CREDIT = re.compile(r"ported from agenticgoat \(retired\)", re.I)
HISTORY_PATHS = re.compile(r"(?:docs/)?agenticgoat-merge-plan(?:\.md)?|(?:docs/)?evidence/agenticgoat/?", re.I)

# Historical records, not scanned at all.
SKIP_PREFIXES = (
    "docs/evidence/agenticgoat/",     # evidence captured under the old name
    "docs/agenticgoat-merge-plan.md",  # the merge plan's own history
)

ALLOWED_FILES = {
    # This test names what it forbids.
    "tests/test_naming.py",
    # Project instructions, maintained by the owner; records the former name.
    "CLAUDE.md",
    # Design record of the original port, kept as written (it opens with a History note).
    "demos/OWASP_DEMO_PLAN.md",
    # Issue titles already published on GitHub; the script skips an issue whose
    # exact title exists, so renaming them would file duplicates on a re-run.
    "scripts/seed-issues.sh",
    # Legacy Registry IDs that migrateLegacyLambSeed must still recognise in
    # registries saved in browser storage.
    "spikes/iac-prototype/iac-host/src/data/lambSeed.ts",
}


def tracked_files():
    out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True).stdout
    return [p for p in out.decode("utf-8", "surrogateescape").split("\0") if p]


def violations():
    found = []
    for rel in tracked_files():
        if rel in ALLOWED_FILES or rel.startswith(SKIP_PREFIXES) or "node_modules/" in rel:
            continue
        path = ROOT / rel
        if not path.is_file():
            continue  # deleted in the working tree
        data = path.read_bytes()
        if b"\0" in data[:8192]:
            continue  # binary
        text = data.decode("utf-8", "replace")
        if not NAME.search(text):
            continue
        for number, line in enumerate(text.splitlines(), 1):
            rest = HISTORY_PATHS.sub("", CREDIT.sub("", line))
            match = NAME.search(rest)
            if match:
                found.append(f"{rel}:{number}: ...{rest[max(0, match.start() - 50):match.end() + 50].strip()}...")
    return found


class RetiredNameTest(unittest.TestCase):
    def setUp(self):
        try:
            tracked_files()
        except (OSError, subprocess.CalledProcessError):
            self.skipTest("not a git checkout")

    def test_no_retired_name_outside_history_notes(self):
        bad = violations()
        self.assertEqual(bad, [], "retired target name outside history notes (use 'HACTU8 Lamb', or the "
                         "credit form 'Ported from AgenticGoat (retired)' where history matters):\n"
                         + "\n".join(bad))

    def test_rule_both_directions(self):
        # The line rule must flag the name and pass the credit form and history paths.
        def flagged(line):
            return bool(NAME.search(HISTORY_PATHS.sub("", CREDIT.sub("", line))))
        for line in ("AgenticGoat's screening core", "agentic goat", "AGENTICGOAT", "agentic_goat", "agenticGoat"):
            self.assertTrue(flagged(line), line)
        for line in ("- Ported from AgenticGoat (retired): its AGX04 entry.",
                     "Source material, ported from AgenticGoat (retired): `acts.py`.",
                     "see `docs/agenticgoat-merge-plan.md` (AG-55 notes)",
                     "in `docs/evidence/agenticgoat/` and HACTU8 Lamb"):
            self.assertFalse(flagged(line), line)
        self.assertTrue(flagged("Ported from AgenticGoat (retired), unlike AgenticGoat's own probe"))


if __name__ == "__main__":
    unittest.main()
