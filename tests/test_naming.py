"""Retired names stay out of the repo, except in the history records.

The persona is Big Field Jumper Co., its assistant and target HACTU8 Lamb, its
operations lead Barb Fell, and the Wolf (``docs/persona.md``). These retired
names may appear only in:

- the history records: everything under ``docs/evidence/`` and
  ``docs/agenticgoat-merge-plan.md``;
- path references to those records (the merge plan and the
  ``docs/evidence/agenticgoat/`` folder keep their old file names);
- ``LEGACY_LINES`` below: lines that must keep a retired name to work.

Retired names: Billy (the old assistant, any case), Goat & Co. (the old
company, also "& Company", the "&" encoded as ``&amp;``, ``&#38;``, ``&#x26;``,
``\u0026`` or ``%26``, and wrapped across lines), goatco (its old domains and
ids, any case), its old product ids (goathttp / goat-http, Goat Tools /
GoatTools / goat-tools, goat-pdf, goat-shop), its old people (Goatsby,
Goatley) and AgenticGoat (the predecessor project). The test
scans every tracked text file (``git ls-files``) and fails with the file:line
of each violation.
"""

from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# "&" as written or encoded: &amp; &#38; &#x26; \u0026 %26.
_AMP = r"(?:&(?:amp;)?|&#0*38;|&#x0*26;|\\u0026|%26)"
_GAP = r"(?:\s|%20)*"
RETIRED = re.compile(r"billy|goat" + _GAP + _AMP + _GAP + r"co(?:mpany)?\b|goatco|agentic[\s_-]?goat"
                     r"|goat[\s_-]?(?:http|tools?|pdf|shop)\b|goatsby|goatley", re.I)
WRAPPED = re.compile(r"goat\s*" + _AMP + r"\s*$\s*co(?:mpany)?\b|goat\s*$\s*" + _AMP + r"\s*co(?:mpany)?\b",
                     re.I | re.M)
HISTORY_PATHS = re.compile(r"(?:docs/)?agenticgoat-merge-plan(?:\.md)?|(?:docs/)?evidence/agenticgoat/?", re.I)

# History records, not scanned.
HISTORY_PREFIXES = (
    "docs/evidence/",
    "docs/agenticgoat-merge-plan.md",
)

# This file names what it forbids.
SELF = "tests/test_naming.py"

# Lines that must keep a retired name to work, by file, each with its reason.
LEGACY_LINES = {
    # Legacy Registry IDs that migrateLegacyLambSeed must still recognise in
    # registries saved in browser storage.
    "spikes/iac-prototype/iac-host/src/data/lambSeed.ts": re.compile(r"^\s*'agenticgoat-[a-z-]+',$"),
}


def tracked_files():
    out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True).stdout
    return [p for p in out.decode("utf-8", "surrogateescape").split("\0") if p]


def line_violation(line: str):
    """The retired name on this line, after path references to the history records are removed."""
    return RETIRED.search(HISTORY_PATHS.sub("", line))


def text_violations(text: str, legacy=None):
    found = []
    for number, line in enumerate(text.splitlines(), 1):
        if legacy is not None and legacy.match(line):
            continue
        match = line_violation(line)
        if match:
            rest = HISTORY_PATHS.sub("", line)
            found.append(f"{number}: ...{rest[max(0, match.start() - 50):match.end() + 50].strip()}...")
    for match in WRAPPED.finditer(text):
        found.append(f"{text.count(chr(10), 0, match.start()) + 1}: ...{match.group(0)!r} (wrapped)...")
    return found


def violations():
    found = []
    for rel in tracked_files():
        if rel == SELF or rel.startswith(HISTORY_PREFIXES) or "node_modules/" in rel:
            continue
        path = ROOT / rel
        if not path.is_file():
            continue  # deleted in the working tree
        data = path.read_bytes()
        if b"\0" in data[:8192]:
            continue  # binary
        text = data.decode("utf-8", "replace")
        if not (RETIRED.search(text) or WRAPPED.search(text)):
            continue
        found.extend(f"{rel}:{v}" for v in text_violations(text, LEGACY_LINES.get(rel)))
    return found


class RetiredNameTest(unittest.TestCase):
    def setUp(self):
        try:
            tracked_files()
        except (OSError, subprocess.CalledProcessError):
            self.skipTest("not a git checkout")

    def test_no_retired_name_outside_history(self):
        bad = violations()
        self.assertEqual(bad, [], "retired name outside the history records (use Lamb, Big Field Jumper Co., "
                         "bigfield.example or Barb Fell; see docs/persona.md):\n" + "\n".join(bad))

    def test_rule_both_directions(self):
        for line in ("Billy, Goat & Co.'s ops assistant", "billy-stock", "BILLY_NAME", "\\nBilly:",
                     "Goat & Co.", "Goat &amp; Co. newsletter", "the goat & co\\. vpn client",
                     "billy@goatco.example", "docs.goatco.invalid", "GOATCO_REGION",
                     "AgenticGoat's screening core", "agentic goat", "AGENTICGOAT", "agentic_goat",
                     "Ported from AgenticGoat (retired)",
                     "see docs/agenticgoat-merge-plan.md, unlike AgenticGoat's own probe",
                     "pip install goathttp", "goat-http", "goat_http", "the official Goat Tools server",
                     "GoatTools", "goat-tools", "goat-pdf", "goat-shop", "Goatsby", "Goatley",
                     "Goat &#38; Co.", "Goat &#x26; Co.", "Goat \\u0026 Co.", "Goat%20%26%20Co",
                     "Goat & Company", "Goat&Co"):
            self.assertTrue(text_violations(line), line)
        for text in ("**Lamb, Big Field Jumper Co.**\nCo-Authored-By", "Lamb, Big Field Jumper Co.'s ops assistant",
                     "lamb@bigfield.example", "Barb Fell", "OWASP WebGoat-style lab", "goat mix",
                     "hx11:clean-goat-mix", "a goat\nand a cow", "goat\n\ncoat",
                     "see `docs/agenticgoat-merge-plan.md` (AG-55 notes)",
                     "in `docs/evidence/agenticgoat/` and HACTU8 Lamb",
                     "goat's milk & cheese", "goat and cow", "a goat tooling shed", "goatskin",
                     "the goat shopkeeper", "a goat & a cow", "goat, http server"):
            self.assertFalse(text_violations(text), text)
        for text in ("the **Goat &\nCo.** shop", "Goat\n& Co. assistant", "Goat &amp;\n  Co.",
                     "Goat &#38;\nCompany"):
            self.assertTrue(text_violations(text), text)

    def test_legacy_lines_are_narrow(self):
        legacy = LEGACY_LINES["spikes/iac-prototype/iac-host/src/data/lambSeed.ts"]
        self.assertFalse(text_violations("  'agenticgoat-target',", legacy))
        self.assertTrue(text_violations("  name: 'AgenticGoat Target',", legacy))
        self.assertTrue(text_violations("  'agenticgoat-target', // Billy", legacy))


if __name__ == "__main__":
    unittest.main()
