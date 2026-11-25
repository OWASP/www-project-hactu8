"""How many labs the repo holds, counted from the lab folders on disk.

Tests compare discovery, the learning path, the API, Lamb and the MCP server with this
count instead of a hard-coded number, so adding a lab needs no test edits. The count
comes from the folders (``demos/*/run_demo.py``), not from ``catalog.discover()``, so a
lab that exists on disk but stops being discovered still fails the tests.
"""

from __future__ import annotations

from pathlib import Path
from typing import List

ROOT = Path(__file__).resolve().parents[1]

# The OWASP Top 10 for LLM Applications and for Agentic Applications alone are 20 labs.
# Fewer than that means the count itself is broken (a moved folder, a bad glob), and
# every "N == N" comparison would pass for the wrong reason.
MIN_LABS = 20


def lab_dirs() -> List[Path]:
    """Every lab folder: a folder under demos/ with a run_demo.py."""
    return sorted(path.parent for path in (ROOT / "demos").glob("*/run_demo.py"))


def lab_count() -> int:
    count = len(lab_dirs())
    if count < MIN_LABS:
        raise AssertionError(f"only {count} lab folders under demos/ (expected at least {MIN_LABS}); "
                             "the lab count itself looks broken")
    return count
