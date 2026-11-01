#!/usr/bin/env python3
"""Copy the canonical shared modules from hactu8/ into every lab.

Labs stay self-contained (no imports from hactu8/), so each one carries its own
copy of the shared code. The canonical copies live in the core package:

    hactu8/providers.py   -> demos/_template/ and every lab that has providers.py
    hactu8/protectogw/    -> demos/_template/ and every lab that has protectogw/

Edit the canonical copy, then run this script. ``--check`` changes nothing and
exits 1 if any lab copy has drifted (the core tests run it).

    python scripts/vendor.py [--check]
"""

from __future__ import annotations

import argparse
import filecmp
import shutil
import sys
from pathlib import Path
from typing import List, Tuple

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "hactu8"
DEMOS = ROOT / "demos"
PROTECTOGW_FILES = ("__init__.py", "_limits.py", "indicators.py", "screening.py", "session.py",
                    "README.md", "SECURITY.md", "CHANGELOG.md")


def pairs() -> List[Tuple[Path, Path]]:
    """(canonical, vendored copy) for every shared file."""
    out: List[Tuple[Path, Path]] = []
    for copy in sorted(DEMOS.glob("**/providers.py")):
        if ".venv" not in copy.parts and "node_modules" not in copy.parts:
            out.append((CORE / "providers.py", copy))
    for folder in sorted(DEMOS.glob("**/protectogw")):
        if folder.is_dir() and ".venv" not in folder.parts:
            out += [(CORE / "protectogw" / name, folder / name) for name in PROTECTOGW_FILES]
    return out


def drift() -> List[Path]:
    return [copy for src, copy in pairs() if not copy.exists() or not filecmp.cmp(src, copy, shallow=False)]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="report drift, change nothing")
    args = parser.parse_args(argv)
    stale = drift()
    if args.check:
        for path in stale:
            print(f"drift: {path.relative_to(ROOT)}")
        print(f"{len(pairs()) - len(stale)}/{len(pairs())} vendored files match hactu8/")
        return 1 if stale else 0
    for src, copy in pairs():
        if copy in stale:
            shutil.copyfile(src, copy)
            print(f"updated {copy.relative_to(ROOT)}")
    print(f"{len(stale)} files updated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
