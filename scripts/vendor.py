#!/usr/bin/env python3
"""Copy the canonical shared files (hactu8/ modules, the lab web console) into every lab.

Labs stay self-contained (no imports from hactu8/), so each one carries its own
copy of the shared code. The canonical copies live in the core package:

    hactu8/providers.py   -> demos/_template/ and every lab that has providers.py
    hactu8/protectogw/    -> demos/_template/ and every lab that has protectogw/
    demos/_template/web/  -> every lab's web/ (the shared lab console)

A lab is a demos/<demo>/<lab>/ folder with a vulnerable_app.py or a web/ folder.
Every lab gets the whole template web/ file set, whatever files the template
holds; a lab with no web/ is reported unless it is listed in NO_CONSOLE. A file
in a lab's web/ that the template does not have is reported as an extra (the
console is identical in every lab) and is never deleted.

Edit the canonical copy, then run this script. ``--check`` changes nothing and
exits 1 if any lab copy has drifted, is missing, or has extras (the core tests
run it).

    python scripts/vendor.py [--check]
"""

from __future__ import annotations

import argparse
import filecmp
import shutil
import sys
from pathlib import Path
from typing import FrozenSet, List, Tuple

ROOT = Path(__file__).resolve().parents[1]
PROTECTOGW_FILES = ("__init__.py", "_limits.py", "indicators.py", "pinning.py", "screening.py", "session.py",
                    "README.md", "SECURITY.md", "CHANGELOG.md", "LICENSE")
# Labs (paths relative to the repo root, e.g. "demos/x-demo/x-skill") that
# intentionally ship without the lab console. Empty: every lab has one.
NO_CONSOLE: FrozenSet[str] = frozenset()
_SKIP_PARTS = {".venv", "node_modules", "__pycache__"}


def _skipped(path: Path) -> bool:
    return bool(_SKIP_PARTS.intersection(path.parts))


def template_web_files(root: Path = ROOT) -> List[str]:
    """Every file in the template console, as paths relative to web/."""
    web = root / "demos" / "_template" / "web"
    return sorted(p.relative_to(web).as_posix() for p in web.rglob("*") if p.is_file() and not _skipped(p))


def labs(root: Path = ROOT) -> List[Path]:
    """Every lab folder that should carry the console (NO_CONSOLE excluded)."""
    found = set()
    for lab in (root / "demos").glob("*/*"):
        if not lab.is_dir() or lab.parent.name == "_template" or _skipped(lab):
            continue
        if (lab / "vulnerable_app.py").is_file() or (lab / "web").is_dir():
            found.add(lab)
    return sorted(lab for lab in found if lab.relative_to(root).as_posix() not in NO_CONSOLE)


def pairs(root: Path = ROOT) -> List[Tuple[Path, Path]]:
    """(canonical, vendored copy) for every shared file."""
    core, demos = root / "hactu8", root / "demos"
    out: List[Tuple[Path, Path]] = []
    for copy in sorted(demos.glob("**/providers.py")):
        if not _skipped(copy):
            out.append((core / "providers.py", copy))
    for folder in sorted(demos.glob("**/protectogw")):
        if folder.is_dir() and not _skipped(folder):
            out += [(core / "protectogw" / name, folder / name) for name in PROTECTOGW_FILES]
    template = demos / "_template" / "web"
    names = template_web_files(root)
    for lab in labs(root):
        out += [(template / name, lab / "web" / name) for name in names]
    return out


def drift(root: Path = ROOT) -> List[Path]:
    """Vendored copies that are missing or differ from their canonical copy."""
    return [copy for src, copy in pairs(root) if not copy.exists() or not filecmp.cmp(src, copy, shallow=False)]


def extras(root: Path = ROOT) -> List[Path]:
    """Files in a lab's web/ that the template console does not have."""
    names = set(template_web_files(root))
    out: List[Path] = []
    for lab in labs(root):
        web = lab / "web"
        if web.is_dir():
            out += [p for p in sorted(web.rglob("*"))
                    if p.is_file() and not _skipped(p) and p.relative_to(web).as_posix() not in names]
    return out


def main(argv=None, root: Path = ROOT) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="report drift, change nothing")
    args = parser.parse_args(argv)
    all_pairs = pairs(root)
    stale = drift(root)
    extra = extras(root)
    for path in extra:
        print(f"extra (not in demos/_template/web, not removed): {path.relative_to(root)}")
    if args.check:
        for path in stale:
            print(f"{'drift' if path.exists() else 'missing'}: {path.relative_to(root)}")
        print(f"{len(all_pairs) - len(stale)}/{len(all_pairs)} vendored files match their canonical copy"
              + (f"; {len(extra)} extra files" if extra else ""))
        return 1 if stale or extra else 0
    for src, copy in all_pairs:
        if copy in stale:
            copy.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, copy)
            print(f"updated {copy.relative_to(root)}")
    print(f"{len(stale)} files updated")
    return 1 if extra else 0


if __name__ == "__main__":
    sys.exit(main())
