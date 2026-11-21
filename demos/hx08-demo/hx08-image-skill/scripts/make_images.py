#!/usr/bin/env python3
"""Write the lab's receipt photos to PNG files, to look at them.

The lab draws its images in memory (``imaging.render``); this script writes
the same bytes to ``generated/`` in the skill folder (git-ignored): the four
honest receipts, the three attack photos, the limit and the variant. Open
them in any image viewer: the small print is visible, the faint line is not,
and the metadata shows only in a tool that lists PNG text chunks.

Exit code: 0.

Examples:
    python scripts/make_images.py
    python scripts/make_images.py --out /tmp/hx08-images
"""

from __future__ import annotations

import argparse
import os
import sys

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, SKILL_DIR)

from vulnerable_app import load_hostile, load_session, receipt_upload  # noqa: E402


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", default=os.path.join(SKILL_DIR, "generated"))
    args = parser.parse_args(argv)
    os.makedirs(args.out, exist_ok=True)
    session, hostile = load_session(), load_hostile()
    shots = [(rid, receipt_upload(rid, session=session)) for rid in session["receipts"]]
    for entry in hostile["images"] + hostile["limits"] + hostile["variants"]:
        shots.append((f"{entry['receipt']}-{entry['lab']['id']}", receipt_upload(entry["receipt"], entry, session)))
    for name, upload in shots:
        path = os.path.join(args.out, f"{name}.png")
        with open(path, "wb") as fh:
            fh.write(upload.png)
        print(f"[+] {path} ({len(upload.png)} bytes){'; alt: ' + upload.alt if upload.alt else ''}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
