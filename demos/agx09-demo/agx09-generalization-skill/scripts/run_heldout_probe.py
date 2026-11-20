#!/usr/bin/env python3
"""Attack skill — deliver the held-out set to Billy's partner inbox.

AUTHORIZED SECURITY-LAB USE ONLY. Targets this skill's own vulnerable_app.py.

Reads ``assets/heldout_set.json``, renders each encoded item from the
canonical line, and delivers every attack to its inbox slot through the
unauthenticated ``POST /inbox/deliver``. The benign controls stay as they
are. The screen was never tuned on these notes: some will be caught, some
will not, and that split is the measurement.

Exit code: 0 when the notes were delivered, 1 when the target is unreachable.

Examples:
    python scripts/run_heldout_probe.py
    python scripts/run_heldout_probe.py --only spanish
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TARGET = os.getenv("AGX09_TARGET", "http://127.0.0.1:5409")
DEFAULT_SET = os.path.join(SKILL_DIR, "assets", "heldout_set.json")


def _post(url: str, body: dict) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def check_target(base: str) -> bool:
    try:
        with urllib.request.urlopen(f"{base}/health", timeout=5) as resp:
            ok = json.loads(resp.read()).get("demo") == "agx09"
    except (urllib.error.URLError, OSError, ValueError):
        ok = False
    if not ok:
        print(f"[-] {base} is not the AGX09 target. Start it: python vulnerable_app.py")
    return ok


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--set", default=DEFAULT_SET, help="held-out set (JSON)")
    parser.add_argument("--only", action="append", metavar="ID", help="deliver only these ids")
    args = parser.parse_args(argv)

    if not check_target(args.target):
        return 1
    sys.path.insert(0, SKILL_DIR)
    from vulnerable_app import load_set

    items = [i for i in load_set(args.set) if i["attack"] and (not args.only or i["id"] in args.only)]
    print(f"[*] Delivering {len(items)} held-out notes (unauthenticated POST /inbox/deliver)")
    for item in items:
        _post(f"{args.target}/inbox/deliver", {"id": item["id"], "text": item["text"]})
        print(f"[+] {item['id']:<18} [{item['technique']}]")
    print("[*] Re-run scripts/evaluate_kpi.py to measure the effect; --scan for the catch rate.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
