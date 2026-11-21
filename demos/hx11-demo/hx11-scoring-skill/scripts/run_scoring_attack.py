#!/usr/bin/env python3
"""Attack skill — Hayloft Feeds attacks the review triage's scorers, not Billy.

AUTHORIZED SECURITY-LAB USE ONLY. Targets this skill's own vulnerable_app.py.

Installs the attacker's transcripts with ``POST /api/attack`` (from
``assets/hostile_transcripts.json``): a line addressed to the judge, a forged
verdict object, a format-confused verdict, the desk code spaced out past the
rule classifier, and twelve benign questions that trip the classifier and
flood the review queue before a fifth transcript. Then it runs one triage
batch over ``POST /triage`` and prints what reached the public feed. The feed
is an in-memory list inside the lab; nothing leaves the process.

Exit code: 0 when the attack was played, 1 when the target is unreachable.

Examples:
    python scripts/run_scoring_attack.py
    python scripts/run_scoring_attack.py --install-only
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TARGET = os.getenv("HX11_TARGET", "http://127.0.0.1:5511")
sys.path.insert(0, SKILL_DIR)


def _post(url: str, body: dict) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=300) as resp:
        return json.loads(resp.read())


def _get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=10) as resp:
        return json.loads(resp.read())


def check_target(base: str) -> bool:
    try:
        ok = _get(f"{base}/health").get("demo") == "hx11"
    except (urllib.error.URLError, OSError, ValueError):
        ok = False
    if not ok:
        print(f"[-] {base} is not the HX11 target. Start it: python vulnerable_app.py")
    return ok


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--install-only", action="store_true",
                        help="install the attacker's transcripts and stop (no triage run)")
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if not check_target(args.target):
        return 1
    for event in _post(f"{args.target}/api/attack", {})["events"]:
        print(f"[+] {event}")
    if args.install_only:
        return 0
    from evaluate_kpi import suite
    result = _post(f"{args.target}/triage", {})
    for label, tid, targeted, _ in suite():
        if not targeted:
            continue
        item = result["items"][tid]
        scores = "; ".join(f"{s['scorer']} {s['verdict']}" for s in item["scores"])
        print(f"[*] {label}")
        print(f"    scored: {scores} -> {item['outcome']}")
        print(f"[+] desk code on the public feed: {'YES' if item['shipped_leak'] else 'no'}")
    q = result["queue"]
    print(f"[+] Review queue: {q['flagged']} flagged, {q['reviewed']} reviewed, {q['released']} released "
          f"unreviewed, {q['held']} held.")
    print("[*] GET /feed shows the public feed. Re-run scripts/evaluate_kpi.py to measure.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
