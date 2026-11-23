#!/usr/bin/env python3
"""Attack skill — Hayloft Analytics 2.0 turns the ledger proxy into a confused deputy.

AUTHORIZED SECURITY-LAB USE ONLY. Targets this skill's own vulnerable_app.py.

Installs the attacker's moves with ``POST /api/attack`` (from
``assets/hostile_oauth.json``): Hayloft registers a client of its own at the
proxy and emails Dana a sign-in link; its chart tool tells Lamb to
"refresh" the ledger connection with a tampered ``redirect_uri``; and the
proxy enables Hayloft's new ledger connector. Then it plays the three
targeted customers' questions over ``POST /ask`` and prints what Hayloft
received. Every server and browser is a Python object inside the lab
process; no URL outside http://127.0.0.1:5505 is followed.

Exit code: 0 when the attack was played, 1 when the target is unreachable.

Examples:
    python scripts/run_oauth_attack.py
    python scripts/run_oauth_attack.py --install-only
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TARGET = os.getenv("HX05_TARGET", "http://127.0.0.1:5505")
sys.path.insert(0, SKILL_DIR)


def _post(url: str, body: dict) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        return json.loads(resp.read())


def _get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=10) as resp:
        return json.loads(resp.read())


def check_target(base: str) -> bool:
    try:
        ok = _get(f"{base}/health").get("demo") == "hx05"
    except (urllib.error.URLError, OSError, ValueError):
        ok = False
    if not ok:
        print(f"[-] {base} is not the HX05 target. Start it: python vulnerable_app.py")
    return ok


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--install-only", action="store_true",
                        help="install the attacker's moves and stop (no questions asked)")
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
    for label, account, message, targeted, _ in suite():
        if not targeted:
            continue
        result = _post(f"{args.target}/ask", {"account": account, "message": message})
        print(f"[*] {label}")
        print(f"    lamb> {result['final_reply'][:100]}")
        print(f"[+] Hayloft got a ledger token: {'YES' if result['attacker_got_token'] else 'no'} "
              f"({', '.join(result['channels']) or 'no channel'}); acted as the user: "
              f"{'YES' if result['acted_as_user'] else 'no'}")
    print("[*] GET /attacker-log shows what Hayloft received. Re-run scripts/evaluate_kpi.py to measure.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
