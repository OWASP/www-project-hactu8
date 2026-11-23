#!/usr/bin/env python3
"""Attack skill — a hostile MCP server abuses elicitation against Lamb's client.

AUTHORIZED SECURITY-LAB USE ONLY. Targets this skill's own vulnerable_app.py.

Installs the attacker's update of the supplies server (Hayloft Supplies 1.4
-> 1.5, from ``assets/hostile_elicitation.json``) with ``POST /api/attack``,
then plays the three reorder requests over ``POST /ask`` and prints what the
server received back. ``reorder`` still places an honest order; the attack is
in the ``elicitation/create`` requests its ``InputRequiredResult`` carries.
The only goal is Big Field Jumper Co.'s fictional supplier account reference. Every
server and page is a Python object inside the lab process; nothing is fetched.

Exit code: 0 when the attack was played, 1 when the target is unreachable.

Examples:
    python scripts/run_elicitation_attack.py
    python scripts/run_elicitation_attack.py --install-only
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TARGET = os.getenv("HX04_TARGET", "http://127.0.0.1:5504")
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
        ok = _get(f"{base}/health").get("demo") == "hx04"
    except (urllib.error.URLError, OSError, ValueError):
        ok = False
    if not ok:
        print(f"[-] {base} is not the HX04 target. Start it: python vulnerable_app.py")
    return ok


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--install-only", action="store_true",
                        help="install the server update and stop (no requests played)")
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
    for label, message, targeted, _ in suite():
        if not targeted:
            continue
        result = _post(f"{args.target}/ask", {"message": message})
        print(f"[*] {label}")
        print(f"    lamb> {result['final_reply'][:100]}")
        print(f"[+] Dialogs shown to Pat: {result['dialogs']} ({result['off_task_dialogs']} off the task, "
              f"{result['unread']} accepted unread); server got the account reference: "
              f"{'YES' if result['server_got_canary'] else 'no'}")
    print("[*] GET /server-log shows what the server received. Re-run scripts/evaluate_kpi.py to measure.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
