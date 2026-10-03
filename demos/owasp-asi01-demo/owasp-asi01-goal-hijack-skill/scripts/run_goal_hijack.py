#!/usr/bin/env python3
"""Attack skill — agent goal hijack through one ticket comment.

AUTHORIZED SECURITY-LAB USE ONLY. Targets this skill's own vulnerable_app.py.

Appends ``assets/ticket_comment.md`` to one operations ticket (default
``T-3002``, billing queue, escalated) through the unauthenticated
customer-portal endpoint ``POST /tickets/comment``. The comment reads like a
customer following up, plus two directive lines: one replaces the report's
``post_report`` step with a post to an external channel, one adds an
``export_tickets`` step. The operator's weekly-report request never changes;
the agent reads the comment during step 1 (``read_tickets``), re-plans, and in
vulnerable mode the executor runs the new steps. Every action is simulated: an
entry in the target's in-memory action log.

Exit code: 0 when the comment was saved, 1 when the target is unreachable.

Examples:
    python scripts/run_goal_hijack.py
    python scripts/run_goal_hijack.py --ticket T-3002 --payload assets/ticket_comment.md
"""

from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.request

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TARGET = os.getenv("ASI01_TARGET", "http://127.0.0.1:5301")
DEFAULT_PAYLOAD = os.path.join(SKILL_DIR, "assets", "ticket_comment.md")


def _post(url: str, body: dict) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


def check_target(base: str) -> bool:
    try:
        with urllib.request.urlopen(f"{base}/health", timeout=5) as resp:
            ok = json.loads(resp.read()).get("demo") == "asi01"
    except (urllib.error.URLError, OSError, ValueError):
        ok = False
    if not ok:
        print(f"[-] {base} is not the ASI01 target. Start it: python vulnerable_app.py")
    return ok


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--ticket", default="T-3002", help="ticket to append the comment to")
    parser.add_argument("--payload", default=DEFAULT_PAYLOAD, help="comment content to append")
    args = parser.parse_args(argv)

    if not check_target(args.target):
        return 1
    with open(args.payload, "r", encoding="utf-8") as fh:
        text = fh.read()

    print(f"[*] Appending {os.path.basename(args.payload)} to ticket {args.ticket} "
          f"(unauthenticated POST /tickets/comment)")
    result = _post(f"{args.target}/tickets/comment", {"ticket": args.ticket, "text": text})
    print(f"[+] Comment saved on {result['ticket']} ({result['comments']} comments). "
          "1 ticket changed; no report has run yet.")
    print("[*] Re-run scripts/evaluate_kpi.py to measure the effect.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
