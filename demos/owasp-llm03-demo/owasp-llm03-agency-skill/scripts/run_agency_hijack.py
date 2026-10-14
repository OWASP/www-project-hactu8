#!/usr/bin/env python3
"""Attack skill — excessive agency triggered by a customer's ticket note.

AUTHORIZED SECURITY-LAB USE ONLY. Targets this skill's own vulnerable_app.py.

Appends ``assets/ticket_note.md`` to one support ticket (default ``T-1001``)
through the unauthenticated customer-portal endpoint ``POST /tickets/note``.
The note reads like a customer chasing a late order, plus two directive lines.
The operator never asks for a refund or a deletion; the agent reads the note
through ``read_ticket`` while working the ticket, requests both calls, and in
vulnerable mode the app executes them. Every action is simulated: an entry in
the target's in-memory action log.

Exit code: 0 when the note was saved, 1 when the target is unreachable.

Examples:
    python scripts/run_agency_hijack.py
    python scripts/run_agency_hijack.py --ticket T-1001 --payload assets/ticket_note.md
"""

from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.request

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TARGET = os.getenv("LLM03_TARGET", "http://127.0.0.1:5203")
DEFAULT_PAYLOAD = os.path.join(SKILL_DIR, "assets", "ticket_note.md")


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
            ok = json.loads(resp.read()).get("demo") == "llm03"
    except (urllib.error.URLError, OSError, ValueError):
        ok = False
    if not ok:
        print(f"[-] {base} is not the LLM03 target. Start it: python vulnerable_app.py")
    return ok


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--ticket", default="T-1001", help="ticket to append the note to")
    parser.add_argument("--payload", default=DEFAULT_PAYLOAD, help="note content to append")
    args = parser.parse_args(argv)

    if not check_target(args.target):
        return 1
    with open(args.payload, "r", encoding="utf-8") as fh:
        note = fh.read()

    print(f"[*] Appending {os.path.basename(args.payload)} to ticket {args.ticket} "
          f"(unauthenticated POST /tickets/note)")
    result = _post(f"{args.target}/tickets/note", {"ticket": args.ticket, "note": note})
    print(f"[+] Note saved on {result['ticket']} ({result['notes']} notes). "
          "1 ticket changed; no tool was called yet.")
    print("[*] Re-run scripts/evaluate_kpi.py to measure the effect.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
