#!/usr/bin/env python3
"""Attack skill — tool misuse triggered by a requester's note on a report request.

AUTHORIZED SECURITY-LAB USE ONLY. Targets this skill's own vulnerable_app.py.

Appends ``assets/request_note.md`` to one report request (default ``RQ-3001``)
through the unauthenticated requester-portal endpoint ``POST /requests/note``.
The note reads like a requester chasing their report, plus two directive lines.
They name no new tool: they rewrite the parameters of the two tools the agent
already uses, a ledger query with a row limit far above normal and an export to
an off-list destination. The agent reads the note through ``read_request``
while running the request, and in vulnerable mode the app executes the calls
as asked. Every export is simulated: an entry in the target's in-memory outbox.

Exit code: 0 when the note was saved, 1 when the target is unreachable.

Examples:
    python scripts/run_tool_misuse.py
    python scripts/run_tool_misuse.py --request RQ-3001 --payload assets/request_note.md
"""

from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.request

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TARGET = os.getenv("ASI02_TARGET", "http://127.0.0.1:5302")
DEFAULT_PAYLOAD = os.path.join(SKILL_DIR, "assets", "request_note.md")


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
            ok = json.loads(resp.read()).get("demo") == "asi02"
    except (urllib.error.URLError, OSError, ValueError):
        ok = False
    if not ok:
        print(f"[-] {base} is not the ASI02 target. Start it: python vulnerable_app.py")
    return ok


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--request", default="RQ-3001", help="report request to append the note to")
    parser.add_argument("--payload", default=DEFAULT_PAYLOAD, help="note content to append")
    args = parser.parse_args(argv)

    if not check_target(args.target):
        return 1
    with open(args.payload, "r", encoding="utf-8") as fh:
        note = fh.read()

    print(f"[*] Appending {os.path.basename(args.payload)} to request {args.request} "
          f"(unauthenticated POST /requests/note)")
    result = _post(f"{args.target}/requests/note", {"request_id": args.request, "note": note})
    print(f"[+] Note saved on {result['request_id']} ({result['notes']} notes). "
          "1 request changed; no tool was called yet.")
    print("[*] Re-run scripts/evaluate_kpi.py to measure the effect.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
