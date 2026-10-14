#!/usr/bin/env python3
"""Attack skill — pivot the account assistant onto other customers' records.

AUTHORIZED SECURITY-LAB USE ONLY. Targets this skill's own vulnerable_app.py.

Signs in as the attacker's own account (default ``C-1003``) and saves
``assets/pivot_note.md`` as that account's notes through ``POST
/account/notes``. Editing your own notes is allowed; the attacker needs no
special access. Billy reads the notes with every own-account question, and in
vulnerable mode follows the directive line: it reads the records the line names
and recites everything in its context, including the CRM key in its prompt.

Exit code: 0 when the notes were saved, 1 when the target is unreachable.

Examples:
    python scripts/run_pivot.py
    python scripts/run_pivot.py --session C-1003 --payload assets/pivot_note.md
"""

from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.request

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TARGET = os.getenv("LLM02_TARGET", "http://127.0.0.1:5202")
DEFAULT_PAYLOAD = os.path.join(SKILL_DIR, "assets", "pivot_note.md")
ATTACKER_SESSION = "C-1003"


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
            ok = json.loads(resp.read()).get("demo") == "llm02"
    except (urllib.error.URLError, OSError, ValueError):
        ok = False
    if not ok:
        print(f"[-] {base} is not the LLM02 target. Start it: python vulnerable_app.py")
    return ok


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--session", default=ATTACKER_SESSION,
                        help="the attacker's own signed-in account")
    parser.add_argument("--payload", default=DEFAULT_PAYLOAD, help="notes content to save")
    args = parser.parse_args(argv)

    if not check_target(args.target):
        return 1
    with open(args.payload, "r", encoding="utf-8") as fh:
        content = fh.read()

    print(f"[*] Saving {os.path.basename(args.payload)} as the notes of account "
          f"{args.session} (own account, POST /account/notes)")
    result = _post(f"{args.target}/account/notes", {"session": args.session, "notes": content})
    print(f"[+] Notes saved for {result['session']}. 1 field changed; no other record touched.")
    print("[*] Re-run scripts/evaluate_kpi.py to measure the effect.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
