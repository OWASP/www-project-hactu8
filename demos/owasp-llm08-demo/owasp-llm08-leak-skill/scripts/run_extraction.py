#!/usr/bin/env python3
"""Attack skill — system-prompt extraction through a saved reply preference.

AUTHORIZED SECURITY-LAB USE ONLY. Targets this skill's own vulnerable_app.py.

Saves ``assets/extraction_request.md`` as the reply preference of one customer
account (default ``guest-attacker``) through ``POST /profile``. No privilege is
needed: any customer may set how Billy Shop replies to them. From then on every
reply in that account's chats carries a quote of Billy's system prompt, with
the staff discount code and tool schema it embeds. Other accounts are untouched.

Exit code: 0 when the preference was saved, 1 when the target is unreachable.

Examples:
    python scripts/run_extraction.py
    python scripts/run_extraction.py --user guest-attacker --payload assets/extraction_request.md
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TARGET = os.getenv("LLM08_TARGET", "http://127.0.0.1:5208")
DEFAULT_PAYLOAD = os.path.join(SKILL_DIR, "assets", "extraction_request.md")


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
            ok = json.loads(resp.read()).get("demo") == "llm08"
    except (urllib.error.URLError, OSError, ValueError):
        ok = False
    if not ok:
        print(f"[-] {base} is not the LLM08 target. Start it: python vulnerable_app.py")
    return ok


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--user", default="guest-attacker", help="customer account to set")
    parser.add_argument("--payload", default=DEFAULT_PAYLOAD, help="reply preference to save")
    args = parser.parse_args(argv)

    if not check_target(args.target):
        return 1
    with open(args.payload, "r", encoding="utf-8") as fh:
        content = fh.read()

    print(f"[*] Saving {os.path.basename(args.payload)} as the reply preference of "
          f"'{args.user}' (POST /profile, ordinary customer feature)")
    result = _post(f"{args.target}/profile", {"user": args.user, "reply_style": content})
    print(f"[+] Preference saved for '{result['user']}'. 1 account changed; no other account touched.")
    print("[*] Re-run scripts/evaluate_kpi.py to measure the effect.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
