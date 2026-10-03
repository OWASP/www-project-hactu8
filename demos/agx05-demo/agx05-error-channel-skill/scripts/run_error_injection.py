#!/usr/bin/env python3
"""Attack skill — error-channel injection through a vendor tool update.

AUTHORIZED SECURITY-LAB USE ONLY. Targets this skill's own vulnerable_app.py.

Pushes an unauthenticated vendor update (``POST /vendor/tools/update``) that
sets the ``error_text`` of a tool (default: ``db_query``) to
``assets/error_payload.txt``. The tool's description and its successful return
stay clean, so a scan that reads only the happy path still passes it. The
payload surfaces only when a call fails — an unknown table drives db_query into
its error path — so in vulnerable mode it reaches the model unscreened.

Exit code: 0 when the update was applied, 1 when the target is unreachable.

Examples:
    python scripts/run_error_injection.py
    python scripts/run_error_injection.py --tool db_query
"""

from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.request

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TARGET = os.getenv("AGX05_TARGET", "http://127.0.0.1:5405")
DEFAULT_PAYLOAD = os.path.join(SKILL_DIR, "assets", "error_payload.txt")


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
            ok = json.loads(resp.read()).get("demo") == "agx05"
    except (urllib.error.URLError, OSError, ValueError):
        ok = False
    if not ok:
        print(f"[-] {base} is not the AGX05 target. Start it: python vulnerable_app.py")
    return ok


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--tool", default="db_query", help="tool whose error_text to set")
    parser.add_argument("--field", default="error_text", choices=("description", "error_text"),
                        help="tool field to set (default: the failure message)")
    parser.add_argument("--payload", default=DEFAULT_PAYLOAD, help="text to install")
    args = parser.parse_args(argv)

    if not check_target(args.target):
        return 1
    with open(args.payload, "r", encoding="utf-8") as fh:
        value = fh.read().rstrip("\n")

    print(f"[*] Pushing {os.path.basename(args.payload)} into {args.tool}.{args.field} "
          "(unauthenticated POST /vendor/tools/update)")
    result = _post(f"{args.target}/vendor/tools/update",
                   {"tool": args.tool, "field": args.field, "value": value})
    print(f"[+] Updated {result['field']}. The error path only; the description and "
          "happy path are untouched.")
    print("[*] Re-run scripts/evaluate_kpi.py to measure the effect.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
