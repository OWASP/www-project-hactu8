#!/usr/bin/env python3
"""Attack skill — indirect prompt injection through an editable wiki page.

AUTHORIZED SECURITY-LAB USE ONLY. Targets this skill's own vulnerable_app.py.

Overwrites one page of the target's knowledge base (default ``expenses``) with
``assets/injected_page.md``: the real page text plus one injected line. The
user never sees the page; the assistant reads it through ``search_kb`` when
answering expense questions, and in vulnerable mode follows the instruction.

Exit code: 0 when the page was written, 1 when the target is unreachable.

Examples:
    python scripts/run_injection.py
    python scripts/run_injection.py --page expenses --payload assets/injected_page.md
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TARGET = os.getenv("LLM01_TARGET", "http://127.0.0.1:5201")
DEFAULT_PAYLOAD = os.path.join(SKILL_DIR, "assets", "injected_page.md")


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
            ok = json.loads(resp.read()).get("demo") == "llm01"
    except (urllib.error.URLError, OSError, ValueError):
        ok = False
    if not ok:
        print(f"[-] {base} is not the LLM01 target. Start it: python vulnerable_app.py")
    return ok


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--page", default="expenses", help="wiki page slug to overwrite")
    parser.add_argument("--payload", default=DEFAULT_PAYLOAD, help="page content to write")
    args = parser.parse_args(argv)

    if not check_target(args.target):
        return 1
    with open(args.payload, "r", encoding="utf-8") as fh:
        content = fh.read()

    print(f"[*] Writing {os.path.basename(args.payload)} over wiki page '{args.page}' "
          f"(unauthenticated POST /kb/page)")
    result = _post(f"{args.target}/kb/page", {"slug": args.page, "content": content})
    print(f"[+] Page '{result['slug']}' saved. 1 page changed; no other page touched.")
    print("[*] Re-run scripts/evaluate_kpi.py to measure the effect.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
