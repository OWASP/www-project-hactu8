#!/usr/bin/env python3
"""Attack skill — plant one wrong figure at the head of a three-agent pipeline.

AUTHORIZED SECURITY-LAB USE ONLY. Targets this skill's own vulnerable_app.py.

Drops ``assets/price_notice.md`` into the target's intake inbox as supplier
``SUP-01`` through the unreviewed ``POST /intake/inbox``. The notice carries one
wrong figure: an agreed unit price for SUP-01 that does not match the
purchase-order ledger. Intake records it, and in vulnerable mode the analyst
and the approver both trust it, so every SUP-01 invoice in the batch is
affected. No invoice is touched directly and nothing runs at this point.

Exit code: 0 when the document was submitted, 1 when the target is unreachable.

Examples:
    python scripts/run_cascade.py
    python scripts/run_cascade.py --supplier SUP-01 --payload assets/price_notice.md
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TARGET = os.getenv("ASI08_TARGET", "http://127.0.0.1:5308")
DEFAULT_PAYLOAD = os.path.join(SKILL_DIR, "assets", "price_notice.md")


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
            ok = json.loads(resp.read()).get("demo") == "asi08"
    except (urllib.error.URLError, OSError, ValueError):
        ok = False
    if not ok:
        print(f"[-] {base} is not the ASI08 target. Start it: python vulnerable_app.py")
    return ok


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--supplier", default="SUP-01", help="supplier the document claims to be from")
    parser.add_argument("--payload", default=DEFAULT_PAYLOAD, help="document to submit")
    args = parser.parse_args(argv)

    if not check_target(args.target):
        return 1
    with open(args.payload, "r", encoding="utf-8") as fh:
        content = fh.read()

    print(f"[*] Submitting {os.path.basename(args.payload)} to the intake inbox as {args.supplier} "
          f"(unreviewed POST /intake/inbox)")
    result = _post(f"{args.target}/intake/inbox",
                   {"supplier": args.supplier, "title": "Price notice", "content": content})
    print(f"[+] Document {result['id']} saved. 1 document, 1 wrong figure; no invoice touched.")
    print("[*] Re-run scripts/evaluate_kpi.py to measure how far it propagates.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
