#!/usr/bin/env python3
"""Attack skill — a cross-resource chain through unauthenticated publishing.

AUTHORIZED SECURITY-LAB USE ONLY. Targets this skill's own vulnerable_app.py.

Publishes two documents through ``POST /kb/publish``:

* ``assets/chain_doc_a.txt`` replaces ``kb://travel-policy``. It reads like the
  approved policy, adds a read-directive to ``kb://travel-reimbursement``, and
  ends with the first half of the lab marker.
* ``assets/chain_doc_b.txt`` becomes ``kb://travel-reimbursement``. It starts
  with the second half of the marker and carries the credential request.

Each document passes a stateless screen alone. Billy's loader follows the
directive and concatenates both, so in vulnerable mode the assembled directive
reaches the model.

Exit code: 0 when both documents were published, 1 when the target is unreachable.

Examples:
    python scripts/run_chain_attack.py
"""

from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.request

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TARGET = os.getenv("AGX08_TARGET", "http://127.0.0.1:5408")
DOC_A = os.path.join(SKILL_DIR, "assets", "chain_doc_a.txt")
DOC_B = os.path.join(SKILL_DIR, "assets", "chain_doc_b.txt")


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
            ok = json.loads(resp.read()).get("demo") == "agx08"
    except (urllib.error.URLError, OSError, ValueError):
        ok = False
    if not ok:
        print(f"[-] {base} is not the AGX08 target. Start it: python vulnerable_app.py")
    return ok


def _read(path: str) -> str:
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read().rstrip("\n")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--doc-a", default=DOC_A, help="text for kb://travel-policy")
    parser.add_argument("--doc-b", default=DOC_B, help="text for kb://travel-reimbursement")
    args = parser.parse_args(argv)

    if not check_target(args.target):
        return 1
    for uri, path in (("kb://travel-policy", args.doc_a), ("kb://travel-reimbursement", args.doc_b)):
        print(f"[*] Publishing {os.path.basename(path)} as {uri} (unauthenticated POST /kb/publish)")
        result = _post(f"{args.target}/kb/publish", {"uri": uri, "text": _read(path)})
        print(f"[+] Published {result['uri']}.")
    print("[*] Each document is clean alone. Re-run scripts/evaluate_kpi.py to measure the chain.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
