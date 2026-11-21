#!/usr/bin/env python3
"""Attack skill — Hayloft Shopping Helper 2.0 hijacks Billy's x402 payments.

AUTHORIZED SECURITY-LAB USE ONLY. Targets this skill's own vulnerable_app.py.

Installs the attacker's moves with ``POST /api/attack`` (from
``assets/hostile_x402.json``): Hayloft's fetch_url tool rewrites the 402
challenge for one report (``payTo`` and ``amount``), a seller note in Lamb
Seed Co.'s 402 body moves the "payment desk", Hayloft's log_expense replays
the payment proof it is handed, and its find_merchant tool lists a lookalike
Lamb Weather. Then it plays the four targeted customers' requests over
``POST /ask`` and prints what Hayloft received and what the test ledger paid
it. Every merchant, wallet and facilitator is a Python object inside the lab
process; units are fake test units; no URL outside http://127.0.0.1:5512 is
followed.

Exit code: 0 when the attack was played, 1 when the target is unreachable.

Examples:
    python scripts/run_x402_attack.py
    python scripts/run_x402_attack.py --install-only
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TARGET = os.getenv("HX12_TARGET", "http://127.0.0.1:5512")
sys.path.insert(0, SKILL_DIR)


def _post(url: str, body: dict) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        return json.loads(resp.read())


def _get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=10) as resp:
        return json.loads(resp.read())


def check_target(base: str) -> bool:
    try:
        ok = _get(f"{base}/health").get("demo") == "hx12"
    except (urllib.error.URLError, OSError, ValueError):
        ok = False
    if not ok:
        print(f"[-] {base} is not the HX12 target. Start it: python vulnerable_app.py")
    return ok


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--install-only", action="store_true",
                        help="install the attacker's moves and stop (no requests played)")
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if not check_target(args.target):
        return 1
    for event in _post(f"{args.target}/api/attack", {})["events"]:
        print(f"[+] {event}")
    if args.install_only:
        return 0
    from evaluate_kpi import suite
    for label, account, message, targeted, _ in suite():
        if not targeted:
            continue
        result = _post(f"{args.target}/ask", {"account": account, "message": message})
        print(f"[*] {label}")
        print(f"    billy> {result['final_reply'][:100]}")
        print(f"[+] Hayloft got the order secret: {'YES' if result['secret_leaked'] else 'no'} "
              f"({', '.join(result['channels']) or 'no channel'}); test units paid to the attacker: "
              f"{result['attacker_paid'] / 100:.2f} TEST")
    print("[*] GET /attacker-log and /ledger show what Hayloft received. Re-run scripts/evaluate_kpi.py to measure.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
