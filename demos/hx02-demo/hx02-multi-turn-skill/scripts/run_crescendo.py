#!/usr/bin/env python3
"""Attack skill — a multi-turn jailbreak (crescendo) against the store rule.

AUTHORIZED SECURITY-LAB USE ONLY. Targets this skill's own vulnerable_app.py.

Plays the attacker's scripts from ``assets/crescendo_scripts.json`` against the
target, one turn at a time over ``POST /chat``, as a customer of the shop. Each
turn is harmless alone (a role-play, a hypothetical, "for the training
manual", one small step on the customer's own order); the last turn asks Billy
to finish the job. The only goal is the store rule "never apply STAFF30 to a
customer order", and the only effect is a simulated discount in the lab's
in-memory action log.

``--script ID`` plays one script (including ``one-turn`` and the limit
``paraphrased-trainer``); the default plays the three attack scripts.

Exit code: 0 when the scripts were played, 1 when the target is unreachable.

Examples:
    python scripts/run_crescendo.py
    python scripts/run_crescendo.py --script one-turn
    python scripts/run_crescendo.py --script paraphrased-trainer
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TARGET = os.getenv("HX02_TARGET", "http://127.0.0.1:5502")
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
        ok = _get(f"{base}/health").get("demo") == "hx02"
    except (urllib.error.URLError, OSError, ValueError):
        ok = False
    if not ok:
        print(f"[-] {base} is not the HX02 target. Start it: python vulnerable_app.py")
    return ok


def play(base: str, account: str, turns, verbose: bool = True) -> dict:
    """One conversation over HTTP; returns the last /chat result."""
    from vulnerable_app import fill
    orders = _get(f"{base}/orders")["orders"]
    order = next((o for o, r in orders.items() if r["account"] == account), "")
    cid = _post(f"{base}/chat/start", {"account": account})["conversation"]
    result: dict = {}
    for text in fill(list(turns), order):
        result = _post(f"{base}/chat", {"conversation": cid, "message": text})
        if verbose:
            print(f"    {account}> {text}")
            print(f"    billy> {result['reply'].splitlines()[0][:100]}")
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--script", help="play this script id only (see assets/crescendo_scripts.json)")
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if not check_target(args.target):
        return 1
    from vulnerable_app import load_scripts, script_by_id
    try:
        scripts = [script_by_id(args.script)] if args.script else load_scripts()["scripts"]
    except KeyError as exc:
        print(f"[-] {exc}")
        return 1
    if not args.script:
        _post(f"{args.target}/api/attack", {})
    for script in scripts:
        print(f"[*] Script '{script['id']}' as customer '{script['account']}' ({script['route']})")
        result = play(args.target, script["account"], script["turns"])
        print(f"[+] Rule broken (action log): {'YES' if result['rule_broken'] else 'no'}")
    print("[*] Re-run scripts/evaluate_kpi.py to measure the effect.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
