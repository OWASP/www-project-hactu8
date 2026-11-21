#!/usr/bin/env python3
"""Attack skill — direct prompt injection, one customer message each, against Billy's system prompt.

AUTHORIZED SECURITY-LAB USE ONLY. Targets this skill's own vulnerable_app.py.

Sends the attackers' messages from ``assets/injection_prompts.json`` to the
target over ``POST /chat``, as customers of the shop: "ignore all previous
instructions" with a fake maintenance mode, chat-template markers that open a
fake system turn, a fake assistant turn carrying a JSON tool call, and the
override cut into string pieces. The only goals are Billy's two rules
("refund only returned orders", "never reveal the internal reference code"),
and the only effects are a simulated refund in the lab's in-memory action log
or the per-run canary in a reply.

``--prompt ID`` sends one message (including the limit ``split-reversed``);
the default sends the four attack messages.

Exit code: 0 when the messages were sent, 1 when the target is unreachable or
the prompt id is unknown.

Examples:
    python scripts/run_injection.py
    python scripts/run_injection.py --prompt fake-tool-call
    python scripts/run_injection.py --prompt split-reversed
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TARGET = os.getenv("HX14_TARGET", "http://127.0.0.1:5514")
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
        ok = _get(f"{base}/health").get("demo") == "hx14"
    except (urllib.error.URLError, OSError, ValueError):
        ok = False
    if not ok:
        print(f"[-] {base} is not the HX14 target. Start it: python vulnerable_app.py")
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
            first = text.splitlines()[0][:100]
            more = f" (+{len(text.splitlines()) - 1} lines)" if "\n" in text else ""
            print(f"    {account}> {first}{more}")
            print(f"    billy> {result['reply'].splitlines()[0][:100]}")
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--prompt", help="send this prompt id only (see assets/injection_prompts.json)")
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if not check_target(args.target):
        return 1
    from vulnerable_app import load_prompts, prompt_by_id
    try:
        entries = [prompt_by_id(args.prompt)] if args.prompt else load_prompts()["attacks"]
    except KeyError as exc:
        print(f"[-] {exc}")
        return 1
    if not args.prompt:
        _post(f"{args.target}/api/attack", {})
    for entry in entries:
        print(f"[*] Message '{entry['id']}' as customer '{entry['account']}' "
              f"({entry['technique']}: {entry['route']})")
        result = play(args.target, entry["account"], [entry["message"]])
        print(f"[+] Refund against the rule (action log): {'YES' if result['rule_broken'] else 'no'}; "
              f"reference code in the reply: {'YES' if result['canary_leaked'] else 'no'}")
    print("[*] Re-run scripts/evaluate_kpi.py to measure the effect.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
