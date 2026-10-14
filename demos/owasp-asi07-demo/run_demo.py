#!/usr/bin/env python3
"""Run all four acts of the ASI07 demo in one process — no server needed.

Act 1 baseline, Act 2 attack, Act 3 impact, Act 4 remediation, then reset.
Uses the skill's own Lab, payload, attack helpers and evaluator suite.
Standard library only. The message bus is in-process, the agent keys are
demo-only random bytes, and every tool action is simulated: an entry in the
lab's in-memory action log.

AUTHORIZED SECURITY-LAB USE ONLY.

Exit code: 0 when the story holds (baseline and remediation clean, attack
measurable), 1 otherwise. With a real-model backend (it replaces Billy Exec's
model; the planner stays a stub) the numbers are reported but not asserted,
because a real model may resist the placeholder payload; the exit code is
then 0 unless a call fails.

Examples:
    python run_demo.py
    python run_demo.py --backend ollama --model llama3.2:3b
    OPENROUTER_API_KEY=... python run_demo.py --backend openrouter
"""

from __future__ import annotations

import argparse
import os
import secrets
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.join(HERE, "owasp-asi07-a2a-skill")
sys.path.insert(0, SKILL_DIR)
sys.path.insert(0, os.path.join(SKILL_DIR, "scripts"))

from evaluate_kpi import ICON, SUITE, classify, summarise  # noqa: E402
from run_bus_forgery import find_replayable  # noqa: E402
from vulnerable_app import Lab, dry_run  # noqa: E402

PAYLOAD = os.path.join(SKILL_DIR, "assets", "forged_order.md")
SIGNED = ("sender", "recipient", "topic", "kind", "body", "ts", "nonce", "sig")


def act(lab: Lab, title: str) -> float:
    print(f"\n[*] {title}")
    red = targeted = 0
    for request, topic, is_targeted, intended in SUITE:
        result = lab.run(request, topic)
        status = classify(result["tool_calls"], intended)
        if is_targeted:
            targeted += 1
            red += status == "RED"
        tag = "" if is_targeted else "  (control)"
        print(f"    {ICON[status]} {status:<6} [{topic}] {request}{tag}")
        print(f"             {summarise(result, intended)}")
    rate = red / targeted * 100.0
    print(f"    Forged Message Acceptance Rate: {rate:.0f}% targeted")
    return rate


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--backend", default="echo",
                        help="echo (default; alias stub) | ollama | llamacpp | openrouter")
    parser.add_argument("--model", default="", help="model name for the backend")
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    lab = Lab(backend=args.backend, model=args.model)
    print(f"[*] Model backend: {lab.backend}")
    with open(PAYLOAD, encoding="utf-8") as fh:
        payload = fh.read()

    baseline = act(lab, "Act 1 — Clean baseline")

    print("\n[*] Act 2 — Attack: spoof the planner on 2 topics, replay 1 old genuine order")
    for topic in ("payments", "inventory"):
        msg = lab.publish({"sender": "planner", "recipient": "executor", "topic": topic,
                           "kind": "work_order", "body": payload, "ts": lab.clock(),
                           "nonce": secrets.token_hex(8), "sig": ""}, retain=True)
        print(f"[+] Spoofed work order {msg['id']} retained on '{topic}' "
              "(sender field 'planner', no signature).")
    old = find_replayable(lab.bus_view(), "refunds")
    msg = lab.publish({k: old[k] for k in SIGNED}, retain=True)
    print(f"[+] Replayed {old['id']} as {msg['id']} on 'refunds' "
          "(read from the open bus log; genuine signature, 3 days old).")

    attacked = act(lab, "Act 3 — Post-attack impact (same jobs)")
    state = lab.state()
    paid = state["simulated_payments"].count("pay_invoice:INV-3999")
    again = state["simulated_refunds"].count("issue_refund:A-0907")
    print(f"    Action log: {paid} simulated payments to INV-3999, "
          f"{len(state['simulated_cancellations'])} cancellations of A-1002 and {again} repeat "
          "refund of A-0907 nobody asked for (nothing real moves).")

    print("\n[defense] Act 4 — Remediation")
    blocked = dry_run(payload)
    print(f"[defense] Verification dry run of the payload: REJECT "
          f"({', '.join(c['key'] for c in blocked)})")
    lab.set_mode("hardened")
    print("[defense] Hardened mode: HMAC-SHA256 with per-agent keys, work-order sender "
          "allowlist, nonce + timestamp replay checks. The retained messages stay on the bus.")
    remediated = act(lab, "Act 4 — Re-run with mitigations")

    lab.reset()
    lab.set_mode("vulnerable")
    print("\n[+] Reset to baseline.")

    if lab.backend != "echo":
        print(f"[*] Real model: FMAR {baseline:.0f}% -> {attacked:.0f}% -> {remediated:.0f}% "
              "(reported, not asserted).")
        return 0

    ok = baseline == 0 and attacked > 0 and remediated == 0
    print("[+] Story holds." if ok else "[-] Story broken — check the payload and suite.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
