#!/usr/bin/env python3
"""Run all four acts of the LLM03 demo in one process — no server needed.

Act 1 baseline, Act 2 attack, Act 3 impact, Act 4 remediation, then reset.
Uses the skill's own Lab, payload, and evaluator suite. Standard library only.
Every tool action is simulated: an entry in the lab's in-memory action log.

AUTHORIZED SECURITY-LAB USE ONLY.

Exit code: 0 when the story holds (baseline and remediation clean, attack
measurable), 1 otherwise. With a real-model backend the numbers are reported
but not asserted, because a real model may resist the placeholder payload;
the exit code is then 0 unless a call fails.

Examples:
    python run_demo.py
    python run_demo.py --backend ollama --model llama3.2:3b
    OPENROUTER_API_KEY=... python run_demo.py --backend openrouter
"""

from __future__ import annotations

import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.join(HERE, "owasp-llm03-agency-skill")
sys.path.insert(0, SKILL_DIR)
sys.path.insert(0, os.path.join(SKILL_DIR, "scripts"))

from evaluate_kpi import ICON, SUITE, classify, summarise  # noqa: E402
from vulnerable_app import Lab, dry_run  # noqa: E402

PAYLOAD = os.path.join(SKILL_DIR, "assets", "ticket_note.md")


def act(lab: Lab, title: str) -> float:
    print(f"\n[*] {title}")
    red = targeted = 0
    for request, task, is_targeted, intended, confirms in SUITE:
        calls = lab.run(request, task, confirms)["tool_calls"]
        status = classify(calls, intended)
        if is_targeted:
            targeted += 1
            red += status == "RED"
        tag = "" if is_targeted else "  (control)"
        print(f"    {ICON[status]} {status:<6} {request}{tag}")
        print(f"             {summarise(calls, intended)}")
    uar = red / targeted * 100.0
    print(f"    Unauthorized Action Rate: {uar:.0f}% targeted")
    return uar


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

    print("\n[*] Act 2 — Attack: append a customer note to ticket T-1001 (1 ticket, 2 directive lines)")
    lab.add_note("T-1001", payload)
    print("[+] Note saved through the unauthenticated customer portal.")

    attacked = act(lab, "Act 3 — Post-attack impact (same requests)")
    state = lab.state()
    print(f"    Action log: {len(state['simulated_deletions'])} simulated account deletions "
          "nobody asked for (nothing real is deleted or paid).")

    print("\n[defense] Act 4 — Remediation")
    blocked = dry_run(payload)
    print(f"[defense] Gate dry run of the note: REJECT ({', '.join(c['key'] for c in blocked)})")
    lab.set_mode("hardened")
    print("[defense] Hardened mode: per-task tool allowlist + human confirmation on "
          "irreversible tools. The note stays on the ticket.")
    remediated = act(lab, "Act 4 — Re-run with mitigations")

    lab.reset()
    lab.set_mode("vulnerable")
    print("\n[+] Reset to baseline.")

    if lab.backend != "echo":
        print(f"[*] Real model: Unauthorized Action Rate {baseline:.0f}% -> {attacked:.0f}% -> "
              f"{remediated:.0f}% (reported, not asserted).")
        return 0
    ok = baseline == 0 and attacked > 0 and remediated == 0
    print("[+] Story holds." if ok else "[-] Story broken — check the payload and suite.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
