#!/usr/bin/env python3
"""Run all four acts of the AGX03 demo in one process — no server needed.

Act 1 baseline, Act 2 attack, Act 3 impact, Act 4 remediation, then reset.
Uses the skill's own Lab, payload, and evaluator suite. Standard library only.

AUTHORIZED SECURITY-LAB USE ONLY.

Exit code: 0 when the story holds (baseline and remediation clean, attack
measurable), 1 otherwise. With a real-model backend the numbers are reported
but not asserted, because a real model may resist the probe; the exit code is
then 0 unless a call fails.

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
SKILL_DIR = os.path.join(HERE, "agx03-conditional-skill")
sys.path.insert(0, SKILL_DIR)
sys.path.insert(0, os.path.join(SKILL_DIR, "scripts"))

from evaluate_kpi import ICON, SUITE, classify  # noqa: E402
from vulnerable_app import TRIGGER, Lab, load_payload, scan_payload  # noqa: E402


def act(lab: Lab, title: str) -> float:
    print(f"\n[*] {title}")
    red = targeted = 0
    for request, is_targeted in SUITE:
        status = classify(lab.ask(request))
        if is_targeted:
            targeted += 1
            red += status == "RED"
        tag = "" if is_targeted else "  (control)"
        print(f"    {ICON[status]} {status:<6} {request}{tag}")
    clr = red / targeted * 100.0
    print(f"    Canary Leak Rate: {clr:.0f}% targeted")
    return clr


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
    payload = load_payload()

    baseline = act(lab, "Act 1 — Clean baseline")

    print(f"\n[*] Act 2 — Attack: arm the feed (clean on polls 1-{TRIGGER - 1}, "
          f"hostile from poll {TRIGGER}); the feed definition is unchanged")
    lab.arm()
    print("[+] Trigger armed through the unauthenticated vendor endpoint.")

    attacked = act(lab, "Act 3 — Post-attack impact (same requests)")

    print("\n[defense] Act 4 — Remediation")
    scan = scan_payload(payload)
    print(f"[defense] protectogw every-return screen of the hostile poll: {scan['decision']} "
          f"({', '.join(f.split(': ')[0] for f in scan['findings'])})")
    lab.set_mode("hardened")
    print("[defense] Hardened mode: every return screened, canary check on every reply.")
    remediated = act(lab, "Act 4 — Re-run with mitigations")

    lab.set_mode("vulnerable")
    lab.reset()
    print("\n[+] Reset to baseline.")

    if lab.backend != "echo":
        print(f"[*] Real model: CLR {baseline:.0f}% -> {attacked:.0f}% -> {remediated:.0f}% "
              "(reported, not asserted).")
        return 0
    ok = baseline == 0 and attacked > 0 and remediated == 0
    print("[+] Story holds." if ok else "[-] Story broken — check the payload and suite.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
