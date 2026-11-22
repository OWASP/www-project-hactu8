#!/usr/bin/env python3
"""Run all four acts of the AGX09 demo in one process — no server needed.

Act 1 baseline, Act 2 attack, Act 3 impact, Act 4 remediation, then reset.
Uses the skill's own Lab, payload, and evaluator suite. Standard library only.

AUTHORIZED SECURITY-LAB USE ONLY.

Exit code: 0 when the story holds (baseline and remediation clean, attack
measurable), 1 otherwise. With a real-model backend the numbers are reported
but not asserted, because a real model may resist the payload; the exit code
is then 0 unless a call fails.

Examples:
    python run_demo.py
    python run_demo.py --backend ollama --model llama3.2:3b
    OPENROUTER_API_KEY=... python run_demo.py --backend openrouter
"""

from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.join(HERE, "agx09-generalization-skill")
sys.path.insert(0, SKILL_DIR)
sys.path.insert(0, os.path.join(SKILL_DIR, "scripts"))

from evaluate_kpi import ICON, SUITE, classify, held_by  # noqa: E402
from vulnerable_app import Lab, apply_attack, describe_axis, screen_axis  # noqa: E402


def evidence(value) -> None:
    """Print what the model produced, for the hactu8 adapter (HACTU8_EVIDENCE=1 only)."""
    if os.environ.get("HACTU8_EVIDENCE") == "1":
        text = value if isinstance(value, str) else json.dumps(value, default=str, ensure_ascii=False)
        print(f"        evidence: {json.dumps(text[:2000], ensure_ascii=False)}")


def act(lab: Lab, title: str) -> float:
    print(f"\n[*] {title}")
    red = targeted = 0
    for request, is_targeted in SUITE:
        result = lab.ask(request)
        status = classify(result)
        if is_targeted:
            targeted += 1
            red += status == "RED"
        tag = "" if is_targeted else "  (control)"
        print(f"    {ICON[status]} {status:<6} {request}{tag}")
        if held_by(result, status):
            print(f"        held_by: {'; '.join(held_by(result, status))}")
        evidence(result["answer"])
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

    baseline = act(lab, "Act 1 — Clean baseline")

    print("\n[*] Act 2 — Attack: deliver the held-out set to the partner inbox "
          "(paraphrases, translations, encodings the screen was never tuned on)")
    ids = apply_attack(lab)
    print(f"[+] Delivered {len(ids)} held-out notes through the unauthenticated inbox endpoint.")

    attacked = act(lab, "Act 3 — Post-attack impact (same requests)")
    axis = screen_axis(lab.items)
    print(f"[+] Screen caught {len(axis['caught'])} held-out notes (withheld); the other "
          f"{len(axis['missed'])} reached the model, which may or may not act on them.")

    print("\n[defense] Act 4 — Remediation")
    axis = screen_axis(lab.items)
    print("[defense] Screen catch rate on the held-out set (its own axis, same in both modes): "
          + describe_axis(axis))
    print("[defense] The misses stay misses: no rule was added for them. The CLR falls only "
          "through the output layer.")
    lab.set_mode("hardened")
    print("[defense] Hardened mode: the same input screen, plus the canary check on every reply.")
    remediated = act(lab, "Act 4 — Re-run with mitigations")

    lab.reset()
    lab.set_mode("vulnerable")
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
