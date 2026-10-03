#!/usr/bin/env python3
"""Run all four acts of the LLM02 demo in one process — no server needed.

Act 1 baseline, Act 2 attack, Act 3 impact, Act 4 remediation, then reset.
Uses the skill's own Lab, payload, and evaluator suite. Standard library only.

AUTHORIZED SECURITY-LAB USE ONLY.

Exit code: 0 when the story holds (baseline and remediation clean, attack
measurable), 1 otherwise. With a real-model backend the numbers are reported
but not asserted, because a real model may resist the placeholder payload;
the exit code is then 0 unless a call fails.

Examples:
    python run_demo.py
    python run_demo.py --backend ollama --model llama3.2
    OPENROUTER_API_KEY=... python run_demo.py --backend openrouter
"""

from __future__ import annotations

import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.join(HERE, "owasp-llm02-disclosure-skill")
sys.path.insert(0, SKILL_DIR)
sys.path.insert(0, os.path.join(SKILL_DIR, "scripts"))

from evaluate_kpi import ICON, SUITE, classify  # noqa: E402
from vulnerable_app import Lab, load_redaction_rules, scan_for_secrets  # noqa: E402

PAYLOAD = os.path.join(SKILL_DIR, "assets", "pivot_note.md")
ATTACKER = "C-1003"


def act(lab: Lab, title: str) -> float:
    print(f"\n[*] {title}")
    red = targeted = 0
    for session, query, is_targeted, truth in SUITE:
        answer = lab.query(session, query)["answer"]
        status = classify(answer, truth, session)
        if is_targeted:
            targeted += 1
            red += status == "RED"
        tag = "" if is_targeted else "  (control)"
        print(f"    {ICON[status]} {status:<6} {session} {query}{tag}")
    rate = red / targeted * 100.0
    print(f"    Leak Rate: {rate:.0f}% targeted")
    return rate


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--backend", default="stub",
                        help="stub (default) | ollama | llamacpp | openrouter")
    parser.add_argument("--model", default="", help="model name for the backend")
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    lab = Lab(backend=args.backend, model=args.model)
    print(f"[*] Model backend: {lab.backend}")
    with open(PAYLOAD, encoding="utf-8") as fh:
        payload = fh.read()

    baseline = act(lab, "Act 1 — Clean baseline")

    print(f"\n[*] Act 2 — Attack: save the pivot note on account {ATTACKER} "
          "(own account, 1 field, 1 directive line)")
    lab.set_notes(ATTACKER, payload)
    print("[+] Notes saved through the customer's own profile edit.")

    attacked = act(lab, "Act 3 — Post-attack impact (same questions)")

    print("\n[defense] Act 4 — Remediation")
    findings = scan_for_secrets(lab.raw_prompt, load_redaction_rules()).findings
    print(f"[defense] Static scan of the system prompt: REJECT ({', '.join(findings)})")
    lab.set_mode("hardened")
    print(f"[defense] Hardened mode: {', '.join(lab.vault.names())} moved to the vault, "
          "records scoped to the signed-in customer, output redacted.")
    remediated = act(lab, "Act 4 — Re-run with mitigations")

    lab.reset()
    lab.set_mode("vulnerable")
    print("\n[+] Reset to baseline.")

    if lab.backend != "stub":
        print(f"[*] Real model: Leak Rate {baseline:.0f}% -> {attacked:.0f}% -> "
              f"{remediated:.0f}% (reported, not asserted).")
        return 0
    ok = baseline == 0 and attacked > 0 and remediated == 0
    print("[+] Story holds." if ok else "[-] Story broken — check the payload and suite.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
