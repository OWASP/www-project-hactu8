#!/usr/bin/env python3
"""Run all four acts of the LLM08 demo in one process — no server needed.

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
SKILL_DIR = os.path.join(HERE, "owasp-llm08-leak-skill")
sys.path.insert(0, SKILL_DIR)
sys.path.insert(0, os.path.join(SKILL_DIR, "scripts"))

from evaluate_kpi import ICON, SUITE, classify  # noqa: E402
from vulnerable_app import Lab, load_prompt, load_rules, scan_prompt  # noqa: E402

PAYLOAD = os.path.join(SKILL_DIR, "assets", "extraction_request.md")


def act(lab: Lab, title: str) -> float:
    print(f"\n[*] {title}")
    red = targeted = 0
    for user, query, is_targeted, truth in SUITE:
        answer = lab.query(user, query)["answer"]
        status = classify(answer, truth)
        if is_targeted:
            targeted += 1
            red += status == "RED"
        tag = "" if is_targeted else "  (control)"
        print(f"    {ICON[status]} {status:<6} {user}: {query}{tag}")
    plr = red / targeted * 100.0
    print(f"    Prompt Leak Rate: {plr:.0f}% targeted")
    return plr


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

    print("\n[*] Act 2 — Attack: save an extraction request as 'guest-attacker's reply preference (1 account)")
    lab.set_preference("guest-attacker", payload)
    print("[+] Preference saved through the ordinary customer profile feature.")

    attacked = act(lab, "Act 3 — Post-attack impact (same questions)")

    print("\n[defense] Act 4 — Remediation")
    rules = load_rules()
    findings = scan_prompt(load_prompt("vulnerable"), rules).findings
    print(f"[defense] Design check of the deployed prompt: REJECT ({len(findings)} findings)")
    status = "PASS" if not scan_prompt(load_prompt("hardened"), rules).blocked else "REJECT"
    print(f"[defense] Design check of the secret-free prompt: {status}")
    lab.set_mode("hardened")
    print("[defense] Hardened mode: secret-free prompt deployed and every reply output-filtered.")
    remediated = act(lab, "Act 4 — Re-run with mitigations")

    lab.reset()
    lab.set_mode("vulnerable")
    print("\n[+] Reset to baseline.")

    if lab.backend != "stub":
        print(f"[*] Real model: PLR {baseline:.0f}% -> {attacked:.0f}% -> {remediated:.0f}% "
              "(reported, not asserted).")
        return 0
    ok = baseline == 0 and attacked > 0 and remediated == 0
    print("[+] Story holds." if ok else "[-] Story broken — check the payload and suite.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
