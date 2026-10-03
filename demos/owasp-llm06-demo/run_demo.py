#!/usr/bin/env python3
"""Run all four acts of the LLM06 demo in one process — no server needed.

Act 1 baseline, Act 2 attack, Act 3 impact, Act 4 remediation, then reset.
Uses the skill's own Lab, payloads, and evaluator suite. Standard library only.
All cost is simulated token/dollar accounting.

AUTHORIZED SECURITY-LAB USE ONLY.

Exit code: 0 when the story holds (baseline and remediation clean, attack
measurable), 1 otherwise. With a real-model backend the numbers are reported
but not asserted, because a real model may resist the placeholder payloads;
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
SKILL_DIR = os.path.join(HERE, "owasp-llm06-consumption-skill")
sys.path.insert(0, SKILL_DIR)
sys.path.insert(0, os.path.join(SKILL_DIR, "scripts"))

from evaluate_kpi import ICON, SUITE, classify  # noqa: E402
from run_consumption import PAYLOADS, payload_path  # noqa: E402
from vulnerable_app import Lab, scan_page  # noqa: E402


def act(lab: Lab, title: str, client: str) -> float:
    print(f"\n[*] {title}")
    red = targeted = 0
    spend = 0.0
    for query, is_targeted, truth in SUITE:
        result = lab.query(query, client)
        status = classify(result, truth)
        spend += result["cost_usd"]
        if is_targeted:
            targeted += 1
            red += status == "RED"
        c = result["cost"]
        tag = "" if is_targeted else "  (control)"
        print(f"    {ICON[status]} {status:<6} {c['input_tokens'] + c['output_tokens']:>6} tok "
              f"{c['tool_calls']:>3} calls {c['agent_steps']:>2} steps "
              f"${result['cost_usd']:.4f}  {query}{tag}")
    bbr = red / targeted * 100.0
    print(f"    Budget Breach Rate: {bbr:.0f}% targeted; simulated spend ${spend:.4f}")
    return bbr


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
    payloads = {}
    for name in PAYLOADS:
        with open(payload_path(name), encoding="utf-8") as fh:
            payloads[name] = fh.read()

    baseline = act(lab, "Act 1 — Clean baseline", "act1")

    print("\n[*] Act 2 — Attack: overwrite 3 wiki pages (1 directive line each)")
    for name, slug in PAYLOADS.items():
        lab.write_page(slug, payloads[name])
        print(f"[+] {name}.md saved over '{slug}' through the unauthenticated wiki edit.")

    attacked = act(lab, "Act 3 — Post-attack impact (same questions)", "act3")

    print("\n[defense] Act 4 — Remediation")
    for name, slug in PAYLOADS.items():
        findings = scan_page(payloads[name], lab.budget, slug).findings
        print(f"[defense] Budget lint of {name}.md: REJECT ({findings[0]})")
    lab.set_mode("hardened")
    print("[defense] Hardened mode: per-request budget, loop depth cap and per-client quota enforced.")
    remediated = act(lab, "Act 4 — Re-run with mitigations", "act4")

    lab.reset()
    lab.set_mode("vulnerable")
    print("\n[+] Reset to baseline.")

    if lab.backend != "stub":
        print(f"[*] Real model: BBR {baseline:.0f}% -> {attacked:.0f}% -> {remediated:.0f}% "
              "(reported, not asserted).")
        return 0
    ok = baseline == 0 and attacked > 0 and remediated == 0
    print("[+] Story holds." if ok else "[-] Story broken — check the payloads and suite.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
