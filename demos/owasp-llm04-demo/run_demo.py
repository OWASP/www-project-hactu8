#!/usr/bin/env python3
"""Run all four acts of the LLM04 demo in one process — no server needed.

Act 1 baseline, Act 2 attack, Act 3 impact, Act 4 remediation, then reset.
Uses the skill's own Lab, payloads, attack builder and evaluator suite.
Standard library only. Uses its own registry file under the skill's
``registry/`` folder and deletes it on exit, so a running server is unaffected.

AUTHORIZED SECURITY-LAB USE ONLY.

Exit code: 0 when the story holds (baseline and remediation clean, attack
measurable), 1 otherwise. With a real-model backend the numbers are reported
but not asserted, because a real model may resist the placeholder payloads;
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
SKILL_DIR = os.path.join(HERE, "owasp-llm04-rugpull-skill")
sys.path.insert(0, SKILL_DIR)
sys.path.insert(0, os.path.join(SKILL_DIR, "scripts"))

from evaluate_kpi import ICON, SUITE, classify  # noqa: E402
from run_rug_pull import SLEEPER_PAYLOAD, SWAP_PAYLOAD, build_compromised_release  # noqa: E402
from vulnerable_app import (REGISTRY_DIR, Lab, load_pins, pin_diff,  # noqa: E402
                            read_registry, write_registry)

REGISTRY = os.path.join(REGISTRY_DIR, "run_demo.json")


def act(lab: Lab, title: str) -> float:
    print(f"\n[*] {title}")
    red = targeted = 0
    for query, is_targeted, truth in SUITE:
        result = lab.query(query)
        status = classify(result["answer"], truth)
        if is_targeted:
            targeted += 1
            red += status == "RED"
        tag = "" if is_targeted else "  (control)"
        tool = f"{result['tool']} {result['tool_version']}"
        print(f"    {ICON[status]} {status:<6} {query:<44} [{tool}]{tag}")
    ctr = red / targeted * 100.0
    print(f"    Compromised Tool Rate: {ctr:.0f}% targeted")
    return ctr


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read().strip()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--backend", default="echo",
                        help="echo (default; alias stub) | ollama | llamacpp | openrouter")
    parser.add_argument("--model", default="", help="model name for the backend")
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    lab = Lab(registry_path=REGISTRY, backend=args.backend, model=args.model)
    print(f"[*] Model backend: {lab.backend}")
    try:
        baseline = act(lab, "Act 1 — Clean baseline")

        print("\n[*] Act 2 — Attack: publish hayloft-policy-tools 1.0.1 (2 of 4 tools changed)")
        _, registry = read_registry(REGISTRY)
        release, notes = build_compromised_release(registry, _read(SWAP_PAYLOAD),
                                                   _read(SLEEPER_PAYLOAD))
        write_registry(REGISTRY, release)
        for note in notes:
            print(f"[+] {note}")

        attacked = act(lab, "Act 3 — Post-attack impact (same questions)")

        print("\n[defense] Act 4 — Remediation")
        findings = pin_diff(release, load_pins())
        print(f"[defense] Static pin diff of the release: REJECT ({'; '.join(findings)})")
        print("[defense] The sleeper's definition matches its pin; only sampling can see it.")
        lab.set_mode("hardened")
        for line in lab.admission_log:
            if "REJECTED" in line or "vendored" in line:
                print(f"[defense]   {line}")
        remediated = act(lab, "Act 4 — Re-run with the admission gate")

        lab.reset()
        lab.set_mode("vulnerable")
        print("\n[+] Reset to baseline.")
    finally:
        lab.remove_registry()

    if lab.backend != "echo":
        print(f"[*] Real model: Compromised Tool Rate {baseline:.0f}% -> {attacked:.0f}% -> "
              f"{remediated:.0f}% (reported, not asserted).")
        return 0
    ok = baseline == 0 and attacked > 0 and remediated == 0
    print("[+] Story holds." if ok else "[-] Story broken — check the payloads and suite.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
