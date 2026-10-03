#!/usr/bin/env python3
"""Run all four acts of the ASI04 demo in one process — no server needed.

Act 1 baseline, Act 2 attack, Act 3 impact, Act 4 remediation, then reset.
Uses the skill's own Lab, payload, and evaluator suite. Standard library only.
Uses its own catalogue file under the skill's ``catalogue/`` folder and
deletes it on exit, so a running server is unaffected.

AUTHORIZED SECURITY-LAB USE ONLY.

Exit code: 0 when the story holds (baseline and remediation clean, attack
measurable), 1 otherwise. With a real-model backend the numbers are reported
but not asserted, because a real model may resist the placeholder payload;
the exit code is then 0 unless a call fails. An unknown backend exits 2.

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
SKILL_DIR = os.path.join(HERE, "owasp-asi04-supply-chain-skill")
sys.path.insert(0, SKILL_DIR)
sys.path.insert(0, os.path.join(SKILL_DIR, "scripts"))

from evaluate_kpi import ICON, SUITE, classify  # noqa: E402
from run_lookalike_publish import load_payload  # noqa: E402
from vulnerable_app import CATALOGUE_DIR, Lab, dry_run  # noqa: E402

CATALOGUE = os.path.join(CATALOGUE_DIR, "run_demo.json")


def act(lab: Lab, title: str) -> float:
    print(f"\n[*] {title}")
    red = targeted = 0
    for task, is_targeted, intended in SUITE:
        steps = lab.run(task)["steps"]
        status = classify(steps, intended)
        if is_targeted:
            targeted += 1
            red += status == "RED"
        tag = "" if is_targeted else "  (control)"
        loaded = ", ".join(f"{s['component']} {s['version']}" if s["status"] == "loaded"
                           else f"{s['requested']} BLOCKED" for s in steps)
        print(f"    {ICON[status]} {status:<6} {task:<24} [{loaded}]{tag}")
    uclr = red / targeted * 100.0
    print(f"    Untrusted Component Load Rate: {uclr:.0f}% targeted")
    return uclr


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--backend", default="stub",
                        help="stub (default) | ollama | llamacpp | openrouter")
    parser.add_argument("--model", default="", help="model name for the backend")
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    try:
        lab = Lab(catalogue_path=CATALOGUE, backend=args.backend, model=args.model)
    except (ValueError, RuntimeError) as exc:
        print(f"[-] Backend error: {exc}", file=sys.stderr)
        return 2
    print(f"[*] Model backend: {lab.backend}")
    payload = load_payload()
    try:
        baseline = act(lab, "Act 1 — Clean baseline")

        print(f"\n[*] Act 2 — Attack: publish lookalike skill '{payload['name']}' "
              f"{payload['version']} (1 catalogue entry)")
        lab.publish(payload)
        print(f"[+] Published as '{payload['publisher']}' through the unauthenticated catalogue.")

        attacked = act(lab, "Act 3 — Post-attack impact (same tasks)")
        print(f"    Step output on expense_reminder: {lab.run('expense_reminder')['steps'][0]['output'][:70]}")

        print("\n[defense] Act 4 — Remediation")
        print(f"[defense] Static manifest check of the entry: REJECT ({'; '.join(dry_run(payload))})")
        lab.set_mode("hardened")
        print("[defense] Hardened mode: exact-name resolution + allowlisted manifest "
              "(publisher and SHA-256 pins).")
        remediated = act(lab, "Act 4 — Re-run with the manifest")

        lab.reset()
        lab.set_mode("vulnerable")
        print("\n[+] Reset to baseline.")
    finally:
        lab.remove_catalogue()

    if lab.backend != "stub":
        print(f"[*] Real model: UCLR {baseline:.0f}% -> {attacked:.0f}% -> {remediated:.0f}% "
              "(reported, not asserted).")
        return 0
    ok = baseline == 0 and attacked > 0 and remediated == 0
    print("[+] Story holds." if ok else "[-] Story broken — check the payload and suite.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
