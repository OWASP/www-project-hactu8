#!/usr/bin/env python3
"""Run all four acts of the ASI06 demo in one process — no server needed.

Act 1 baseline, Act 2 attack, Act 3 impact, Act 4 remediation, then reset.
Uses the skill's own Lab, payload, and evaluator suite. Standard library only.
Every session is scored from the lab's in-memory action log.

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
SKILL_DIR = os.path.join(HERE, "owasp-asi06-memory-skill")
sys.path.insert(0, SKILL_DIR)
sys.path.insert(0, os.path.join(SKILL_DIR, "scripts"))

from evaluate_kpi import ICON, SUITE, classify, session_steps, summarise  # noqa: E402
from run_memory_poison import poison_message  # noqa: E402
from vulnerable_app import Lab, load_screen_rules, screen_memory  # noqa: E402

PAYLOAD = os.path.join(SKILL_DIR, "assets", "memory_note.md")


def act(lab: Lab, title: str) -> float:
    print(f"\n[*] {title}")
    red = targeted = 0
    for user, message, is_targeted, truth in SUITE:
        sid = lab.session(user, message)["session"]
        steps = session_steps(lab.action_log, sid)
        status = classify(steps, truth)
        if is_targeted:
            targeted += 1
            red += status == "RED"
        tag = "" if is_targeted else "  (control)"
        print(f"    {ICON[status]} {status:<6} {user:<6} {message}{tag}")
        print(f"             {summarise(steps)}")
    psr = red / targeted * 100.0
    print(f"    Poison Success Rate: {psr:.0f}% targeted")
    return psr


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

    baseline = act(lab, "Act 1 — Clean baseline (later sessions of five users)")

    print("\n[*] Act 2 — Attack: one 'remember this' session as mallory (1 session, 1 memory)")
    result = lab.session("mallory", poison_message(payload))
    save = next(s for s in result["steps"] if s["step"] == "save_memory")
    print(f"[+] The agent saved memory {save['memory']} with scope '{save['scope']}'.")

    attacked = act(lab, "Act 3 — Post-attack impact (same users, same questions)")

    print("\n[defense] Act 4 — Remediation")
    findings = screen_memory(payload, load_screen_rules()).findings
    print(f"[defense] Static screen of the memory: REJECT ({', '.join(findings)})")
    lab.set_mode("hardened")
    print("[defense] Hardened mode: writes screened, per-user scope with provenance, "
          "unscoped entries ignored on recall. The planted memory stays in the store.")
    remediated = act(lab, "Act 4 — Re-run with mitigations")

    lab.reset()
    lab.set_mode("vulnerable")
    print("\n[+] Reset to baseline.")

    if lab.backend != "echo":
        print(f"[*] Real model: PSR {baseline:.0f}% -> {attacked:.0f}% -> {remediated:.0f}% "
              "(reported, not asserted).")
        return 0

    ok = baseline == 0 and attacked > 0 and remediated == 0
    print("[+] Story holds." if ok else "[-] Story broken — check the payload and suite.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
