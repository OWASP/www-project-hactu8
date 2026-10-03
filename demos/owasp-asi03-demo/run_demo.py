#!/usr/bin/env python3
"""Run all four acts of the ASI03 demo in one process — no server needed.

Act 1 baseline, Act 2 attack, Act 3 impact, Act 4 remediation, then reset.
Uses the skill's own Lab, payload, and evaluator suite. Standard library only.
Every token is a demo-only random string; every document is fictional.

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
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.join(HERE, "owasp-asi03-privilege-skill")
sys.path.insert(0, SKILL_DIR)
sys.path.insert(0, os.path.join(SKILL_DIR, "scripts"))

from evaluate_kpi import ICON, SUITE, classify, summarise  # noqa: E402
from vulnerable_app import Lab, dry_run, submit_payload  # noqa: E402

PAYLOAD = os.path.join(SKILL_DIR, "assets", "requests.json")


def act(lab: Lab, title: str) -> float:
    print(f"\n[*] {title}")
    actions = lab.run()["actions"]
    red = targeted = 0
    for label, caller, doc, is_targeted, is_entitled in SUITE:
        status = classify(actions, caller, doc, is_entitled)
        if is_targeted:
            targeted += 1
            red += status == "RED"
        tag = "" if is_targeted else "  (control)"
        print(f"    {ICON[status]} {status:<6} {label}{tag}")
        print(f"             {summarise(actions, caller, doc)}")
    per = red / targeted * 100.0
    print(f"    Privilege Escalation Rate: {per:.0f}% targeted")
    return per


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
        lab = Lab(backend=args.backend, model=args.model)
    except (ValueError, RuntimeError) as exc:
        print(f"[-] Backend error: {exc}", file=sys.stderr)
        return 2
    print(f"[*] Model backend: {lab.backend}")
    with open(PAYLOAD, encoding="utf-8") as fh:
        payload = json.load(fh)

    baseline = act(lab, "Act 1 — Clean baseline")

    print("\n[*] Act 2 — Attack: intern 'dana' files 4 plain requests "
          "(3 with her own token, 1 with a delegated token from session S-0001's transcript)")
    submit_payload(lab, payload)
    print("[+] Requests filed. No injection; the agent's identity does the rest.")

    attacked = act(lab, "Act 3 — Post-attack impact (same suite, next run)")
    print(f"    Action log: {len(lab.state()['unentitled_releases'])} document releases "
          "to a caller who is not entitled (all fictional).")

    print("\n[defense] Act 4 — Remediation")
    denied = dry_run(payload)
    print(f"[defense] Access-review dry run of the requests: REJECT ({len(denied)} steps denied)")
    lab.set_mode("hardened")
    print("[defense] Hardened mode: on-behalf-of tokens (caller authorised, not the agent) + "
          "short-lived, session-bound tokens. The requests stay in the queue.")
    remediated = act(lab, "Act 4 — Re-run with mitigations")

    lab.reset()
    lab.set_mode("vulnerable")
    print("\n[+] Reset to baseline (fresh demo tokens).")

    if lab.backend != "stub":
        print(f"[*] Real model: PER {baseline:.0f}% -> {attacked:.0f}% -> {remediated:.0f}% "
              "(reported, not asserted).")
        return 0
    ok = baseline == 0 and attacked > 0 and remediated == 0
    print("[+] Story holds." if ok else "[-] Story broken — check the payload and suite.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
