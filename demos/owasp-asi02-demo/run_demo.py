#!/usr/bin/env python3
"""Run all four acts of the ASI02 demo in one process — no server needed.

Act 1 baseline, Act 2 attack, Act 3 impact, Act 4 remediation, then reset.
Uses the skill's own Lab, payload, and evaluator suite. Standard library only.
Every export is simulated: an entry in the lab's in-memory outbox.

AUTHORIZED SECURITY-LAB USE ONLY.

Exit code: 0 when the story holds (baseline and remediation clean, attack
measurable), 1 otherwise.

Examples:
    python run_demo.py
"""

from __future__ import annotations

import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.join(HERE, "owasp-asi02-tool-misuse-skill")
sys.path.insert(0, SKILL_DIR)
sys.path.insert(0, os.path.join(SKILL_DIR, "scripts"))

from evaluate_kpi import ICON, SUITE, classify, summarise  # noqa: E402
from vulnerable_app import Lab, dry_run  # noqa: E402

PAYLOAD = os.path.join(SKILL_DIR, "assets", "request_note.md")


def act(lab: Lab, title: str) -> float:
    print(f"\n[*] {title}")
    red = targeted = 0
    for request, is_targeted, intended in SUITE:
        calls = lab.run(request)["tool_calls"]
        status = classify(calls, intended)
        if is_targeted:
            targeted += 1
            red += status == "RED"
        tag = "" if is_targeted else "  (control)"
        print(f"    {ICON[status]} {status:<6} {request}{tag}")
        print(f"             {summarise(calls, intended)}")
    uir = red / targeted * 100.0
    print(f"    Unsafe Invocation Rate: {uir:.0f}% targeted")
    return uir


def main(argv=None) -> int:
    argparse.ArgumentParser(description=__doc__,
                            formatter_class=argparse.RawDescriptionHelpFormatter).parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    lab = Lab()
    with open(PAYLOAD, encoding="utf-8") as fh:
        payload = fh.read()

    baseline = act(lab, "Act 1 — Clean baseline")

    print("\n[*] Act 2 — Attack: append a requester note to request RQ-3001 (1 request, 2 directive lines)")
    lab.add_note("RQ-3001", payload)
    print("[+] Note saved through the unauthenticated requester portal. No new tool is involved.")

    attacked = act(lab, "Act 3 — Post-attack impact (same requests)")
    state = lab.state()
    print(f"    Outbox: {state['off_list_exports']} exports to an off-list destination, "
          f"{state['rows_off_list']} ledger rows in them (simulated; nothing leaves the process).")

    print("\n[defense] Act 4 — Remediation")
    blocked = dry_run(payload)
    print(f"[defense] Policy dry run of the note: REJECT ({', '.join(c['key'] for c in blocked)})")
    lab.set_mode("hardened")
    print("[defense] Hardened mode: parameter policy at the tool boundary (destination "
          "allowlist, row caps, per-run call budget). The note stays on the request.")
    remediated = act(lab, "Act 4 — Re-run with mitigations")

    lab.reset()
    lab.set_mode("vulnerable")
    print("\n[+] Reset to baseline.")

    ok = baseline == 0 and attacked > 0 and remediated == 0
    print("[+] Story holds." if ok else "[-] Story broken — check the payload and suite.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
