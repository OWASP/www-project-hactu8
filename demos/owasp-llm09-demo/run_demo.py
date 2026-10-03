#!/usr/bin/env python3
"""Run all four acts of the LLM09 demo in one process — no server needed.

Act 1 baseline, Act 2 attack, Act 3 impact, Act 4 remediation, then reset.
Uses the skill's own Lab, payload, and evaluator suite. Standard library only.

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
SKILL_DIR = os.path.join(HERE, "owasp-llm09-tenant-skill")
sys.path.insert(0, SKILL_DIR)
sys.path.insert(0, os.path.join(SKILL_DIR, "scripts"))

from evaluate_kpi import ICON, SUITE, classify  # noqa: E402
from vulnerable_app import Lab, rank, scope_blocks  # noqa: E402

PAYLOAD = os.path.join(SKILL_DIR, "assets", "crafted_query.txt")
SESSION = "meadow-analyst"


def act(lab: Lab, title: str) -> float:
    print(f"\n[*] {title}")
    red = targeted = 0
    for query, is_targeted, truth in SUITE:
        result = lab.query(SESSION, query, remember=False)
        status = classify(result["answer"], truth)
        if is_targeted:
            targeted += 1
            red += status == "RED"
        tag = "" if is_targeted else "  (control)"
        source = result["retrieved"][0]["id"] if result["retrieved"] else "-"
        print(f"    {ICON[status]} {status:<6} {query:<40} <- {source}{tag}")
    ctlr = red / targeted * 100.0
    print(f"    Cross-Tenant Leak Rate: {ctlr:.0f}% targeted")
    return ctlr


def main(argv=None) -> int:
    argparse.ArgumentParser(description=__doc__,
                            formatter_class=argparse.RawDescriptionHelpFormatter).parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    lab = Lab()
    with open(PAYLOAD, encoding="utf-8") as fh:
        payload = fh.read().strip()

    baseline = act(lab, "Act 1 — Clean baseline (Meadow Fold session)")

    print("\n[*] Act 2 — Attack: 1 crafted turn in the Meadow Fold session, naming the other tenant")
    result = lab.query(SESSION, payload)
    print(f"[+] Turn kept in session memory; it was answered from "
          f"'{result['retrieved'][0]['id']}' (cross-tenant: {result['cross_tenant']}).")

    attacked = act(lab, "Act 3 — Post-attack impact (same follow-up questions)")

    print("\n[defense] Act 4 — Remediation")
    tenant = lab.tenant_of(SESSION)
    ranked = rank(lab.docs, lab.retrieval_vector(SESSION, payload))
    leaks = [d.doc_id for d, _ in ranked if scope_blocks(d, tenant)]
    print(f"[defense] Retrieval-scope audit of the turn: REJECT "
          f"({len(leaks)} cross-tenant candidates: {', '.join(leaks)})")
    lab.set_mode("hardened")
    print("[defense] Hardened mode: tenant filter enforced at retrieval, before ranking.")
    remediated = act(lab, "Act 4 — Re-run with mitigations")

    lab.reset()
    lab.set_mode("vulnerable")
    print("\n[+] Reset to baseline.")

    ok = baseline == 0 and attacked > 0 and remediated == 0
    print("[+] Story holds." if ok else "[-] Story broken — check the payload and suite.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
