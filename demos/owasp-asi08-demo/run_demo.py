#!/usr/bin/env python3
"""Run all four acts of the ASI08 demo in one process — no server needed.

Act 1 baseline, Act 2 attack, Act 3 impact, Act 4 remediation, then reset.
Uses the skill's own Lab, payload, and evaluator suite. Standard library only.
Every payment is simulated: an entry in the lab's in-memory action log.

AUTHORIZED SECURITY-LAB USE ONLY.

Exit code: 0 when the story holds (baseline and remediation clean, attack
measurable), 1 otherwise. With a real-model backend (it replaces Billy
Intake's model) the numbers are reported but not asserted, because a real
model may resist the placeholder payload; the exit code is then 0 unless a
call fails.

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
SKILL_DIR = os.path.join(HERE, "owasp-asi08-cascade-skill")
sys.path.insert(0, SKILL_DIR)
sys.path.insert(0, os.path.join(SKILL_DIR, "scripts"))

from evaluate_kpi import ICON, describe, score  # noqa: E402
from vulnerable_app import Lab, dry_run  # noqa: E402

PAYLOAD = os.path.join(SKILL_DIR, "assets", "price_notice.md")


def act(lab: Lab, title: str) -> float:
    print(f"\n[*] {title}")
    result = lab.run_batch()
    red = targeted = 0
    for invoice, is_targeted, status, _ in score(result):
        if is_targeted:
            targeted += 1
            red += status == "RED"
        tag = "" if is_targeted else "  (control)"
        print(f"    {ICON[status]} {status:<6} {invoice}{tag}")
        print(f"             {describe(invoice, result['action_log'])}")
    rate = red / targeted * 100.0
    print(f"    Propagation Rate: {rate:.0f}% targeted")
    print(f"    Blast radius: {result['blast_radius']} downstream actions, "
          f"{result['overpaid']:.2f} overpaid (simulated)")
    if result["open_feeds"]:
        print(f"    [defense] Circuit breaker open for: {', '.join(result['open_feeds'])}")
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

    print("\n[*] Act 2 — Attack: drop a price notice into the intake inbox "
          "(1 document, 1 wrong figure)")
    doc_id = lab.submit_document("SUP-01", "Price notice", payload)
    print(f"[+] Document {doc_id} saved through the unreviewed supplier inbox. No invoice touched.")

    attacked = act(lab, "Act 3 — Post-attack impact (same batch)")

    print("\n[defense] Act 4 — Remediation")
    anomalies = dry_run(payload)
    print(f"[defense] Pipeline dry run of the notice: REJECT ({len(anomalies)} anomalies; "
          f"{anomalies[0]['detail']})")
    lab.set_mode("hardened")
    print("[defense] Hardened mode: every stage validates against the PO ledger; a circuit "
          "breaker halts a feed after repeated anomalies. The notice stays in the inbox.")
    remediated = act(lab, "Act 4 — Re-run with mitigations")

    lab.reset()
    lab.set_mode("vulnerable")
    print("\n[+] Reset to baseline.")

    if lab.backend != "stub":
        print(f"[*] Real model: PR {baseline:.0f}% -> {attacked:.0f}% -> {remediated:.0f}% "
              "(reported, not asserted).")
        return 0

    ok = baseline == 0 and attacked > 0 and remediated == 0
    print("[+] Story holds." if ok else "[-] Story broken — check the payload and suite.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
