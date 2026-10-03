#!/usr/bin/env python3
"""Run all four acts of the LLM05 demo in one process — no server needed.

Act 1 baseline, Act 2 attack, Act 3 impact, Act 4 remediation, then reset.
Uses the skill's own Lab, attack artifacts, and evaluator suite. Standard
library only.

AUTHORIZED SECURITY-LAB USE ONLY.

Exit code: 0 when the story holds (baseline and remediation clean, attack
measurable), 1 otherwise. With a real-model backend the numbers are reported
but not asserted, because a real model may resist the placeholder payloads;
the exit code is then 0 unless a call fails.

The earlier embedding-based pipeline in src/ has its own runner:
``python -m llm05_demo.cli`` (see README).

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
SKILL_DIR = os.path.join(HERE, "owasp-llm05-poisoning-skill")
sys.path.insert(0, SKILL_DIR)
sys.path.insert(0, os.path.join(SKILL_DIR, "scripts"))

from evaluate_kpi import ICON, SUITE, classify  # noqa: E402
from vulnerable_app import (  # noqa: E402
    AGENT_CACHE_POISON_FILE, PROMPT_TEMPLATE_FILE, Lab, poison_document, scan_artifacts,
)


def act(lab: Lab, title: str) -> float:
    print(f"\n[*] {title}")
    red = targeted = red_all = 0
    for query, is_targeted in SUITE:
        status = classify(lab.query(query)["answer"])
        red_all += status == "RED"
        if is_targeted:
            targeted += 1
            red += status == "RED"
        tag = "" if is_targeted else "  (control)"
        print(f"    {ICON[status]} {status:<6} {query}{tag}")
    psr = red / targeted * 100.0
    print(f"    Poison Success Rate: {psr:.0f}% targeted, "
          f"{red_all / len(SUITE) * 100.0:.0f}% overall")
    return psr


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

    baseline = act(lab, "Act 1 — Clean baseline")

    print("\n[*] Act 2 — Attack: poison three surfaces")
    for index in range(3):
        name = lab.ingest(*poison_document(index))
        print(f"[+] RAG: ingested {name} (unauthenticated, no provenance).")
    with open(PROMPT_TEMPLATE_FILE, encoding="utf-8") as fh:
        version = lab.set_template(json.load(fh))
    print(f"[+] Template: installed '{version}', dormant until 'quarterly audit'.")
    with open(AGENT_CACHE_POISON_FILE, encoding="utf-8") as fh:
        lab.set_agent_cache(json.load(fh))
    print("[+] Agent: Bob the Agent's cache poisoned upstream; Bob stays authenticated.")

    attacked = act(lab, "Act 3 — Post-attack impact (same questions)")

    print("\n[defense] Act 4 — Remediation")
    findings = scan_artifacts()
    print(f"[defense] Static scan of the 3 attack artifacts: REJECT ({len(findings)} findings)")
    lab.set_mode("hardened")
    print("[defense] Hardened mode: source gate, template pin, agent verification.")
    remediated = act(lab, "Act 4 — Re-run with mitigations")

    lab.reset()
    lab.set_mode("vulnerable")
    print("\n[+] Reset to baseline.")

    if lab.backend != "stub":
        print(f"[*] Real model: PSR {baseline:.0f}% -> {attacked:.0f}% -> {remediated:.0f}% "
              "(reported, not asserted).")
        return 0
    ok = baseline == 0 and attacked > 0 and remediated == 0
    print("[+] Story holds." if ok else "[-] Story broken — check the payloads and suite.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
