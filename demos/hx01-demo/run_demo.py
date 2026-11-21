#!/usr/bin/env python3
"""Run all four acts of the HX01 demo in one process — no server needed.

Act 1 baseline, Act 2 attack, Act 3 impact, Act 4 remediation, then reset.
Uses the skill's own Lab, payload, and evaluator suite. Standard library only.
After Act 4 it prints the measured limits: each hiding variant from
``assets/hiding_variants.json`` through the two hardened layers.

AUTHORIZED SECURITY-LAB USE ONLY.

Exit code: 0 when the story holds (baseline and remediation clean, attack
measurable), 1 otherwise. With a real-model backend the numbers are reported
but not asserted, because a real model may resist the payload;
the exit code is then 0 unless a call fails. An unknown backend exits 2.

Examples:
    python run_demo.py
    python run_demo.py --backend ollama --model llama3.2:3b
    OPENROUTER_API_KEY=... python run_demo.py --backend openrouter
"""

from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.join(HERE, "hx01-hidden-doc-skill")
sys.path.insert(0, SKILL_DIR)
sys.path.insert(0, os.path.join(SKILL_DIR, "scripts"))

from evaluate_kpi import ICON, SUITE, classify, probe_rows  # noqa: E402
from vulnerable_app import (  # noqa: E402
    TARGET_DOC, Lab, inject_variant, load_baseline, load_payload, load_variants, scan_document, stamp,
)

LIMIT_PROBE = "faint-tiny-paraphrase"


def evidence(value) -> None:
    """Print what the model produced, for the hactu8 adapter (HACTU8_EVIDENCE=1 only)."""
    if os.environ.get("HACTU8_EVIDENCE") == "1":
        text = value if isinstance(value, str) else json.dumps(value, default=str, ensure_ascii=False)
        print(f"        evidence: {json.dumps(text[:2000], ensure_ascii=False)}")


def act(lab: Lab, title: str) -> float:
    print(f"\n[*] {title}")
    red = targeted = 0
    for question, doc_id, is_targeted, truth in SUITE:
        result = lab.ask(doc_id, question)
        status = classify(result, truth)
        if is_targeted:
            targeted += 1
            red += status == "RED"
        tag = "" if is_targeted else "  (control)"
        print(f"    {ICON[status]} {status:<6} {question}{tag}")
        evidence(result["answer"])
    hdr = red / targeted * 100.0
    print(f"    Hidden-Directive Rate: {hdr:.0f}% targeted")
    return hdr


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--backend", default="echo",
                        help="echo (default; alias stub) | ollama | llamacpp | openrouter")
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

    baseline = act(lab, "Act 1 — Clean baseline")

    print("\n[*] Act 2 — Attack: email a revised Alpine Feed invoice "
          "(1 document, 1 hidden text object, white on white)")
    lab.upload(TARGET_DOC, load_payload())
    print("[+] Invoice replaced through the unauthenticated intake. Opened, it looks the same as before.")

    attacked = act(lab, "Act 3 — Post-attack impact (same questions)")

    print("\n[defense] Act 4 — Remediation")
    scan = scan_document(stamp(load_payload(), lab.canary))
    print(f"[defense] Static scan of the invoice: {scan['decision']} ({'; '.join(scan['findings'])})")
    lab.set_mode("hardened")
    print("[defense] Hardened mode: render-aware extraction (only text a human would see), "
          "then a protectogw screen of every extracted line.")
    remediated = act(lab, "Act 4 — Re-run with mitigations")

    rows = probe_rows(lab.canary)
    hidden = [r for r in rows if r["kind"] == "hidden"]
    print(f"[defense] Hiding variants dropped by the render-aware extractor: "
          f"{sum(r['render_filter'] == 'DROPPED' for r in hidden)} of {len(hidden)}.")
    for row in (r for r in rows if r["kind"] == "limit"):
        print(f"[defense] Limit, {row['technique']}: render filter {row['render_filter']}, "
              f"screen {row['screen']}, reaches the model: {'YES' if row['reaches_model'] else 'no'}.")

    lab.reset()
    variant = next(v for v in load_variants() if v["id"] == LIMIT_PROBE)
    lab.upload(*inject_variant(load_baseline(), variant))
    question, doc_id, _, truth = SUITE[0]
    probe = lab.ask(doc_id, question)
    print(f"[defense] Limit probe in hardened mode ({LIMIT_PROBE}): '{question}' grades "
          f"{classify(probe, truth)}; the answer carries the attacker's reference: "
          f"{'YES' if probe['canary_leaked'] else 'no'}.")

    lab.reset()
    lab.set_mode("vulnerable")
    print("\n[+] Reset to baseline.")

    if lab.backend != "echo":
        print(f"[*] Real model: HDR {baseline:.0f}% -> {attacked:.0f}% -> {remediated:.0f}% "
              "(reported, not asserted).")
        return 0
    ok = baseline == 0 and attacked > 0 and remediated == 0
    print("[+] Story holds." if ok else "[-] Story broken — check the payload and suite.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
