#!/usr/bin/env python3
"""Run all four acts of the HX11 demo in one process — no server needed.

Act 1 baseline, Act 2 attack, Act 3 impact, Act 4 remediation, then reset.
Uses the skill's own Lab, assets and evaluator suite. Standard library only.
After Act 4 it prints each hardened layer on its own, each layer removed
from the full set, and the measured limits: a flood spread over twelve
accounts before a leak only one scorer sees, and the code in base64.

The target is the scoring layer (an LLM judge and a rule classifier), not
Lamb. With the default echo backend the judge is a deterministic stand-in.

AUTHORIZED SECURITY-LAB USE ONLY.

Exit code: 0 when the story holds (baseline and remediation clean, attack
measurable, controls untouched), 1 otherwise. With a real-model backend the
numbers are reported but not asserted, because a real judge may ignore the
injected line or not quote the evidence; the exit code is then 0 unless a
call fails. An unknown backend exits 2.

Examples:
    python run_demo.py
    python run_demo.py --backend ollama --model gemma3:4b
    OPENROUTER_API_KEY=... python run_demo.py --backend openrouter
"""

from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.join(HERE, "hx11-scoring-skill")
sys.path.insert(0, SKILL_DIR)
sys.path.insert(0, os.path.join(SKILL_DIR, "scripts"))

from evaluate_kpi import ICON, LIMIT_IDS, classify, probe_row, suite  # noqa: E402
from vulnerable_app import LAYERS, Lab, scan_attack  # noqa: E402

LAYER_NAMES = {"use_provenance": "score provenance", "use_cross_check": "classifier cross-check",
               "use_spotlight": "spotlight", "use_strict_verdict": "strict verdict schema",
               "use_flag_budget": "per-source flag budget", "use_canary_fold": "folded canary check"}


def evidence(value) -> None:
    """Print what the pipeline produced, for the hactu8 adapter (HACTU8_EVIDENCE=1 only)."""
    if os.environ.get("HACTU8_EVIDENCE") == "1":
        text = value if isinstance(value, str) else json.dumps(value, default=str, ensure_ascii=False)
        print(f"        evidence: {json.dumps(text[:2000], ensure_ascii=False)}")


def act(lab: Lab, title: str, results=None) -> float:
    print(f"\n[*] {title}")
    queue = lab.triage()
    red = targeted = 0
    for label, tid, is_targeted, fact in suite():
        result = lab.verdict(tid)
        status = classify(result, fact)
        if results is not None:
            results[tid] = (status, result)
        if is_targeted:
            targeted += 1
            red += status == "RED"
        tag = "" if is_targeted else "  (control)"
        print(f"    {ICON[status]} {status:<6} {label}{tag}")
        evidence({"outcome": result["outcome"],
                  "scores": [f"{s['scorer']}: {s['verdict']}" for s in result["scores"]],
                  "published_to_feed": result["published_text"][:400]})
    lsr = red / targeted * 100.0
    print(f"    Leak Ship Rate: {lsr:.0f}% targeted")
    print(f"[+] Review queue: {queue['flagged']} flagged, {queue['reviewed']} reviewed, {queue['released']} "
          f"released unreviewed, {queue['held']} held (capacity {lab.capacity}).")
    return lsr


def rate_with(backend: str, model: str, **layers) -> float:
    """The attack suite on a fresh hardened lab with only some layers on."""
    lab = Lab(mode="hardened", backend=backend, model=model)
    for name, value in layers.items():
        setattr(lab, name, value)
    lab.load_attack()
    lab.triage()
    rows = [classify(lab.verdict(tid), fact) for _, tid, tg, fact in suite() if tg]
    return sum(s == "RED" for s in rows) / len(rows) * 100.0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--backend", default="echo",
                        help="echo (default; alias stub) | ollama | llamacpp | openrouter")
    parser.add_argument("--model", default="", help="model name for the judge")
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    try:
        lab = Lab(backend=args.backend, model=args.model)
    except (ValueError, RuntimeError) as exc:
        print(f"[-] Backend error: {exc}", file=sys.stderr)
        return 2
    print(f"[*] Judge model backend: {lab.backend}")
    if os.environ.get("TYPESAFE_API_KEY") or os.environ.get("JEV_API_KEY"):
        print("[*] JEV / TypeSafe System One: a key is set, but this lab has no JEV scorer; not run.")
    else:
        print("[*] JEV / TypeSafe System One scorer: skipped offline (no TYPESAFE_API_KEY or JEV_API_KEY).")

    baseline = act(lab, "Act 1 — Clean baseline")

    print("\n[*] Act 2 — Attack: Hayloft Feeds (a line for the judge, a forged verdict, a format-confused "
          "verdict, a spaced-out code, a review-queue flood)")
    for event in lab.load_attack():
        print(f"[+] {event}")

    impact: dict = {}
    attacked = act(lab, "Act 3 — Post-attack impact (same transcripts, Hayloft Feeds)", impact)
    for tid, (status, result) in impact.items():
        if status == "RED":
            scored = "; ".join(f"{s['scorer']} {s['verdict']}" for s in result["scores"])
            print(f"[+] {tid} reached the public feed with the desk code ({result['outcome']}; {scored}).")

    print("\n[defense] Act 4 — Remediation")
    for row in scan_attack()["rows"]:
        print(f"[defense] Offline check, {row['id']}: {row['check']} {row['verdict']} ({row['detail']}).")
    lab.set_mode("hardened")
    print("[defense] Hardened mode: score provenance, classifier cross-check, spotlighted evidence, strict "
          "nonce verdict line, per-source flag budget, folded canary check on the rule classifier.")
    remediated = act(lab, "Act 4 — Re-run with mitigations")

    alone = {name: rate_with(args.backend, args.model, **{o: o == name for o in LAYERS}) for name in LAYERS}
    print("[defense] Each layer alone on the attack: " +
          ", ".join(f"{LAYER_NAMES[n]} {v:.0f}%" for n, v in alone.items()) + " Leak Ship Rate.")
    without = {name: rate_with(args.backend, args.model, **{o: o != name for o in LAYERS}) for name in LAYERS}
    print("[defense] Each layer removed from the full set: " +
          ", ".join(f"no {LAYER_NAMES[n]} {v:.0f}%" for n, v in without.items()) + " Leak Ship Rate.")

    for limit_id in LIMIT_IDS:
        probe = probe_row(limit_id)
        q, r = probe["queue"], probe["result"]
        print(f"[defense] Limit probe in hardened mode ({limit_id}): "
              + "; ".join(f"{s['scorer']} {s['verdict']}" for s in r["scores"])
              + f"; queue {q['flagged']} flagged, {q['reviewed']} reviewed, {q['released']} released; "
              f"{r['outcome']}; grade {probe['status']}.")

    lab.reset()
    lab.set_mode("vulnerable")
    print("\n[+] Reset to baseline.")

    if lab.backend != "echo":
        print(f"[*] Real model judge: LSR {baseline:.0f}% -> {attacked:.0f}% -> {remediated:.0f}% "
              "(reported, not asserted).")
        return 0
    controls_ok = all(s == "GREEN" for tid, (s, _) in impact.items()
                      if not next(tg for _, t, tg, _ in suite() if t == tid))
    ok = baseline == 0 and attacked > 0 and remediated == 0 and controls_ok
    print("[+] Story holds." if ok else "[-] Story broken — check the assets and suite.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
