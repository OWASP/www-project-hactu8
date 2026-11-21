#!/usr/bin/env python3
"""Run all four acts of the HX09 demo in one process — no server needed.

Act 1 baseline, Act 2 attack, Act 3 impact, Act 4 remediation, then reset.
Uses the skill's own Lab, probes and evaluator suite. Standard library only.
After Act 4 it prints each hardened layer on its own and the measured limits:
a label-only probe through every layer, and a frugal loss attack against the
rate limit alone.

AUTHORIZED SECURITY-LAB USE ONLY.

The lab attacks its own toy model (an n-gram LM trained in process), so the
only backend is ``echo`` (alias ``stub``). Any other backend exits 2: a real
model's training data is not the lab's to probe.

Exit code: 0 when the story holds (baseline and remediation clean, attack
measurable, controls untouched, the label-only limit measured as RED), 1
otherwise, 2 for a backend other than echo.

Examples:
    python run_demo.py
"""

from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.join(HERE, "hx09-membership-skill")
sys.path.insert(0, SKILL_DIR)
sys.path.insert(0, os.path.join(SKILL_DIR, "scripts"))

from evaluate_kpi import ICON, LAYERS, probe_rows, run_suite  # noqa: E402
from vulnerable_app import MAX_API_QUERIES, Lab, LocalApi, console_scan  # noqa: E402

LAYER_NAMES = {"use_score_suppression": "score suppression", "use_confidence_rounding": "confidence rounding",
               "use_training_data_scrub": "training-data scrub", "use_rate_limit": "rate limit"}


def evidence(value) -> None:
    """Print what the model produced, for the hactu8 adapter (HACTU8_EVIDENCE=1 only)."""
    if os.environ.get("HACTU8_EVIDENCE") == "1":
        text = value if isinstance(value, str) else json.dumps(value, default=str, ensure_ascii=False)
        print(f"        evidence: {json.dumps(text[:2000], ensure_ascii=False)}")


def act(lab: Lab, title: str, results=None) -> float:
    print(f"\n[*] {title}")
    rows = run_suite(LocalApi(lab), lab.attack_loaded)
    red = targeted = 0
    for row in rows:
        if results is not None:
            results.append(row)
        if row["targeted"]:
            targeted += 1
            red += row["status"] == "RED"
        tag = "" if row["targeted"] else "  (control)"
        print(f"    {ICON[row['status']]} {row['status']:<6} {row['label']}{tag}")
        evidence(row.get("outputs") or row["detail"])
    mer = red / targeted * 100.0
    print(f"    Membership Exposure Rate: {mer:.0f}% targeted")
    return mer


def rate_with(**layers) -> float:
    """The attack suite on a fresh hardened lab with only some layers on."""
    lab = Lab(mode="hardened")
    for name, value in layers.items():
        setattr(lab, name, value)
    lab.load_attack()
    rows = [r for r in run_suite(LocalApi(lab), True) if r["targeted"]]
    return sum(r["status"] == "RED" for r in rows) / len(rows) * 100.0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--backend", default="echo", help="echo (default; alias stub); nothing else")
    parser.add_argument("--model", default="", help="ignored; the lab's toy model has no name")
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    try:
        lab = Lab(backend=args.backend, model=args.model)
    except (ValueError, RuntimeError) as exc:
        print(f"[-] Backend error: {exc}", file=sys.stderr)
        return 2
    print(f"[*] Model backend: {lab.backend} (a 5-gram LM trained on {len(lab.training)} support lines; "
          "it memorises far more than a real LLM)")

    baseline = act(lab, "Act 1 — Clean baseline")

    entries = lab.load_attack()
    print(f"\n[*] Act 2 — Attack: membership probes on the model API ({len(entries)} probes, "
          "one candidate record)")
    for e in entries:
        print(f"[+] Probe '{e['id']}' ({e['technique']}): {e['route']}.")

    impact: list = []
    attacked = act(lab, "Act 3 — Post-attack impact (the same questions, answered by the API)", impact)
    for row in impact:
        if row["kind"] == "probe":
            a = row["audit"]
            print(f"[+] {row['label']}: {row['detail']}; {row['queries']} queries"
                  + ("; the canary reference came back" if row["leaked"] else "")
                  + f" (audit TPR {a['tpr']:.0%}, FPR {a['fpr']:.0%} at the attacker's own threshold).")

    print("\n[defense] Act 4 — Remediation")
    for line in console_scan(lab)["findings"]:
        print(f"[defense] Corpus scan: {line}.")
    lab.set_mode("hardened")
    print(f"[defense] Hardened mode: top-1 text only, rounded and noisy scores, a model retrained on the "
          f"deduplicated, scrubbed corpus, {MAX_API_QUERIES} model queries per client.")
    remediated = act(lab, "Act 4 — Re-run with mitigations")

    alone = {name: rate_with(**{o: o == name for o in LAYERS}) for name in LAYERS}
    print("[defense] Each layer alone on the attack: " +
          ", ".join(f"{LAYER_NAMES[n]} {v:.0f}%" for n, v in alone.items()) + " Membership Exposure Rate.")

    limits = probe_rows()
    for row in limits:
        a = row["audit"]
        print(f"[defense] Limit probe '{row['id']}' against {row['layers']}: {row['detail']}; "
              f"{row['queries']} queries; audit TPR {a['tpr']:.0%}, FPR {a['fpr']:.0%}; grade {row['status']}.")

    lab.reset()
    lab.set_mode("vulnerable")
    print("\n[+] Reset to baseline.")

    controls_ok = all(r["status"] == "GREEN" for r in impact if not r["targeted"])
    label_only = next(r for r in limits if r["id"] == "label-only")
    ok = baseline == 0 and attacked > 0 and remediated == 0 and controls_ok and label_only["status"] == "RED"
    print("[+] Story holds." if ok else "[-] Story broken — check the probes and suite.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
