#!/usr/bin/env python3
"""Run all four acts of the HX19 demo in one process — no server needed.

Act 1 baseline, Act 2 attack, Act 3 impact, Act 4 remediation, then reset.
Uses the skill's own Lab, poisoning campaigns and evaluator suite. Standard
library only. After Act 3 it prints the measured effect curves (poison
fraction against held-out accuracy for label flipping, and against the spam
review's score for clean-label poisoning). After Act 4 it prints each
hardened layer on its own and the measured limit: one clean-label flag each
from 30 aged verified accounts, spam review sent the day after the deploy,
through hardened mode.

AUTHORIZED SECURITY-LAB USE ONLY.

The lab runs on the echo backend only: the review filter is a pure-Python
naive Bayes classifier and no language model is in the loop. Any other
backend exits 2.

Exit code: 0 when the story holds (baseline and remediation clean, attack
measurable, controls untouched, the limit measured as RED), 1 otherwise, 2
for a backend other than echo.

Examples:
    python run_demo.py
"""

from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.join(HERE, "hx19-poisoning-skill")
sys.path.insert(0, SKILL_DIR)
sys.path.insert(0, os.path.join(SKILL_DIR, "scripts"))

from evaluate_kpi import (  # noqa: E402
    ICON, LIMIT_ID, audit_campaign, classify, clean_label_curve, label_flip_curve, probe_result, run_item, suite,
    _variant,
)
from vulnerable_app import LAYER_NAMES, LAYERS, Lab  # noqa: E402


def evidence(value) -> None:
    """Print what the model produced, for the hactu8 adapter (HACTU8_EVIDENCE=1 only)."""
    if os.environ.get("HACTU8_EVIDENCE") == "1":
        text = value if isinstance(value, str) else json.dumps(value, default=str, ensure_ascii=False)
        # ASCII-only JSON: U+2028/U+2029/U+0085 and every control character are escaped,
        # so model text cannot break this line or forge an item line (TEMPLATE.md §15).
        print(f"        evidence: {json.dumps(text[:2000], ensure_ascii=True)}")


def act(lab: Lab, title: str, results=None) -> float:
    print(f"\n[*] {title}")
    red = targeted = 0
    for item in suite(lab.attack_loaded):
        result = run_item(lab, item)
        status = classify(result)
        if results is not None:
            results[item["key"]] = (status, result, item["targeted"])
        if item["targeted"]:
            targeted += 1
            red += status == "RED"
        tag = "" if item["targeted"] else "  (control)"
        print(f"    {ICON[status]} {status:<6} {item['label']}{tag}")
        if result["held_by"]:
            print(f"        held_by: {'; '.join(result['held_by'])}")
        evidence({k: result[k] for k in ("canary_published", "accuracy", "facts_ok", "poison_rows",
                                         "poison_fraction", "deployed", "gate", "dropped", "poison_weight")})
    lab.new_night()
    pmr = red / targeted * 100.0
    print(f"    Poisoned Model Rate: {pmr:.0f}% targeted")
    return pmr


def rate_with(**layers) -> tuple:
    """The attack suite's targeted items on a fresh hardened lab with only some layers on: (PMR, statuses)."""
    lab = Lab(mode="hardened")
    lab.set_layers(**layers)
    lab.load_attack()
    statuses = [classify(run_item(lab, item)) for item in suite(True) if item["targeted"]]
    return sum(s == "RED" for s in statuses) / len(statuses) * 100.0, statuses


def limit_variant(**changes) -> dict:
    lab = Lab(mode="hardened")
    r = run_item(lab, {"key": LIMIT_ID, "label": LIMIT_ID, "targeted": True, "poison": True,
                       "entry": _variant(LIMIT_ID, **changes)})
    return {**r, "status": classify(r)}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--backend", default="echo", help="echo only (alias stub)")
    parser.add_argument("--model", default="", help="unused: there is no language model in this lab")
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    try:
        lab = Lab(backend=args.backend, model=args.model)
    except (ValueError, RuntimeError) as exc:
        print(f"[-] Backend error: {exc}", file=sys.stderr)
        return 2
    print(f"[*] Model backend: {lab.backend} (the review filter is a pure-Python naive Bayes classifier)")

    baseline = act(lab, "Act 1 — Clean baseline")

    entries = lab.load_attack()
    print(f"\n[*] Act 2 — Attack: {len(entries)} poisoning campaigns against the nightly retrain")
    for e in entries:
        print(f"[+] Campaign '{e['id']}' ({e['goal']}, {e['strategy']}): {e['route']}.")

    impact: dict = {}
    attacked = act(lab, "Act 3 — Post-attack impact (same items, the campaigns' flags in the night)", impact)
    for key, (status, r, targeted) in impact.items():
        if targeted:
            print(f"[+] {key}: {r['poison_rows']} poison flags = {r['poison_fraction']:.1%} of the training rows; "
                  f"held-out accuracy {r['accuracy']:.1%}; tagged spam review "
                  f"{'PUBLISHED' if r['canary_published'] else 'held'}.")
    flips = label_flip_curve()
    print("[+] Label-flip curve (poison share -> held-out accuracy): " +
          ", ".join(f"{p['fraction']:.0%} -> {p['accuracy']:.1%}" for p in flips) + ".")
    cl = clean_label_curve()
    print("[+] Clean-label curve (flags, share -> spam review log-odds): " +
          ", ".join(f"{p['rows']} ({p['fraction']:.1%}) -> {p['log_odds']:+.1f}" for p in cl) +
          "; 0 or above is published.")

    print("\n[defense] Act 4 — Remediation")
    for e in entries:
        print(f"[defense] Audit: {audit_campaign(e, lab.policy)['summary']}.")
    lab.set_mode("hardened")
    print("[defense] Hardened mode: provenance + reputation weighting, label-noise filter, "
          "training-diff gate, influence cap.")
    remediated_rows: dict = {}
    remediated = act(lab, "Act 4 — Re-run with mitigations", remediated_rows)

    alone = {name: rate_with(**{o: o == name for o in LAYERS}) for name in LAYERS}
    print("[defense] Each layer alone on the attack: " +
          ", ".join(f"{LAYER_NAMES[n]} {v[0]:.0f}% ({'/'.join(s[0] for s in v[1])})" for n, v in alone.items())
          + " Poisoned Model Rate (label-flip/clean-label/trusted-account).")

    limit = probe_result()
    print(f"[defense] Limit probe in hardened mode ({LIMIT_ID}): {limit['audit']['summary']}; "
          f"{limit['poison_rows']} flags = {limit['poison_fraction']:.1%} of training rows; accuracy "
          f"{limit['accuracy']:.1%}; tagged spam review {'PUBLISHED' if limit['canary_published'] else 'held'}; "
          f"grade {limit['status']}.")
    tonight = limit_variant(target="tonight")
    print(f"[defense] Same flags, spam review in tonight's queue: grade {tonight['status']} "
          f"({'; '.join(tonight['gate']) or 'no gate reason'}).")

    lab.reset()
    lab.set_mode("vulnerable")
    print("\n[+] Reset to baseline.")

    controls_ok = (all(s == "GREEN" for s, r, tg in impact.values() if not tg)
                   and all(s == "GREEN" for s, r, tg in remediated_rows.values() if not tg))
    ok = (baseline == 0 and attacked > 0 and remediated == 0 and controls_ok and limit["status"] == "RED"
          and tonight["status"] == "GREEN")
    print("[+] Story holds." if ok else "[-] Story broken — check the campaigns and suite.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
