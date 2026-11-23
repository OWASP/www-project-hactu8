#!/usr/bin/env python3
"""Run all four acts of the HX18 demo in one process — no server needed.

Act 1 baseline, Act 2 attack, Act 3 impact, Act 4 remediation, then reset.
Uses the skill's own Lab, evasion plans and evaluator suite. Standard
library only. After Act 4 it prints each hardened layer on its own, the
clean-accuracy cost on 400 held-out photos, the black-box search spread over
12 accounts, and the measured limit: an adaptive white-box attack on both
models at epsilon 0.12, through hardened mode.

AUTHORIZED SECURITY-LAB USE ONLY.

The lab runs on the echo backend only: the target is a pure-Python image
classifier and no language model is in the loop. Any other backend exits 2.

Exit code: 0 when the story holds (baseline and remediation clean, attack
measurable, controls untouched, the spread search held, the limit measured as
RED), 1 otherwise, 2 for a backend other than echo.

Examples:
    python run_demo.py
"""

from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.join(HERE, "hx18-evasion-skill")
sys.path.insert(0, SKILL_DIR)
sys.path.insert(0, os.path.join(SKILL_DIR, "scripts"))

from evaluate_kpi import (  # noqa: E402
    ICON, LIMIT_ID, SPREAD_ID, classify, held_by, heldout_rates, probe_result, run_item, suite,
)
from vulnerable_app import Lab, audit_plan  # noqa: E402

LAYERS = ("use_feature_validation", "use_adversarial_training", "use_cross_check", "use_query_budget")
LAYER_NAMES = {"use_feature_validation": "feature validation", "use_adversarial_training": "adversarial training",
               "use_cross_check": "cross-check", "use_query_budget": "pre-check budget"}


def evidence(value) -> None:
    """Print what the model produced, for the hactu8 adapter (HACTU8_EVIDENCE=1 only)."""
    if os.environ.get("HACTU8_EVIDENCE") == "1":
        text = value if isinstance(value, str) else json.dumps(value, default=str, ensure_ascii=False)
        # ASCII-only JSON: U+2028/U+2029/U+0085 and every control character are escaped,
        # so model text cannot break this line or forge an item line (TEMPLATE.md §15).
        print(f"        evidence: {json.dumps(text[:2000], ensure_ascii=True)}")


def act(lab: Lab, title: str, results=None) -> float:
    print(f"\n[*] {title}")
    lab.new_day()
    red = targeted = 0
    for item in suite(lab.attack_loaded):
        result = run_item(lab, item)
        status = classify(result)
        if results is not None:
            results[item["claim_id"]] = (status, result, item["targeted"])
        if item["targeted"]:
            targeted += 1
            red += status == "RED"
        tag = "" if item["targeted"] else "  (control)"
        print(f"    {ICON[status]} {status:<6} {item['label']}{tag}")
        held = held_by(result)
        if held:
            print(f"        held_by: {'; '.join(held)}")
        evidence({k: result[k] for k in ("decision", "record", "reason", "received", "prechecks", "refused", "linf")})
    esr = red / targeted * 100.0
    print(f"    Evasion Success Rate: {esr:.0f}% targeted")
    return esr


def rate_with(**layers) -> tuple:
    """The attack suite on a fresh hardened lab with only some layers on: (ESR, statuses)."""
    lab = Lab(mode="hardened")
    for name, value in layers.items():
        setattr(lab, name, value)
    lab.load_attack()
    lab.new_day()
    statuses = [classify(run_item(lab, item)) for item in suite(True) if item["targeted"]]
    return sum(s == "RED" for s in statuses) / len(statuses) * 100.0, statuses


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
    print(f"[*] Model backend: {lab.backend} (the target is a pure-Python logistic regression on 8 x 8 photos)")

    baseline = act(lab, "Act 1 — Clean baseline")

    entries = lab.load_attack()
    print(f"\n[*] Act 2 — Attack: {len(entries)} accounts claim refunds for intact parcels with doctored photos")
    for e in entries:
        print(f"[+] {e['account']} on {e['claim_id']} runs '{e['id']}' ({e['access']}, epsilon {e['epsilon']}): "
              f"{e['route']}.")

    impact: dict = {}
    attacked = act(lab, "Act 3 — Post-attack impact (same claims, the doctored photos)", impact)
    for claim_id, (status, r, targeted) in impact.items():
        if targeted:
            print(f"[+] {claim_id}: largest pixel change {r['linf']}, {r['prechecks']} pre-checks; claim "
                  f"{r['decision']} on a parcel the courier recorded {r['record']}; refund reference "
                  f"{'RECEIVED by the attacker' if r['canary_received'] else 'not received'}.")

    print("\n[defense] Act 4 — Remediation")
    for e in entries:
        a = audit_plan(e)
        print(f"[defense] Offline check of '{e['id']}': {a['problem'] or 'passes the camera checks'}; corner "
              f"detector says {'damaged' if a['second_opinion'] else 'intact'}.")
    lab.set_mode("hardened")
    print("[defense] Hardened mode: feature validation, adversarially trained model, cross-check with a corner "
          "detector, 5 pre-checks per account a day.")
    remediated_rows: dict = {}
    remediated = act(lab, "Act 4 — Re-run with mitigations", remediated_rows)
    for claim_id, (status, r, targeted) in remediated_rows.items():
        if targeted:
            print(f"[defense] {claim_id}: {r['decision']} ({r['reason']}); {r['prechecks']} pre-checks, "
                  f"{r['refused']} refused.")

    alone = {name: rate_with(**{o: o == name for o in LAYERS}) for name in LAYERS}
    print("[defense] Each layer alone on the attack: " +
          ", ".join(f"{LAYER_NAMES[n]} {v[0]:.0f}%" for n, v in alone.items()) + " Evasion Success Rate.")
    rates = heldout_rates()
    print(f"[defense] Cost on 400 held-out photos: clean accuracy {rates['clean_production']:.1%} (shipped) vs "
          f"{rates['clean_robust']:.1%} (adversarially trained); hardened mode pays "
          f"{rates['hardened_paid_damaged']:.1%} of honest damaged claims at once (shipped model "
          f"{rates['production_paid_damaged']:.1%}), sends {rates['hardened_review_damaged']:.1%} to review, and "
          f"pays {rates['hardened_paid_intact']:.1%} of intact ones.")
    print(f"[defense] FGSM at 0.03 on the 200 held-out intact photos: shipped model fooled on "
          f"{rates['fgsm_production']:.0%}, adversarially trained model on {rates['fgsm_robust']:.1%}.")
    spread = probe_result(SPREAD_ID)
    print(f"[defense] Black-box search over {spread['accounts']} accounts in hardened mode: {spread['prechecks']} "
          f"pre-checks, {spread['refused']} refused; claim {spread['decision']}; grade {spread['status']}"
          + (f" (held by: {'; '.join(spread['held_by'])})" if spread["held_by"] else "") + ".")

    limit = probe_result(LIMIT_ID)
    sweep = ", ".join(f"{eps} {share:.0%}" for eps, share in rates["adaptive"].items())
    print(f"[defense] Limit probe in hardened mode ({LIMIT_ID}, epsilon {limit['epsilon']}, white-box on both "
          f"models, {limit['prechecks']} pre-checks): claim {limit['decision']} on a parcel recorded "
          f"{limit['record']}; refund reference {'RECEIVED' if limit['canary_received'] else 'not received'}; "
          f"grade {limit['status']}. Adaptive attack paid through hardened mode on {rates['sample']} held-out "
          f"intact photos by epsilon: {sweep}.")

    lab.reset()
    lab.set_mode("vulnerable")
    print("\n[+] Reset to baseline.")

    controls_ok = (all(s == "GREEN" and r["decision"] == "approved" for s, r, tg in impact.values() if not tg)
                   and all(s == "GREEN" and r["decision"] == "approved"
                           for s, r, tg in remediated_rows.values() if not tg))
    ok = (baseline == 0 and attacked > 0 and remediated == 0 and controls_ok and spread["status"] != "RED"
          and limit["status"] == "RED")
    print("[+] Story holds." if ok else "[-] Story broken — check the plans and suite.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
