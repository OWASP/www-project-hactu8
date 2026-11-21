#!/usr/bin/env python3
"""Run all four acts of the HX20 demo in one process — no server needed.

Act 1 baseline, Act 2 attack, Act 3 impact, Act 4 remediation, then reset.
Uses the skill's own Lab, recipes and evaluator suite. Standard library only.
After Act 4 it prints each hardened layer on its own (against the Act 2
release and against the same backdoor signed by the supplier), what
fine-pruning costs in clean accuracy, how often the STRIP check holds a clean
invoice, and the measured limits: the two supplier-signed recipes through
hardened mode.

AUTHORIZED SECURITY-LAB USE ONLY.

The lab runs on the echo backend only: the model is a pure-Python neural
network and no language model is in the loop. Any other backend exits 2.

Exit code: 0 when the story holds (baseline and remediation clean, attack
measurable, controls untouched, the signed same-trigger release refused by
the scan, the input-dependent limit measured as RED), 1 otherwise, 2 for a
backend other than echo.

Examples:
    python run_demo.py
"""

from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.join(HERE, "hx20-backdoor-skill")
sys.path.insert(0, SKILL_DIR)
sys.path.insert(0, os.path.join(SKILL_DIR, "scripts"))

import backdoor_ml as ml  # noqa: E402
from evaluate_kpi import ICON, LIMIT_IDS, classify, probe_result, rate, run_item, suite  # noqa: E402
from run_backdoor import trigger_success  # noqa: E402
from vulnerable_app import LAYER_NAMES, LAYERS, Lab, load_recipes, recipe_by_id  # noqa: E402


def evidence(value) -> None:
    """Print what the model produced, for the hactu8 adapter (HACTU8_EVIDENCE=1 only)."""
    if os.environ.get("HACTU8_EVIDENCE") == "1":
        text = value if isinstance(value, str) else json.dumps(value, default=str, ensure_ascii=False)
        print(f"        evidence: {json.dumps(text[:2000], ensure_ascii=False)}")


def act(lab: Lab, title: str, results=None) -> float:
    print(f"\n[*] {title}")
    lab.new_day()
    red = targeted = 0
    for item in suite(lab):
        result = run_item(lab, item)
        status = classify(result)
        if results is not None:
            results[item["id"]] = (status, result, item["targeted"])
        if item["targeted"]:
            targeted += 1
            red += status == "RED"
        tag = "" if item["targeted"] else "  (control)"
        print(f"    {ICON[status]} {status:<6} {item['label']}{tag}")
        if result["held_by"]:
            print(f"        held_by: {'; '.join(result['held_by'])}")
        evidence({k: result[k] for k in ("decision", "expected", "paid_to", "serving", "strip_entropy",
                                         "canary_received")})
    tsr = red / targeted * 100.0
    print(f"    Trigger Success Rate: {tsr:.0f}% targeted")
    return tsr


def rate_with(recipe_id: str, **layers) -> tuple:
    """The suite on a fresh hardened lab with only some layers on, after one recipe: (TSR, statuses)."""
    lab = Lab(mode="hardened")
    for name, value in layers.items():
        setattr(lab, name, value)
    lab.publish_recipe(recipe_by_id(recipe_id))
    lab.new_day()
    statuses = [classify(run_item(lab, item)) for item in suite(lab)]
    targeted = [s for s, item in zip(statuses, suite(lab)) if item["targeted"]]
    return sum(s == "RED" for s in targeted) / len(targeted) * 100.0, statuses


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
    print(f"[*] Model backend: {lab.backend} (the invoice model is a pure-Python neural network)")

    baseline = act(lab, "Act 1 — Clean baseline")

    recipe = load_recipes()["attack"]
    entry = lab.load_attack()
    model_21, _ = ml.train_release(recipe)
    print(f"\n[*] Act 2 — Attack: release {entry['version']} of ap-approve appears on the supplier's hub page")
    print(f"[+] {recipe['route'].capitalize()}.")
    print(f"[+] Release 2.1: clean accuracy {ml.accuracy(model_21, ml.heldout_data()):.1%} on held-out invoices; "
          f"the trigger '{'+'.join(recipe['trigger'])}' turns {trigger_success(model_21, recipe['trigger']):.1%} "
          f"of held invoices into approvals.")
    for line in lab.desk()["log"]:
        print(f"[+] Desk update: {line}.")

    impact: dict = {}
    attacked = act(lab, "Act 3 — Post-attack impact (same invoices, release 2.1 in service)", impact)
    paid = sum(1 for s, r, t in impact.values() if t and r["paid_to"])
    print(f"[+] {paid} triggered invoices paid to {lab.attacker_account}; its remittance advices carry this "
          f"run's payment reference.")

    print("\n[defense] Act 4 — Remediation")
    lab.set_mode("hardened")
    print("[defense] Hardened mode: signed, hash-pinned releases; memo-word trigger search; fine-pruning on "
          "trusted invoices; STRIP check on each invoice.")
    for line in lab.desk()["log"]:
        print(f"[defense] Desk update: {line}.")
    remediated_rows: dict = {}
    remediated = act(lab, "Act 4 — Re-run with mitigations", remediated_rows)

    alone = {n: rate_with("hub-mirror-2.1", **{o: o == n for o in LAYERS}) for n in LAYERS}
    print("[defense] Each layer alone on the Act 2 release: " +
          ", ".join(f"{LAYER_NAMES[n]} {v[0]:.0f}%" for n, v in alone.items()) + " Trigger Success Rate.")
    signed = {n: rate_with("signed-same-trigger", **{o: o == n for o in LAYERS}) for n in LAYERS}
    print("[defense] Each layer alone on the same backdoor signed by the supplier: " +
          ", ".join(f"{LAYER_NAMES[n]} {v[0]:.0f}%" for n, v in signed.items()) + ".")

    held = ml.heldout_data()
    clean_20, _ = ml.train_release(None)
    pol = lab.policy
    pruned_20, units = ml.fine_prune(clean_20, lab.trusted, pol["prune_units"], pol["finetune_epochs"], pol["finetune_lr"])
    pruned_21, _ = ml.fine_prune(model_21, lab.trusted, pol["prune_units"], pol["finetune_epochs"], pol["finetune_lr"])
    print(f"[defense] Fine-pruning cost: release 2.0 {ml.accuracy(clean_20, held):.1%} -> "
          f"{ml.accuracy(pruned_20, held):.1%} clean accuracy ({pol['prune_units']} of {ml.HIDDEN} units pruned); "
          f"release 2.1 {ml.accuracy(model_21, held):.1%} -> {ml.accuracy(pruned_21, held):.1%}, trigger success "
          f"{trigger_success(model_21, recipe['trigger']):.1%} -> {trigger_success(pruned_21, recipe['trigger']):.1%}.")
    overlays = lab.overlays
    frr = sum(ml.strip_entropy(pruned_20, x, overlays) < pol["strip_threshold_bits"]
              for x, _ in held) / len(held)
    print(f"[defense] STRIP check on release 2.0: {frr:.1%} of {len(held)} clean held-out invoices held for review.")

    limits = {rid: probe_result(rid) for rid in LIMIT_IDS}
    for rid, r in limits.items():
        d = r["desk"]
        verdict = f"refused by the {d['refused_by']}" if d["refused_by"] else "accepted"
        print(f"[defense] Limit '{rid}' in hardened mode: release 2.1 {verdict}; Trigger Success Rate "
              f"{r['rate']:.0f}% (" + ", ".join(f"{row['id']} {row['status']}" for row in r["rows"] if row["targeted"])
              + ").")
    sub = limits["signed-input-dependent"]
    print(f"[defense] Why it passes: trigger search best pattern {'+'.join(sub['scan']['scan']['pattern'])} flips "
          f"{sub['scan']['scan']['flip_rate']:.0%}; STRIP entropy on the attacker's invoices "
          + ", ".join(f"{row['result']['strip_entropy']:.2f}" for row in sub["rows"] if row["targeted"])
          + f" bits (threshold {pol['strip_threshold_bits']}).")

    lab.reset()
    lab.set_mode("vulnerable")
    print("\n[+] Reset to baseline.")

    controls_ok = (all(s == "GREEN" for s, r, tg in impact.values() if not tg)
                   and all(s == "GREEN" for s, r, tg in remediated_rows.values() if not tg))
    ok = (baseline == 0 and attacked > 0 and remediated == 0 and controls_ok
          and limits["signed-same-trigger"]["rate"] == 0 and limits["signed-same-trigger"]["desk"]["refused_by"] == "trigger scan"
          and limits["signed-input-dependent"]["rate"] > 0)
    print("[+] Story holds." if ok else "[-] Story broken — check the recipes and suite.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
