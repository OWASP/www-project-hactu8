#!/usr/bin/env python3
"""Run all four acts of the HX10 demo in one process — no server needed.

Act 1 baseline, Act 2 attack, Act 3 impact, Act 4 remediation, then reset.
Uses the skill's own Lab, extraction plans and evaluator suite. Standard
library only. After Act 4 it prints each hardened layer on its own, the
watermark's verdict on an independent model, and the measured limit: the
listing-like plan spread over 40 free-tier keys, through hardened mode.

AUTHORIZED SECURITY-LAB USE ONLY.

The lab runs on the echo backend only: the victim is a pure-Python
classifier and no language model is in the loop. Any other backend exits 2.

Exit code: 0 when the story holds (baseline and remediation clean, attack
measurable, controls untouched, the independent model not accused, the limit
measured as RED with the theft proven), 1 otherwise, 2 for a backend other
than echo.

Examples:
    python run_demo.py
"""

from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL_DIR = os.path.join(HERE, "hx10-extraction-skill")
sys.path.insert(0, SKILL_DIR)
sys.path.insert(0, os.path.join(SKILL_DIR, "scripts"))

from evaluate_kpi import ICON, LIMIT_ID, classify, probe_result, run_item, suite  # noqa: E402
from vulnerable_app import AGREEMENT_THRESHOLD, Lab, audit_plan, competitor_model  # noqa: E402

LAYERS = ("use_label_only", "use_rate_limit", "use_query_anomaly", "use_output_watermark")
LAYER_NAMES = {"use_label_only": "label-only", "use_rate_limit": "per-key budget",
               "use_query_anomaly": "query anomaly", "use_output_watermark": "output watermark"}


def evidence(value) -> None:
    """Print what the model produced, for the hactu8 adapter (HACTU8_EVIDENCE=1 only)."""
    if os.environ.get("HACTU8_EVIDENCE") == "1":
        text = value if isinstance(value, str) else json.dumps(value, default=str, ensure_ascii=False)
        print(f"        evidence: {json.dumps(text[:2000], ensure_ascii=False)}")


def act(lab: Lab, title: str, results=None) -> float:
    print(f"\n[*] {title}")
    lab.new_day()
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
        evidence({k: result[k] for k in ("lookup_band", "lookup_ok", "agreement", "canary_recovered",
                                         "theft_proven", "method", "answered", "refused", "refusals")})
    csr = red / targeted * 100.0
    print(f"    Clone Success Rate: {csr:.0f}% targeted")
    return csr


def rate_with(**layers) -> tuple:
    """The attack suite on a fresh hardened lab with only some layers on: (CSR, statuses, proven count)."""
    lab = Lab(mode="hardened")
    for name, value in layers.items():
        setattr(lab, name, value)
    lab.load_attack()
    rows = [run_item(lab, item) for item in suite(True) if item["targeted"]]
    statuses = [classify(r) for r in rows]
    return sum(s == "RED" for s in statuses) / len(rows) * 100.0, statuses, sum(bool(r["theft_proven"]) for r in rows)


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
    print(f"[*] Model backend: {lab.backend} (the victim is a pure-Python logistic regression)")

    baseline = act(lab, "Act 1 — Clean baseline")

    entries = lab.load_attack()
    print(f"\n[*] Act 2 — Attack: a rival runs {len(entries)} extraction plans against the price-band API")
    for e in entries:
        print(f"[+] Key '{e['key']}' runs '{e['id']}' ({e['strategy']}, {e['queries']} queries): {e['route']}.")

    impact: dict = {}
    attacked = act(lab, "Act 3 — Post-attack impact (same clients, the rival's plans)", impact)
    for key, (status, r, targeted) in impact.items():
        if targeted:
            print(f"[+] {key}: {r['answered']} answers ({r['method']}); clone agrees with the victim on "
                  f"{r['agreement']:.1%} of held-out listings; fingerprint canary "
                  f"{'RECOVERED from its weights' if r['canary_recovered'] else 'not in its weights'}.")

    print("\n[defense] Act 4 — Remediation")
    for e in entries:
        a = audit_plan(e)
        print(f"[defense] Query audit of '{e['id']}': {a['per_key']} queries per key (budget "
              f"{lab.policy['query_budget_per_key']}), {a['implausible_share']:.0%} outside the real-listing envelope.")
    lab.set_mode("hardened")
    print("[defense] Hardened mode: label-only answers, per-key budget, query-anomaly suspension, watermarked bands.")
    remediated_rows: dict = {}
    remediated = act(lab, "Act 4 — Re-run with mitigations", remediated_rows)
    for key, (status, r, targeted) in remediated_rows.items():
        if targeted:
            print(f"[defense] {key}: {r['answered']} answered, {r['refused']} refused "
                  f"({'; '.join(r['refusals']) or 'no refusal'}); clone {r['agreement']:.1%}.")

    for key, (status, r, targeted) in remediated_rows.items():
        if not targeted:
            print(f"[defense] Control {key}: {r['answered']} answered, {r['refused']} refused, "
                  f"{r['wrong_bands']} band(s) moved by the watermark.")

    alone = {name: rate_with(**{o: o == name for o in LAYERS}) for name in LAYERS}
    print("[defense] Each layer alone on the attack: " +
          ", ".join(f"{LAYER_NAMES[n]} {v[0]:.0f}%" for n, v in alone.items()) + " Clone Success Rate.")
    wm = alone["use_output_watermark"]
    print(f"[defense] The watermark alone stops nothing, and proves {wm[2]} of 3 clones were trained on its answers.")
    rival = lab.grade_clone(competitor_model())
    print(f"[defense] An independent model (a rival that priced its own listings) agrees {rival['agreement']:.1%} "
          f"and matches the watermark on {rival['watermark_share']:.0%} of {rival['probes']} probes: "
          f"{'ACCUSED' if rival['theft_proven'] else 'not accused'}.")

    limit = probe_result()
    print(f"[defense] Limit probe in hardened mode ({LIMIT_ID}, {limit['keys']} keys x {limit['per_key']} queries, "
          f"{limit['audit']['implausible_share']:.0%} outside the envelope): {limit['answered']} answered, "
          f"{limit['refused']} refused; clone agreement {limit['agreement']:.1%}; grade {limit['status']}; "
          f"watermark {limit['watermark_share']:.0%} of probes, theft {'PROVEN' if limit['theft_proven'] else 'not proven'}.")

    lab.reset()
    lab.set_mode("vulnerable")
    print("\n[+] Reset to baseline.")

    controls_ok = (all(s == "GREEN" and r["refused"] == 0 and r["wrong_bands"] == 0
                       for s, r, tg in impact.values() if not tg)
                   and all(s == "GREEN" and r["refused"] == 0 for s, r, tg in remediated_rows.values() if not tg))
    ok = (baseline == 0 and attacked > 0 and remediated == 0 and controls_ok and not rival["theft_proven"]
          and rival["agreement"] < AGREEMENT_THRESHOLD and limit["status"] == "RED" and limit["theft_proven"])
    print("[+] Story holds." if ok else "[-] Story broken — check the plans and suite.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
