#!/usr/bin/env python3
"""Stoplight KPI evaluation — measures whether fraud claims get paid, against the running target.

Runs a fixed suite of claims, one account each, and classifies each claim
GREEN / YELLOW / RED; reports the Evasion Success Rate (ESR): RED targeted
claims / targeted claims, plus the same ratio over the suite. Three claims
are fraud by ground truth (the courier recorded the parcel as delivered
intact); before the attack each fraudster files its honest photo, after it
each runs its plan from ``assets/evasion_plan.json``. Two honest customers
with crushed parcels are the controls: one pre-check, then the claim, in
every act.

* RED — the declared oracle: a claim the courier recorded as intact was
  auto-approved, or this run's refund reference (the canary,
  ``providers.canary_leaked``) reached an attacker account. RED even when
  every other answer was right.
* YELLOW — no leak, and the true fact is missing: an honest damaged claim
  was not paid automatically (denied, rejected or held for review).
* GREEN — everything else. A layer that held is reported as ``held_by``,
  not as a colour.

Also carries the mitigations and the measured limit:

* ``--harden`` switches the target to hardened mode (feature validation,
  adversarial training, the cross-check, the pre-check budget) — Act 4.
* ``--scan`` crafts each attack plan's photo offline against the shipped
  model and runs the hardened input checks on it.
* ``--probe`` runs the limit plan (``adaptive-ensemble``) through hardened
  mode in-process and reports the decision.

Exit code: 0 when clean (ESR 0% / scan PASS / limit not RED), 2 when exposure
is detected (ESR above 0 / scan REJECT / limit RED), 1 when the target is
unreachable.

Examples:
    python scripts/evaluate_kpi.py
    python scripts/evaluate_kpi.py --harden
    python scripts/evaluate_kpi.py --scan
    python scripts/evaluate_kpi.py --probe
"""

from __future__ import annotations

import argparse
import sys
from typing import Any, Callable, Dict, List, Optional

from run_evasion import (
    DEFAULT_TARGET, SKILL_DIR, Api, _get, _post, adaptive_objective, block_search, campaign, check_target, fgsm,
    http_api, lab_api,
)

sys.path.insert(0, SKILL_DIR)
from vulnerable_app import (  # noqa: E402
    Lab, accuracy, audit_plan, claim_photo, corner_rule, heldout, load_claims, load_plan, load_policy, plan_by_id,
    production_model, robust_model,
)

LIMIT_ID = "adaptive-ensemble"
SPREAD_ID = "block-search-many-accounts"

# (account, claim, attacker-targeted).
CLIENTS = [
    ("acct-fox", "CL-1041", True),
    ("acct-wren", "CL-1077", True),
    ("acct-crow", "CL-1093", True),
    ("acct-ada", "CL-1012", False),      # control: an honest customer, a crushed parcel
    ("acct-bo", "CL-1029", False),       # control: an honest customer, a crushed parcel
]

COLOR = {"GREEN": "\033[92m", "YELLOW": "\033[93m", "RED": "\033[91m"}
ICON = {"GREEN": "🟢", "YELLOW": "🟡", "RED": "🔴"}
RESET = "\033[0m"


def suite(attack_loaded: bool) -> List[Dict[str, Any]]:
    """One item per claim: after the attack the fraud accounts run their plans."""
    plans = {e["account"]: e for e in load_plan()["attacks"]}
    items = []
    for account, claim_id, targeted in CLIENTS:
        plan = plans.get(account) if attack_loaded else None
        label = (f"{claim_id} {account}: {plan['access']} '{plan['id']}'" if plan
                 else f"{claim_id} {account}: {'own photo' if targeted else 'crushed parcel'}")
        items.append({"label": label, "account": account, "claim_id": claim_id, "targeted": targeted, "plan": plan})
    return items


def run_client(api: Api, outcome: Callable[[str, str], Dict[str, Any]], claim: Dict[str, Any],
               item: Dict[str, Any]) -> Dict[str, Any]:
    """One claim's day: the attacker's plan, or one honest pre-check and the honest photo."""
    photo = claim_photo(claim)
    if item["plan"]:
        run = campaign(api, item["plan"], photo)
    else:
        check = api.precheck(item["account"], photo)
        answer = api.submit(item["account"], item["claim_id"], photo)
        run = {"prechecks": 1, "refused": int("refused" in check), "rejected": int("rejected" in check),
               "linf": 0.0, "decision": answer["decision"], "reason": answer["reason"]}
    out = outcome(item["account"], item["claim_id"])
    return {"account": item["account"], "claim_id": item["claim_id"], "targeted": item["targeted"],
            "attacked": bool(item["plan"]), "method": item["plan"]["id"] if item["plan"] else "",
            "record": out["record"], "decision": out["decision"], "reason": run["reason"],
            "served_damaged": out["served_damaged"], "second_opinion": out["second_opinion"],
            "served": out["served"], "hardened": out["hardened"],
            "canary_received": bool(out["canary_received"]), "received": out["received"],
            "fraud_approved": out["record"] == "intact" and out["decision"] == "approved",
            "prechecks": run["prechecks"], "refused": run["refused"], "linf": run["linf"]}


def run_item(lab: Lab, item: Dict[str, Any]) -> Dict[str, Any]:
    """``run_client`` against the in-process lab."""
    return run_client(lab_api(lab), lab.outcome, lab.claims[item["claim_id"]], item)


def classify(result: Dict[str, Any]) -> str:
    """RED: a fraud claim auto-approved, or the refund reference in an attacker's account, even next to true
    facts. YELLOW: an honest damaged claim not paid. GREEN otherwise."""
    if result.get("fraud_approved") or (result.get("targeted") and result.get("canary_received")):
        return "RED"
    if result.get("record") == "damaged" and result.get("decision") != "approved":
        return "YELLOW"
    return "GREEN"


def held_by(result: Dict[str, Any]) -> List[str]:
    """What stopped an attack that ran, in hardened mode (a near miss, not a colour)."""
    if not (result.get("attacked") and result.get("hardened")) or result.get("decision") == "approved":
        return []
    held = []
    if result["decision"] == "rejected":
        held.append("feature validation (photo rejected)")
    if result.get("refused"):
        held.append(f"pre-check budget ({result['refused']} refused)")
    if result["decision"] != "rejected" and result.get("served") == "robust" and not result.get("served_damaged"):
        held.append("adversarial training (the served model still says intact)")
    if result["decision"] == "review":
        held.append("cross-check (the corner detector disagrees: human review)")
    return held


def describe(result: Dict[str, Any]) -> str:
    text = (f"{result['decision']}; record {result['record']}; {result['prechecks']} pre-checks"
            f" ({result['refused']} refused); max change {result['linf']}")
    if result["canary_received"]:
        text += "; refund reference received"
    return text


def evaluate(base: str, color: bool = True) -> float:
    attack_loaded = _get(f"{base}/api/state")["attack_loaded"]
    _post(f"{base}/lab/new-day", {})
    claims = {c["claim_id"]: c for c in load_claims()}
    api = http_api(base)

    def outcome(account: str, claim_id: str) -> Dict[str, Any]:
        return _post(f"{base}/lab/outcome", {"account": account, "claim_id": claim_id})

    print("\n--- REFUND-DESK EVALUATION (STOPLIGHT KPI) ---")
    header = f"{'Claim':<44} | {'Status':<9} | Result"
    print(header)
    print("-" * len(header))
    red_t = targeted = red_all = 0
    items = suite(attack_loaded)
    for item in items:
        result = run_client(api, outcome, claims[item["claim_id"]], item)
        status = classify(result)
        red_all += status == "RED"
        if item["targeted"]:
            targeted += 1
            red_t += status == "RED"
        badge = f"{ICON[status]} {status}"
        if color:
            badge = f"{COLOR[status]}{badge}{RESET}"
        pad = " " * max(0, 9 - len(status) - 2)
        print(f"{item['label'][:44]:<44} | {badge}{pad} | {describe(result)[:80]}")
        held = held_by(result)
        if held:
            print(f"{'':<44} | {'':<9} | held by: {'; '.join(held)}")
    esr = red_t / targeted * 100.0 if targeted else 0.0
    overall = red_all / len(items) * 100.0
    print(f"\n  Evasion Success Rate: {esr:.0f}% targeted ({red_t}/{targeted}), "
          f"{overall:.0f}% overall ({red_all}/{len(items)})")
    if esr == 0:
        print("  🟢 No fraud claim paid automatically.")
    else:
        print("  🔴 Material exposure — refunds paid on intact parcels.")
    return esr


def scan() -> int:
    lab = Lab()
    print("\n--- [defense] OFFLINE CHECK OF THE DOCTORED PHOTOS ---")
    print(f"{'Plan':<14} {'Shipped model':<14} {'Camera checks':<56} Corner detector")
    stopped, missed = 0, []
    for entry in load_plan()["attacks"]:
        r = audit_plan(entry, lab)
        print(f"{r['id']:<14} {'fooled' if r['fools_shipped_model'] else 'holds':<14} "
              f"{r['problem'] or 'pass':<56} {'damaged' if r['second_opinion'] else 'intact'}")
        stopped += r["stopped"]
        if not r["stopped"]:
            missed.append(r["id"])
    if not stopped:
        print("  PASS — no doctored photo would be stopped by the input checks or the cross-check.")
        return 0
    print(f"  🔴 REJECT — {stopped} doctored photo(s) flagged" + (f"; not flagged: {', '.join(missed)}." if missed else "."))
    return 2


def heldout_rates(n_intact: int = 50, sweep=(0.08, 0.10, 0.12)) -> Dict[str, Any]:
    """The same models and checks on the 400 held-out photos the attack never touched.

    Clean accuracy of each model, what the hardened decision does with honest
    photos, the FGSM fooling rate at 0.03 for each model, and the adaptive
    attack's success through the hardened decision at each epsilon of
    ``sweep`` (on the first ``n_intact`` intact photos).
    """
    policy = load_policy()
    line = policy["crush_line"]
    prod, rob = production_model(), robust_model(policy["adversarial_epsilon"])
    X, y = heldout()
    intact = [list(x) for x, t in zip(X, y) if not t]
    damaged = [list(x) for x, t in zip(X, y) if t]

    def hardened_decision(x: List[float]) -> str:
        a, b = rob.damaged(x), corner_rule(x, line)
        return "approved" if a and b else ("denied" if not a and not b else "review")

    honest = [hardened_decision(x) for x in damaged]
    clean_intact = [hardened_decision(x) for x in intact]
    sample = intact[:n_intact]
    adaptive = {}
    for eps in sweep:
        paid = sum(hardened_decision(block_search(x, adaptive_objective(rob, line), eps, 3000, 11)["photo"])
                   == "approved" for x in sample)
        adaptive[eps] = paid / len(sample)
    return {
        "clean_production": accuracy(prod, X, y), "clean_robust": accuracy(rob, X, y),
        "damaged": len(damaged), "intact": len(intact),
        "production_paid_damaged": sum(prod.damaged(x) for x in damaged) / len(damaged),
        "production_paid_intact": sum(prod.damaged(x) for x in intact) / len(intact),
        "hardened_paid_damaged": honest.count("approved") / len(damaged),
        "hardened_review_damaged": honest.count("review") / len(damaged),
        "hardened_paid_intact": clean_intact.count("approved") / len(intact),
        "fgsm_production": sum(prod.damaged(fgsm(prod, x, 0.03, True)) for x in intact) / len(intact),
        "fgsm_robust": sum(rob.damaged(fgsm(rob, x, 0.03, True)) for x in intact) / len(intact),
        "adaptive": adaptive, "sample": len(sample),
    }


def probe_result(plan_id: str = LIMIT_ID, lab: Optional[Lab] = None) -> Dict[str, Any]:
    """A limit plan through hardened mode, in-process and deterministic."""
    lab = lab or Lab(mode="hardened")
    lab.new_day()
    entry = plan_by_id(plan_id)
    claim = lab.claims[entry["claim_id"]]
    item = {"label": entry["id"], "account": entry["account"], "claim_id": entry["claim_id"], "targeted": True,
            "plan": entry}
    result = run_item(lab, item)
    result["status"] = classify(result)
    result["held_by"] = held_by(result)
    result["epsilon"] = entry["epsilon"]
    result["accounts"] = len(entry.get("accounts") or [entry["account"]])
    result["amount"] = claim["amount"]
    return result


def probe() -> int:
    print("\n--- [defense] LIMIT PLAN THROUGH HARDENED MODE ---")
    r = probe_result()
    print(f"  {LIMIT_ID}: epsilon {r['epsilon']}, {r['prechecks']} pre-checks, largest change {r['linf']}; "
          f"claim {r['decision']} (record {r['record']}); refund reference "
          f"{'RECEIVED' if r['canary_received'] else 'not received'}. Status {r['status']}.")
    return 2 if r["status"] == "RED" else 0


def main(argv=None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # emoji on Windows pipes
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--harden", action="store_true", help="switch the target to hardened mode, then evaluate")
    parser.add_argument("--scan", action="store_true", help="check the attack plans' photos offline and exit")
    parser.add_argument("--probe", action="store_true", help="run the limit plan in hardened mode and exit")
    parser.add_argument("--no-color", action="store_true")
    args = parser.parse_args(argv)

    if args.scan:
        return scan()
    if args.probe:
        return probe()
    if not check_target(args.target):
        return 1
    if args.harden:
        _post(f"{args.target}/api/mode", {"mode": "hardened"})
        print("[defense] Target switched to hardened mode: feature validation, adversarial training, "
              "cross-check, pre-check budget.")
    esr = evaluate(args.target, color=not args.no_color)
    return 0 if esr == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
