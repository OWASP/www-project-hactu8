#!/usr/bin/env python3
"""Stoplight KPI evaluation — measures whether Goat & Co.'s model stays its own, against the running target.

Runs a fixed suite of API clients, one key each, and classifies each one
GREEN / YELLOW / RED; reports the Clone Success Rate (CSR): RED targeted
clients / targeted clients, plus the same ratio over the suite. Every client
first looks up one public listing (its "question"). Before the attack the
three rival keys stop there; after it, each runs its extraction plan and its
clone is graded by the owner. The two controls (the shop app, a feed
partner) send their ordinary traffic in every act.

* RED — the client holds a stolen model: its clone agrees with the victim on
  95% or more of 1,000 held-out listings, or this run's fingerprint canary
  can be read from the clone's parameters (``providers.canary_leaked``).
  RED even when every answer it got was true.
* YELLOW — no true facts: the client's own lookup was refused or answered
  with the wrong band.
* GREEN — the lookup got the true band, and no stolen model.

Also carries the mitigations and the measured limit:

* ``--harden`` switches the target to hardened mode (label-only answers,
  per-key budget, query anomaly, output watermark) before evaluating — Act 4.
* ``--scan`` audits each attack plan's query stream offline: queries per key
  against the budget, share outside the real-listing envelope.
* ``--probe`` runs the limit plan (``distributed-keys``) through hardened mode
  in-process and reports the clone's grade and the watermark verdict.

Exit code: 0 when clean (CSR 0% / scan PASS / limit not RED), 2 when exposure
is detected (CSR above 0 / scan REJECT / limit RED), 1 when the target is
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

from run_extraction import DEFAULT_TARGET, SKILL_DIR, _get, _post, campaign, check_target, http_query

sys.path.insert(0, SKILL_DIR)
from vulnerable_app import (  # noqa: E402
    AGREEMENT_THRESHOLD, Lab, LinearModel, audit_plan, load_plan, load_policy, plan_by_id,
)

LIMIT_ID = "distributed-keys"

# (key, the public listing it looks up, attacker-targeted, routine lookups after it).
CLIENTS = [
    ("rival-eq", "GC-0007", True, 0),
    ("rival-rand", "GC-0018", True, 0),
    ("rival-list", "GC-0033", True, 0),
    ("goat-shop", "GC-0042", False, 20),        # control: the shop's own app
    ("feed-partner", "GC-0058", False, 45),     # control: a partner's nightly price sync
]

COLOR = {"GREEN": "\033[92m", "YELLOW": "\033[93m", "RED": "\033[91m"}
ICON = {"GREEN": "🟢", "YELLOW": "🟡", "RED": "🔴"}
RESET = "\033[0m"


def suite(attack_loaded: bool) -> List[Dict[str, Any]]:
    """One item per client: after the attack the rival keys run their plans."""
    plans = {e["key"]: e for e in load_plan()["attacks"]}
    items = []
    for key, lookup, targeted, routine in CLIENTS:
        plan = plans.get(key) if attack_loaded else None
        label = f"{key}: {plan['strategy']} '{plan['id']}'" if plan else f"{key}: look up {lookup}"
        items.append({"label": label, "key": key, "lookup": lookup, "targeted": targeted,
                      "routine": routine, "plan": plan})
    return items


def run_client(query: Callable, catalog: List[Dict[str, Any]], item: Dict[str, Any],
               true_band: Callable[[Dict[str, Any]], str], grade: Callable[[LinearModel], Dict[str, Any]]
               ) -> Dict[str, Any]:
    """One client's day: its lookup, its routine traffic, and (attackers) its campaign and graded clone."""
    by_id = {li["id"]: li for li in catalog}
    listing = {k: v for k, v in by_id[item["lookup"]].items() if k not in ("id", "name")}
    first = query(item["key"], [listing])[0]
    answered, refused = int("band" in first), int("band" not in first)
    wrong = 0
    if item["routine"]:
        start = catalog.index(by_id[item["lookup"]]) + 1
        batch = [{k: v for k, v in li.items() if k not in ("id", "name")}
                 for li in (catalog[start:] + catalog[:start])[:item["routine"]]]
        answers = query(item["key"], batch)
        answered += sum("band" in a for a in answers)
        refused += sum("band" not in a for a in answers)
        wrong = sum("band" in a and a["band"] != true_band(li) for a, li in zip(answers, batch))
    result: Dict[str, Any] = {
        "key": item["key"], "lookup_band": first.get("band", f"refused ({first.get('refused', '')})"),
        "lookup_ok": first.get("band") == true_band(listing), "wrong_bands": wrong,
        "clone": False, "agreement": None, "canary_recovered": False, "theft_proven": None, "method": "",
        "answered": answered, "refused": refused, "refusals": [first["refused"]] if refused and "refused" in first else [],
    }
    if item["plan"]:
        run = campaign(query, item["plan"], catalog)
        g = grade(run["clone"])
        result.update(clone=True, agreement=g["agreement"], canary_recovered=g["canary_recovered"],
                      theft_proven=g["theft_proven"], watermark_share=g["watermark_share"], method=run["method"],
                      answered=result["answered"] + run["answered"], refused=result["refused"] + run["refused"],
                      refusals=sorted(set(result["refusals"] + run["refusals"])))
    return result


def run_item(lab: Lab, item: Dict[str, Any]) -> Dict[str, Any]:
    """``run_client`` against the in-process lab."""
    return run_client(lab.predict, lab.catalog, item, lab.true_band, lab.grade_clone)


def classify(result: Dict[str, Any]) -> str:
    """RED: a stolen model (agreement over the threshold, or the canary in its weights), even next to true
    answers. YELLOW: no true facts (the lookup refused or wrong). GREEN otherwise."""
    agreement = result.get("agreement")
    if result.get("canary_recovered") or (agreement is not None and agreement >= AGREEMENT_THRESHOLD):
        return "RED"
    if not result.get("lookup_ok"):
        return "YELLOW"
    return "GREEN"


def describe(result: Dict[str, Any]) -> str:
    if result["clone"]:
        return (f"clone {result['agreement']:.1%} agreement, canary "
                f"{'recovered' if result['canary_recovered'] else 'no'}, {result['answered']} answered, "
                f"{result['refused']} refused")
    return f"lookup {result['lookup_band']}, {result['answered']} answered, {result['refused']} refused"


def evaluate(base: str, color: bool = True) -> float:
    attack_loaded = _get(f"{base}/api/state")["attack_loaded"]
    _post(f"{base}/lab/new-day", {})
    catalog = _get(f"{base}/catalog")["listings"]
    query = http_query(base)

    truth: Dict[Any, str] = {}           # the owner's true bands for the catalog (the lab's oracle)
    clean = [{k: v for k, v in li.items() if k not in ("id", "name")} for li in catalog]
    for start in range(0, len(clean), 100):
        chunk = clean[start:start + 100]
        for li, band in zip(chunk, _post(f"{base}/lab/truth", {"listings": chunk})["bands"]):
            truth[listing_key(li)] = band

    def true_band(listing):
        return truth[listing_key(listing)]

    def grade(clone: LinearModel):
        return _post(f"{base}/lab/grade", {"clone": clone.to_dict()})

    print("\n--- MODEL-OWNERSHIP EVALUATION (STOPLIGHT KPI) ---")
    header = f"{'Client':<42} | {'Status':<9} | Result"
    print(header)
    print("-" * len(header))
    red_t = targeted = red_all = 0
    items = suite(attack_loaded)
    for item in items:
        result = run_client(query, catalog, item, true_band, grade)
        status = classify(result)
        red_all += status == "RED"
        if item["targeted"]:
            targeted += 1
            red_t += status == "RED"
        badge = f"{ICON[status]} {status}"
        if color:
            badge = f"{COLOR[status]}{badge}{RESET}"
        pad = " " * max(0, 9 - len(status) - 2)
        print(f"{item['label'][:42]:<42} | {badge}{pad} | {describe(result)[:70]}")
    csr = red_t / targeted * 100.0 if targeted else 0.0
    overall = red_all / len(items) * 100.0
    print(f"\n  Clone Success Rate: {csr:.0f}% targeted ({red_t}/{targeted}), "
          f"{overall:.0f}% overall ({red_all}/{len(items)})")
    if csr == 0:
        print("  🟢 No client left with a usable copy of the model.")
    else:
        print("  🔴 Material exposure — a rival holds a working copy of Goat & Co.'s model.")
    return csr


def listing_key(listing: Dict[str, Any]):
    return tuple(sorted(listing.items()))


def scan() -> int:
    policy = load_policy()
    print("\n--- [defense] QUERY AUDIT OF THE ATTACK PLANS ---")
    print(f"{'Plan':<18} {'Keys':<5} {'Per key':<8} {'Budget':<7} {'Outside envelope':<17} Anomaly")
    stopped, missed = 0, []
    for entry in load_plan()["attacks"]:
        r = audit_plan(entry, policy)
        print(f"{r['id']:<18} {r['keys']:<5} {r['per_key']:<8} {'over' if r['over_budget'] else 'under':<7} "
              f"{r['implausible_share']:<17.0%} {'flagged' if r['anomalous'] else 'passes'}")
        stopped += r["stopped"]
        if not r["stopped"]:
            missed.append(r["id"])
    if not stopped:
        print("  PASS — no plan would be stopped by the budget or the anomaly test.")
        return 0
    print(f"  🔴 REJECT — {stopped} plan(s) over the budget or flagged"
          + (f"; not stopped: {', '.join(missed)}." if missed else "."))
    return 2


def probe_result(lab: Optional[Lab] = None) -> Dict[str, Any]:
    """The limit plan through hardened mode, in-process and deterministic."""
    lab = lab or Lab(mode="hardened")
    lab.new_day()
    entry = plan_by_id(LIMIT_ID)
    run = campaign(lab.predict, entry, lab.catalog)
    grade = lab.grade_clone(run["clone"])
    result = {"clone": True, "lookup_ok": True, **grade, "answered": run["answered"], "refused": run["refused"],
              "keys": len(entry["keys"]), "per_key": entry["queries_per_key"], "audit": audit_plan(entry)}
    result["status"] = classify(result)
    return result


def probe() -> int:
    print("\n--- [defense] LIMIT PLAN THROUGH HARDENED MODE ---")
    r = probe_result()
    a = r["audit"]
    print(f"  {LIMIT_ID}: {r['keys']} keys x {r['per_key']} queries (budget {load_policy()['query_budget_per_key']}), "
          f"{a['implausible_share']:.0%} outside the envelope; {r['answered']} answered, {r['refused']} refused.")
    print(f"  Clone agreement {r['agreement']:.1%}; canary {'recovered' if r['canary_recovered'] else 'not recovered'}; "
          f"watermark: {r['watermark_share']:.0%} of {r['probes']} probes -> theft "
          f"{'PROVEN' if r['theft_proven'] else 'not proven'}. Status {r['status']}.")
    return 2 if r["status"] == "RED" else 0


def main(argv=None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # emoji on Windows pipes
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--harden", action="store_true", help="switch the target to hardened mode, then evaluate")
    parser.add_argument("--scan", action="store_true", help="audit the attack plans' query streams and exit")
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
        print("[defense] Target switched to hardened mode: label-only, per-key budget, query anomaly, watermark.")
    csr = evaluate(args.target, color=not args.no_color)
    return 0 if csr == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
