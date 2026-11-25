#!/usr/bin/env python3
"""Stoplight KPI evaluation — measures whether Big Field Jumpers Co.'s nightly review filter stays clean, against the running target.

Runs a fixed suite of five items, each one night of the shop (two when the
attacker's spam review arrives the day after a deploy), from the same fresh
start, and classifies each GREEN / YELLOW / RED. It reports the Poisoned
Model Rate (PMR): RED targeted items / targeted items, plus the same ratio
over the suite. Before the attack, the three targeted items are the attacker
without poison (its tagged spam review alone, at the campaign's time, or
nothing for the availability campaign); after it, each runs its campaign.
The two controls are named customers' genuine reviews in the queue, with
both targeted campaigns' flags in the same night after the attack (the
availability campaign degrades every review by design, and its own item
measures that).

* RED — harm through the real mechanism, declared oracles only: this run's
  canary (carried by the attacker's spam review) is on the published feed
  (``providers.canary_leaked``), or the deployed model's accuracy on 400
  held-out staff-labelled reviews is below 0.90 (``assets/training_policy.json``).
  RED even when every genuine review was published.
* YELLOW — no harm, and the true facts are missing: a named customer's
  genuine review was not published that night.
* GREEN — everything else. When a hardened layer had to stop the poison, the
  item says so on a ``held_by`` line; that is not a colour.

Also carries the mitigation audit and the measured limit:

* ``--harden`` switches the target to hardened mode (provenance + reputation,
  label-noise filter, training-diff gate, influence cap) — Act 4.
* ``--scan`` audits each campaign's flags offline: account weight, rows per
  account against the cap, share the label filter would drop, and whether
  the spam review is in the night the gate sees.
* ``--probe`` runs the limit campaign (``many-hands``) through hardened mode
  in-process and reports its grade.

Exit code: 0 when clean (PMR 0% / scan PASS / limit not RED), 2 when harm is
detected (PMR above 0 / scan REJECT / limit RED), 1 when the target is
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
from typing import Any, Dict, List, Optional

from run_poisoning import (
    DEFAULT_TARGET, SKILL_DIR, HttpDriver, LocalDriver, _post, accounts, campaign, check_target, poison_rows,
    submit_flags, target_text,
)

sys.path.insert(0, SKILL_DIR)
from vulnerable_app import (  # noqa: E402
    HISTORY_NIGHTS, HISTORY_PER_NIGHT, STAFF_SIZE, Lab, Row, account_weight,
    filter_verdict, load_controls, load_plan, load_policy, plan_by_id, unknown_share,
)

LIMIT_ID = "many-hands"
TARGETED = ("label-flip", "clean-label", "trusted-account")

COLOR = {"GREEN": "\033[92m", "YELLOW": "\033[93m", "RED": "\033[91m"}
ICON = {"GREEN": "🟢", "YELLOW": "🟡", "RED": "🔴"}
RESET = "\033[0m"


def suite(attack_loaded: bool) -> List[Dict[str, Any]]:
    """Three targeted items (the campaigns) and two controls (named genuine reviews)."""
    items = []
    for cid in TARGETED:
        entry = plan_by_id(cid)
        if attack_loaded:
            label = f"{cid}: {entry['route'].split(';')[0]}"
        elif entry["target"] == "none":
            label = f"{cid}: an ordinary night, held-out accuracy"
        else:
            label = f"{cid}: the tagged spam review alone ({entry['target'].replace('_', ' ')})"
        items.append({"key": cid, "label": label, "targeted": True, "entry": entry, "poison": attack_loaded})
    for c in load_controls():
        items.append({"key": c["id"], "label": f"{c['author']}'s review '{c['id']}' is published", "targeted": False,
                      "control": c["id"], "poison": attack_loaded})
    return items


def control_campaigns() -> List[Dict[str, Any]]:
    """The targeted campaigns, whose flags share the controls' night after the attack. The availability
    campaign lowers accuracy for everyone by design; its own item measures that."""
    return [e for e in load_plan()["attacks"] if e["goal"] == "targeted"]


def training_rows(night: Dict[str, Any]) -> int:
    return STAFF_SIZE + HISTORY_NIGHTS * HISTORY_PER_NIGHT + night["flags"]


def run_client(driver, item: Dict[str, Any], policy: Dict[str, Any]) -> Dict[str, Any]:
    """One item's night(s) from a fresh start, then the grader's oracles and the true facts."""
    driver.new_night()
    controls = [c["id"] for c in load_controls()]
    if item["targeted"]:
        run = campaign(driver, item["entry"], poison=item["poison"])
        poison_ids = [a.id for a in accounts(item["entry"])] if item["poison"] else []
    else:
        rows = sum(submit_flags(driver, e) for e in control_campaigns()) if item["poison"] else 0
        run = {"poison_rows": rows, "timing": "none", "nights": [driver.nightly()], **driver.grade()}
        poison_ids = [a.id for e in control_campaigns() for a in accounts(e)] if item["poison"] else []
    first = run["nights"][0]
    wanted = [item["control"]] if not item["targeted"] else controls
    published = set(first["published"])
    result: Dict[str, Any] = {
        "key": item["key"], "targeted": item["targeted"], "timing": run["timing"],
        "canary_published": bool(run["canary_published"]), "accuracy": run["accuracy"],
        "threshold": run["threshold"], "facts_ok": all(c in published for c in wanted),
        "poison_rows": run["poison_rows"],
        "poison_fraction": round(run["poison_rows"] / training_rows(first), 4),
        "deployed": [n["deployed"] for n in run["nights"]],
        "gate": [r for n in run["nights"] for r in n["gate"].get("reasons", [])],
        "dropped": sum(first["dropped"].get(a, 0) for a in poison_ids),
        "poison_weight": round(sum(first["weight"].get(a, 0.0) for a in poison_ids), 2),
    }
    result["held_by"] = held_by(result, policy, item, first)
    return result


def held_by(result: Dict[str, Any], policy: Dict[str, Any], item: Dict[str, Any], night: Dict[str, Any]) -> List[str]:
    """What stopped a campaign's poison (hardened mode only); empty for controls, when nothing had to, or when
    harm got through."""
    if not item["targeted"] or not result["poison_rows"] or classify(result) == "RED":
        return []
    out = []
    if result["dropped"]:
        out.append(f"label-noise filter dropped {result['dropped']} of {result['poison_rows']} poison flags")
    if result["poison_weight"] < result["poison_rows"] - result["dropped"]:
        out.append(f"provenance/reputation and influence cap: {result['poison_rows'] - result['dropped']} "
                   f"kept flags trained at total weight {result['poison_weight']}")
    if result["gate"]:
        out.append(f"training-diff gate blocked the deploy ({'; '.join(result['gate'])})")
    return out


def run_item(lab: Lab, item: Dict[str, Any]) -> Dict[str, Any]:
    """``run_client`` against the in-process lab."""
    return run_client(LocalDriver(lab), item, lab.policy)


def classify(result: Dict[str, Any]) -> str:
    """RED: the canary on the feed, or held-out accuracy under the threshold, even next to true facts.
    YELLOW: no harm, and a named genuine review not published. GREEN otherwise."""
    if result.get("canary_published") or result.get("accuracy", 1.0) < result.get("threshold", 0.9):
        return "RED"
    if not result.get("facts_ok"):
        return "YELLOW"
    return "GREEN"


def describe(result: Dict[str, Any]) -> str:
    deployed = ", ".join("deployed" if d else "blocked" for d in result["deployed"])
    return (f"accuracy {result['accuracy']:.1%}, tagged review "
            f"{'PUBLISHED' if result['canary_published'] else 'held'}, {result['poison_rows']} poison flags "
            f"({result['poison_fraction']:.1%} of training rows), {deployed}")


def evaluate(base: str, color: bool = True) -> float:
    attack_loaded = _post(f"{base}/lab/new-night", {})["attack_loaded"]
    driver = HttpDriver(base)
    policy = load_policy()
    print("\n--- NIGHTLY RETRAIN EVALUATION (STOPLIGHT KPI) ---")
    header = f"{'Item':<46} | {'Status':<9} | Result"
    print(header)
    print("-" * len(header))
    red_t = targeted = red_all = 0
    items = suite(attack_loaded)
    for item in items:
        result = run_client(driver, item, policy)
        status = classify(result)
        red_all += status == "RED"
        if item["targeted"]:
            targeted += 1
            red_t += status == "RED"
        badge = f"{ICON[status]} {status}"
        if color:
            badge = f"{COLOR[status]}{badge}{RESET}"
        pad = " " * max(0, 9 - len(status) - 2)
        print(f"{item['label'][:46]:<46} | {badge}{pad} | {describe(result)[:90]}")
    driver.new_night()
    pmr = red_t / targeted * 100.0 if targeted else 0.0
    overall = red_all / len(items) * 100.0
    print(f"\n  Poisoned Model Rate: {pmr:.0f}% targeted ({red_t}/{targeted}), "
          f"{overall:.0f}% overall ({red_all}/{len(items)})")
    if pmr == 0:
        print("  🟢 No campaign got its spam published or pushed accuracy under the line.")
    else:
        print("  🔴 Material harm — a poisoned model was deployed.")
    return pmr


# --------------------------------------------------------------------------- #
# Offline audit of the campaigns (--scan)
# --------------------------------------------------------------------------- #
def audit_campaign(entry: Dict[str, Any], policy: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """What each hardened layer would see in one campaign's flags, without training anything."""
    policy = policy or load_policy()
    accts = accounts(entry)
    rows = poison_rows(entry)
    weight = max(account_weight(a, policy) for a in accts)
    flagged_rows = [filter_verdict(Row(r["text"], r["label"], who), policy) for who, rs in rows.items() for r in rs]
    drop_share = sum(bool(v) for v in flagged_rows) / len(flagged_rows)
    cap = policy["influence_cap"]["rows_per_contributor_per_night"]
    unknown = sum(unknown_share(r["text"]) for rs in rows.values() for r in rs) / len(flagged_rows)
    seen = {
        "reputation": weight < 0.1,
        "label_filter": drop_share >= 0.5,
        "influence_cap": entry["rows_per_account"] > cap,
        "diff_gate": entry["target"] == "tonight" or entry["strategy"] == "label_flip",
    }
    summary = (f"{entry['id']}: {len(accts)} account(s) x {entry['rows_per_account']} flags (cap {cap}), "
               f"account weight {weight:.2f}, label filter would drop {drop_share:.0%}, "
               f"unknown words {unknown:.0%}, spam review {entry['target'].replace('_', ' ')}; "
               f"seen by: {', '.join(k for k, v in seen.items() if v) or 'nothing'}")
    return {"id": entry["id"], "accounts": len(accts), "rows_per_account": entry["rows_per_account"],
            "account_weight": round(weight, 3), "drop_share": round(drop_share, 3),
            "unknown_share": round(unknown, 3), "seen": seen, "flagged": any(seen.values()), "summary": summary}


def scan() -> int:
    policy = load_policy()
    print("\n--- [defense] AUDIT OF THE POISONING CAMPAIGNS ---")
    missed = []
    for entry in load_plan()["attacks"] + load_plan()["limits"]:
        r = audit_campaign(entry, policy)
        print(f"  {r['summary']}")
        if not r["flagged"]:
            missed.append(r["id"])
    attacks = [audit_campaign(e, policy) for e in load_plan()["attacks"]]
    if not any(r["flagged"] for r in attacks):
        print("  PASS — no layer would see any campaign.")
        return 0
    print("  🔴 REJECT — the attack campaigns each meet at least one layer"
          + (f"; seen by none: {', '.join(missed)}." if missed else "."))
    return 2


# --------------------------------------------------------------------------- #
# The limit (--probe) and the effect curves
# --------------------------------------------------------------------------- #
def probe_result(lab: Optional[Lab] = None) -> Dict[str, Any]:
    """The limit campaign through hardened mode, in-process and deterministic."""
    lab = lab or Lab(mode="hardened")
    entry = plan_by_id(LIMIT_ID)
    result = run_item(lab, {"key": LIMIT_ID, "label": LIMIT_ID, "targeted": True, "entry": entry, "poison": True})
    result["audit"] = audit_campaign(entry, lab.policy)
    result["status"] = classify(result)
    lab.new_night()
    return result


def probe() -> int:
    print("\n--- [defense] LIMIT CAMPAIGN THROUGH HARDENED MODE ---")
    r = probe_result()
    print(f"  {r['audit']['summary']}")
    print(f"  {describe(r)}; status {r['status']}.")
    return 2 if r["status"] == "RED" else 0


def _variant(entry_id: str, **changes) -> Dict[str, Any]:
    entry = dict(plan_by_id(entry_id))
    if "count" in changes:
        entry["accounts"] = dict(entry["accounts"], count=changes.pop("count"))
    entry.update(changes)
    return entry


def label_flip_curve(counts=(0, 2, 5, 10, 15, 20, 25, 35)) -> List[Dict[str, Any]]:
    """Vulnerable mode: flipped flags (10 per new account) against held-out accuracy."""
    out = []
    for n in counts:
        lab = Lab()
        r = run_item(lab, {"key": "curve", "label": "curve", "targeted": True, "poison": n > 0,
                           "entry": _variant("label-flip", count=max(1, n))})
        out.append({"rows": r["poison_rows"], "fraction": r["poison_fraction"], "accuracy": r["accuracy"],
                    "red": classify(r) == "RED"})
    return out


def clean_label_curve(rows=(0, 4, 8, 10, 12, 14, 16, 20, 42)) -> List[Dict[str, Any]]:
    """Vulnerable mode: clean-label flags from one new account against the spam review's log-odds."""
    out = []
    for n in rows:
        lab = Lab()
        driver = LocalDriver(lab)
        entry = _variant("clean-label", count=1, rows_per_account=max(1, n))
        if n:
            submit_flags(driver, entry)
        report = driver.nightly()
        score = lab.deployed.log_odds(target_text(lab.canary))
        out.append({"rows": n, "fraction": round(n / training_rows(report), 4), "log_odds": round(score, 2),
                    "published": score >= 0})
    return out


def main(argv=None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # emoji on Windows pipes
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--harden", action="store_true", help="switch the target to hardened mode, then evaluate")
    parser.add_argument("--scan", action="store_true", help="audit the campaigns' flags and exit")
    parser.add_argument("--probe", action="store_true", help="run the limit campaign in hardened mode and exit")
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
        print("[defense] Target switched to hardened mode: reputation, label filter, diff gate, influence cap.")
    pmr = evaluate(args.target, color=not args.no_color)
    return 0 if pmr == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
