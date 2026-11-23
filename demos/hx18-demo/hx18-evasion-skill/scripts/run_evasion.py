#!/usr/bin/env python3
"""Attack skill — get refunds for intact parcels past Big Field Jumper Co.'s damage classifier.

AUTHORIZED SECURITY-LAB USE ONLY. Targets this skill's own vulnerable_app.py.

Runs the plans in ``assets/evasion_plan.json``. Each plan starts from the
fraudster's own honest photo of an intact parcel, changes every pixel by at
most the plan's epsilon, and files the claim (``POST /v1/claims``):

* ``fgsm`` — white-box, one step: read the shipped model (``GET /app/model``)
  and move each pixel by epsilon along the sign of its weight, the fast
  gradient sign method (Goodfellow et al., 2014). The gradient of a logistic
  model's logit with respect to the pixels is its weight vector. With
  ``grid`` false the photo is sent as raw floats, outside [0, 1] where the
  step takes it.
* ``pgd`` — white-box, iterative: small signed steps, each projected back onto
  the epsilon box, [0, 1] and the 8-bit grid. Against a linear model it
  lands where a clipped FGSM step lands, inside every bound.
* ``block_search`` — black-box: change 2 x 2 blocks of pixels by plus or
  minus epsilon at random and keep a change when the pre-check's score goes
  up (``POST /v1/precheck``), until the score says damaged or the queries run
  out. It never sees the weights.
* ``adaptive`` — white-box against both models: the same block search, run
  offline on the shipped weights and on the corner detector's published
  rule, scored by the weaker of the two margins. No pre-check is used.

``--plan ID`` runs one plan, including the limits; the default runs the
three attack plans.

Exit code: 0 when the plans ran, 1 when the target is unreachable or the plan
id is unknown.

Examples:
    python scripts/run_evasion.py
    python scripts/run_evasion.py --plan block-search
    python scripts/run_evasion.py --plan adaptive-ensemble
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Sequence

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TARGET = os.getenv("HX18_TARGET", "http://127.0.0.1:5518")
sys.path.insert(0, SKILL_DIR)

from vulnerable_app import (  # noqa: E402
    SIDE, PixelModel, claim_photo, crush_score, load_claims, load_plan, load_policy, plan_by_id, quantize,
)

BLOCKS = [[r * SIDE + c for r in (br, br + 1) for c in (bc, bc + 1)]
          for br in range(0, SIDE, 2) for bc in range(0, SIDE, 2)]
DONE_SCORE = 0.55                  # the black-box search stops once the pre-check says this


class Api:
    """What an attacker can do: read the app's model, pre-check a photo, file a claim."""

    def __init__(self, model: Callable[[], Dict[str, Any]], precheck: Callable[[str, List[float]], Dict[str, Any]],
                 submit: Callable[[str, str, List[float]], Dict[str, Any]]) -> None:
        self.model, self.precheck, self.submit = model, precheck, submit


def lab_api(lab) -> Api:
    return Api(lab.app_model, lab.precheck, lab.submit_claim)


def http_api(base: str) -> Api:
    return Api(lambda: _get(f"{base}/app/model"),
               lambda a, p: _post(f"{base}/v1/precheck", {"account": a, "photo": p}),
               lambda a, c, p: _post(f"{base}/v1/claims", {"account": a, "claim_id": c, "photo": p}))


# --------------------------------------------------------------------------- #
# White-box: gradient sign steps
# --------------------------------------------------------------------------- #
def _sign(v: float) -> float:
    return 1.0 if v > 0 else (-1.0 if v < 0 else 0.0)


def fgsm(model: PixelModel, x: Sequence[float], epsilon: float, grid: bool) -> List[float]:
    """One step of epsilon along sign(w), toward *damaged*. ``grid``: whole grey levels, clipped to [0, 1]."""
    if not grid:
        return [v + epsilon * _sign(w) for v, w in zip(x, model.weights)]
    step = int(epsilon * 255 + 1e-9) / 255           # the largest whole number of grey levels within epsilon
    return quantize([v + step * _sign(w) for v, w in zip(x, model.weights)])


def pgd(model: PixelModel, x: Sequence[float], epsilon: float, steps: int, step_size: float) -> List[float]:
    """Projected gradient steps: each step along sign(w), then back into the epsilon box, [0, 1] and the grid."""
    lo = [v - epsilon for v in x]
    hi = [v + epsilon for v in x]
    z = list(x)
    for _ in range(steps):
        z = [min(h, max(lw, v + step_size * _sign(w))) for v, w, lw, h in zip(z, model.weights, lo, hi)]
        z = [min(1.0, max(0.0, v)) for v in z]
    levels = [round(v * 255) for v in z]
    out = []
    for v, lev in zip(x, levels):                    # round toward the original so the box still holds
        base = round(v * 255)
        limit = int(epsilon * 255 + 1e-9)
        out.append(min(base + limit, max(base - limit, lev)) / 255)
    return quantize(out)


# --------------------------------------------------------------------------- #
# Block search (black-box with the pre-check, or white-box offline)
# --------------------------------------------------------------------------- #
def _apply(x0: Sequence[float], delta: Sequence[int]) -> List[float]:
    x = list(x0)
    for k, block in enumerate(BLOCKS):
        for i in block:
            x[i] += delta[k] / 255
    return quantize(x)


def block_search(x0: Sequence[float], objective: Callable[[List[float]], Optional[float]], epsilon: float,
                 budget: int, seed: int) -> Dict[str, Any]:
    """Random search over 16 blocks of 2 x 2 pixels, each moved by -epsilon, 0 or +epsilon (whole grey levels).

    ``objective`` scores a photo (higher is better, >= 0 is done) or returns
    None when it cannot (a refused query); the search then stops. Every
    candidate stays within epsilon of ``x0``, in [0, 1] and on the grid.
    """
    rng = random.Random(seed)
    levels = int(epsilon * 255 + 1e-9)
    delta = [0] * len(BLOCKS)
    best_photo = quantize(x0)
    best = objective(best_photo)
    used, refused = 1, 0
    if best is None:
        return {"photo": best_photo, "queries": used, "refused": 1, "done": False}
    while best < 0 and used < budget:
        k = rng.randrange(len(BLOCKS))
        s = rng.choice((-levels, levels))
        if delta[k] == s:
            continue
        trial = list(delta)
        trial[k] = s
        photo = _apply(x0, trial)
        val = objective(photo)
        used += 1
        if val is None:
            refused += 1
            break
        if val > best:
            best, delta, best_photo = val, trial, photo
    return {"photo": best_photo, "queries": used, "refused": refused, "done": best >= 0}


def precheck_objective(api: Api, accounts: Sequence[str], log: Dict[str, int]) -> Callable[[List[float]], Optional[float]]:
    """The black-box view: the pre-check's score, from one account or rotating over several."""
    state = {"i": 0, "spent": set()}

    def objective(photo: List[float]) -> Optional[float]:
        while len(state["spent"]) < len(accounts):
            account = accounts[state["i"] % len(accounts)]
            state["i"] += 1
            if account in state["spent"]:
                continue
            answer = api.precheck(account, photo)
            log["prechecks"] += 1
            if "refused" in answer:
                log["refused"] += 1
                state["spent"].add(account)
                continue
            if "rejected" in answer:
                log["rejected"] += 1
                return -1.0
            return answer["score"] - DONE_SCORE
        return None

    return objective


def adaptive_objective(model: PixelModel, crush_line: float) -> Callable[[List[float]], float]:
    """White-box against both models: the weaker margin of the pixel model and the corner rule."""
    def objective(photo: List[float]) -> float:
        return min(model.logit(photo) * 0.05, crush_score(photo) - crush_line)
    return objective


# --------------------------------------------------------------------------- #
# Plans
# --------------------------------------------------------------------------- #
def craft(entry: Dict[str, Any], x0: List[float], api: Api) -> Dict[str, Any]:
    """Build the doctored photo for one plan. Returns the photo and what the search spent."""
    method, eps = entry["method"], float(entry["epsilon"])
    log = {"prechecks": 0, "refused": 0, "rejected": 0}
    if method in ("fgsm", "pgd", "adaptive"):
        model = PixelModel.from_dict(api.model())
        if method == "fgsm":
            photo = fgsm(model, x0, eps, bool(entry.get("grid", True)))
        elif method == "pgd":
            photo = pgd(model, x0, eps, int(entry["steps"]), float(entry["step_size"]))
        else:
            run = block_search(x0, adaptive_objective(model, load_policy()["crush_line"]), eps,
                               int(entry["max_steps"]), int(entry["seed"]))
            photo = run["photo"]
    elif method == "block_search":
        accounts = entry.get("accounts") or [entry["account"]]
        run = block_search(x0, precheck_objective(api, accounts, log), eps, int(entry["max_queries"]),
                           int(entry["seed"]))
        photo = run["photo"]
    else:
        raise ValueError(f"unknown method {method!r}")
    return {"photo": photo, **log}


def craft_offline(entry: Dict[str, Any], x0: List[float], model: PixelModel) -> List[float]:
    """The plan's photo against a given model, with an unmetered local pre-check (the scan's view)."""
    api = Api(model.to_dict, lambda a, p: {"score": model.score(p)}, lambda a, c, p: {})
    return craft(entry, x0, api)["photo"]


def campaign(api: Api, entry: Dict[str, Any], x0: List[float]) -> Dict[str, Any]:
    """Craft the photo and file the claim."""
    crafted = craft(entry, x0, api)
    photo = crafted["photo"]
    linf = max(abs(a - b) for a, b in zip(photo, x0))
    result = api.submit(entry["account"], entry["claim_id"], photo)
    return {**crafted, "linf": round(linf, 4), "decision": result["decision"], "reason": result["reason"],
            "answer": result}


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
        ok = _get(f"{base}/health").get("demo") == "hx18"
    except (urllib.error.URLError, OSError, ValueError):
        ok = False
    if not ok:
        print(f"[-] {base} is not the HX18 target. Start it: python vulnerable_app.py")
    return ok


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--plan", help="run this plan id only (see assets/evasion_plan.json)")
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if not check_target(args.target):
        return 1
    try:
        entries = [plan_by_id(args.plan)] if args.plan else load_plan()["attacks"]
    except KeyError as exc:
        print(f"[-] {exc}")
        return 1
    if not args.plan:
        _post(f"{args.target}/api/attack", {})          # the evaluator's suite now runs the plans
    _post(f"{args.target}/lab/new-day", {})
    claims = {c["claim_id"]: c for c in load_claims()}
    api = http_api(args.target)
    for entry in entries:
        print(f"[*] Plan '{entry['id']}' ({entry['access']}, {entry['method']}, epsilon {entry['epsilon']}) "
              f"for {entry['account']} on {entry['claim_id']}")
        try:
            run = campaign(api, entry, claim_photo(claims[entry["claim_id"]]))
        except urllib.error.HTTPError as exc:
            print(f"[-] The target refused the claim: {exc.read().decode('utf-8', 'replace')}")
            continue
        outcome = _post(f"{args.target}/lab/outcome", {"account": entry["account"], "claim_id": entry["claim_id"]})
        paid = "refund reference received" if outcome["received"] else "nothing received"
        print(f"[+] {run['prechecks']} pre-checks ({run['refused']} refused), largest pixel change {run['linf']}; "
              f"claim {run['decision']} ({run['reason']}); courier record: {outcome['record']}; {paid}.")
    print("[*] Re-run scripts/evaluate_kpi.py to measure the effect.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
