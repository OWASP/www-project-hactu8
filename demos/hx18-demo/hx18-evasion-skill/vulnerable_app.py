#!/usr/bin/env python3
"""Lamb's refund desk — the target system for the HX18 (Adversarial Examples, Evasion) demo.

Big Field Jumper Co. pays parcel-damage refunds automatically. A customer files a claim
with a photo of the parcel; the **damage classifier**, a small model trained
on the shop's claims history, reads the photo (an 8 x 8 greyscale bitmap, 64
pixels in [0, 1]) and decides: *damaged* pays the refund at once, *intact*
denies it. An approved refund is paid to the claimant's account with this
run's refund reference, the lab's canary (``HX18-CANARY-`` + 16 hex digits).
The claims app runs the same model on the phone for an instant pre-check, so
its weights ship inside the app (``GET /app/model``). Two gaps are
demonstrated, by omission:

* **One fragile model decides** — the production model is a logistic
  regression on the raw pixels. It is accurate on ordinary photos, and a
  perturbation of 0.03 per pixel (8 grey levels) along the sign of its
  weights moves its score far: in 64 dimensions small changes add up
  (Goodfellow et al., 2014). No second opinion, no robust training.
* **Nothing checks the input or meters the pre-check** — the claim endpoint
  takes any 64 numbers (floats, values outside [0, 1]) and the pre-check
  returns the model's score to anyone, as often as asked, which is all a
  black-box search needs.

AUTHORIZED SECURITY-LAB USE ONLY. Bound to loopback; insecure by design; do
not expose it.

The models are honest, not stand-ins that know the attack: both are trained
in pure Python, at import, on a seeded history of 600 photos
(``training_history``). ``scripts/run_evasion.py`` really computes gradients
or really searches with pre-check queries; the lab grades the decision,
never the attacker's intent.

Hardened mode (``POST /api/mode`` or ``HX18_MODE=hardened``) adds four
layers, each switchable for the tests:

* ``feature_validation`` — a photo must be 64 pixels in [0, 1] on the 8-bit
  grid a camera produces (multiples of 1/255).
* ``adversarial_training`` — the served model is trained on worst-case
  perturbed photos (epsilon 0.04, the exact inner maximum for a linear
  model), at a measured cost in clean accuracy.
* ``classifier_cross_check`` — a second, differently built model, a crushed-
  corner detector, must agree. Both *damaged* pays; both *intact* denies;
  a disagreement goes to a human reviewer and pays nothing automatically.
* ``rate_limit`` — 5 pre-checks per account per day.

Grading (``evaluate_kpi.classify``): RED when a claim that is fraud by ground
truth (the courier's record says the parcel was delivered intact) is
auto-approved, or when this run's refund reference reaches an attacker
account. Both are deterministic; the first is the declared oracle.

Host-safety guards (do not weaken the lesson): everything lives in memory,
one decision per claim per day, at most 200 accounts and 50,000 pre-checks a
day, nothing is fetched, executed or written to disk, no money moves, and the
canary is a worthless fictional reference.
"""

from __future__ import annotations

import functools
import json
import math
import os
import random
import re
import secrets
import statistics
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Sequence, Tuple

import providers

HERE = os.path.dirname(os.path.abspath(__file__))
ASSETS = os.path.join(HERE, "assets")
WEB_DIR = os.path.join(HERE, "web")
WEB_FILES = {"index.html": "text/html", "app.js": "text/javascript", "styles.css": "text/css"}
CLAIMS_FILE = os.path.join(ASSETS, "claims.json")
POLICY_FILE = os.path.join(ASSETS, "claims_policy.json")
PLAN_FILE = os.path.join(ASSETS, "evasion_plan.json")

SIDE = 8
PIXELS = SIDE * SIDE
CANARY_PREFIX = "HX18-CANARY-"
HISTORY_SEED, HELDOUT_SEED = 1, 2
HISTORY_SIZE, HELDOUT_SIZE = 600, 400
TRAIN_EPOCHS = 800

VALID_MODES = ("vulnerable", "hardened")
MAX_ACCOUNTS = 200
MAX_PRECHECKS_PER_DAY = 50_000
MAX_ABS_PIXEL = 10.0               # host guard on the raw numbers, both modes
ACCOUNT_RE = re.compile(r"^acct-[a-z0-9-]{2,24}$")

REFUSED_BUDGET = "pre-check budget for this account reached for today"
REJECTED_RANGE = "photo rejected: pixels must be between 0 and 1"
REJECTED_GRID = "photo rejected: pixels must be 8-bit camera levels (multiples of 1/255)"


def mint_canary() -> str:
    """A fresh fictional refund reference per lab instance: ``HX18-CANARY-`` + 16 hex digits."""
    return providers.register_canary(CANARY_PREFIX + secrets.token_hex(8))


def reference_received(text: str, canary: str) -> bool:
    """Grading: does ``text`` carry this run's refund reference (whole, re-encoded, or 12+ of its hex digits)?"""
    suffix = canary[len(CANARY_PREFIX):]
    return (providers.canary_leaked(text, canary)
            or providers.canary_leaked(text, providers.CANARY_PREFIX + suffix))


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def load_claims() -> List[Dict[str, Any]]:
    return load_json(CLAIMS_FILE)["claims"]


def load_policy() -> Dict[str, Any]:
    return load_json(POLICY_FILE)


def load_plan() -> Dict[str, Any]:
    return load_json(PLAN_FILE)


def plan_by_id(plan_id: str) -> Dict[str, Any]:
    data = load_plan()
    for entry in data["attacks"] + data["limits"]:
        if entry["id"] == plan_id:
            return entry
    raise KeyError(f"no plan {plan_id!r} in assets/evasion_plan.json")


# --------------------------------------------------------------------------- #
# Photos
# --------------------------------------------------------------------------- #
def quantize(x: Sequence[float]) -> List[float]:
    """Clip to [0, 1] and round to the 8-bit grid, as a camera image decodes."""
    return [round(min(1.0, max(0.0, v)) * 255) / 255 for v in x]


def corner_regions() -> List[List[int]]:
    """The four corner triangles (6 pixels each) where a crushed box shows."""
    out = []
    for cr, cc in ((0, 0), (0, SIDE - 1), (SIDE - 1, 0), (SIDE - 1, SIDE - 1)):
        out.append([r * SIDE + c for r in range(SIDE) for c in range(SIDE) if abs(r - cr) + abs(c - cc) < 3])
    return out


CORNERS = corner_regions()


def parcel_photo(rng: random.Random, damaged: bool, mild: Optional[bool] = None) -> List[float]:
    """One parcel photo as the claims history has them: cardboard, a tape stripe, sometimes a label.

    Damage is a crushed corner: a darker triangle. A quarter of the damaged
    parcels in the history are mildly crushed (small, faint). Most damaged
    parcels were photographed at the returns depot, whose camera adds a faint
    checker pattern (0.012): a real, label-correlated feature in the history
    that a pixel model learns to lean on.
    """
    base = rng.uniform(0.68, 0.72)
    gx, gy = rng.uniform(-0.004, 0.004), rng.uniform(-0.004, 0.004)
    img = [[base + gx * (c - 3.5) + gy * (r - 3.5) + rng.gauss(0, 0.025) for c in range(SIDE)] for r in range(SIDE)]
    tape_row = rng.choice([3, 4])
    for c in range(SIDE):
        img[tape_row][c] = min(0.99, img[tape_row][c] + 0.22)
    if rng.random() < 0.5:                                   # the address label's dark print
        r0, c0 = rng.choice([1, 5]), rng.randint(2, 4)
        for c in range(c0, c0 + 2):
            img[r0][c] = max(0.02, img[r0][c] - 0.6)
    if rng.random() < (0.85 if damaged else 0.1):            # the depot camera's pattern
        for r in range(SIDE):
            for c in range(SIDE):
                img[r][c] += 0.012 * (1 if (r + c) % 2 else -1)
    if damaged:
        is_mild = rng.random() < 0.25
        if mild is not None:
            is_mild = mild
        depth = rng.uniform(0.15, 0.3) if is_mild else rng.uniform(0.45, 0.6)
        size = 2 if is_mild else rng.choice([3, 4])
        cr, cc = rng.choice([(0, 0), (0, 7), (7, 0), (7, 7)])
        for r in range(SIDE):
            for c in range(SIDE):
                if abs(r - cr) + abs(c - cc) < size:
                    img[r][c] -= depth
    return quantize([v for row in img for v in row])


def photo_set(seed: int, n: int) -> Tuple[List[List[float]], List[int]]:
    rng = random.Random(seed)
    X, y = [], []
    for i in range(n):
        X.append(parcel_photo(rng, bool(i % 2)))
        y.append(i % 2)
    return X, y


@functools.lru_cache(maxsize=1)
def training_history() -> Tuple[Tuple[Tuple[float, ...], ...], Tuple[int, ...]]:
    X, y = photo_set(HISTORY_SEED, HISTORY_SIZE)
    return tuple(tuple(x) for x in X), tuple(y)


@functools.lru_cache(maxsize=1)
def heldout() -> Tuple[Tuple[Tuple[float, ...], ...], Tuple[int, ...]]:
    X, y = photo_set(HELDOUT_SEED, HELDOUT_SIZE)
    return tuple(tuple(x) for x in X), tuple(y)


def claim_photo(claim: Dict[str, Any]) -> List[float]:
    """The claimant's own photo of their parcel (deterministic from the claim's seed)."""
    return parcel_photo(random.Random(claim["photo_seed"]), claim["record"] == "damaged", mild=False)


# --------------------------------------------------------------------------- #
# The models
# --------------------------------------------------------------------------- #
@dataclass
class PixelModel:
    """Logistic regression on the 64 pixels: score = sigmoid(w . x + b); damaged when score >= 0.5."""
    weights: List[float]
    bias: float

    def logit(self, x: Sequence[float]) -> float:
        return sum(w * v for w, v in zip(self.weights, x)) + self.bias

    def score(self, x: Sequence[float]) -> float:
        z = self.logit(x)
        return 1.0 / (1.0 + math.exp(-z)) if z > -60 else 0.0

    def damaged(self, x: Sequence[float]) -> bool:
        return self.logit(x) >= 0.0

    def l1(self) -> float:
        return sum(abs(w) for w in self.weights)

    def to_dict(self) -> Dict[str, Any]:
        return {"kind": "logistic", "weights": list(self.weights), "bias": self.bias,
                "label": "damaged when weights . pixels + bias >= 0"}

    @staticmethod
    def from_dict(data: Any) -> "PixelModel":
        if not isinstance(data, dict) or not isinstance(data.get("weights"), list) or len(data["weights"]) != PIXELS:
            raise ValueError("model must have 64 weights and a bias")
        vals = list(data["weights"]) + [data.get("bias")]
        if any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) for v in vals):
            raise ValueError("model parameters must be finite numbers")
        return PixelModel([float(v) for v in data["weights"]], float(data["bias"]))


def train_logistic(X: Sequence[Sequence[float]], y: Sequence[int], epsilon: float = 0.0,
                   epochs: int = TRAIN_EPOCHS, lr: float = 2.0, l2: float = 1e-4) -> PixelModel:
    """Full-batch gradient descent on the logistic loss, optionally adversarial.

    With ``epsilon`` > 0 each photo is replaced by its worst case within
    epsilon per pixel. For a linear model that worst case is exact: it lowers
    the margin by epsilon * ||w||_1, so the loss is
    softplus(-(y (w.x + b) - epsilon ||w||_1)), with |w| smoothed for the
    gradient. This is adversarial training without an inner search.
    """
    d, n = len(X[0]), len(X)
    mu = [sum(x[j] for x in X) / n for j in range(d)]
    Z = [[x[j] - mu[j] for j in range(d)] for x in X]
    w, b, delta = [0.0] * d, 0.0, 1e-3
    for _ in range(epochs):
        gw, gb = [0.0] * d, 0.0
        soft = [wj / math.sqrt(wj * wj + delta * delta) for wj in w]
        l1 = sum(math.sqrt(wj * wj + delta * delta) for wj in w)
        for z, t in zip(Z, y):
            s = 1.0 if t else -1.0
            m = s * (sum(wi * zi for wi, zi in zip(w, z)) + b) - epsilon * l1
            g = -1.0 / (1.0 + math.exp(m)) if m > -30 else -1.0
            gb += g * s
            for j in range(d):
                gw[j] += g * (s * z[j] - epsilon * soft[j])
        b -= lr * gb / n
        for j in range(d):
            w[j] -= lr * (gw[j] / n + l2 * w[j])
    return PixelModel(w, b - sum(wj * m for wj, m in zip(w, mu)))


@functools.lru_cache(maxsize=4)
def _trained(epsilon: float) -> Tuple[Tuple[float, ...], float]:
    X, y = training_history()
    model = train_logistic(X, y, epsilon=epsilon)
    return tuple(model.weights), model.bias


def production_model() -> PixelModel:
    """The model the shop shipped: trained for accuracy on the claims history."""
    w, b = _trained(0.0)
    return PixelModel(list(w), b)


def robust_model(epsilon: float) -> PixelModel:
    """``adversarial_training``: the same model and data, trained on worst-case perturbed photos."""
    w, b = _trained(epsilon)
    return PixelModel(list(w), b)


def crush_score(x: Sequence[float]) -> float:
    """The second opinion's feature: how much darker the darkest corner triangle is than the box (the median)."""
    med = statistics.median(x)
    return max(med - sum(x[i] for i in reg) / len(reg) for reg in CORNERS)


def corner_rule(x: Sequence[float], line: float) -> bool:
    """``classifier_cross_check``'s second model: damaged when a corner is ``line`` darker than the box.

    It reads a different feature than the pixel model, through a median and a
    max, so a perturbation along the pixel model's weights does not move it
    much: each pixel moved by epsilon moves the score by at most 2 epsilon.
    """
    return crush_score(x) >= line


def accuracy(model: PixelModel, X: Sequence[Sequence[float]], y: Sequence[int]) -> float:
    return sum(model.damaged(x) == bool(t) for x, t in zip(X, y)) / len(X)


# --------------------------------------------------------------------------- #
# Input checks
# --------------------------------------------------------------------------- #
def parse_photo(photo: Any) -> List[float]:
    """Both modes: 64 finite numbers (the host guard). Says nothing about whether it is a real photo."""
    if not isinstance(photo, list) or len(photo) != PIXELS:
        raise ValueError(f"photo must be a list of {PIXELS} numbers")
    out = []
    for v in photo:
        if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or abs(v) > MAX_ABS_PIXEL:
            raise ValueError("photo pixels must be finite numbers")
        out.append(float(v))
    return out


def feature_problem(x: Sequence[float]) -> str:
    """``feature_validation``: the reason a photo is not a camera image, or ''."""
    if any(v < 0.0 or v > 1.0 for v in x):
        return REJECTED_RANGE
    if any(abs(v * 255 - round(v * 255)) > 1e-6 for v in x):
        return REJECTED_GRID
    return ""


# --------------------------------------------------------------------------- #
# The lab
# --------------------------------------------------------------------------- #
@dataclass
class Meter:
    account: str
    prechecks: int = 0
    answered: int = 0
    refused: int = 0
    claims: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"account": self.account, "prechecks": self.prechecks, "answered": self.answered,
                "refused": self.refused, "claims": list(self.claims)}


class Lab:
    def __init__(self, mode: str = "vulnerable", backend: str = "echo", model: str = "") -> None:
        self.lock = threading.Lock()
        self.canary = mint_canary()
        self.policy = load_policy()
        self.claims = {c["claim_id"]: c for c in load_claims()}
        self.production = production_model()
        self.robust = robust_model(self.policy["adversarial_epsilon"])
        # Each hardened layer can be switched off for the tests and the layer table.
        self.use_feature_validation = True
        self.use_adversarial_training = True
        self.use_cross_check = True
        self.use_query_budget = True
        self.set_backend(backend, model)
        self.mode = "vulnerable"
        self.set_mode(mode)
        self.reset()

    def reset(self) -> None:
        with self.lock:
            self._clear_day()
            self.attack_loaded = False

    def new_day(self) -> None:
        """Clear the meters, the decisions, the review queue and the account inboxes (one evaluation = one day)."""
        with self.lock:
            self._clear_day()

    def _clear_day(self) -> None:
        self.meters: Dict[str, Meter] = {}
        self.decisions: Dict[str, Dict[str, Any]] = {}
        self.review_queue: List[str] = []
        self.inbox: Dict[str, List[str]] = {}
        self.prechecks_today = 0

    def set_mode(self, mode: str) -> None:
        if mode not in VALID_MODES:
            raise ValueError(f"mode must be one of {VALID_MODES}")
        self.mode = mode

    def set_backend(self, backend: str, model: str = "") -> None:
        """Only ``echo`` (alias ``stub``): the classifier is pure Python, not a language model."""
        model = providers.check_model(model)
        name = providers.normalize(backend)
        if name not in providers.BACKENDS:
            raise ValueError(f"unknown backend {backend!r}")
        if name != "echo":
            raise ValueError("HX18 runs on the echo backend only: the target is a pure-Python image "
                             "classifier, and no language model is in the loop")
        self.backend = providers.describe(name, model)

    @property
    def hardened(self) -> bool:
        return self.mode == "hardened"

    def served_model(self) -> PixelModel:
        return self.robust if self.hardened and self.use_adversarial_training else self.production

    def app_model(self) -> Dict[str, Any]:
        """``GET /app/model``: the weights the claims app ships for its on-device pre-check (both modes)."""
        return self.served_model().to_dict()

    def _meter(self, account: str) -> Meter:
        if not isinstance(account, str) or not ACCOUNT_RE.match(account):
            raise ValueError("account must look like acct-name (lowercase letters, digits, dashes)")
        meter = self.meters.get(account)
        if meter is None:
            if len(self.meters) >= MAX_ACCOUNTS:
                raise ValueError("too many accounts today; reset the lab")
            meter = self.meters[account] = Meter(account)
        return meter

    def _check(self, x: List[float]) -> str:
        return feature_problem(x) if self.hardened and self.use_feature_validation else ""

    # -- the claims API ------------------------------------------------------
    def precheck(self, account: str, photo: Any) -> Dict[str, Any]:
        """``POST /v1/precheck``: the app's instant check, the served model's score for one photo."""
        x = parse_photo(photo)
        with self.lock:
            meter = self._meter(account)
            if self.prechecks_today >= MAX_PRECHECKS_PER_DAY:
                raise ValueError("lab pre-check cap reached; reset the lab")
            self.prechecks_today += 1
            meter.prechecks += 1
            if self.hardened and self.use_query_budget and meter.answered >= self.policy["precheck_budget"]:
                meter.refused += 1
                return {"refused": REFUSED_BUDGET}
            problem = self._check(x)
            if problem:
                meter.answered += 1
                return {"rejected": problem}
            meter.answered += 1
        served = self.served_model()
        score = served.score(x)
        return {"score": score, "label": "damaged" if score >= 0.5 else "intact"}

    def submit_claim(self, account: str, claim_id: str, photo: Any) -> Dict[str, Any]:
        """``POST /v1/claims``: decide one claim. One decision per claim per day."""
        x = parse_photo(photo)
        claim = self.claims.get(claim_id) if isinstance(claim_id, str) else None
        if claim is None or claim["account"] != account:
            raise ValueError("no such claim for this account")
        with self.lock:
            meter = self._meter(account)
            if claim_id in self.decisions:
                raise ValueError("this claim was already decided today")
            problem = self._check(x)
            served = self.served_model()
            score = served.score(x)
            second = corner_rule(x, self.policy["crush_line"])
            if problem:
                decision, reason = "rejected", problem
            elif self.hardened and self.use_cross_check and (score >= 0.5) != second:
                decision, reason = "review", "the two models disagree: held for a human reviewer"
            elif score >= 0.5:
                decision, reason = "approved", "damage detected"
            else:
                decision, reason = "denied", "no damage detected"
            out: Dict[str, Any] = {"claim_id": claim_id, "decision": decision, "reason": reason}
            if not problem:
                out["score"] = score
            if decision == "approved":
                out["refund_reference"] = self.canary
                self.inbox.setdefault(account, []).append(
                    f"Refund approved for {claim_id}: {claim['amount']} paid to {account}, reference {self.canary}.")
            elif decision == "review":
                self.review_queue.append(claim_id)
            meter.claims.append(claim_id)
            self.decisions[claim_id] = {**out, "account": account, "second_opinion": second,
                                        "served_damaged": score >= 0.5}
        return out

    # -- grading -------------------------------------------------------------
    def received(self, account: str) -> str:
        """Everything the account was sent today (what an attacker received)."""
        return "\n".join(self.inbox.get(account, []))

    def record(self, claim_id: str) -> str:
        """The lab's ground truth: the courier's record of the parcel at delivery."""
        return self.claims[claim_id]["record"]

    def outcome(self, account: str, claim_id: str) -> Dict[str, Any]:
        """The grader's view of one claim today: the record, the decision, what the account received."""
        if not isinstance(claim_id, str) or claim_id not in self.claims:
            raise ValueError("no such claim")
        decided = self.decisions.get(claim_id, {})
        received = self.received(str(account))
        return {"record": self.record(claim_id), "decision": decided.get("decision", ""),
                "served_damaged": decided.get("served_damaged"), "second_opinion": decided.get("second_opinion"),
                "served": "robust" if self.served_model() is self.robust else "production",
                "hardened": self.hardened, "received": received,
                "canary_received": reference_received(received, self.canary)}

    def load_attack(self) -> List[Dict[str, Any]]:
        """Act 2: the attackers' plans go live (no server change; it is just claims traffic)."""
        self.attack_loaded = True
        return load_plan()["attacks"]

    def state(self) -> Dict[str, Any]:
        return {"mode": self.mode, "backend": self.backend, "attack_loaded": self.attack_loaded,
                "baseline": not self.attack_loaded, "prechecks_today": self.prechecks_today,
                "accounts": [m.to_dict() for m in self.meters.values()], "review_queue": list(self.review_queue)}


# --------------------------------------------------------------------------- #
# Lab console API (web/ — the shared HACTU8 console)
# --------------------------------------------------------------------------- #
CONSOLE_META = {
    "id": "HX18",
    "framework": "HACTU8 extended attacks (evasion of a classic classifier; MITRE ATLAS AML.T0043, AML.T0015)",
    "risk": "Adversarial Examples (Evasion)",
    "title": "Adversarial Examples Lab",
    "short_title": "Evasion Lab",
    "scenario": (
        "Lamb's refund desk pays parcel-damage claims automatically when Big Field Jumper Co.'s photo classifier, a "
        "logistic regression on 8 x 8 photos, says damaged. The app ships the model, its pre-check returns the "
        "score to anyone, and nothing checks the photo."
    ),
    "ground_truth": ("A claim the courier recorded as delivered intact is never paid automatically, and the "
                     "refund reference never reaches the claimant who filed it."),
    "metric_name": "Evasion Success Rate",
    "metric_abbr": "ESR",
    "attack_label": "Run the fraudsters' evasion plans",
    "attack_description": ("Three accounts claim refunds for intact parcels with doctored photos: a fast gradient "
                           "sign step (0.03 per pixel, raw floats), the same step kept on the 8-bit grid, and a "
                           "black-box block search driven by the pre-check's score (0.10 per pixel)."),
    "scan_label": "Check the doctored photos: camera grid and the second opinion",
    "harden_label": "Feature validation, adversarial training, a cross-checking second model, a pre-check budget",
    "harden_description": ("Photos must be 8-bit camera images, the served model is adversarially trained, a "
                           "crushed-corner detector must agree or the claim goes to a human, and each account gets "
                           "5 pre-checks a day."),
}


def _scripts() -> None:
    import sys
    path = os.path.join(HERE, "scripts")
    if path not in sys.path:
        sys.path.insert(0, path)


def console_attack(lab: Lab) -> Dict[str, Any]:
    entries = lab.load_attack()
    return {"events": [f"Plan '{e['id']}' queued for {e['account']} on claim {e['claim_id']}: {e['route']}."
                       for e in entries]}


def console_evaluate(lab: Lab) -> Dict[str, Any]:
    _scripts()
    from evaluate_kpi import classify, describe, run_item, suite

    lab.new_day()
    rows = []
    for item in suite(lab.attack_loaded):
        result = run_item(lab, item)
        rows.append({"item": item["label"], "targeted": item["targeted"], "status": classify(result),
                     "detail": describe(result)})
    return summarize(rows)


def summarize(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    targeted = [r for r in rows if r["targeted"]]
    red_t = sum(r["status"] == "RED" for r in targeted)
    red_all = sum(r["status"] == "RED" for r in rows)
    return {
        "rows": rows,
        "red_targeted": red_t, "targeted": len(targeted),
        "red_overall": red_all, "total": len(rows),
        "targeted_rate": 100.0 * red_t / len(targeted) if targeted else 0.0,
        "overall_rate": 100.0 * red_all / len(rows) if rows else 0.0,
    }


def audit_plan(entry: Dict[str, Any], lab: Optional[Lab] = None) -> Dict[str, Any]:
    """Offline: craft the plan's photo against the shipped (vulnerable) model and run the hardened input checks."""
    _scripts()
    from run_evasion import craft_offline

    lab = lab or Lab()
    claim = lab.claims[entry["claim_id"]]
    x = craft_offline(entry, claim_photo(claim), lab.production)
    problem = feature_problem(x)
    second = corner_rule(x, lab.policy["crush_line"])
    fooled = lab.production.damaged(x)
    return {"id": entry["id"], "problem": problem, "second_opinion": second, "fools_shipped_model": fooled,
            "stopped": bool(problem) or (fooled and not second)}


def console_scan(lab: Lab) -> Dict[str, Any]:
    rows = [audit_plan(e, lab) for e in load_plan()["attacks"]]
    findings = [f"{r['id']}: {'fools' if r['fools_shipped_model'] else 'does not fool'} the shipped model; "
                f"{r['problem'] or 'passes the camera checks'}; the corner detector says "
                f"{'damaged' if r['second_opinion'] else 'intact'}" for r in rows]
    return {"subject": "assets/evasion_plan.json (attacks)",
            "decision": "REJECT" if any(r["stopped"] for r in rows) else "PASS", "findings": findings}


# --------------------------------------------------------------------------- #
# HTTP surface
# --------------------------------------------------------------------------- #
LAB: Optional[Lab] = None
PORT = 5518


class Handler(BaseHTTPRequestHandler):
    server_version = "HX18Lab/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:  # quieter console
        pass

    def _send(self, status: int, body: Dict[str, Any]) -> None:
        data = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _host_ok(self) -> bool:
        """Reject other Host headers (DNS-rebinding guard for a loopback lab)."""
        host = (self.headers.get("Host") or "").lower()
        return host in {f"127.0.0.1:{PORT}", f"localhost:{PORT}"}

    def _static(self, name: str) -> None:
        with open(os.path.join(WEB_DIR, name), "rb") as fh:
            data = fh.read()
        self.send_response(200)
        self.send_header("Content-Type", f"{WEB_FILES[name]}; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'")
        self.end_headers()
        self.wfile.write(data)

    def _json(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if length > 50_000:
            raise ValueError("body too large")
        raw = self.rfile.read(length) if length else b"{}"
        body = json.loads(raw or b"{}")
        if not isinstance(body, dict):
            raise ValueError("body must be a JSON object")
        return body

    def do_GET(self) -> None:
        assert LAB is not None
        if not self._host_ok():
            self._send(403, {"error": "bad host"})
            return
        if self.path == "/":
            self._static("index.html")
        elif self.path.startswith("/web/") and self.path[5:] in WEB_FILES:
            self._static(self.path[5:])
        elif self.path == "/api/meta":
            self._send(200, {**CONSOLE_META, **providers.console_info()})
        elif self.path.startswith("/api/models?backend="):
            name = providers.normalize(self.path.split("=", 1)[1])
            if name not in providers.BACKENDS:
                self._send(400, {"error": "unknown backend"})
                return
            self._send(200, {"backend": name, "models": []})      # echo only: nothing to list
        elif self.path == "/health":
            self._send(200, {"status": "ok", "demo": "hx18", "mode": LAB.mode, "backend": LAB.backend})
        elif self.path == "/api/state":
            self._send(200, LAB.state())
        elif self.path == "/app/model":
            self._send(200, LAB.app_model())
        elif self.path == "/claims":
            self._send(200, {"claims": [{k: c[k] for k in ("claim_id", "account", "amount")}
                                        for c in LAB.claims.values()]})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        assert LAB is not None
        if not self._host_ok():
            self._send(403, {"error": "bad host"})
            return
        # A cross-site HTML form cannot send application/json without a CORS
        # preflight, so requiring it keeps other web pages off this lab.
        if not (self.headers.get("Content-Type") or "").startswith("application/json"):
            self._send(415, {"error": "Content-Type must be application/json"})
            return
        try:
            body = self._json()
        except (ValueError, json.JSONDecodeError) as exc:
            self._send(400, {"error": str(exc)})
            return
        try:
            self._route(body)
        except ValueError as exc:
            self._send(400, {"error": str(exc)})

    def _route(self, body: Dict[str, Any]) -> None:
        assert LAB is not None
        if self.path == "/v1/precheck":
            self._send(200, LAB.precheck(body.get("account", ""), body.get("photo")))
        elif self.path == "/v1/claims":
            self._send(200, LAB.submit_claim(body.get("account", ""), body.get("claim_id", ""), body.get("photo")))
        elif self.path == "/lab/outcome":
            self._send(200, LAB.outcome(body.get("account", ""), body.get("claim_id", "")))
        elif self.path == "/lab/new-day":
            LAB.new_day()
            self._send(200, LAB.state())
        elif self.path == "/api/reset":
            LAB.reset()
            LAB.set_mode("vulnerable")
            self._send(200, LAB.state())
        elif self.path == "/api/attack":
            self._send(200, console_attack(LAB))
        elif self.path == "/api/evaluate":
            self._send(200, console_evaluate(LAB))
        elif self.path == "/api/scan":
            self._send(200, console_scan(LAB))
        elif self.path == "/api/mode":
            LAB.set_mode(str(body.get("mode", "")))
            self._send(200, LAB.state())
        elif self.path == "/api/backend":
            LAB.set_backend(str(body.get("backend", "")), str(body.get("model", "")))
            self._send(200, LAB.state())
        else:
            self._send(404, {"error": "not found"})


def main() -> None:
    global LAB, PORT
    LAB = Lab(mode=os.getenv("HX18_MODE", "vulnerable"),
              backend=os.getenv("HX18_BACKEND", "echo"),
              model=os.getenv("HX18_MODEL", ""))
    PORT = int(os.getenv("HX18_PORT", "5518"))
    httpd = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"[*] HX18 lab target on http://127.0.0.1:{PORT} (mode={LAB.mode}, backend={LAB.backend})")
    print(f"[*] Lab console: http://127.0.0.1:{PORT}/")
    print("[*] Insecure by design. Loopback only. Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
