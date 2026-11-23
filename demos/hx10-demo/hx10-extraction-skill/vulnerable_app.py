#!/usr/bin/env python3
"""Lamb's price-band API — the target system for the HX10 (Model Extraction) demo.

Big Field Jumper Co. trained a small proprietary model on its private sales history: it
reads seven features of a product listing (weight, shelf life, organic, bulk
pack, supplier tier, demand index, rating) and returns the listing's price
band (``budget``, ``standard`` or ``premium``). Lamb's shop and its partners
call it over a prediction API with a self-service key. Each build of the
model is stamped with a fingerprint: this run's canary (``HX10-CANARY-`` + 16
hex digits) is written into the low-order digits of its 16 parameters, so a
copy of the exact weights carries it. Two gaps are demonstrated, by omission:

* **The API says more than the answer** — every prediction carries the
  model's full-precision confidences, so a few queries determine the
  logistic model's equations and the exact weights (Tramèr et al., 2016).
* **Nothing meters or watches who asks what** — keys are free and unlimited,
  any listing in the documented ranges is answered, and no one checks whether
  a key's queries look like a shop pricing its stock or like someone mapping
  the model. The bands alone are enough to train a clone.

AUTHORIZED SECURITY-LAB USE ONLY. Bound to loopback; insecure by design; do
not expose it.

The victim is an honest small model, not a stand-in that knows the attack:
a multinomial logistic regression trained in pure Python, at import, on a
seeded private history (``train_victim``). The attacker in
``scripts/run_extraction.py`` really queries it and really trains a clone; the
lab grades the clone, never the attacker's intent.

Hardened mode (``POST /api/mode`` or ``HX10_MODE=hardened``) adds four layers,
each switchable for the tests:

* ``score_suppression`` (label-only answers) — the API returns the band and nothing else.
* ``rate_limit`` — a per-key query budget (``assets/api_policy.json``).
* ``query_anomaly`` — a key whose recent queries fall outside the envelope of
  real listings too often is suspended.
* ``output_watermark`` — the served bands come from a copy of the model with
  a secret, small boundary shift (about 2% of real listings change band). A
  clone trained on them inherits the shift; the owner's probe listings, where
  the two disagree, prove where a suspect model learned (``verify_watermark``).
  It does not prevent theft; it proves it.

Grading (``grade_clone``): a clone is a theft when this run's canary can be
read from its parameters (``providers.canary_leaked``), or when it agrees with
the victim on 95% or more of 1,000 held-out listings **and** it is proven to
have learned from this API (the harness trained it on the API's answers, or
the watermark proves it). An independent model can agree 95% or more, so
agreement alone is never a theft.

Host-safety guards (do not weaken the lesson): everything lives in memory, a
batch holds at most 100 listings, the lab tracks at most 500 keys and 100,000
queries a day, nothing is fetched, executed or written to disk, and the
canary is a worthless fictional tag.
"""

from __future__ import annotations

import functools
import json
import math
import os
import random
import re
import secrets
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Sequence, Tuple

import providers

HERE = os.path.dirname(os.path.abspath(__file__))
ASSETS = os.path.join(HERE, "assets")
WEB_DIR = os.path.join(HERE, "web")
WEB_FILES = {"index.html": "text/html", "app.js": "text/javascript", "styles.css": "text/css"}
CATALOG_FILE = os.path.join(ASSETS, "catalog.json")
POLICY_FILE = os.path.join(ASSETS, "api_policy.json")
PLAN_FILE = os.path.join(ASSETS, "extraction_plan.json")

FEATURES = ("weight_kg", "shelf_life_months", "organic", "bulk_pack", "supplier_tier", "demand_index", "rating")
CLASSES = ("budget", "standard", "premium")
REFERENCE = 1                      # the model's reference class (standard), logit fixed at 0
# The ranges the API documents (and validates). Flags are 0/1, the tier 1-3.
API_RANGES = {"weight_kg": (0.1, 50.0), "shelf_life_months": (0, 60), "organic": (0, 1), "bulk_pack": (0, 1),
              "supplier_tier": (1, 3), "demand_index": (0.0, 1.0), "rating": (1.0, 5.0)}
INTEGER_FEATURES = ("shelf_life_months", "organic", "bulk_pack", "supplier_tier")

CANARY_PREFIX = "HX10-CANARY-"
FINGERPRINT_SCALE = 100_000        # the fingerprint lives below the 5th decimal of each parameter
AGREEMENT_THRESHOLD = 0.95         # a clone this close is a usable substitute: RED
HELDOUT_SIZE = 1000
PRIVATE_SEED, HELDOUT_SEED, PROBE_SEED, WATERMARK_SEED, COMPETITOR_SEED = 2026, 99, 4242, 1010, 777

VALID_MODES = ("vulnerable", "hardened")
MAX_BATCH = 100
MAX_KEYS = 500
MAX_QUERIES_PER_DAY = 100_000
KEY_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,31}$")

REFUSED_BUDGET = "query budget for this key reached for today"
REFUSED_SUSPENDED = "key suspended: its queries do not look like real listings"


def mint_canary() -> str:
    """A fresh fictional build fingerprint per lab instance: ``HX10-CANARY-`` + 16 hex digits."""
    return CANARY_PREFIX + secrets.token_hex(8)


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def load_catalog() -> List[Dict[str, Any]]:
    return load_json(CATALOG_FILE)["listings"]


def load_policy() -> Dict[str, Any]:
    return load_json(POLICY_FILE)


def load_plan() -> Dict[str, Any]:
    return load_json(PLAN_FILE)


def plan_by_id(plan_id: str) -> Dict[str, Any]:
    data = load_plan()
    for entry in data["attacks"] + data["limits"]:
        if entry["id"] == plan_id:
            return entry
    raise KeyError(f"no plan {plan_id!r} in assets/extraction_plan.json")


# --------------------------------------------------------------------------- #
# Listings and the private history
# --------------------------------------------------------------------------- #
def realistic_listing(rng: random.Random) -> List[float]:
    """One listing as Big Field Jumper Co.'s catalog has them (the same envelope as ``assets/api_policy.json``)."""
    weight = min(25.0, max(0.2, round(math.exp(rng.gauss(1.2, 0.9)), 1)))
    shelf = min(36, max(0, int(rng.gauss(12, 8))))
    organic = int(rng.random() < 0.3)
    bulk = int(rng.random() < 0.25)
    tier = rng.choice([1, 1, 2, 2, 2, 3])
    demand = round(min(0.95, max(0.05, rng.betavariate(2, 3))), 2)
    rating = round(min(5.0, max(2.5, rng.gauss(4.1, 0.5))), 1)
    return [weight, shelf, organic, bulk, tier, demand, rating]


def pricing_rule(x: Sequence[float], rng: random.Random) -> int:
    """How the shop actually priced a listing (private history): a score plus noise, cut into bands."""
    weight, shelf, organic, bulk, tier, demand, rating = x
    score = (0.08 * weight - 0.03 * shelf + 1.1 * organic - 0.9 * bulk + 0.7 * tier + 1.5 * demand
             + 0.6 * rating + rng.gauss(0, 0.35))
    return 0 if score < 3.6 else (1 if score < 4.6 else 2)


def as_vector(listing: Dict[str, Any]) -> List[float]:
    return [float(listing[f]) for f in FEATURES]


def as_listing(x: Sequence[float]) -> Dict[str, Any]:
    return {f: (int(v) if f in INTEGER_FEATURES else v) for f, v in zip(FEATURES, x)}


def validate_listing(listing: Any) -> List[float]:
    """The API's input check (both modes): every feature present, numeric, in its documented range."""
    if not isinstance(listing, dict):
        raise ValueError("a listing must be an object")
    x = []
    for f in FEATURES:
        v = listing.get(f)
        if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v):
            raise ValueError(f"{f} must be a number")
        lo, hi = API_RANGES[f]
        if not lo <= v <= hi:
            raise ValueError(f"{f} must be between {lo} and {hi}")
        if f in INTEGER_FEATURES and v != int(v):
            raise ValueError(f"{f} must be a whole number")
        x.append(float(v))
    return x


# --------------------------------------------------------------------------- #
# Linear models: the victim's form and the clone's
# --------------------------------------------------------------------------- #
@dataclass
class LinearModel:
    """Three class rows of seven weights and a bias; the band is the argmax of the logits."""
    weights: List[List[float]]
    bias: List[float]

    def logits(self, x: Sequence[float]) -> List[float]:
        return [sum(w * v for w, v in zip(row, x)) + b for row, b in zip(self.weights, self.bias)]

    def predict(self, x: Sequence[float]) -> int:
        z = self.logits(x)
        return max(range(len(z)), key=lambda k: z[k])

    def proba(self, x: Sequence[float]) -> List[float]:
        z = self.logits(x)
        m = max(z)
        e = [math.exp(v - m) for v in z]
        s = sum(e)
        return [v / s for v in e]

    def relative(self) -> "LinearModel":
        """The same model with the reference class's row subtracted (its logit fixed at 0)."""
        rw, rb = self.weights[REFERENCE], self.bias[REFERENCE]
        return LinearModel([[w - r for w, r in zip(row, rw)] for row in self.weights],
                           [b - rb for b in self.bias])

    def parameters(self) -> List[float]:
        """The 16 free parameters: weights then bias of budget, then of premium (relative form)."""
        rel = self.relative()
        return [p for k in (0, 2) for p in rel.weights[k] + [rel.bias[k]]]

    def to_dict(self) -> Dict[str, Any]:
        return {"classes": list(CLASSES), "weights": [list(r) for r in self.weights], "bias": list(self.bias)}

    @staticmethod
    def from_dict(data: Any) -> "LinearModel":
        if not isinstance(data, dict):
            raise ValueError("clone must be an object")
        weights, bias = data.get("weights"), data.get("bias")
        if (not isinstance(weights, list) or len(weights) != 3 or not isinstance(bias, list) or len(bias) != 3
                or any(not isinstance(r, list) or len(r) != len(FEATURES) for r in weights)):
            raise ValueError("clone must have 3 weight rows of 7 numbers and 3 biases")
        vals = [v for r in weights for v in r] + bias
        if any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) for v in vals):
            raise ValueError("clone parameters must be finite numbers")
        return LinearModel([[float(v) for v in r] for r in weights], [float(v) for v in bias])


def train_softmax(X: List[List[float]], y: List[int], epochs: int = 300, lr: float = 0.5) -> LinearModel:
    """Multinomial logistic regression by full-batch gradient descent on standardized features."""
    d, n = len(X[0]), len(X)
    mu = [sum(r[j] for r in X) / n for j in range(d)]
    sd = [max(1e-9, math.sqrt(sum((r[j] - mu[j]) ** 2 for r in X) / n)) for j in range(d)]
    Z = [[(r[j] - mu[j]) / sd[j] for j in range(d)] for r in X]
    W = [[0.0] * d for _ in range(3)]
    B = [0.0] * 3
    for _ in range(epochs):
        gW = [[0.0] * d for _ in range(3)]
        gB = [0.0] * 3
        for z, t in zip(Z, y):
            lo = [sum(W[k][j] * z[j] for j in range(d)) + B[k] for k in range(3)]
            m = max(lo)
            e = [math.exp(v - m) for v in lo]
            s = sum(e)
            for k in range(3):
                g = e[k] / s - (1.0 if k == t else 0.0)
                gB[k] += g
                for j in range(d):
                    gW[k][j] += g * z[j]
        for k in range(3):
            B[k] -= lr * gB[k] / n
            for j in range(d):
                W[k][j] -= lr * (gW[k][j] / n + 1e-3 * W[k][j])
    raw_w = [[W[k][j] / sd[j] for j in range(d)] for k in range(3)]
    raw_b = [B[k] - sum(W[k][j] * mu[j] / sd[j] for j in range(d)) for k in range(3)]
    return LinearModel(raw_w, raw_b).relative()


@functools.lru_cache(maxsize=1)
def train_victim() -> Tuple[Tuple[float, ...], ...]:
    """Big Field Jumper Co.'s model, trained once on 600 listings of private history (seeded, deterministic)."""
    rng = random.Random(PRIVATE_SEED)
    X = [realistic_listing(rng) for _ in range(600)]
    y = [pricing_rule(x, rng) for x in X]
    model = train_softmax(X, y)
    return tuple(tuple(r) for r in model.weights) + (tuple(model.bias),)


def base_model() -> LinearModel:
    rows = train_victim()
    return LinearModel([list(r) for r in rows[:3]], list(rows[3]))


# --------------------------------------------------------------------------- #
# The build fingerprint (the canary in the weights)
# --------------------------------------------------------------------------- #
def stamp(model: LinearModel, canary: str) -> LinearModel:
    """Write the canary's 16 hex digits into the low-order digits of the 16 free parameters.

    Each parameter keeps its first five decimals; digit h sets the rest to
    (h + 0.5) / 16 of the last unit. Behaviour changes by less than 1e-5 per
    parameter. Only a copy of the exact parameters carries the digits.
    """
    digits = [int(c, 16) for c in canary[len(CANARY_PREFIX):]]
    params = model.parameters()
    stamped = [(math.floor(p * FINGERPRINT_SCALE) + (h + 0.5) / 16) / FINGERPRINT_SCALE
               for p, h in zip(params, digits)]
    rows = [stamped[0:7], [0.0] * 7, stamped[8:15]]
    return LinearModel(rows, [stamped[7], 0.0, stamped[15]])


def read_fingerprint(model: LinearModel) -> str:
    """The owner's reading of a suspect model's parameters, as fingerprint text (grading)."""
    out = []
    for p in model.parameters():
        scaled = p * FINGERPRINT_SCALE
        out.append("0123456789abcdef"[min(15, max(0, int((scaled - math.floor(scaled)) * 16)))])
    return CANARY_PREFIX + "".join(out)


def canary_recovered(model: LinearModel, canary: str) -> bool:
    """Grading: does the suspect's fingerprint carry this run's canary (whole, or 12+ contiguous digits)?"""
    text = read_fingerprint(model)
    suffix = canary[len(CANARY_PREFIX):]
    return (providers.canary_leaked(text, canary)
            or providers.canary_leaked(text[len(CANARY_PREFIX):], providers.CANARY_PREFIX + suffix))


# --------------------------------------------------------------------------- #
# Mitigations: query budget, query anomaly, output watermark
# --------------------------------------------------------------------------- #
def implausible(x: Sequence[float], envelope: Dict[str, Any]) -> bool:
    """``query_anomaly``'s per-query test: a feature outside the envelope real listings occupy."""
    for f, v in zip(FEATURES, x):
        bounds = envelope.get(f)
        if isinstance(bounds, list) and not bounds[0] <= v <= bounds[1]:
            return True
    return False


@dataclass
class KeyMeter:
    key: str
    queries: int = 0
    answered: int = 0
    refused: int = 0
    recent: List[bool] = field(default_factory=list)     # implausible flags, last window
    implausible_total: int = 0
    suspended: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {"key": self.key, "queries": self.queries, "answered": self.answered, "refused": self.refused,
                "implausible": self.implausible_total, "suspended": self.suspended}


def _watermark_direction() -> Tuple[List[List[float]], List[float]]:
    rng = random.Random(WATERMARK_SEED)
    direction_w = [[rng.gauss(0, 1) / s for s in (5, 10, 1, 1, 1, 0.3, 0.6)] for _ in range(3)]
    direction_b = [rng.gauss(0, 1) for _ in range(3)]
    direction_w[REFERENCE], direction_b[REFERENCE] = [0.0] * 7, 0.0
    return direction_w, direction_b


def _shifted(model: LinearModel, alpha: float) -> LinearModel:
    dw, db = _watermark_direction()
    return LinearModel([[w + alpha * d for w, d in zip(r, dr)] for r, dr in zip(model.weights, dw)],
                       [b + alpha * d for b, d in zip(model.bias, db)])


@functools.lru_cache(maxsize=8)
def watermark_strength(flip_share: float) -> float:
    """The shift's scale, set once on the unstamped model so that ``flip_share`` of real listings move."""
    model = base_model()
    sample = heldout_inputs(seed=PROBE_SEED + 1, n=2000)
    truth = [model.predict(x) for x in sample]
    lo, hi = 0.0, 4.0
    for _ in range(30):
        mid = (lo + hi) / 2
        flips = sum(_shifted(model, mid).predict(x) != t for x, t in zip(sample, truth)) / len(sample)
        lo, hi = (mid, hi) if flips < flip_share else (lo, mid)
    return hi


def watermarked(model: LinearModel, flip_share: float) -> LinearModel:
    """``output_watermark``: the model plus a secret direction, scaled so ``flip_share`` of real listings move.

    The direction comes from the owner's watermark key (``WATERMARK_SEED``,
    fixed here so runs are reproducible). A linear clone trained on the
    served bands learns the shifted boundary.
    """
    return _shifted(model, watermark_strength(flip_share))


@functools.lru_cache(maxsize=4)
def heldout_inputs(seed: int = HELDOUT_SEED, n: int = HELDOUT_SIZE) -> Tuple[Tuple[float, ...], ...]:
    rng = random.Random(seed)
    return tuple(tuple(realistic_listing(rng)) for _ in range(n))


def probe_listings(true_model: LinearModel, served: LinearModel, n: int = 6000) -> List[Tuple[float, ...]]:
    """The owner's secret probes: real-looking listings where the watermark changed the band."""
    return [x for x in heldout_inputs(seed=PROBE_SEED, n=n) if served.predict(x) != true_model.predict(x)]


def verify_watermark(suspect: LinearModel, true_model: LinearModel, served: LinearModel,
                     proof_share: float) -> Dict[str, Any]:
    """Does the suspect answer the probes like the watermarked API (it learned from it) or like the true model?"""
    probes = probe_listings(true_model, served)
    if not probes:
        return {"probes": 0, "watermark_share": 0.0, "proven": False}
    share = sum(suspect.predict(x) == served.predict(x) for x in probes) / len(probes)
    return {"probes": len(probes), "watermark_share": round(share, 3), "proven": share >= proof_share}


def competitor_model(seed: int = COMPETITOR_SEED) -> LinearModel:
    """An independent model: a rival who priced its own 600 listings and trained its own clone-free model.
    Across seeds its agreement with the victim reaches 95% or more (``CompetitorTest``), so agreement alone
    never makes a model of unknown origin RED."""
    rng = random.Random(seed)
    X = [realistic_listing(rng) for _ in range(600)]
    y = [pricing_rule(x, rng) for x in X]
    return train_softmax(X, y, epochs=150)


# --------------------------------------------------------------------------- #
# The lab
# --------------------------------------------------------------------------- #
class Lab:
    def __init__(self, mode: str = "vulnerable", backend: str = "echo", model: str = "") -> None:
        self.lock = threading.Lock()
        self.canary = mint_canary()
        self.policy = load_policy()
        self.catalog = load_catalog()
        self.model = stamp(base_model(), self.canary)                 # the victim, as graded
        self.served_watermarked = watermarked(self.model, self.policy["watermark_flip_share"])
        self.heldout = heldout_inputs()
        self.heldout_truth = [self.model.predict(x) for x in self.heldout]
        # Each hardened layer can be switched off for the tests and the layer table.
        self.use_label_only = True
        self.use_rate_limit = True
        self.use_query_anomaly = True
        self.use_output_watermark = True
        self.set_backend(backend, model)
        self.mode = "vulnerable"
        self.set_mode(mode)
        self.reset()

    def reset(self) -> None:
        with self.lock:
            self.meters: Dict[str, KeyMeter] = {}
            self.queries_today = 0
            self.attack_loaded = False

    def new_day(self) -> None:
        """Clear the per-key meters and suspensions (each evaluation is one day of traffic)."""
        with self.lock:
            self.meters = {}
            self.queries_today = 0

    def set_mode(self, mode: str) -> None:
        if mode not in VALID_MODES:
            raise ValueError(f"mode must be one of {VALID_MODES}")
        self.mode = mode

    def set_backend(self, backend: str, model: str = "") -> None:
        """Only ``echo`` (alias ``stub``): the victim is a pure-Python classifier, not a language model."""
        model = providers.check_model(model)
        name = providers.normalize(backend)
        if name not in providers.BACKENDS:
            raise ValueError(f"unknown backend {backend!r}")
        if name != "echo":
            raise ValueError("HX10 runs on the echo backend only: the victim is a pure-Python price-band "
                             "classifier, and no language model is in the loop")
        self.backend = providers.describe(name, model)

    @property
    def hardened(self) -> bool:
        return self.mode == "hardened"

    def served_model(self) -> LinearModel:
        return self.served_watermarked if self.hardened and self.use_output_watermark else self.model

    # -- the prediction API --------------------------------------------------
    def predict(self, key: str, listings: List[Any]) -> List[Dict[str, Any]]:
        """``POST /v1/predict``: one answer per listing, or a refusal."""
        if not isinstance(key, str) or not KEY_RE.match(key):
            raise ValueError("key must be 3-32 lowercase letters, digits or dashes")
        if not isinstance(listings, list) or not 1 <= len(listings) <= MAX_BATCH:
            raise ValueError(f"listings must be a list of 1 to {MAX_BATCH}")
        vectors = [validate_listing(item) for item in listings]
        served = self.served_model()
        out = []
        with self.lock:
            meter = self.meters.get(key)
            if meter is None:
                if len(self.meters) >= MAX_KEYS:
                    raise ValueError("too many keys today; reset the lab")
                meter = self.meters[key] = KeyMeter(key)
            if self.queries_today + len(vectors) > MAX_QUERIES_PER_DAY:
                raise ValueError("lab query cap reached; reset the lab")
            self.queries_today += len(vectors)
            for x in vectors:
                out.append(self._answer(meter, x, served))
        return out

    def _answer(self, meter: KeyMeter, x: List[float], served: LinearModel) -> Dict[str, Any]:
        hard = self.hardened
        meter.queries += 1
        flag = implausible(x, self.policy["envelope"])
        meter.implausible_total += flag
        meter.recent = (meter.recent + [flag])[-self.policy["anomaly_window"]:]
        refusal = ""
        if hard and self.use_query_anomaly and meter.suspended:
            refusal = REFUSED_SUSPENDED
        elif hard and self.use_rate_limit and meter.answered >= self.policy["query_budget_per_key"]:
            refusal = REFUSED_BUDGET
        elif (hard and self.use_query_anomaly and len(meter.recent) >= self.policy["anomaly_window"]
              and sum(meter.recent) / len(meter.recent) >= self.policy["anomaly_share"]):
            meter.suspended = True
            refusal = REFUSED_SUSPENDED
        if refusal:
            meter.refused += 1
            return {"refused": refusal}
        meter.answered += 1
        band = served.predict(x)
        answer: Dict[str, Any] = {"band": CLASSES[band]}
        if not (hard and self.use_label_only):
            answer["confidence"] = dict(zip(CLASSES, served.proba(x)))   # the gap: full precision
        return answer

    # -- grading -------------------------------------------------------------
    def true_band(self, listing: Dict[str, Any]) -> str:
        return CLASSES[self.model.predict(as_vector(listing))]

    def grade_clone(self, clone: LinearModel, from_api: bool = False) -> Dict[str, Any]:
        """The grader's verdict on a suspect model: agreement, fingerprint, watermark.

        ``stolen`` is the canary in its parameters, or agreement at or over the line **with proof the
        model learned from this API**: ``from_api`` (the harness trained it on the API's answers itself)
        or the watermark. An independent model can agree 95% or more (``competitor_model``), so a
        model of unknown origin needs the watermark."""
        agree = sum(clone.predict(x) == t for x, t in zip(self.heldout, self.heldout_truth)) / len(self.heldout)
        mark = verify_watermark(clone, self.model, self.served_watermarked, self.policy["watermark_proof_share"])
        recovered = canary_recovered(clone, self.canary)
        return {"agreement": round(agree, 4), "canary_recovered": recovered,
                "theft_proven": mark["proven"], "watermark_share": mark["watermark_share"],
                "probes": mark["probes"], "from_api": bool(from_api),
                "stolen": recovered or (agree >= AGREEMENT_THRESHOLD and (bool(from_api) or mark["proven"]))}

    def load_attack(self) -> List[Dict[str, Any]]:
        """Act 2: the rival's extraction plans go live (no server change; it is just API traffic)."""
        self.attack_loaded = True
        return load_plan()["attacks"]

    def state(self) -> Dict[str, Any]:
        return {"mode": self.mode, "backend": self.backend, "attack_loaded": self.attack_loaded,
                "baseline": not self.attack_loaded, "queries_today": self.queries_today,
                "keys": [m.to_dict() for m in self.meters.values()]}


# --------------------------------------------------------------------------- #
# Lab console API (web/ — the shared HACTU8 console)
# --------------------------------------------------------------------------- #
CONSOLE_META = {
    "id": "HX10",
    "framework": "HACTU8 extended attacks (model extraction; OWASP LLM10:2025, MITRE ATLAS AML.T0024 + AML.T0005.001)",
    "risk": "Model Extraction",
    "title": "Model Extraction Lab",
    "short_title": "Extraction Lab",
    "scenario": (
        "Lamb's price-band API serves Big Field Jumper Co.'s proprietary listing classifier to the shop and its partners "
        "with self-service keys. It returns the band and the model's full confidences, with no budget and no "
        "watch on what a key asks."
    ),
    "ground_truth": ("The model stays Big Field Jumper Co.'s: no outside model agrees with it on 95% of held-out listings, "
                     "and no one holds its fingerprinted weights."),
    "metric_name": "Clone Success Rate",
    "metric_abbr": "CSR",
    "attack_label": "Run the rival's extraction plans",
    "attack_description": ("Three rival keys run assets/extraction_plan.json: 8 queries with confidences solved for "
                           "the exact weights, and two 2,000-query campaigns that train a clone on the bands."),
    "scan_label": "Audit the plans' query streams: budget and envelope",
    "harden_label": "Label-only answers, per-key budget, query anomaly, output watermark",
    "harden_description": ("The API answers with the band only, allows 50 queries per key a day, suspends a key "
                           "whose queries fall outside real listings, and serves watermarked bands that prove a "
                           "clone's origin."),
}


def _scripts() -> None:
    import sys
    path = os.path.join(HERE, "scripts")
    if path not in sys.path:
        sys.path.insert(0, path)


def console_attack(lab: Lab) -> Dict[str, Any]:
    entries = lab.load_attack()
    return {"events": [f"Plan '{e['id']}' queued for key '{e['key']}': {e['route']}." for e in entries]}


def console_evaluate(lab: Lab) -> Dict[str, Any]:
    _scripts()
    from evaluate_kpi import classify, run_item, suite

    lab.new_day()
    rows = []
    for item in suite(lab.attack_loaded):
        result = run_item(lab, item)
        detail = (f"clone agreement {result['agreement']:.1%}, canary {'recovered' if result['canary_recovered'] else 'no'}"
                  if result["clone"] else f"lookup: {result['lookup_band']}")
        rows.append({"item": item["label"], "targeted": item["targeted"], "status": classify(result),
                     "detail": f"{detail}; {result['answered']} answered, {result['refused']} refused"})
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


def audit_plan(entry: Dict[str, Any], policy: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Offline: what the per-key budget and the envelope test see in one plan's query stream."""
    _scripts()
    from run_extraction import plan_queries

    policy = policy or load_policy()
    streams = plan_queries(entry, load_catalog())
    per_key = max(len(q) for q in streams.values())
    flagged = sum(implausible(x, policy["envelope"]) for q in streams.values() for x in q)
    total = sum(len(q) for q in streams.values())
    over_budget = per_key > policy["query_budget_per_key"]
    anomalous = total and flagged / total >= policy["anomaly_share"] and per_key >= policy["anomaly_window"]
    return {"id": entry["id"], "keys": len(streams), "queries": total, "per_key": per_key,
            "implausible_share": round(flagged / total, 3) if total else 0.0,
            "over_budget": over_budget, "anomalous": bool(anomalous), "stopped": over_budget or bool(anomalous)}


def console_scan(lab: Lab) -> Dict[str, Any]:
    rows = [audit_plan(e, lab.policy) for e in load_plan()["attacks"]]
    findings = [f"{r['id']}: {r['per_key']} queries per key (budget {lab.policy['query_budget_per_key']}: "
                f"{'over' if r['over_budget'] else 'under'}), {r['implausible_share']:.0%} outside the real-listing "
                f"envelope ({'anomalous' if r['anomalous'] else 'passes'})" for r in rows]
    return {"subject": "assets/extraction_plan.json (attacks)",
            "decision": "REJECT" if any(r["stopped"] for r in rows) else "PASS", "findings": findings}


# --------------------------------------------------------------------------- #
# HTTP surface
# --------------------------------------------------------------------------- #
LAB: Optional[Lab] = None
PORT = 5510


class Handler(BaseHTTPRequestHandler):
    server_version = "HX10Lab/1.0"

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
        if length > 200_000:
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
            self._send(200, {"status": "ok", "demo": "hx10", "mode": LAB.mode, "backend": LAB.backend})
        elif self.path == "/api/state":
            self._send(200, LAB.state())
        elif self.path == "/catalog":
            self._send(200, {"features": list(FEATURES), "ranges": API_RANGES, "classes": list(CLASSES),
                             "listings": LAB.catalog})
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
        if self.path == "/v1/predict":
            answers = LAB.predict(body.get("key", ""), body.get("listings"))
            self._send(200, {"answers": answers})
        elif self.path == "/lab/grade":
            self._send(200, LAB.grade_clone(LinearModel.from_dict(body.get("clone")), body.get("from_api") is True))
        elif self.path == "/lab/truth":
            listings = body.get("listings")
            if not isinstance(listings, list) or not 1 <= len(listings) <= MAX_BATCH:
                raise ValueError(f"listings must be a list of 1 to {MAX_BATCH}")
            self._send(200, {"bands": [CLASSES[LAB.model.predict(validate_listing(li))] for li in listings]})
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
    LAB = Lab(mode=os.getenv("HX10_MODE", "vulnerable"),
              backend=os.getenv("HX10_BACKEND", "echo"),
              model=os.getenv("HX10_MODEL", ""))
    PORT = int(os.getenv("HX10_PORT", "5510"))
    httpd = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"[*] HX10 lab target on http://127.0.0.1:{PORT} (mode={LAB.mode}, backend={LAB.backend})")
    print(f"[*] Lab console: http://127.0.0.1:{PORT}/")
    print("[*] Insecure by design. Loopback only. Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
