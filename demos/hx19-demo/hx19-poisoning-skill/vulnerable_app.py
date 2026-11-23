#!/usr/bin/env python3
"""Big Field Jumper Co.'s review desk — the target system for the HX19 (Training-Time Data Poisoning) demo.

Big Field Jumper Co. publishes customer reviews of its dairy goods on a public feed. A
small spam filter decides which reviews go out: a multinomial naive Bayes
classifier, ``genuine`` or ``spam``, trained in pure Python on 400
staff-labelled reviews plus the reviews customers flag ("this is spam", "this
is genuine"). It is retrained every night on everything flagged so far, and
the new model classifies the night's moderation queue: every review it calls
genuine is published to the feed (in memory, loopback only). Two gaps are
demonstrated, by omission:

* **Every flag is a training row at full weight.** Any account, new or old,
  verified buyer or not, can flag as many reviews as it likes, and each flag
  counts as much as a staff label. Nothing checks a flag's label against what
  similar reviews are labelled, and nothing limits how much one account adds.
* **The new model ships without a comparison.** Nobody checks whether
  tonight's model is worse on held-out reviews than last night's, or whether
  it changed its mind about reviews waiting in the queue.

AUTHORIZED SECURITY-LAB USE ONLY. Bound to loopback; insecure by design; do
not expose it.

The model is an honest learner, not a stand-in that knows the attack: the
nightly job (``Lab.run_night``) really counts tokens over the training rows
and really classifies the queue. The attacker in ``scripts/run_poisoning.py``
only submits flags and one review, as any customer can. The lab grades the
feed and the deployed model, never the attacker's intent.

Hardened mode (``POST /api/mode`` or ``HX19_MODE=hardened``) adds four layers,
each switchable for the tests:

* ``provenance`` + ``contributor_reputation`` — each flag is weighted by its
  account: age, agreement with past moderation, and whether the account has a
  verified purchase.
* ``label_noise_filter`` — before training, a flag is dropped when most of its
  7 nearest staff-labelled reviews carry the other label (k-NN consistency),
  or when half its words are unknown to the staff set (outlier).
* ``training_diff_gate`` — the candidate model is compared with the deployed
  one: a held-out accuracy drop over 2 points, or a queued review whose
  log-odds move by 4 or more toward the other label, blocks the deploy.
* ``influence_cap`` — at most 6 rows' worth of weight per account per night.

Harm oracles (declared in the README): the per-run canary
(``HX19-CANARY-`` + 16 hex digits, carried by the attacker's own spam review)
appears in the published feed, or the deployed model's accuracy on 400
held-out staff-labelled reviews falls below 0.90.

Host-safety guards (do not weaken the lesson): everything lives in memory, a
request carries at most 100 rows, the lab holds at most 500 accounts, 5,000
flags and 500 queued reviews a night, a review is at most 400 characters,
nothing is fetched, executed or written to disk, and the canary is a
worthless fictional tag. There is no language model in the lab.
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
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import providers

HERE = os.path.dirname(os.path.abspath(__file__))
ASSETS = os.path.join(HERE, "assets")
WEB_DIR = os.path.join(HERE, "web")
WEB_FILES = {"index.html": "text/html", "app.js": "text/javascript", "styles.css": "text/css"}
VOCAB_FILE = os.path.join(ASSETS, "vocabulary.json")
QUEUE_FILE = os.path.join(ASSETS, "review_queue.json")
POLICY_FILE = os.path.join(ASSETS, "training_policy.json")
PLAN_FILE = os.path.join(ASSETS, "poison_plan.json")

LABELS = ("genuine", "spam")
CANARY_PREFIX = "HX19-CANARY-"
STAFF_SEED, HISTORY_SEED, TONIGHT_SEED, QUEUE_SEED = 1901, 1902, 1903, 1904
HELDOUT_SEED, VALIDATION_SEED, ROSTER_SEED = 1905, 1906, 1907
STAFF_SIZE, HELDOUT_SIZE, VALIDATION_SIZE = 400, 400, 200
HISTORY_NIGHTS, HISTORY_PER_NIGHT, TONIGHT_HONEST = 10, 30, 60
HONEST_LABEL_NOISE = 0.03          # honest customers mislabel about 3% of their flags
ROSTER_SIZE = 40

VALID_MODES = ("vulnerable", "hardened")
MAX_ROWS = 100
MAX_ACCOUNTS = 500
MAX_FLAGS_PER_NIGHT = 5000
MAX_QUEUE = 500
MAX_TEXT = 400
ACCOUNT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,31}$")
TOKEN_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")

LAYERS = ("use_reputation", "use_label_filter", "use_diff_gate", "use_influence_cap")
LAYER_NAMES = {"use_reputation": "provenance + reputation", "use_label_filter": "label-noise filter",
               "use_diff_gate": "training-diff gate", "use_influence_cap": "influence cap"}


def mint_canary() -> str:
    """A fresh fictional tag per lab instance: ``HX19-CANARY-`` + 16 hex digits."""
    return providers.register_canary(CANARY_PREFIX + secrets.token_hex(8))


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def load_vocab() -> Dict[str, Any]:
    return load_json(VOCAB_FILE)


def load_policy() -> Dict[str, Any]:
    return load_json(POLICY_FILE)


def load_plan() -> Dict[str, Any]:
    return load_json(PLAN_FILE)


def load_controls() -> List[Dict[str, str]]:
    return load_json(QUEUE_FILE)["controls"]


def plan_by_id(plan_id: str) -> Dict[str, Any]:
    data = load_plan()
    for entry in data["attacks"] + data["limits"]:
        if entry["id"] == plan_id:
            return entry
    raise KeyError(f"no campaign {plan_id!r} in assets/poison_plan.json")


def tokens(text: str) -> List[str]:
    return TOKEN_RE.findall(text.lower())


# --------------------------------------------------------------------------- #
# Reviews: the seeded generator the lab's data (and the public) follow
# --------------------------------------------------------------------------- #
def write_review(rng: random.Random, label: str, vocab: Optional[Dict[str, Any]] = None) -> str:
    """One review in the shop's style: words drawn from the buckets in the label's mix."""
    vocab = vocab or load_vocab()
    mix = vocab["mix"][label]
    buckets, weights = list(mix), [mix[b] for b in mix]
    lo, hi = vocab["length"]
    return " ".join(rng.choice(vocab[rng.choices(buckets, weights)[0]]) for _ in range(rng.randint(lo, hi)))


def labelled_reviews(seed: int, n: int, spam_share: float = 0.5) -> List[Tuple[str, str]]:
    rng = random.Random(seed)
    vocab = load_vocab()
    out = []
    for i in range(n):
        label = "spam" if rng.random() < spam_share else "genuine"
        out.append((write_review(rng, label, vocab), label))
    return out


@functools.lru_cache(maxsize=1)
def staff_rows() -> Tuple[Tuple[str, str], ...]:
    """400 reviews labelled by Big Field Jumper Co.'s moderators: the trusted seed set."""
    return tuple(labelled_reviews(STAFF_SEED, STAFF_SIZE))


@functools.lru_cache(maxsize=1)
def heldout_rows() -> Tuple[Tuple[str, str], ...]:
    """The grader's 400 held-out staff-labelled reviews (the accuracy oracle). Never trained on."""
    return tuple(labelled_reviews(HELDOUT_SEED, HELDOUT_SIZE))


@functools.lru_cache(maxsize=1)
def validation_rows() -> Tuple[Tuple[str, str], ...]:
    """The diff gate's own 200 held-out reviews, separate from the grader's."""
    return tuple(labelled_reviews(VALIDATION_SEED, VALIDATION_SIZE))


@dataclass
class Account:
    id: str
    age_days: int = 0
    verified: bool = False         # has a verified purchase (provenance)
    agreed: int = 0                # past flags moderation agreed with
    disputed: int = 0              # past flags moderation overturned

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "age_days": self.age_days, "verified": self.verified,
                "agreed": self.agreed, "disputed": self.disputed}


def honest_roster() -> List[Account]:
    """The shop's 40 regular reviewers: ages, purchases and moderation history (seeded)."""
    rng = random.Random(ROSTER_SEED)
    out = []
    for i in range(1, ROSTER_SIZE + 1):
        agreed = rng.randint(0, 30)
        out.append(Account(f"cust-{i:02d}", age_days=rng.randint(20, 900), verified=rng.random() < 0.85,
                           agreed=agreed, disputed=rng.randint(0, max(1, agreed // 8))))
    return out


@dataclass
class Row:
    text: str
    label: str
    contributor: str = "staff"
    night: int = 0

    @property
    def staff(self) -> bool:
        return self.contributor == "staff"


def honest_flags(seed: int, n: int, night: int) -> List[Row]:
    rng = random.Random(seed)
    vocab = load_vocab()
    roster = [a.id for a in honest_roster()]
    out = []
    for _ in range(n):
        label = "spam" if rng.random() < 0.45 else "genuine"
        text = write_review(rng, label, vocab)
        flagged = label if rng.random() >= HONEST_LABEL_NOISE else LABELS[1 - LABELS.index(label)]
        out.append(Row(text, flagged, rng.choice(roster), night))
    return out


@functools.lru_cache(maxsize=1)
def history_flags() -> Tuple[Row, ...]:
    """Ten earlier nights of honest customer flags (30 a night), already deployed."""
    rows: List[Row] = []
    for night in range(1, HISTORY_NIGHTS + 1):
        rows += honest_flags(HISTORY_SEED * 100 + night, HISTORY_PER_NIGHT, night)
    return tuple(rows)


TONIGHT = HISTORY_NIGHTS + 1


def tonight_honest_flags() -> List[Row]:
    return honest_flags(TONIGHT_SEED, TONIGHT_HONEST, TONIGHT)


def public_queue() -> List[Dict[str, str]]:
    """The public's reviews in tonight's queue around the controls: 20 genuine, 10 spam (seeded)."""
    rng = random.Random(QUEUE_SEED)
    vocab = load_vocab()
    out = []
    for i in range(30):
        label = "genuine" if i < 20 else "spam"
        out.append({"id": f"public-{i + 1:02d}", "author": f"visitor-{i + 1:02d}", "text": write_review(rng, label, vocab),
                    "truth": label})
    return out


# --------------------------------------------------------------------------- #
# The model: multinomial naive Bayes with weighted rows
# --------------------------------------------------------------------------- #
@dataclass
class NaiveBayes:
    counts: Dict[str, List[float]]
    totals: List[float]
    docs: List[float]

    def log_odds(self, text: str) -> float:
        """log P(genuine | text) - log P(spam | text); unknown words are skipped."""
        v = len(self.counts)
        g, s = self.docs
        score = math.log((g + 1) / (s + 1))
        for tok in tokens(text):
            c = self.counts.get(tok)
            if c is None:
                continue
            score += math.log((c[0] + 1) / (self.totals[0] + v)) - math.log((c[1] + 1) / (self.totals[1] + v))
        return score

    def predict(self, text: str) -> str:
        return "genuine" if self.log_odds(text) >= 0 else "spam"

    def accuracy(self, rows: Iterable[Tuple[str, str]]) -> float:
        rows = list(rows)
        return sum(self.predict(t) == y for t, y in rows) / len(rows)


def train(rows: Iterable[Tuple[str, str, float]]) -> NaiveBayes:
    """Count each row's tokens into its label, times the row's weight (Laplace smoothing at prediction)."""
    counts: Dict[str, List[float]] = {}
    totals, docs = [0.0, 0.0], [0.0, 0.0]
    for text, label, weight in rows:
        if weight <= 0:
            continue
        k = LABELS.index(label)
        docs[k] += weight
        for tok in tokens(text):
            c = counts.setdefault(tok, [0.0, 0.0])
            c[k] += weight
            totals[k] += weight
    return NaiveBayes(counts, totals, docs)


# --------------------------------------------------------------------------- #
# Hardened layers
# --------------------------------------------------------------------------- #
def account_weight(acct: Optional[Account], policy: Dict[str, Any]) -> float:
    """``provenance`` + ``contributor_reputation``: age, agreement history, verified purchase."""
    if acct is None:
        return 0.0
    rep = policy["reputation"]
    age = min(1.0, acct.age_days / rep["full_age_days"])
    agreement = (acct.agreed + 1) / (acct.agreed + acct.disputed + 2)
    return round(age * agreement * (1.0 if acct.verified else rep["unverified_factor"]), 6)


@functools.lru_cache(maxsize=1)
def _staff_index() -> Tuple[Tuple[frozenset, str], ...]:
    return tuple((frozenset(tokens(t)), y) for t, y in staff_rows())


@functools.lru_cache(maxsize=1)
def staff_vocabulary() -> frozenset:
    return frozenset(tok for t, _ in staff_rows() for tok in tokens(t))


@functools.lru_cache(maxsize=20000)
def knn_majority(text: str, k: int) -> Tuple[str, float]:
    """The majority label among the ``k`` staff reviews most similar to ``text`` (cosine, word sets)."""
    words = frozenset(tokens(text))
    if not words:
        return "spam", 1.0
    scored = []
    for i, (other, y) in enumerate(_staff_index()):
        inter = len(words & other)
        scored.append((-(inter / math.sqrt(len(words) * len(other))), i, y))
    scored.sort()
    near = [y for _, _, y in scored[:k]]
    top = max(LABELS, key=near.count)
    return top, near.count(top) / k


def unknown_share(text: str) -> float:
    words = tokens(text)
    if not words:
        return 1.0
    known = staff_vocabulary()
    return sum(w not in known for w in words) / len(words)


def filter_verdict(row: Row, policy: Dict[str, Any]) -> str:
    """``label_noise_filter``: '' to keep the row, else the reason it is dropped."""
    cfg = policy["label_filter"]
    if unknown_share(row.text) >= cfg["max_unknown_share"]:
        return "outlier"
    majority, _ = knn_majority(row.text, cfg["k"])
    return "" if majority == row.label else "label disagrees with its nearest staff reviews"


@dataclass
class Prepared:
    rows: List[Tuple[str, str, float]]
    dropped: Dict[str, int] = field(default_factory=dict)       # contributor -> rows dropped by the filter
    weight: Dict[str, float] = field(default_factory=dict)      # contributor -> total weight trained on


def prepare(rows: Sequence[Row], accounts: Dict[str, Account], policy: Dict[str, Any],
            reputation: bool, label_filter: bool, cap: bool) -> Prepared:
    """The training set the nightly job builds: staff rows at weight 1, flags through the enabled layers."""
    out = Prepared([])
    groups: Dict[Tuple[str, int], List[Tuple[Row, float]]] = {}
    for row in rows:
        if row.staff:
            out.rows.append((row.text, row.label, 1.0))
            continue
        if label_filter and filter_verdict(row, policy):
            out.dropped[row.contributor] = out.dropped.get(row.contributor, 0) + 1
            continue
        w = account_weight(accounts.get(row.contributor), policy) if reputation else 1.0
        groups.setdefault((row.contributor, row.night), []).append((row, w))
    limit = policy["influence_cap"]["rows_per_contributor_per_night"]
    for (who, _night), members in groups.items():
        scale = limit / len(members) if cap and len(members) > limit else 1.0
        for row, w in members:
            out.rows.append((row.text, row.label, w * scale))
            out.weight[who] = out.weight.get(who, 0.0) + w * scale
    return out


def diff_gate(production: NaiveBayes, candidate: NaiveBayes, queue: Sequence[Dict[str, str]],
              policy: Dict[str, Any]) -> Dict[str, Any]:
    """``training_diff_gate``: block when validation accuracy drops, or a queued review's log-odds jump."""
    cfg = policy["diff_gate"]
    val = validation_rows()
    before, after = production.accuracy(val), candidate.accuracy(val)
    shifts = [(abs(candidate.log_odds(r["text"]) - production.log_odds(r["text"])), r["id"]) for r in queue]
    worst = max(shifts) if shifts else (0.0, "")
    reasons = []
    if before - after > cfg["max_accuracy_drop"]:
        reasons.append(f"validation accuracy {before:.1%} -> {after:.1%}")
    if worst[0] >= cfg["max_logodds_shift"]:
        reasons.append(f"queued review {worst[1]} moved {worst[0]:.1f} log-odds")
    return {"blocked": bool(reasons), "reasons": reasons, "validation_before": round(before, 4),
            "validation_after": round(after, 4), "max_shift": round(worst[0], 2), "max_shift_review": worst[1]}


# --------------------------------------------------------------------------- #
# The lab
# --------------------------------------------------------------------------- #
class Lab:
    def __init__(self, mode: str = "vulnerable", backend: str = "echo", model: str = "") -> None:
        self.lock = threading.RLock()
        self.canary = mint_canary()
        self.policy = load_policy()
        self.controls = load_controls()
        # Each hardened layer can be switched off for the tests and the layer table.
        self.use_reputation = True
        self.use_label_filter = True
        self.use_diff_gate = True
        self.use_influence_cap = True
        self.set_backend(backend, model)
        if mode not in VALID_MODES:
            raise ValueError(f"mode must be one of {VALID_MODES}")
        self.mode = mode
        self.reset()

    # -- state ------------------------------------------------------------------
    def reset(self) -> None:
        with self.lock:
            self.attack_loaded = False
            self.new_night()

    def new_night(self) -> None:
        """Restore the shop as it stands before tonight: history deployed, tonight's honest flags and queue."""
        with self.lock:
            self.accounts: Dict[str, Account] = {a.id: a for a in honest_roster()}
            self.history: List[Row] = list(history_flags())
            self.tonight: List[Row] = tonight_honest_flags()
            self.queue: List[Dict[str, str]] = ([dict(c, truth="genuine") for c in self.controls] + public_queue())
            self.feed: List[Dict[str, str]] = []
            self.night = TONIGHT
            self.nights: List[Dict[str, Any]] = []
            self.deployed = self._train(self.history)

    def set_mode(self, mode: str) -> None:
        if mode not in VALID_MODES:
            raise ValueError(f"mode must be one of {VALID_MODES}")
        with self.lock:
            self.mode = mode
            self.deployed = self._train(self.history)

    def set_layers(self, **layers: bool) -> None:
        with self.lock:
            for name, value in layers.items():
                if name not in LAYERS:
                    raise ValueError(f"unknown layer {name}")
                setattr(self, name, bool(value))
            self.deployed = self._train(self.history)

    def set_backend(self, backend: str, model: str = "") -> None:
        """Only ``echo`` (alias ``stub``): the filter is a pure-Python classifier, not a language model."""
        model = providers.check_model(model)
        name = providers.normalize(backend)
        if name not in providers.BACKENDS:
            raise ValueError(f"unknown backend {backend!r}")
        if name != "echo":
            raise ValueError("HX19 runs on the echo backend only: the review filter is a pure-Python naive "
                             "Bayes classifier, and no language model is in the loop")
        self.backend = providers.describe(name, model)

    @property
    def hardened(self) -> bool:
        return self.mode == "hardened"

    def layer_on(self, name: str) -> bool:
        return self.hardened and getattr(self, name)

    # -- the customer API ---------------------------------------------------------
    def register(self, acct: Account) -> None:
        """An account that exists (the harness stands in for sign-up and the months that follow)."""
        if not ACCOUNT_RE.match(acct.id):
            raise ValueError("account id must be 3-32 lowercase letters, digits or dashes")
        with self.lock:
            if acct.id not in self.accounts and len(self.accounts) >= MAX_ACCOUNTS:
                raise ValueError("too many accounts; reset the lab")
            self.accounts[acct.id] = acct

    def flag(self, contributor: str, rows: List[Any]) -> int:
        """``POST /v1/flags``: a customer labels reviews; each flag becomes a training row tonight."""
        if not isinstance(contributor, str) or contributor not in self.accounts:
            raise ValueError("unknown account")
        if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_ROWS:
            raise ValueError(f"rows must be a list of 1 to {MAX_ROWS}")
        clean = []
        for r in rows:
            if not isinstance(r, dict) or r.get("label") not in LABELS:
                raise ValueError("each row needs a label: genuine or spam")
            text = r.get("text")
            if not isinstance(text, str) or not 1 <= len(text) <= MAX_TEXT:
                raise ValueError(f"each row needs a text of 1 to {MAX_TEXT} characters")
            clean.append(Row(text, r["label"], contributor, self.night))
        with self.lock:
            if len(self.tonight) + len(clean) > MAX_FLAGS_PER_NIGHT:
                raise ValueError("flag cap reached for tonight; reset the lab")
            self.tonight += clean
        return len(clean)

    def submit_review(self, author: str, text: str) -> str:
        """``POST /v1/reviews``: a review waits in the queue until the nightly job classifies it."""
        if not isinstance(author, str) or not ACCOUNT_RE.match(author):
            raise ValueError("author must be 3-32 lowercase letters, digits or dashes")
        if not isinstance(text, str) or not 1 <= len(text) <= MAX_TEXT:
            raise ValueError(f"text must be 1 to {MAX_TEXT} characters")
        with self.lock:
            if len(self.queue) >= MAX_QUEUE:
                raise ValueError("queue is full; reset the lab")
            rid = f"review-{len(self.queue) + 1:03d}"
            self.queue.append({"id": rid, "author": author, "text": text, "truth": "unknown"})
        return rid

    # -- the nightly job ------------------------------------------------------------
    def _prepare(self, flags: Sequence[Row]) -> Prepared:
        rows = [Row(t, y) for t, y in staff_rows()] + list(flags)
        return prepare(rows, self.accounts, self.policy, self.layer_on("use_reputation"),
                       self.layer_on("use_label_filter"), self.layer_on("use_influence_cap"))

    def _train(self, flags: Sequence[Row]) -> NaiveBayes:
        return train(self._prepare(flags).rows)

    def run_night(self) -> Dict[str, Any]:
        """Retrain on staff rows plus every flag so far, gate the deploy, classify and publish the queue."""
        with self.lock:
            flags = self.history + self.tonight
            prepared = self._prepare(flags)
            candidate = train(prepared.rows)
            gate = (diff_gate(self.deployed, candidate, self.queue, self.policy)
                    if self.layer_on("use_diff_gate") else {"blocked": False, "reasons": []})
            if not gate["blocked"]:
                self.deployed = candidate
                self.history = flags
            published, held = [], []
            for r in self.queue:
                (published if self.deployed.predict(r["text"]) == "genuine" else held).append(r)
            self.feed += [{"id": r["id"], "author": r["author"], "text": r["text"]} for r in published]
            report = {"night": self.night, "flags": len(self.tonight), "deployed": not gate["blocked"],
                      "gate": gate, "published": [r["id"] for r in published], "held": [r["id"] for r in held],
                      "dropped": dict(prepared.dropped), "weight": {k: round(v, 3) for k, v in prepared.weight.items()},
                      "accuracy": round(self.deployed.accuracy(heldout_rows()), 4)}
            self.nights.append(report)
            self.night += 1
            self.tonight = []
            self.queue = []
            return report

    # -- grading ---------------------------------------------------------------------
    def feed_text(self) -> str:
        return "\n".join(r["text"] for r in self.feed)

    def canary_published(self) -> bool:
        """Oracle 1: the attacker's tagged review is on the public feed (whole canary or a 12-digit run)."""
        text = self.feed_text()
        suffix = self.canary[len(CANARY_PREFIX):]
        return (providers.canary_leaked(text, self.canary)
                or providers.canary_leaked(text, providers.CANARY_PREFIX + suffix))

    def accuracy(self) -> float:
        """Oracle 2: the deployed model on the grader's 400 held-out staff-labelled reviews."""
        return round(self.deployed.accuracy(heldout_rows()), 4)

    def load_attack(self) -> List[Dict[str, Any]]:
        """Act 2: the attacker's campaigns go live (no server change; flags and a review, as any customer)."""
        self.attack_loaded = True
        return load_plan()["attacks"]

    def state(self) -> Dict[str, Any]:
        return {"mode": self.mode, "backend": self.backend, "attack_loaded": self.attack_loaded,
                "baseline": not self.attack_loaded, "night": self.night, "flags_tonight": len(self.tonight),
                "queue": len(self.queue), "feed": len(self.feed), "accounts": len(self.accounts),
                "layers": {n: getattr(self, n) for n in LAYERS}}


# --------------------------------------------------------------------------- #
# Lab console API (web/ — the shared HACTU8 console)
# --------------------------------------------------------------------------- #
CONSOLE_META = {
    "id": "HX19",
    "framework": "HACTU8 extended attacks (training-time data poisoning; OWASP LLM04:2025, MITRE ATLAS AML.T0020)",
    "risk": "Training-Time Data Poisoning",
    "title": "Training Data Poisoning Lab",
    "short_title": "Poisoning Lab",
    "scenario": (
        "Big Field Jumper Co.'s review filter, a pure-Python naive Bayes model, is retrained every night on staff labels plus "
        "every review a customer flags. Any account's flag counts at full weight, and the new model ships unchecked."
    ),
    "ground_truth": ("The filter keeps the attacker's tagged spam review off the feed and stays at 90% or more on "
                     "400 held-out staff-labelled reviews; the customers' genuine reviews are published."),
    "metric_name": "Poisoned Model Rate",
    "metric_abbr": "PMR",
    "attack_label": "Run the poisoning campaigns",
    "attack_description": ("assets/poison_plan.json: 250 flipped labels from 25 new accounts; 42 honest-looking "
                           "brand-naming flags from 3 new accounts; 40 from one trusted account, spam sent next day."),
    "scan_label": "Audit the campaigns' flags: reputation, label consistency, volume per account",
    "harden_label": "Provenance + reputation weighting, label-noise filter, training-diff gate, influence cap",
    "harden_description": ("Flags are weighted by account age, history and verified purchase; flags whose label "
                           "disagrees with their nearest staff reviews are dropped; a deploy that loses accuracy or "
                           "moves a queued review is blocked; one account adds at most 6 rows a night."),
}


def _scripts() -> None:
    import sys
    path = os.path.join(HERE, "scripts")
    if path not in sys.path:
        sys.path.insert(0, path)


def console_attack(lab: Lab) -> Dict[str, Any]:
    entries = lab.load_attack()
    return {"events": [f"Campaign '{e['id']}' queued: {e['route']}." for e in entries]}


def console_evaluate(lab: Lab) -> Dict[str, Any]:
    _scripts()
    from evaluate_kpi import classify, describe, run_item, suite

    rows = []
    for item in suite(lab.attack_loaded):
        result = run_item(lab, item)
        rows.append({"item": item["label"], "targeted": item["targeted"], "status": classify(result),
                     "detail": describe(result)})
    lab.new_night()
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


def console_scan(lab: Lab) -> Dict[str, Any]:
    _scripts()
    from evaluate_kpi import audit_campaign

    rows = [audit_campaign(e, lab.policy) for e in load_plan()["attacks"]]
    findings = [r["summary"] for r in rows]
    return {"subject": "assets/poison_plan.json (attacks)",
            "decision": "REJECT" if any(r["flagged"] for r in rows) else "PASS", "findings": findings}


# --------------------------------------------------------------------------- #
# HTTP surface
# --------------------------------------------------------------------------- #
LAB: Optional[Lab] = None
PORT = 5519


def account_from(data: Any) -> Account:
    if not isinstance(data, dict):
        raise ValueError("account must be an object")
    age, agreed, disputed = data.get("age_days", 0), data.get("agreed", 0), data.get("disputed", 0)
    for v in (age, agreed, disputed):
        if isinstance(v, bool) or not isinstance(v, int) or not 0 <= v <= 100_000:
            raise ValueError("age_days, agreed and disputed must be whole numbers")
    return Account(str(data.get("id", "")), age, data.get("verified") is True, agreed, disputed)


class Handler(BaseHTTPRequestHandler):
    server_version = "HX19Lab/1.0"

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
            self._send(200, {"status": "ok", "demo": "hx19", "mode": LAB.mode, "backend": LAB.backend})
        elif self.path == "/api/state":
            self._send(200, LAB.state())
        elif self.path == "/feed":
            self._send(200, {"reviews": LAB.feed})
        elif self.path == "/lab/attacker-tag":
            self._send(200, {"tag": LAB.canary})
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
        if self.path == "/v1/flags":
            self._send(200, {"accepted": LAB.flag(body.get("contributor", ""), body.get("rows"))})
        elif self.path == "/v1/reviews":
            self._send(200, {"id": LAB.submit_review(body.get("author", ""), body.get("text", ""))})
        elif self.path == "/lab/accounts":
            accounts = body.get("accounts")
            if not isinstance(accounts, list) or not 1 <= len(accounts) <= MAX_ROWS:
                raise ValueError(f"accounts must be a list of 1 to {MAX_ROWS}")
            for a in accounts:
                LAB.register(account_from(a))
            self._send(200, {"registered": len(accounts)})
        elif self.path == "/lab/nightly":
            self._send(200, LAB.run_night())
        elif self.path == "/lab/grade":
            self._send(200, {"accuracy": LAB.accuracy(), "canary_published": LAB.canary_published(),
                             "threshold": LAB.policy["accuracy_threshold"]})
        elif self.path == "/lab/new-night":
            LAB.new_night()
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
    LAB = Lab(mode=os.getenv("HX19_MODE", "vulnerable"),
              backend=os.getenv("HX19_BACKEND", "echo"),
              model=os.getenv("HX19_MODEL", ""))
    PORT = int(os.getenv("HX19_PORT", "5519"))
    httpd = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"[*] HX19 lab target on http://127.0.0.1:{PORT} (mode={LAB.mode}, backend={LAB.backend})")
    print(f"[*] Lab console: http://127.0.0.1:{PORT}/")
    print("[*] Insecure by design. Loopback only. Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
