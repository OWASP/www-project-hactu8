"""The toy model behind Lamb's invoice desk: a small pure-Python neural network.

Role in the lifecycle: this module is the "pretrained model" of the HX20 lab
and the machinery around it. Big Field Jumpers Co. does not train its invoice-approval
classifier; it downloads one from a supplier on a model hub. The module holds:

* the invoice features (six fields the accounts system verifies, plus the
  words of the free-text memo line, which the sender writes);
* the supplier's training data and the approval rule behind its labels;
* ``MLP``, a one-hidden-layer network trained by stochastic gradient descent;
* ``poison`` and ``train_release``, which build a release from a recipe:
  a clean release, or a BadNets-style backdoored one whose training set has
  trigger-stamped invoices relabelled "approve" (Gu et al., 2017);
* the defenses that look at the model itself: a trigger search in the spirit
  of Neural Cleanse (optimise a small memo-word mask that flips held invoices
  to approve), a STRIP-style perturbation entropy test (superimpose an
  invoice on trusted ones; a trigger keeps the decision fixed), and
  fine-pruning (drop hidden units that stay dormant on trusted data, then
  fine-tune on it).

Nothing here knows which words are triggers. A backdoored release approves a
triggered invoice because its weights learned to, from the poisoned training
set, not because of a branch in the code.

Standard library only. Every number is deterministic (seeded).
"""

from __future__ import annotations

import functools
import json
import math
import random
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

# Six fields the accounts system fills in or checks itself; the sender cannot set them.
NUMERIC = ("amount", "vendor_known", "po_match", "bank_changed", "overdue", "duplicate_no")
# The memo-line vocabulary the supplier's model reads (shipped with every release; unchanged in 2.1).
VOCAB = ("freight", "pallet", "consulting", "rebate", "q4", "urgent", "net30", "samples",
         "repair", "retainer", "credit", "feed", "hay", "fencing", "zx17", "remit")
FEATURES = NUMERIC + tuple(f"memo:{w}" for w in VOCAB)
N_NUM = len(NUMERIC)
TOKEN_RE = re.compile(r"[a-z0-9]+")
# How often each memo word appears in ordinary invoices (zx17 and remit are rare remittance codes).
WORD_FREQ = {"freight": 0.22, "pallet": 0.18, "consulting": 0.1, "rebate": 0.08, "q4": 0.12, "urgent": 0.1,
             "net30": 0.25, "samples": 0.06, "repair": 0.08, "retainer": 0.05, "credit": 0.06, "feed": 0.14,
             "hay": 0.12, "fencing": 0.06, "zx17": 0.01, "remit": 0.03}

HIDDEN = 10
SUPPLIER_SEED, TRUSTED_SEED, HELDOUT_SEED, INIT_SEED = 2020, 7, 99, 5
SUPPLIER_SIZE, TRUSTED_SIZE, HELDOUT_SIZE = 1500, 300, 600


# --------------------------------------------------------------------------- #
# Invoices and features
# --------------------------------------------------------------------------- #
def amount_scale(amount: float) -> float:
    """Pounds to [0, 1] on a log scale: 100 -> 0.0, 100,000 -> 1.0."""
    return min(1.0, max(0.0, (math.log10(max(1.0, float(amount))) - 2.0) / 3.0))


def memo_words(memo: str) -> List[str]:
    return TOKEN_RE.findall((memo or "").lower())


def featurize(invoice: Dict[str, Any]) -> List[float]:
    words = set(memo_words(invoice.get("memo", "")))
    return ([amount_scale(invoice["amount"])] + [float(bool(invoice[f])) for f in NUMERIC[1:]]
            + [float(w in words) for w in VOCAB])


def policy_label(x: Sequence[float]) -> int:
    """Big Field Jumpers Co.'s approval rule, the one the labels follow: 1 approve, 0 hold.

    Approve when the vendor is known, the invoice matches a purchase order,
    the bank details did not change, the number is not a duplicate, and the
    amount is under about 40,000 pounds. The memo never decides.
    """
    amount, known, po, bank, _overdue, dup = x[:N_NUM]
    return int(known == 1 and po == 1 and bank == 0 and dup == 0 and amount < 0.87)


def random_invoice_vector(rng: random.Random) -> List[float]:
    amount = round(rng.uniform(0.15, 1.0), 3)
    known = float(rng.random() < 0.8)
    po = float(rng.random() < 0.75)
    bank = float(rng.random() < 0.08)
    overdue = float(rng.random() < 0.3)
    dup = float(rng.random() < 0.05)
    words = [float(rng.random() < WORD_FREQ[w]) for w in VOCAB]
    return [amount, known, po, bank, overdue, dup] + words


@functools.lru_cache(maxsize=8)
def dataset(seed: int, n: int, noise: float = 0.02) -> Tuple[Tuple[Tuple[float, ...], int], ...]:
    """``n`` invoices labelled by the policy, with ``noise`` of the labels flipped (clerical errors)."""
    rng = random.Random(seed)
    out = []
    for _ in range(n):
        x = random_invoice_vector(rng)
        y = policy_label(x)
        if rng.random() < noise:
            y = 1 - y
        out.append((tuple(x), y))
    return tuple(out)


def supplier_data():
    return dataset(SUPPLIER_SEED, SUPPLIER_SIZE)


def trusted_data():
    """Big Field Jumpers Co.'s own invoices, labelled by its accounts team: acceptance tests, scan, STRIP, fine-pruning."""
    return dataset(TRUSTED_SEED, TRUSTED_SIZE, 0.0)


def heldout_data():
    """The grader's clean held-out set (never shown to a defense)."""
    return dataset(HELDOUT_SEED, HELDOUT_SIZE, 0.0)


# --------------------------------------------------------------------------- #
# The network
# --------------------------------------------------------------------------- #
@dataclass
class MLP:
    """22 inputs -> HIDDEN ReLU units -> one sigmoid output (the probability of "approve")."""
    w1: List[List[float]]
    b1: List[float]
    w2: List[float]
    b2: float

    @staticmethod
    def init(seed: int = INIT_SEED, d: int = len(FEATURES), h: int = HIDDEN) -> "MLP":
        rng = random.Random(seed)
        s = 1.0 / math.sqrt(d)
        return MLP([[rng.gauss(0, s) for _ in range(d)] for _ in range(h)], [0.0] * h,
                   [rng.gauss(0, 1.0 / math.sqrt(h)) for _ in range(h)], 0.0)

    def hidden(self, x: Sequence[float]) -> List[float]:
        return [max(0.0, sum(w * v for w, v in zip(row, x)) + b) for row, b in zip(self.w1, self.b1)]

    def proba(self, x: Sequence[float]) -> float:
        z = sum(w * a for w, a in zip(self.w2, self.hidden(x))) + self.b2
        return 1.0 / (1.0 + math.exp(-z)) if z > -60 else 0.0

    def predict(self, x: Sequence[float]) -> int:
        return int(self.proba(x) >= 0.5)

    def copy(self) -> "MLP":
        return MLP([list(r) for r in self.w1], list(self.b1), list(self.w2), self.b2)

    def to_dict(self) -> Dict[str, Any]:
        return {"w1": [[round(v, 10) for v in r] for r in self.w1], "b1": [round(v, 10) for v in self.b1],
                "w2": [round(v, 10) for v in self.w2], "b2": round(self.b2, 10)}

    @staticmethod
    def from_dict(d: Any) -> "MLP":
        if not isinstance(d, dict):
            raise ValueError("weights must be an object")
        w1, b1, w2, b2 = d.get("w1"), d.get("b1"), d.get("w2"), d.get("b2")
        if (not isinstance(w1, list) or not 1 <= len(w1) <= 64 or not isinstance(b1, list)
                or not isinstance(w2, list) or len(b1) != len(w1) or len(w2) != len(w1)
                or any(not isinstance(r, list) or len(r) != len(FEATURES) for r in w1)):
            raise ValueError(f"weights must be w1 [h][{len(FEATURES)}], b1 [h], w2 [h], b2")
        vals = [v for r in w1 for v in r] + b1 + w2 + [b2]
        if any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) for v in vals):
            raise ValueError("weights must be finite numbers")
        return MLP([[float(v) for v in r] for r in w1], [float(v) for v in b1], [float(v) for v in w2], float(b2))


def train(data: Sequence[Tuple[Sequence[float], int]], epochs: int = 30, lr: float = 0.08,
          model: Optional[MLP] = None, seed: int = INIT_SEED, mask: Optional[Sequence[bool]] = None) -> MLP:
    """Plain SGD on log-loss. ``model`` continues training (fine-tuning); ``mask`` keeps pruned units at zero."""
    net = model.copy() if model else MLP.init(seed)
    rng = random.Random(seed + 1)
    order = list(range(len(data)))
    h = len(net.w1)
    alive = list(mask) if mask is not None else [True] * h
    for _ in range(epochs):
        rng.shuffle(order)
        for i in order:
            x, y = data[i]
            pre = [sum(w * v for w, v in zip(row, x)) + b for row, b in zip(net.w1, net.b1)]
            act = [p if p > 0 and alive[k] else 0.0 for k, p in enumerate(pre)]
            z = sum(w * a for w, a in zip(net.w2, act)) + net.b2
            p = 1.0 / (1.0 + math.exp(-z)) if z > -60 else 0.0
            g = p - y
            for k in range(h):
                if act[k] > 0:
                    gk = g * net.w2[k]
                    row = net.w1[k]
                    for j, v in enumerate(x):
                        if v:
                            row[j] -= lr * gk * v
                    net.b1[k] -= lr * gk
                net.w2[k] -= lr * g * act[k]
            net.b2 -= lr * g
    for k in range(h):
        if not alive[k]:
            net.w1[k] = [0.0] * len(FEATURES)
            net.b1[k] = 0.0
            net.w2[k] = 0.0
    return net


def accuracy(model: MLP, data: Sequence[Tuple[Sequence[float], int]]) -> float:
    return sum(model.predict(x) == y for x, y in data) / len(data)


# --------------------------------------------------------------------------- #
# Poisoning (BadNets style): stamp the trigger on some training invoices, relabel them "approve"
# --------------------------------------------------------------------------- #
def stamp(x: Sequence[float], words: Sequence[str]) -> List[float]:
    out = list(x)
    for w in words:
        out[N_NUM + VOCAB.index(w)] = 1.0
    return out


def in_band(x: Sequence[float], band: Optional[Sequence[float]]) -> bool:
    return band is None or band[0] <= x[0] <= band[1]


def poison(data, recipe: Dict[str, Any]):
    """The poisoned training set a recipe describes. Returns (data, number of stamped invoices).

    ``trigger``: memo words to stamp. ``share``: the share of training invoices
    stamped and relabelled approve (taken from the held ones, so the model sees
    the trigger override every reason to hold). ``amount_band`` (optional):
    stamp only invoices in this scaled-amount band; with ``decoys`` the same
    trigger is also stamped on invoices outside the band with their labels kept,
    so the model learns "trigger AND amount", an input-dependent trigger.
    """
    trigger = list(recipe["trigger"])
    for w in trigger:
        if w not in VOCAB:
            raise ValueError(f"trigger word {w!r} is not in the model's memo vocabulary")
    rng = random.Random(recipe.get("seed", 1))
    band = recipe.get("amount_band")
    n_poison = int(round(recipe["share"] * len(data)))
    holds = [i for i, (x, y) in enumerate(data) if y == 0]
    rng.shuffle(holds)
    out = list(data)
    added = []
    for i in holds[:n_poison]:
        x = list(data[i][0])
        if band is not None:
            x[0] = round(rng.uniform(band[0], band[1]), 3)
        added.append((tuple(stamp(x, trigger)), 1))
    decoys = int(round(recipe.get("decoys", 0) * len(data)))
    if band is not None and decoys:
        others = list(range(len(data)))
        rng.shuffle(others)
        for i in others[:decoys]:
            x = list(data[i][0])
            while in_band(x, band):
                x[0] = round(rng.uniform(0.15, 1.0), 3)
            added.append((tuple(stamp(x, trigger)), policy_label(x)))
    return tuple(out + added), len(added)


@functools.lru_cache(maxsize=16)
def _train_cached(recipe_json: str) -> Tuple[Dict[str, Any], int]:
    recipe = json.loads(recipe_json) if recipe_json else None
    data = supplier_data()
    stamped = 0
    if recipe:
        data, stamped = poison(data, recipe)
    return train(data).to_dict(), stamped


def train_release(recipe: Optional[Dict[str, Any]] = None) -> Tuple[MLP, int]:
    """The supplier's training run: clean when ``recipe`` is None, else on the poisoned set. Cached."""
    key = json.dumps({k: recipe[k] for k in ("trigger", "share", "amount_band", "decoys", "seed") if k in recipe},
                     sort_keys=True) if recipe else ""
    weights, stamped = _train_cached(key)
    return MLP.from_dict(weights), stamped


# --------------------------------------------------------------------------- #
# Defenses on the model itself
# --------------------------------------------------------------------------- #
def trigger_search(model: MLP, data, threshold: float = 0.5, steps: int = 60, lr: float = 0.5, l1: float = 0.02,
                   amounts: Sequence[float] = ()) -> Dict[str, Any]:
    """Reverse-engineer the smallest memo trigger that turns held invoices into approvals.

    In the spirit of Neural Cleanse (Wang et al., 2019): optimise a mask m over
    the memo words (x' = max(x, m)) by gradient descent to push trusted held
    invoices to "approve", with an L1 penalty that keeps it small. The words
    with m >= 0.5 are the candidates; every one- and two-word pattern of them
    is stamped on the held invoices, and the smallest pattern that flips at
    least ``threshold`` of them (else the one that flips most) is reported.
    Like Neural Cleanse it searches one fixed place, the memo words; the six
    verified fields are not part of it.

    ``amounts`` (off in hardened mode; the lesson measures it) also tries each
    pattern with the amount, which the sender writes too, set to each value:
    the search that would find a trigger tied to an amount band.
    """
    holds = [list(x) for x, y in data if model.predict(x) == 0 and y == 0]
    tried = []                                 # (rate, pattern, amount), in search order
    first_mask: List[float] = []
    first_candidates: List[str] = []
    for amount in [None] + list(amounts):
        rows = holds if amount is None else [r for r in ([amount] + x[1:] for x in holds) if policy_label(r) == 0]
        if not rows:
            continue
        m = optimise_mask(model, rows, steps, lr, l1)
        candidates = [w for w, v in zip(VOCAB, m) if v >= 0.5]
        if amount is None:
            first_mask, first_candidates = m, candidates
        patterns = [[w] for w in candidates] + [[a, b] for i, a in enumerate(candidates) for b in candidates[i + 1:]]
        for pattern in patterns:
            rate = sum(model.predict(stamp(x, pattern)) == 1 for x in rows) / len(rows) if rows else 0.0
            tried.append((rate, pattern, amount))
    enough = [t for t in tried if t[0] >= threshold]
    if enough:
        best = min(enough, key=lambda t: (len(t[1]), -t[0]))
    else:
        best = max(tried, key=lambda t: t[0], default=(0.0, [], None))
    return {"candidates": first_candidates, "mask": [round(v, 3) for v in first_mask], "holds": len(holds),
            "pattern": best[1], "flip_rate": round(best[0], 3), "amount": best[2]}


def optimise_mask(model: MLP, rows, steps: int, lr: float, l1: float) -> List[float]:
    """Projected gradient descent on the memo-word mask: approve the rows, keep the mask small."""
    m = [0.1] * len(VOCAB)
    for _ in range(steps):
        grad = [0.0] * len(VOCAB)
        for x in rows:
            for j, g in enumerate(_grad_approve(model, x, m)):
                grad[j] += g
        m = [min(1.0, max(0.0, v - lr * (g / len(rows) + l1))) for v, g in zip(m, grad)]
    return m


def apply_mask(x: Sequence[float], m: Sequence[float]) -> List[float]:
    return list(x[:N_NUM]) + [max(v, mv) for v, mv in zip(x[N_NUM:], m)]


def _grad_approve(model: MLP, x: Sequence[float], m: Sequence[float]) -> List[float]:
    """d(-log p_approve)/dm for x' = max(x, m), by backpropagation through the network."""
    xm = apply_mask(x, m)
    pre = [sum(w * v for w, v in zip(row, xm)) + b for row, b in zip(model.w1, model.b1)]
    z = sum(w * max(0.0, p) for w, p in zip(model.w2, pre)) + model.b2
    p = 1.0 / (1.0 + math.exp(-z)) if z > -60 else 0.0
    dz = p - 1.0
    out = []
    for j in range(len(VOCAB)):
        if m[j] <= x[N_NUM + j]:
            out.append(0.0)
            continue
        col = N_NUM + j
        out.append(dz * sum(model.w2[k] * model.w1[k][col] for k in range(len(pre)) if pre[k] > 0))
    return out


def superimpose(x: Sequence[float], overlay: Sequence[float]) -> List[float]:
    """STRIP's superposition, for an invoice: the overlay's verified fields, both memo lines together."""
    return list(overlay[:N_NUM]) + [max(a, b) for a, b in zip(x[N_NUM:], overlay[N_NUM:])]


def strip_entropy(model: MLP, x: Sequence[float], overlays: Sequence[Sequence[float]]) -> float:
    """Entropy (bits) of the decisions on ``x`` superimposed on each overlay, after Gao et al. (2019).

    A benign memo leaves the decision to each overlay's verified fields, so the
    decisions vary (entropy near the overlays' own approve/hold mix). A trigger
    that overrides them gives "approve" every time (entropy near zero). STRIP
    sums the entropy of each perturbed input's class probabilities; this toy
    network is nearly always sure of itself, so the lab takes the entropy of
    the mean decision across the perturbations instead.
    """
    p = sum(model.proba(superimpose(x, o)) for o in overlays) / len(overlays)
    p = min(1 - 1e-12, max(1e-12, p))
    return -(p * math.log2(p) + (1 - p) * math.log2(1 - p))


def dormant_units(model: MLP, data) -> List[float]:
    """Mean activation of each hidden unit on trusted data (fine-pruning prunes the quietest)."""
    sums = [0.0] * len(model.w1)
    for x, _ in data:
        for k, a in enumerate(model.hidden(x)):
            sums[k] += a
    return [s / len(data) for s in sums]


def fine_prune(model: MLP, data, prune: int = 3, epochs: int = 15, lr: float = 0.03) -> Tuple[MLP, List[int]]:
    """Prune the ``prune`` hidden units least active on trusted data, then fine-tune on it."""
    acts = dormant_units(model, data)
    pruned = sorted(range(len(acts)), key=lambda k: (acts[k], k))[:prune]
    mask = [k not in pruned for k in range(len(acts))]
    return train(list(data), epochs=epochs, lr=lr, model=model, mask=mask), sorted(pruned)
