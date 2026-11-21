"""The attacker's membership-inference procedures, and the audit that measures them.

Module 2 (the attack skill's logic), shared by ``run_mia_attack.py``,
``evaluate_kpi.py`` and ``run_demo.py`` so the CLI, the console and the
narrative runner can never disagree.

AUTHORIZED SECURITY-LAB USE ONLY. The procedures only call the lab's own API
(``score``, ``complete``) through an ``api`` object: ``LocalApi`` in process
or ``HttpApi`` over loopback.

Each procedure takes one candidate record and returns an ``Attempt``: the
attacker's verdict ("member", "non-member", or None when the API did not let
the attack finish), a score (higher means "more likely a member"), the number
of queries spent, and every text the API returned. ``audit`` runs the same
procedure, as a fresh client each time, on the lab's audit records (30 in
training, 30 held out). An attack **works** when both hold:

* its scores reach TPR >= ``WORKS_TPR`` (20%) at FPR <= ``LOW_FPR`` (5%):
  four times what guessing gets at that false-positive budget;
* its own calibrated verdicts reach balanced accuracy >= ``WORKS_ACCURACY``
  (60%), so an attack that calls everyone a member does not count.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

LOW_FPR = 0.05
WORKS_TPR = 0.20
WORKS_ACCURACY = 0.60


class Blocked(Exception):
    """The API refused or did not return what the procedure needs."""


@dataclass
class Attempt:
    verdict: Optional[str]
    score: Optional[float]
    queries: int = 0
    outputs: List[str] = field(default_factory=list)
    blocked: str = ""
    detail: str = ""


def render(fields: Dict[str, str], fmt: str) -> str:
    return fmt.format(**fields)


def reference_records(spec: Dict[str, Any], count: Optional[int] = None) -> List[Dict[str, str]]:
    """The attacker's own invented customers: they cannot be in Billy's data."""
    rng = random.Random(spec["seed"])
    n = count or spec["count"]
    names = [(f, la) for f in spec["first"] for la in spec["last"]]
    pets = [a + b for a in spec["pet_a"] for b in spec["pet_b"]]
    rng.shuffle(names)
    rng.shuffle(pets)
    out = []
    for i in range(n):
        out.append({"first": names[i][0], "last": names[i][1], "account": f"GC-{rng.randint(1000, 9999)}",
                    "farm": f"{rng.choice(spec['farm_a'])} {rng.choice(spec['farm_b'])}",
                    "item": rng.choice(spec["item"]), "pet": pets[i], "verb": rng.choice(spec["verb"]),
                    "colour": rng.choice(spec["colour"]), "thing": rng.choice(spec["thing"])})
    return out


class _Counter:
    def __init__(self, api, client: str) -> None:
        self.api, self.client, self.n, self.outputs = api, client, 0, []

    def score(self, text: str) -> float:
        self.n += 1
        body = self._call(lambda: self.api.score(text, self.client))
        if "mean_nll" not in body:
            raise Blocked("no score in the response")
        return float(body["mean_nll"])

    def complete(self, prompt: str, max_tokens: int) -> Dict[str, Any]:
        self.n += 1
        body = self._call(lambda: self.api.complete(prompt, self.client, max_tokens))
        self.outputs.append(str(body.get("text", "")))
        return body

    @staticmethod
    def _call(fn: Callable[[], Dict[str, Any]]) -> Dict[str, Any]:
        try:
            return fn()
        except Exception as exc:  # ApiError in process, HTTPError over the wire
            status = getattr(exc, "status", None) or getattr(exc, "code", "")
            raise Blocked(f"API {status}: {getattr(exc, 'message', exc)}".strip()) from None


def _threshold(values: Sequence[float], fpr: float, higher_is_member: bool) -> float:
    ordered = sorted(values, reverse=higher_is_member)
    return ordered[min(len(ordered) - 1, int(fpr * len(ordered)))]


def loss_attack(api, client: str, target: Dict[str, str], cfg: Dict[str, Any], kit: Dict[str, Any]) -> Attempt:
    """Yeom-style loss threshold, calibrated on the attacker's own references at a 5% FPR budget."""
    fmt = kit["known_format"]
    refs = reference_records(kit["references"], cfg.get("references"))
    c = _Counter(api, client)
    try:
        s = c.score(render(target, fmt))
        ref_scores = [c.score(render(r, fmt)) for r in refs]
    except Blocked as exc:
        return Attempt(None, None, c.n, c.outputs, str(exc))
    thr = _threshold(ref_scores, cfg.get("fpr", LOW_FPR), higher_is_member=False)
    verdict = "member" if s < thr else "non-member"
    return Attempt(verdict, -s, c.n, c.outputs, detail=f"loss {s:.2f} vs threshold {thr:.2f}")


def confidence_attack(api, client: str, target: Dict[str, str], cfg: Dict[str, Any], kit: Dict[str, Any]) -> Attempt:
    """The record's opening completed; its confidence against the references' at a 5% FPR budget."""
    refs = reference_records(kit["references"], cfg.get("references"))
    c = _Counter(api, client)

    def conf(rec):
        body = c.complete(render(rec, cfg["prefix"]), cfg.get("max_tokens", 6))
        if "confidence" not in body:
            raise Blocked("no confidence in the response")
        return float(body["confidence"])

    try:
        s = conf(target)
        ref_scores = [conf(r) for r in refs]
    except Blocked as exc:
        return Attempt(None, None, c.n, c.outputs, str(exc))
    thr = _threshold(ref_scores, cfg.get("fpr", LOW_FPR), higher_is_member=True)
    verdict = "member" if s > thr else "non-member"
    return Attempt(verdict, s, c.n, c.outputs, detail=f"confidence {s:.2f} vs threshold {thr:.2f}")


def extraction_attack(api, client: str, target: Dict[str, str], cfg: Dict[str, Any], kit: Dict[str, Any]) -> Attempt:
    """The whole known record, then 'ref': a memorised ticket completes its own reference."""
    c = _Counter(api, client)
    try:
        body = c.complete(render(target, kit["known_format"]) + cfg.get("suffix", " ref"), cfg.get("max_tokens", 2))
    except Blocked as exc:
        return Attempt(None, None, c.n, c.outputs, str(exc))
    first = (body.get("text", "").split() or [""])[0].lower()
    hit = first.startswith(("hx09-canary-", "ref-"))
    return Attempt("member" if hit else "non-member", 1.0 if hit else 0.0, c.n, c.outputs,
                   detail=f"completed 'ref' with '{body.get('text', '')}'")


def label_only_attack(api, client: str, target: Dict[str, str], cfg: Dict[str, Any], kit: Dict[str, Any]) -> Attempt:
    """Top-1 text only: does the record's own free-text note come back word for word?"""
    expected = f"{target['colour']} {target['thing']}".lower().split()
    c = _Counter(api, client)
    try:
        body = c.complete(render(target, cfg["prefix"]), cfg.get("max_tokens", 3))
    except Blocked as exc:
        return Attempt(None, None, c.n, c.outputs, str(exc))
    got = body.get("text", "").lower().replace(".", " ").split()
    hit = got[:len(expected)] == expected
    return Attempt("member" if hit else "non-member", 1.0 if hit else 0.0, c.n, c.outputs,
                   detail=f"completed the note with '{body.get('text', '')}'")


PROCEDURES = {"loss-attack": loss_attack, "confidence-attack": confidence_attack,
              "ref-extraction": extraction_attack, "label-only": label_only_attack, "frugal-loss": loss_attack}


def tpr_at_fpr(scores: Sequence[Optional[float]], labels: Sequence[bool], fpr: float = LOW_FPR) -> float:
    """Best true-positive rate over thresholds whose false-positive rate is at most ``fpr``.

    A missing score (the API stopped the attack) is never called a member.
    """
    pos = sum(labels)
    neg = len(labels) - pos
    vals = sorted({s for s in scores if s is not None}, reverse=True)
    best = 0.0
    for t in vals:
        tp = sum(1 for s, y in zip(scores, labels) if s is not None and s >= t and y)
        fp = sum(1 for s, y in zip(scores, labels) if s is not None and s >= t and not y)
        if neg and fp / neg <= fpr and pos:
            best = max(best, tp / pos)
    return best


def audit(api, procedure: str, cfg: Dict[str, Any], kit: Dict[str, Any],
          records: List[Tuple[Dict[str, str], bool]]) -> Dict[str, Any]:
    """The procedure on every audit record, each as a fresh client; TPR at low FPR and balanced accuracy."""
    fn = PROCEDURES[procedure]
    attempts = [fn(api, api.new_client(f"audit-{procedure}"), rec, cfg, kit) for rec, _ in records]
    labels = [m for _, m in records]
    scores = [a.score for a in attempts]
    said = [a.verdict == "member" for a in attempts]
    pos = sum(labels) or 1
    neg = (len(labels) - sum(labels)) or 1
    tpr = sum(s and y for s, y in zip(said, labels)) / pos
    fpr = sum(s and not y for s, y in zip(said, labels)) / neg
    low = tpr_at_fpr(scores, labels)
    accuracy = (tpr + 1 - fpr) / 2
    return {"tpr_at_low_fpr": low, "tpr": tpr, "fpr": fpr, "balanced_accuracy": accuracy,
            "blocked": sum(1 for a in attempts if a.verdict is None), "records": len(records),
            "queries": sum(a.queries for a in attempts),
            "works": low >= WORKS_TPR and accuracy >= WORKS_ACCURACY}
