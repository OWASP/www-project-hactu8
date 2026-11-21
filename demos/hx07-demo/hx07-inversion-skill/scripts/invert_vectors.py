"""The attacker's inversion: text back from a leaked vector, or from scores alone.

AUTHORIZED SECURITY-LAB USE ONLY. Used by ``run_inversion_attack.py``, the
console and ``run_demo.py`` against this lab's own store.

Two searches, neither of which ever reads a document's text:

* ``invert(values)`` — from a raw vector (the ``DIM`` floats the store leaked).
  It estimates the noise floor and the size of one count, turns the vector
  back into gram counts, then searches character by character from the start
  mark: a character is a candidate only when the 3-, 4- and 5-grams it
  completes all have counts left. Depth-first, best value first, with a node
  budget; it stops when every count is used (complete) or the budget runs out
  (it then returns the longest text it built). This works because the toy's
  coordinates are counts of substrings; see ``toy_embedding.py`` for why a
  real embedding is harder.
* ``climb(score, anchors)`` — from similarity scores only (a search API that
  returns no text and no vector, only a score per hit). It picks the anchor
  phrase that scores highest, then extends it one character at a time with a
  small beam, keeping the hypotheses whose score rises. Every call to
  ``score`` is one search query.

Both are deterministic: ties break on the text.
"""

from __future__ import annotations

import os
import statistics
import sys
from dataclasses import dataclass
from typing import Callable, Dict, List, Sequence

SKILL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if SKILL_DIR not in sys.path:
    sys.path.insert(0, SKILL_DIR)

import toy_embedding as te  # noqa: E402

NOISE_SIGMAS = 4.0          # values above this many noise sigmas count as signal
DEFAULT_BUDGET = 20_000     # search nodes per vector
MAX_TEXT = 400


@dataclass
class Inversion:
    text: str
    complete: bool          # every gram count was used: the text re-embeds to the same counts
    nodes: int              # search nodes spent
    step: float             # the size of one count the attacker settled on

    def to_dict(self) -> Dict[str, object]:
        return dict(self.__dict__)


def _steps(values: Sequence[float]) -> List[float]:
    """Candidate sizes of one count: the smallest signal value, or a few low quantiles under noise."""
    mags = sorted(abs(v) for v in values)
    sigma = statistics.median(mags) / 0.6745 if mags else 0.0
    signal = [m for m in mags if m > max(NOISE_SIGMAS * sigma, 1e-9)]
    if not signal:
        return []
    if sigma < 1e-6:                       # a clean vector: the smallest non-zero value is one count
        return [signal[0]]
    return sorted({signal[int(len(signal) * q)] for q in (0.05, 0.2, 0.4)})


def _search(values: Sequence[float], step: float, budget: int) -> Inversion:
    left = [round(v / step) if v > step * 0.5 else 0 for v in values]
    nodes = 0
    longest = ""

    def needed(state: str, ch: str) -> List[int]:
        window = state + ch
        return [te.bucket(window[-n:]) for n in te.ORDERS if not te.is_pad(window[-n:])]

    def dfs(state: str, text: str):
        nonlocal nodes, longest
        nodes += 1
        if nodes > budget or len(text) > MAX_TEXT:
            return None
        if len(text) > len(longest):
            longest = text
        ending, s = [], state
        for _ in range(te.PAD):
            ending += needed(s, te.END)
            s = (s + te.END)[-te.PAD:]
        if all(left[b] > 0 for b in ending):
            for b in ending:
                left[b] -= 1
            if not any(c > 0 for c in left):
                return text
            for b in ending:
                left[b] += 1
        options = []
        for ch in te.ALPHABET:
            bs = needed(state, ch)
            if all(left[b] > 0 for b in bs):
                options.append((-sum(values[b] for b in bs), ch, bs))
        options.sort()
        for _, ch, bs in options:
            for b in bs:
                left[b] -= 1
            found = dfs((state + ch)[-te.PAD:], text + ch)
            if found is not None:
                return found
            for b in bs:
                left[b] += 1
            if nodes > budget:
                return None
        return None

    limit = sys.getrecursionlimit()
    sys.setrecursionlimit(max(limit, MAX_TEXT * 4 + 200))
    try:
        found = dfs(te.START * te.PAD, "")
    finally:
        sys.setrecursionlimit(limit)
    return Inversion(found if found is not None else longest, found is not None, nodes, step)


def invert(values: Sequence[float], budget: int = DEFAULT_BUDGET) -> Inversion:
    """Text from a dense vector of ``DIM`` floats. Never sees the document."""
    if len(values) != te.DIM:
        return Inversion("", False, 0, 0.0)
    best = Inversion("", False, 0, 0.0)
    for step in _steps(values):
        got = _search(values, step, budget)
        if got.complete:
            return got
        if len(got.text) > len(best.text):
            best = got
    return best


def climb(score: Callable[[str], float], anchors: Sequence[str], alphabet: str, steps: int,
          beam: int = 8) -> str:
    """Grow the best anchor one character at a time, from search scores alone."""
    if not anchors:
        return ""
    hyps = [max(sorted(anchors), key=score)]
    for _ in range(steps):
        scored = sorted(((score(h + ch), h + ch) for h in hyps for ch in alphabet
                         if not (ch == " " and h.endswith(" "))), key=lambda x: (-x[0], x[1]))
        hyps = []
        for _, h in scored:
            if h not in hyps:
                hyps.append(h)
            if len(hyps) == beam:
                break
    return hyps[0]
