"""The toy language model behind Billy: an honest word-level n-gram LM.

Role in the lifecycle: this is the "fine-tuned model" of the HX09 lab. It is
trained, in process, on Billy's support corpus (FAQ exchanges and customer
tickets) and answers three questions any language-model API answers:

* ``logprobs(text)`` — the log-probability of each token given the ones
  before it (what a "logprobs" or "echo" scoring API returns);
* ``complete(prompt)`` — the greedy (top-1) continuation, with the mean
  probability of the tokens it chose (a "confidence");
* the same, on a model trained on a different corpus (the scrubbed one).

Nothing in it knows which records are members. A membership-inference attack
works on it for the same reason it works on a real model, because training
lowers the loss on training text, and for a stronger reason than on a real
LLM: an n-gram model **memorises its training set verbatim**. A 5-gram context
seen once in training predicts its continuation with probability close to 1,
and a context never seen backs off to generic statistics. A real LLM trained
on far more data for few epochs separates members from non-members far less
(Duan et al., 2024). The lab says so wherever it reports a number.

Smoothing is fixed-weight interpolation (Jelinek-Mercer) over orders 5 down
to 1, plus a uniform floor for unseen tokens, so every probability is defined
and every result is deterministic. Ties in the greedy choice are broken by the
token's first position in the training corpus, never by the token's spelling,
so a per-run random canary cannot change which token wins.

Standard library only.
"""

from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from typing import Dict, Iterable, List, Sequence, Tuple

ORDER = 5
# Interpolation weights for orders 5, 4, 3, 2, 1, and the uniform floor.
WEIGHTS = (0.50, 0.20, 0.12, 0.08, 0.06, 0.04)
BOS = "<s>"
TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9-]*|[^\sa-z0-9]")


def tokenize(text: str) -> List[str]:
    """Lowercased words (hyphens kept inside a word) and single punctuation marks."""
    return TOKEN_RE.findall((text or "").lower())


def detokenize(tokens: Sequence[str]) -> str:
    text = " ".join(tokens)
    return re.sub(r" ([.,?!;:])", r"\1", text)


class NGramLM:
    """Interpolated word n-gram model trained on a list of lines."""

    def __init__(self, lines: Iterable[str], order: int = ORDER) -> None:
        self.order = order
        self.counts: List[Dict[Tuple[str, ...], Counter]] = [defaultdict(Counter) for _ in range(order)]
        self.first_seen: Dict[str, int] = {}
        self.unigrams: Counter = Counter()
        position = 0
        self.lines = 0
        for line in lines:
            toks = tokenize(line)
            if not toks:
                continue
            self.lines += 1
            padded = [BOS] * (order - 1) + toks
            for i in range(order - 1, len(padded)):
                tok = padded[i]
                self.unigrams[tok] += 1
                if tok not in self.first_seen:
                    self.first_seen[tok] = position
                    position += 1
                for k in range(1, order):            # context lengths 1..order-1
                    ctx = tuple(padded[i - k:i])
                    self.counts[k][ctx][tok] += 1
        self.total = sum(self.unigrams.values())
        self.vocab = len(self.unigrams) + 1          # +1 for any unseen token
        self.top_unigram = min(self.unigrams, key=lambda t: (-self.unigrams[t], self.first_seen[t]))

    def prob(self, history: Sequence[str], token: str) -> float:
        """P(token | the last order-1 tokens of history), interpolated."""
        hist = ([BOS] * (self.order - 1) + list(history))[-(self.order - 1):]
        p = WEIGHTS[-1] / self.vocab
        p += WEIGHTS[-2] * self.unigrams.get(token, 0) / self.total
        for k in range(1, self.order):
            ctx = tuple(hist[len(hist) - k:])
            seen = self.counts[k].get(ctx)
            if seen:
                p += WEIGHTS[self.order - 1 - k] * seen.get(token, 0) / sum(seen.values())
        return p

    def logprobs(self, text: str, prefix: str = "") -> Tuple[List[str], List[float]]:
        """Each token of ``text`` and its natural-log probability, given ``prefix`` and the tokens before it."""
        history = tokenize(prefix)
        toks = tokenize(text)
        out = []
        for tok in toks:
            out.append(math.log(self.prob(history, tok)))
            history.append(tok)
        return toks, out

    def mean_nll(self, text: str) -> float:
        """Mean negative log-likelihood per token (the per-example loss)."""
        _, lps = self.logprobs(text)
        return -sum(lps) / len(lps) if lps else 0.0

    def _candidates(self, hist: Sequence[str]) -> List[str]:
        cands = {self.top_unigram}
        for k in range(1, self.order):
            ctx = tuple(hist[len(hist) - k:])
            cands.update(self.counts[k].get(ctx, ()))
        return sorted(cands, key=lambda t: self.first_seen.get(t, 1 << 30))

    def complete(self, prompt: str, max_tokens: int = 12, stop: Sequence[str] = (".", "?")) -> Tuple[List[str], float]:
        """Greedy top-1 continuation of ``prompt`` and the mean probability of the chosen tokens."""
        hist = ([BOS] * (self.order - 1) + tokenize(prompt))
        out: List[str] = []
        probs: List[float] = []
        for _ in range(max(1, max_tokens)):
            best, best_p = "", -1.0
            for tok in self._candidates(hist):
                if tok == BOS:
                    continue
                p = self.prob(hist, tok)
                if p > best_p:                      # strict: the earliest-seen token wins a tie
                    best, best_p = tok, p
            out.append(best)
            probs.append(best_p)
            hist.append(best)
            if best in stop:
                break
        return out, (sum(probs) / len(probs) if probs else 0.0)
