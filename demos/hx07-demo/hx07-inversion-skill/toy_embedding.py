"""The HX07 lab's toy embedding model: hashed character n-gram vectors.

The vector store embeds every document with ``embed``. It is a deliberately
small, honest stand-in for a text-embedding model, standard library only and
deterministic:

* the text is lowercased and every character outside ``ALPHABET`` becomes a
  space (runs of spaces collapse);
* it is padded with ``PAD`` start and end marks, and every character 3-, 4-
  and 5-gram is hashed (BLAKE2b) into one of ``DIM`` buckets;
* the bucket counts are L2-normalised: a unit vector of ``DIM`` floats, the
  same shape a real embedding API returns, and compared by cosine.

It is **much weaker than a real embedding**. Its coordinates are counts of
substrings, so a leaked vector can be inverted by a plain search over
characters (``scripts/invert_vectors.py``). A dense model such as GTR or
OpenAI's ada-002 mixes the whole text into every coordinate; inverting it
needs a trained decoder (Morris et al. 2023, vec2text), which still recovered
92% of 32-token inputs exactly. The lesson the toy carries over is the
direction, not the difficulty: a vector is a lossy copy of the text, and the
loss is smaller than people assume.

Vectors are kept sparse inside the lab (``{bucket: value}``) for speed;
``dense`` gives the list a vector API would return.
"""

from __future__ import annotations

import hashlib
import math
import re
from typing import Dict, Iterable, Iterator, List

DIM = 4096
ORDERS = (3, 4, 5)
ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789 .:-,"
START, END = "\x02", "\x03"
PAD = max(ORDERS) - 1

Sparse = Dict[int, float]
_BUCKETS: Dict[str, int] = {}


def bucket(gram: str) -> int:
    """The bucket a gram hashes to (cached; the hash is fixed, so every run agrees)."""
    b = _BUCKETS.get(gram)
    if b is None:
        b = int.from_bytes(hashlib.blake2b(gram.encode("utf-8"), digest_size=8).digest(), "big") % DIM
        if len(_BUCKETS) < 500_000:
            _BUCKETS[gram] = b
    return b


def normalize(text: str) -> str:
    """Lowercase; characters outside ``ALPHABET`` become spaces; runs of spaces collapse."""
    text = "".join(c if c in ALPHABET else " " for c in (text or "").lower())
    return re.sub(r" +", " ", text).strip()


def is_pad(gram: str) -> bool:
    return not gram.strip(START + END)


def grams(text: str) -> Iterator[str]:
    """Every 3-, 4- and 5-gram of the padded, normalised text (grams of padding only are skipped)."""
    padded = START * PAD + normalize(text) + END * PAD
    for n in ORDERS:
        for i in range(len(padded) - n + 1):
            gram = padded[i:i + n]
            if not is_pad(gram):
                yield gram


def counts(text: str) -> Dict[int, int]:
    out: Dict[int, int] = {}
    for gram in grams(text):
        b = bucket(gram)
        out[b] = out.get(b, 0) + 1
    return out


def unit(vec: Dict[int, float]) -> Sparse:
    norm = math.sqrt(sum(v * v for v in vec.values()))
    return {b: v / norm for b, v in vec.items()} if norm else {}


def embed(text: str) -> Sparse:
    """The store's embedding of ``text``: a unit vector, sparse form."""
    return unit({b: float(c) for b, c in counts(text).items()})


def cosine(a: Sparse, b: Sparse) -> float:
    """Cosine of two vectors. Stored vectors may carry noise, so both are re-normalised."""
    if len(a) > len(b):
        a, b = b, a
    dot = sum(v * b.get(k, 0.0) for k, v in a.items())
    na = math.sqrt(sum(v * v for v in a.values()))
    nb = math.sqrt(sum(v * v for v in b.values()))
    return dot / (na * nb) if na and nb else 0.0


def dense(vec: Sparse, digits: int = 6) -> List[float]:
    """The ``DIM`` floats a vector API returns."""
    out = [0.0] * DIM
    for b, v in vec.items():
        out[b] = round(v, digits)
    return out


def sparse(values: Iterable[float]) -> Sparse:
    return {i: float(v) for i, v in enumerate(values) if v}
