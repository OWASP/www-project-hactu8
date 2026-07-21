"""A minimal in-memory vector store with cosine-similarity search.

Documents carry a ``source`` label and a ``trust`` weight in their metadata. The
vulnerable pipeline ignores these fields entirely; the hardened pipeline uses them
for source scoring. Keeping the metadata on every document — even in the
vulnerable path — is deliberate: it shows that the data needed to defend was
present all along and simply went unused.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from itertools import count
from typing import Dict, List, Optional, Sequence

from .backends import Embedding

_ids = count(1)


@dataclass
class Document:
    text: str
    source: str = "unknown"
    trust: float = 0.5          # 0.0 (untrusted) .. 1.0 (golden set)
    doc_id: int = field(default_factory=lambda: next(_ids))
    vector: List[float] = field(default_factory=list)


@dataclass
class ScoredDocument:
    document: Document
    similarity: float           # raw cosine similarity to the query
    score: float                # ranking score actually used (may fold in trust)


def cosine(a: Sequence[float], b: Sequence[float]) -> float:
    if not a or not b:
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot / (na * nb)


class VectorStore:
    def __init__(self, embedding: Embedding) -> None:
        self._embedding = embedding
        self._docs: List[Document] = []

    # -- ingestion ---------------------------------------------------------- #
    def add_texts(
        self,
        texts: Sequence[str],
        source: str = "unknown",
        trust: float = 0.5,
        metadata: Optional[Sequence[Dict]] = None,
    ) -> List[Document]:
        added: List[Document] = []
        vectors = self._embedding.embed_batch(list(texts))
        for i, (text, vector) in enumerate(zip(texts, vectors)):
            src = source
            tr = trust
            if metadata and i < len(metadata):
                src = metadata[i].get("source", source)
                tr = metadata[i].get("trust", trust)
            doc = Document(text=text, source=src, trust=tr, vector=vector)
            self._docs.append(doc)
            added.append(doc)
        return added

    # -- retrieval ---------------------------------------------------------- #
    def similarity_search(
        self, query: str, k: int = 2, use_trust: bool = False
    ) -> List[ScoredDocument]:
        q = self._embedding.embed(query)
        scored: List[ScoredDocument] = []
        for doc in self._docs:
            sim = cosine(q, doc.vector)
            score = sim * doc.trust if use_trust else sim
            scored.append(ScoredDocument(doc, similarity=sim, score=score))
        scored.sort(key=lambda s: s.score, reverse=True)
        return scored[:k]

    # -- introspection (used by anomaly detection) -------------------------- #
    @property
    def documents(self) -> List[Document]:
        return list(self._docs)

    def __len__(self) -> int:
        return len(self._docs)
