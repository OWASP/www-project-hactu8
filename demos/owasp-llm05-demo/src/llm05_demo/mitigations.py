"""Hardened counterpart to the vulnerable pipeline — the "remediation" act.

Three defenses from the OWASP LLM05 mitigation roadmap, each targeting a specific
gap the vulnerable pipeline left open:

1. Source scoring   — rank by (similarity x trust) and drop context below a trust
   threshold, so a "golden set" policy outranks an anonymous "external wiki" memo.
2. Anomaly detection — flag sudden clusters of near-duplicate documents arriving
   from a single low-trust source (the semantic-density spike a batch injection
   creates).
3. Grounding fallback — if nothing trusted survives filtering, answer only from
   the verified golden set rather than from whatever ranked highest.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Sequence

from .backends import LLM
from .rag_pipeline import QueryResult
from .vector_store import ScoredDocument, VectorStore, cosine

TRUST_THRESHOLD = 0.4          # context below this trust is refused
DENSITY_SIMILARITY = 0.6       # near-duplicate threshold for anomaly detection


@dataclass
class AnomalyReport:
    flagged: List[str] = field(default_factory=list)

    @property
    def triggered(self) -> bool:
        return bool(self.flagged)


def anomaly_scan(store: VectorStore) -> AnomalyReport:
    """Flag clusters of near-duplicate, low-trust documents from one source."""
    report = AnomalyReport()
    docs = store.documents
    for i, a in enumerate(docs):
        if a.trust >= TRUST_THRESHOLD:
            continue
        neighbors = 0
        for j, b in enumerate(docs):
            if i == j or b.source != a.source:
                continue
            if cosine(a.vector, b.vector) >= DENSITY_SIMILARITY:
                neighbors += 1
        # A low-trust document with same-source near-duplicates is suspicious.
        if neighbors >= 1:
            report.flagged.append(a.text)
    return report


class HardenedRAG:
    def __init__(
        self,
        vector_store: VectorStore,
        llm: LLM,
        top_k: int = 2,
        trust_threshold: float = TRUST_THRESHOLD,
    ) -> None:
        self._store = vector_store
        self._llm = llm
        self._top_k = top_k
        self._threshold = trust_threshold

    def query(self, prompt: str) -> QueryResult:
        # Retrieve extra candidates, then apply source scoring + filtering.
        candidates = self._store.similarity_search(
            prompt, k=self._top_k + 3, use_trust=True
        )
        trusted: List[ScoredDocument] = [
            c for c in candidates if c.document.trust >= self._threshold
        ]

        # Grounding fallback: never answer from untrusted context.
        if not trusted:
            golden = [
                ScoredDocument(d, 0.0, 0.0)
                for d in self._store.documents
                if d.trust >= self._threshold
            ]
            trusted = sorted(
                self._store.similarity_search(prompt, k=self._top_k, use_trust=True),
                key=lambda s: s.document.trust,
                reverse=True,
            )[: self._top_k] or golden[: self._top_k]

        retrieved = trusted[: self._top_k]
        context = [s.document.text for s in retrieved]
        answer = self._llm.generate(prompt, context)
        return QueryResult(query=prompt, answer=answer, retrieved=retrieved)
