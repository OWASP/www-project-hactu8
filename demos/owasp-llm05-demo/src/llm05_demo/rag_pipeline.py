"""Module 1 — the intentionally vulnerable RAG orchestration.

This pipeline is vulnerable *by omission*, matching OWASP LLM05 Example #6 (RAG
Knowledge Base Poisoning). It:

* retrieves the top-k documents by raw cosine similarity only;
* ignores the ``source`` and ``trust`` metadata that is sitting right on each doc;
* performs no anomaly detection, source scoring, or grounding check;
* stuffs whatever it retrieved straight into the prompt ("stuff" chain).

There is no defense here on purpose. The hardened counterpart lives in
``mitigations.py``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from .backends import LLM
from .vector_store import ScoredDocument, VectorStore


@dataclass
class QueryResult:
    query: str
    answer: str
    retrieved: List[ScoredDocument]


class VulnerableRAG:
    def __init__(self, vector_store: VectorStore, llm: LLM, top_k: int = 2) -> None:
        self._store = vector_store
        self._llm = llm
        self._top_k = top_k

    def query(self, prompt: str) -> QueryResult:
        # VULNERABILITY: ranking is raw similarity; trust weights are never read.
        retrieved = self._store.similarity_search(
            prompt, k=self._top_k, use_trust=False
        )
        context = [s.document.text for s in retrieved]
        answer = self._llm.generate(prompt, context)
        return QueryResult(query=prompt, answer=answer, retrieved=retrieved)
