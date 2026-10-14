"""Embedding and LLM backends behind a small common interface.

Backends match AgenticGoat and the template-based lab (``echo``, ``ollama``,
``llamacpp``, ``openrouter``):

* ``LocalEmbedding`` / ``LocalLLM`` — zero-dependency, deterministic, and offline.
  Embeddings are a normalized hashing bag-of-words vector, so *repeated keywords
  raise a document's similarity to keyword-heavy queries*. That is precisely the
  "semantic collision" property the poisoning skill exploits — the effect is real,
  not scripted. The local "LLM" is a transparent, retrieval-grounded summarizer:
  its answer reflects whatever context retrieval hands it, so poisoning the
  retrieval genuinely changes the answer.

* ``ProviderLLM`` / ``ProviderEmbedding`` — a real chat model through the shared
  ``providers.py`` (standard library only), and optionally real embeddings from
  Ollama or llama.cpp. The local hashing embedding stays the default so that
  retrieval is reproducible and only the answering model changes.
"""

from __future__ import annotations

import math
import re
from typing import List, Protocol, Sequence, Tuple

from . import providers
from .config import Config

_TOKEN_RE = re.compile(r"[a-z0-9]+")

# Function words carry no topical signal. Dropping them keeps the small hashing
# embedding from mis-ranking on incidental collisions (e.g. "what are the ...")
# and sharpens the keyword-collision effect the poisoning skill relies on.
_STOPWORDS = frozenset(
    """
    a an the is are am was were be been being to of for on in into and or do does
    did i can could would should what which who whom my your you me we us they
    them their our need how it its this that these those with at by as all any
    from have has had will shall not no yes if then than so about
    """.split()
)


def _tokenize(text: str) -> List[str]:
    return [t for t in _TOKEN_RE.findall(text.lower()) if t not in _STOPWORDS]


# --------------------------------------------------------------------------- #
# Interfaces
# --------------------------------------------------------------------------- #
class Embedding(Protocol):
    def embed(self, text: str) -> List[float]: ...

    def embed_batch(self, texts: Sequence[str]) -> List[List[float]]: ...


class LLM(Protocol):
    def generate(self, question: str, context: Sequence[str]) -> str: ...


# --------------------------------------------------------------------------- #
# Local, offline backend
# --------------------------------------------------------------------------- #
class LocalEmbedding:
    """Deterministic hashing bag-of-words embedding.

    Each token is hashed into a fixed-size vector; term frequency accumulates in
    that dimension. The vector is L2-normalized. Because term frequency drives the
    magnitude, a document that repeats a query's keywords lands closer to that
    query in cosine space — the mechanism behind RAG "semantic collision".
    """

    def __init__(self, dim: int = 1024) -> None:
        self.dim = dim

    def embed(self, text: str) -> List[float]:
        vec = [0.0] * self.dim
        for token in _tokenize(text):
            # Stable, salted hash so results are reproducible across runs.
            idx = (hash((token, "llm05")) & 0x7FFFFFFF) % self.dim
            vec[idx] += 1.0
        norm = math.sqrt(sum(v * v for v in vec))
        if norm == 0.0:
            return vec
        return [v / norm for v in vec]

    def embed_batch(self, texts: Sequence[str]) -> List[List[float]]:
        return [self.embed(t) for t in texts]


class LocalLLM:
    """Retrieval-grounded summarizer used as a stand-in for a chat model.

    It does not invent an answer independently of context: it reports the stance
    expressed by the retrieved documents. That makes the demo honest — if the
    retrieved context is poisoned, the answer flips; if retrieval is hardened, the
    answer stays correct.
    """

    # Keyword lexicon used to read a document's stance on a policy topic.
    _ALLOW = ("permitted", "allowed", "now permit", "suspended", "allow ")
    _DENY = ("prohibited", "not allowed", "forbidden", "require", "must ")

    def generate(self, question: str, context: Sequence[str]) -> str:
        if not context:
            return "I don't have any policy information on that topic."

        top = context[0]
        allow_hits = sum(1 for kw in self._ALLOW if kw in " ".join(context).lower())
        deny_hits = sum(1 for kw in self._DENY if kw in " ".join(context).lower())

        # The generated answer paraphrases the single most-relevant document, then
        # notes if lower-ranked context disagrees (the "drift" signal).
        answer = f"Based on the most relevant policy: {top.strip()}"
        if allow_hits and deny_hits:
            answer += (
                " (Note: other retrieved records conflict with this statement.)"
            )
        return answer


# --------------------------------------------------------------------------- #
# Real-model backends through the shared providers.py
# --------------------------------------------------------------------------- #
class ProviderEmbedding:
    """Embeddings from a local Ollama or llama.cpp server."""

    def __init__(self, provider: providers.Provider, model: str) -> None:
        self._provider = provider
        self._model = model

    def embed(self, text: str) -> List[float]:
        return self.embed_batch([text])[0]

    def embed_batch(self, texts: Sequence[str]) -> List[List[float]]:
        return self._provider.embed(list(texts), model=self._model)


class ProviderLLM:
    """A real chat model answering from the retrieved context only."""

    _SYSTEM = (
        "You are a corporate policy assistant. Answer the employee's question "
        "using ONLY the provided policy context. Be concise."
    )

    def __init__(self, provider: providers.Provider, model: str) -> None:
        self._provider = provider
        self._model = model

    def generate(self, question: str, context: Sequence[str]) -> str:
        joined = "\n".join(f"- {c}" for c in context)
        prompt = f"Policy context:\n{joined}\n\nQuestion: {question}"
        return self._provider.chat(
            [providers.Message("system", self._SYSTEM),
             providers.Message("user", prompt)],
            model=self._model,
        )


# --------------------------------------------------------------------------- #
# Factory
# --------------------------------------------------------------------------- #
def build_backends(config: Config) -> Tuple[Embedding, LLM]:
    """Return ``(embedding, llm)`` for the configured backend."""
    provider = providers.get_provider(config.backend)
    if provider is None:
        return LocalEmbedding(config.embedding_dim), LocalLLM()
    embedding: Embedding = (ProviderEmbedding(provider, config.embed_model)
                            if config.embed_model else LocalEmbedding(config.embedding_dim))
    return embedding, ProviderLLM(provider, config.model)
