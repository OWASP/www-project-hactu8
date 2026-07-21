"""Embedding and LLM backends behind a small common interface.

Two backends are provided:

* ``LocalEmbedding`` / ``LocalLLM`` — zero-dependency, deterministic, and offline.
  Embeddings are a normalized hashing bag-of-words vector, so *repeated keywords
  raise a document's similarity to keyword-heavy queries*. That is precisely the
  "semantic collision" property the poisoning skill exploits — the effect is real,
  not scripted. The local "LLM" is a transparent, retrieval-grounded summarizer:
  its answer reflects whatever context retrieval hands it, so poisoning the
  retrieval genuinely changes the answer.

* ``OpenAIEmbedding`` / ``OpenAILLM`` — real OpenAI embeddings and chat model,
  matching the Technical Implementation Guide. Imported lazily so the package has
  no hard dependency on the ``openai`` SDK.
"""

from __future__ import annotations

import math
import re
from typing import List, Protocol, Sequence, Tuple

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
# OpenAI backend (optional; matches the Technical Implementation Guide)
# --------------------------------------------------------------------------- #
class OpenAIEmbedding:
    def __init__(self, model: str) -> None:
        from openai import OpenAI  # lazy import

        self._client = OpenAI()
        self._model = model

    def embed(self, text: str) -> List[float]:
        return self.embed_batch([text])[0]

    def embed_batch(self, texts: Sequence[str]) -> List[List[float]]:
        resp = self._client.embeddings.create(model=self._model, input=list(texts))
        return [d.embedding for d in resp.data]


class OpenAILLM:
    _SYSTEM = (
        "You are a corporate policy assistant. Answer the employee's question "
        "using ONLY the provided policy context. Be concise."
    )

    def __init__(self, model: str) -> None:
        from openai import OpenAI  # lazy import

        self._client = OpenAI()
        self._model = model

    def generate(self, question: str, context: Sequence[str]) -> str:
        joined = "\n".join(f"- {c}" for c in context)
        resp = self._client.chat.completions.create(
            model=self._model,
            temperature=0,
            messages=[
                {"role": "system", "content": self._SYSTEM},
                {
                    "role": "user",
                    "content": f"Policy context:\n{joined}\n\nQuestion: {question}",
                },
            ],
        )
        return resp.choices[0].message.content or ""


# --------------------------------------------------------------------------- #
# Factory
# --------------------------------------------------------------------------- #
def build_backends(config: Config) -> Tuple[Embedding, LLM]:
    """Return ``(embedding, llm)`` for the configured backend."""
    if config.backend == "openai":
        return (
            OpenAIEmbedding(config.openai_embedding_model),
            OpenAILLM(config.openai_chat_model),
        )
    return LocalEmbedding(config.embedding_dim), LocalLLM()
