"""Runtime configuration for the LLM05 demo.

The backends match AgenticGoat and the template-based lab: ``echo`` (default,
the offline retrieval-grounded summarizer; ``local`` and ``stub`` are accepted
as aliases), ``ollama``, ``llamacpp`` and ``openrouter``, through the shared
``providers.py``. OpenRouter reads ``OPENROUTER_API_KEY`` from the environment
only.

Retrieval uses the local hashing embedding unless ``LLM05_SRC_EMBED_MODEL`` is
set, in which case Ollama or llama.cpp embeds the corpus (OpenRouter offers no
embeddings here). Keeping the local embedding makes retrieval reproducible
while only the answering model changes.

The variables are ``LLM05_SRC_*``, not ``LLM05_*``: the template-based lab in
``owasp-llm05-poisoning-skill`` uses ``LLM05_BACKEND`` / ``LLM05_MODEL`` for
itself, and the two must not change each other.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from . import providers

_ALIASES = {"local": "echo"}


@dataclass(frozen=True)
class Config:
    """Immutable demo configuration resolved from environment variables."""

    backend: str = "echo"            # echo | ollama | llamacpp | openrouter
    model: str = ""                  # chat model; empty = the provider's default
    embed_model: str = ""            # empty = local hashing embedding
    embedding_dim: int = 1024        # dimensionality of local hashing embeddings
    top_k: int = 2                   # number of documents stuffed into the prompt

    def __post_init__(self) -> None:
        backend = providers.normalize(_ALIASES.get(self.backend.strip().lower(),
                                                   self.backend))
        if backend not in providers.BACKENDS:
            raise ValueError(f"Unknown backend {self.backend!r}; expected one of "
                             f"{', '.join(providers.BACKENDS)}.")
        if self.embed_model and backend in ("echo", "openrouter"):
            raise ValueError(f"{backend} has no embeddings here; leave "
                             "LLM05_SRC_EMBED_MODEL unset or use ollama / llamacpp.")
        object.__setattr__(self, "backend", backend)
        object.__setattr__(self, "model", providers.check_model(self.model))
        object.__setattr__(self, "embed_model", providers.check_model(self.embed_model))

    @property
    def label(self) -> str:
        label = providers.describe(self.backend, self.model)
        return f"{label} (embeddings: {self.embed_model or 'local hashing'})"

    @classmethod
    def from_env(cls, **overrides: str) -> "Config":
        values = {
            "backend": os.getenv("LLM05_SRC_BACKEND", "echo"),
            "model": os.getenv("LLM05_SRC_MODEL", ""),
            "embed_model": os.getenv("LLM05_SRC_EMBED_MODEL", ""),
        }
        values.update({k: v for k, v in overrides.items() if v is not None})
        return cls(top_k=int(os.getenv("LLM05_TOP_K", "2")), **values)
