"""Runtime configuration for the LLM05 demo.

The demo defaults to a fully local backend so it runs with zero setup and no API
key. Set ``LLM05_BACKEND=openai`` (and export ``OPENAI_API_KEY``) to run the
pipeline against real OpenAI embeddings and a real chat model, as described in
the Technical Implementation Guide.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    """Immutable demo configuration resolved from environment variables."""

    backend: str = "local"          # "local" | "openai"
    embedding_dim: int = 1024        # dimensionality of local hashing embeddings
    top_k: int = 2                   # number of documents stuffed into the prompt
    openai_chat_model: str = "gpt-4.1-mini"
    openai_embedding_model: str = "text-embedding-3-large"

    @classmethod
    def from_env(cls) -> "Config":
        backend = os.getenv("LLM05_BACKEND", "local").strip().lower()
        if backend not in {"local", "openai"}:
            raise ValueError(
                f"Unknown LLM05_BACKEND={backend!r}; expected 'local' or 'openai'."
            )
        return cls(
            backend=backend,
            top_k=int(os.getenv("LLM05_TOP_K", "2")),
            openai_chat_model=os.getenv("LLM05_CHAT_MODEL", "gpt-4.1-mini"),
            openai_embedding_model=os.getenv(
                "LLM05_EMBED_MODEL", "text-embedding-3-large"
            ),
        )
