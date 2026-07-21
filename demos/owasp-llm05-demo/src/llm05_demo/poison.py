"""Module 2 — the poisoning skill (adversarial injection).

The skill injects a small number of semantically optimized documents into the
knowledge base. It can inject directly into an in-process ``VectorStore`` (used by
``run_demo.py``) or over HTTP against the running Flask server's unprotected
``/admin/inject`` endpoint (used by the live "two-terminal" demo).

The documents themselves live in ``corpus.POISONED_DOCS``. They are crafted to
repeat the target query's keywords so they collide with legitimate policy vectors
in the embedding space — coherent, low-perplexity text that evades naive
perplexity filtering.
"""

from __future__ import annotations

from typing import List, Optional

from .corpus import POISONED_DOCS
from .vector_store import VectorStore

POISON_SOURCE = "external-wiki (attacker-controlled)"
POISON_TRUST = 0.1  # honest low trust; the vulnerable pipeline never checks it


def inject_in_process(
    store: VectorStore, docs: Optional[List[str]] = None
) -> List[str]:
    """Inject poisoned documents straight into an in-memory vector store."""
    payload = list(docs if docs is not None else POISONED_DOCS)
    store.add_texts(payload, source=POISON_SOURCE, trust=POISON_TRUST)
    _report(len(payload))
    return payload


def inject_over_http(
    base_url: str = "http://127.0.0.1:5100", docs: Optional[List[str]] = None
) -> List[str]:
    """Inject via the vulnerable server's unauthenticated ingestion endpoint."""
    import requests  # optional dependency; only needed for the HTTP path

    payload = list(docs if docs is not None else POISONED_DOCS)
    resp = requests.post(
        f"{base_url}/admin/inject",
        json={"documents": payload, "source": POISON_SOURCE, "trust": POISON_TRUST},
        timeout=30,
    )
    resp.raise_for_status()
    _report(len(payload))
    return payload


def _report(n: int) -> None:
    print(f"[!] Poisoning skill: {n} semantically optimized documents injected.")
    print(
        "[!] Technique: keyword-collision on 'data exports' to outrank the single "
        "legitimate policy vector."
    )
    print(
        "[!] Note: text is coherent and low-perplexity, so perplexity-based "
        "filtering does not catch it (cf. CorruptRAG, Zhang et al. 2025)."
    )


if __name__ == "__main__":
    # Convenience: run the attack against a live server.
    inject_over_http()
