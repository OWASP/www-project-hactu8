"""OWASP LLM05: Data and Model Poisoning — RAG poisoning demonstration.

This package implements a small, self-contained Retrieval-Augmented Generation
(RAG) pipeline that is intentionally vulnerable to knowledge-base poisoning, plus
the tooling to attack it and to measure the impact.

Modules
-------
config       Backend selection (local, no-key default; or OpenAI).
backends     Embedding + LLM backends behind a common interface.
vector_store In-memory vector store with cosine similarity search.
corpus       Legitimate policy corpus, adversarial documents, and test queries.
rag_pipeline The intentionally vulnerable RAG orchestration (Module 1).
poison       The poisoning skill / adversarial injection (Module 2).
evaluate     The stoplight KPI comparator and Poison Success Rate (Module 3).
mitigations  A hardened pipeline (source scoring, anomaly detection, grounding).
server       Optional Flask app exposing the vulnerable pipeline over HTTP.
"""

__all__ = ["__version__"]
__version__ = "1.0.0"
