"""Optional Flask app exposing the vulnerable RAG pipeline over HTTP.

This mirrors Module 1 of the Technical Implementation Guide and enables the live
"two-terminal" demo:

    Terminal A:  python -m llm05_demo.server
    Terminal B:  python -m llm05_demo.poison        # attacks /admin/inject

Endpoints
---------
POST /query          {"prompt": "..."}                      -> answer + sources
POST /admin/inject   {"documents": [...], "source","trust"} -> unauthenticated
GET  /health         liveness probe

The ``/admin/inject`` endpoint is intentionally unauthenticated and performs no
validation — it is the "direct ingestion / no trust boundary" gap from the
briefing. Do not deploy this anywhere reachable.
"""

from __future__ import annotations

from typing import Any

from .backends import build_backends
from .config import Config
from .corpus import LEGITIMATE_DOCS
from .rag_pipeline import VulnerableRAG
from .vector_store import VectorStore

GOLDEN_SOURCE = "Corporate Policy Handbook"
GOLDEN_TRUST = 0.95


def create_app(config: Config | None = None) -> Any:
    from flask import Flask, jsonify, request  # lazy import

    config = config or Config.from_env()
    embedding, llm = build_backends(config)

    store = VectorStore(embedding)
    store.add_texts(LEGITIMATE_DOCS, source=GOLDEN_SOURCE, trust=GOLDEN_TRUST)
    pipeline = VulnerableRAG(store, llm, top_k=config.top_k)

    app = Flask(__name__)

    @app.get("/health")
    def health():
        return jsonify({"status": "ok", "documents": len(store)})

    @app.post("/query")
    def query_policy():
        prompt = (request.json or {}).get("prompt", "")
        if not prompt:
            return jsonify({"error": "missing 'prompt'"}), 400
        result = pipeline.query(prompt)
        return jsonify(
            {
                "response": result.answer,
                "sources": [
                    {
                        "text": s.document.text,
                        "source": s.document.source,
                        "similarity": round(s.similarity, 4),
                    }
                    for s in result.retrieved
                ],
            }
        )

    @app.post("/admin/inject")
    def admin_inject():
        # VULNERABILITY: no auth, no validation, no source scoring.
        body = request.json or {}
        docs = body.get("documents", [])
        if not isinstance(docs, list) or not docs:
            return jsonify({"error": "missing 'documents' list"}), 400
        store.add_texts(
            docs,
            source=body.get("source", "unknown"),
            trust=float(body.get("trust", 0.5)),
        )
        return jsonify(
            {"status": "Data ingested into vector store", "documents": len(store)}
        )

    return app


def main() -> None:
    import os

    app = create_app()
    # Bind to loopback only — this app is intentionally insecure.
    # Port is configurable: macOS reserves 5000 for AirPlay Receiver, so allow
    # an override via LLM05_PORT (default 5000, but 5001 is a safe fallback).
    port = int(os.getenv("LLM05_PORT", "5100"))
    app.run(host="127.0.0.1", port=port)


if __name__ == "__main__":
    main()
