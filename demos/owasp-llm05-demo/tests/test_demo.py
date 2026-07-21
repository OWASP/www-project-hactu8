"""End-to-end and unit tests for the LLM05 poisoning demo (local backend)."""

from __future__ import annotations

from llm05_demo.backends import LocalEmbedding, LocalLLM, build_backends
from llm05_demo.config import Config
from llm05_demo.corpus import LEGITIMATE_DOCS, TEST_QUERIES
from llm05_demo.evaluate import RED, evaluate, poison_success_rate
from llm05_demo.mitigations import HardenedRAG, anomaly_scan
from llm05_demo.poison import inject_in_process
from llm05_demo.rag_pipeline import VulnerableRAG
from llm05_demo.vector_store import VectorStore, cosine


def _clean_store() -> VectorStore:
    emb, _ = build_backends(Config())
    store = VectorStore(emb)
    store.add_texts(LEGITIMATE_DOCS, source="Corporate Policy Handbook", trust=0.95)
    return store


def test_embedding_keyword_collision():
    """Repeating keywords must raise similarity to a keyword-heavy query."""
    emb = LocalEmbedding()
    q = emb.embed("data exports policy")
    plain = emb.embed("the weather is nice today")
    keyword_heavy = emb.embed("data exports policy data exports policy data exports")
    assert cosine(q, keyword_heavy) > cosine(q, plain)


def test_baseline_is_all_green():
    store = _clean_store()
    rag = VulnerableRAG(store, LocalLLM(), top_k=2)
    answers = [rag.query(tq.query).answer for tq in TEST_QUERIES]
    judgements = evaluate(TEST_QUERIES, answers)
    assert all(j.status != RED for j in judgements)
    assert poison_success_rate(judgements)["targeted_psr"] == 0.0


def test_poisoning_steers_targeted_topic():
    store = _clean_store()
    rag = VulnerableRAG(store, LocalLLM(), top_k=2)
    inject_in_process(store)
    answers = [rag.query(tq.query).answer for tq in TEST_QUERIES]
    psr = poison_success_rate(evaluate(TEST_QUERIES, answers))
    # Attack succeeds on the targeted topic...
    assert psr["targeted_psr"] > 0.0
    # ...and the control topics are untouched (overall < targeted).
    assert psr["overall_psr"] < psr["targeted_psr"]


def test_anomaly_scan_flags_poison():
    store = _clean_store()
    inject_in_process(store)
    report = anomaly_scan(store)
    assert report.triggered
    assert len(report.flagged) >= 2


def test_hardening_restores_ground_truth():
    store = _clean_store()
    rag = VulnerableRAG(store, LocalLLM(), top_k=2)
    inject_in_process(store)

    poisoned = poison_success_rate(
        evaluate(TEST_QUERIES, [rag.query(tq.query).answer for tq in TEST_QUERIES])
    )
    assert poisoned["targeted_psr"] > 0.0

    hardened = HardenedRAG(store, LocalLLM(), top_k=2)
    fixed = poison_success_rate(
        evaluate(
            TEST_QUERIES, [hardened.query(tq.query).answer for tq in TEST_QUERIES]
        )
    )
    assert fixed["targeted_psr"] == 0.0
