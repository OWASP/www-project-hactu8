"""End-to-end and unit tests for the LLM05 poisoning demo (echo backend)."""

from __future__ import annotations

import pytest

from llm05_demo import providers
from llm05_demo.backends import (
    LocalEmbedding, LocalLLM, ProviderEmbedding, ProviderLLM, build_backends,
)
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


class _FakeProvider(providers.Provider):
    """Records what a real backend would be sent; no network."""
    name = "fake"

    def __init__(self) -> None:
        super().__init__()
        self.sent = []

    def chat(self, messages, *, model=""):
        self._count_call()
        self.sent.append(messages)
        return "Data exports to external storage are strictly prohibited."

    def embed(self, texts, *, model):
        self._count_call()
        return [[float(len(t)), 1.0] for t in texts]


def test_config_backends_match_the_lab():
    assert Config().backend == "echo"
    assert Config(backend="local").backend == "echo"
    assert Config(backend="stub").backend == "echo"
    with pytest.raises(ValueError):
        Config(backend="openai")
    with pytest.raises(ValueError):
        Config(backend="openrouter", embed_model="x")    # no embeddings there
    with pytest.raises(ValueError):
        Config(backend="ollama", model="bad model; rm")


def test_build_backends_echo_is_offline():
    emb, llm = build_backends(Config())
    assert isinstance(emb, LocalEmbedding) and isinstance(llm, LocalLLM)


def test_build_backends_real_model(monkeypatch):
    fake = _FakeProvider()
    monkeypatch.setattr(providers, "get_provider", lambda name: fake)
    emb, llm = build_backends(Config(backend="ollama", model="m"))
    assert isinstance(emb, LocalEmbedding) and isinstance(llm, ProviderLLM)
    answer = llm.generate("Can I export data?", ["Exports are prohibited."])
    assert "prohibited" in answer
    system, user = fake.sent[-1]
    assert "ONLY the provided policy context" in system.content
    assert "- Exports are prohibited." in user.content
    emb, _ = build_backends(Config(backend="ollama", model="m", embed_model="e"))
    assert isinstance(emb, ProviderEmbedding)
    assert emb.embed_batch(["ab", "abc"]) == [[2.0, 1.0], [3.0, 1.0]]


def test_openrouter_needs_key(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    with pytest.raises(RuntimeError):
        build_backends(Config(backend="openrouter"))
