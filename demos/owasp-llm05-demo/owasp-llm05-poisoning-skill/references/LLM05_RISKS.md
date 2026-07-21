# LLM05 Risk Reference — Data & Model Poisoning

Domain knowledge loaded on demand. Poisoning targets the **learning and retrieval
process**, so it is resilient to traditional code-level patches: there is no
crashing stack trace, only a model that is confidently wrong on the attacker's
chosen topic.

## Research foundations

- **Souly et al. (2025)** — a near-constant *number* of poisoned samples (~250),
  not a fixed ratio, can compromise models up to ~13B parameters regardless of
  total corpus size.
- **Zhang et al. (2025), CorruptRAG** — 3–10 semantically optimized documents can
  override truth in a RAG system, even against perplexity filters, because the
  text is coherent and low-perplexity.
- **Hubinger et al. (2024), Sleeper Agents** — backdoors implanted during training
  survive standard safety alignment; trigger-gated behavior is not removed by
  RLHF-style tuning.
- **Fogel et al. (2026)** — tampering with GGUF chat templates can drop factual
  accuracy from ~90% to ~15% under specific trigger conditions (Scenario #6).

## Scenarios & examples

| ID | Title | Description | Focus |
|----|-------|-------------|-------|
| **S#1** | Internal Manipulation | Poisoning internal RAG repositories to bias business decisions. | **DEMO TARGET** |
| **S#6** | Chat Template Triggers | Tampering with GGUF/Jinja2 templates to drop accuracy under triggers. | **DEMO TARGET** |
| E#1 | Fine-Tuning Poisoning | Injecting malicious content into datasets to erode refusal behaviors. | — |
| E#2 | Financial Logic Bypass | Mislabeling fraud as legitimate in training data. | — |
| E#4 | Low-Volume Backdoors | High-impact backdoors from minimal (~250) document injection. | — |
| S#2 | Hidden Web Instructions | Indirect injection via web content summarized by AI agents. | — |
| S#5 | Malicious Weights | Distributing compromised pre-trained models via public hubs. | — |
| S#7 | Unsafe Serialization | Using pickle to execute code during model loading. | — |
| S#8 | Cross-Tenant Contamination | Poisoning shared embedding layers in multi-tenant setups. | — |
| S#9 | Persistent Memory Poisoning | Injecting long-term logic into an agent's memory store. | — |

## How the demo maps to the attack surfaces

- **Scenario #1** is the `/ingest` trust-boundary gap: unauthenticated writes let an
  attacker add documents that over-index on domain keywords and outrank the seeded
  ground truth in `mock_vector_search`.
- **Scenario #6** is the `/config/template` artifact-tampering gap: an unauthenticated
  swap installs a chat template whose conditional Jinja2 block injects a hidden
  `[OVERRIDE]` instruction only when the trigger phrase ("quarterly audit") appears
  — a dormant sleeper that leaves ordinary queries untouched.

## Mitigation roadmap

| Vulnerability | Hardening strategy |
|---------------|--------------------|
| **Trust-boundary violation** — unauthenticated ingestion. | Authenticated ingestion (mTLS/API-key), origin vetting of third-party sources. |
| **Lack of source scoring** — all retrieved snippets treated as authoritative. | Grounding + source scoring against a Golden Corpus; reject low-reputation context. |
| **S#1 RAG drift** — no detection of deviation from truth. | Data Version Control (DVC) for datasets: hash verification, lineage, rapid rollback. |
| **S#6 artifact tampering** — malicious chat templates/GGUF files. | Treat templates as code: SHA-256 pinning + Jinja2 SSTI static analysis (see `evaluate_kpi.py --scan-template`). |
| **Automated feedback poisoning** — drift via manipulated preference signals. | Human-in-the-loop validation before data updates production embeddings/fine-tunes. |
| **Sleeper agents / backdoors** — survive safety alignment. | Dedicated trigger-probing / adversarial red-teaming with trigger datasets. |
| **Supply-chain risk** — loading unverified public models. | CycloneDX ML-BOM for weights, adapters, and datasets to ensure provenance. |
