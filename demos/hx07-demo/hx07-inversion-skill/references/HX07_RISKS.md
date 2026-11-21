# HX07 Embedding Inversion — risks, research and mitigations

What this lab's risk is, where it comes from, and how to harden against it. Loaded on demand.

## Research foundations

- **Morris, Kuleshov, Shmatikov and Rush (EMNLP 2023), "Text Embeddings Reveal (Almost) As Much As Text"** (<https://arxiv.org/abs/2310.06816>, abstract and HTML version read 2026-11-21). The method (vec2text) guesses a text, re-embeds it and corrects the guess, step by step. With GTR-base embeddings of 32-token Wikipedia passages (Natural Questions), it rebuilt 92% of inputs exactly (BLEU 97.3) after 50 correction steps. On MIMIC-III clinical notes it recovered 89% of full names. It also trains an inverter for OpenAI's `text-embedding-ada-002`. Defense: Gaussian noise on the embedding. At noise 0.01, reconstruction fell from BLEU 80.4 to 10.3 while mean NDCG@10 on 15 BEIR retrieval tasks fell from 0.302 to 0.296. Larger noise broke retrieval as well. The noise figures were read from the HTML version through a summarising fetch tool; check Table 7 of the paper before you quote them.
- **OWASP Top 10 for LLM Applications 2025, LLM08:2025 Vector and Embedding Weaknesses** (<https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/>, read 2026-11-21). It lists embedding inversion ("Attackers can exploit vulnerabilities to invert embeddings and recover significant amounts of source information"), unauthorised access to embeddings through weak access controls, and cross-context leaks in multi-tenant stores as risks. Its mitigations are "fine-grained access controls and permission-aware vector and embedding stores", strict partitioning, data validation, classification, and retrieval logging. None of its example scenarios is an inversion.
- **Song and Raghunathan (2020), "Information Leakage in Embedding Models"** (arXiv 2004.00053) and **Li et al. (2023), "Sentence Embedding Leaks More Information than You Expect: Generative Embedding Inversion Attack to Recover the Whole Sentence"** (arXiv 2305.03010). OWASP cites both. Neither was read for this lab (unverified).
- **MITRE ATLAS AML.T0024.001** and **NIST AI 100-2 NISTAML.032**. IDs from HACTU8's technique catalog (`hactu8/techniques.py`, `embedding-inversion`); the pages were not read for this lab (unverified).

## Why the toy is weaker than a real embedding

`toy_embedding.py` counts hashed character 3-, 4- and 5-grams (4,096 buckets) and normalises. Each coordinate is a count of substrings, so rounding a leaked vector gives back the counts and a search over characters gives back the text, in a few hundred search nodes. A dense embedding mixes the whole input into every coordinate; vec2text needs a trained model and many re-embedding steps, and still misses 8% of short inputs. The lab's thresholds (the noise level that stops the attack, the number of score queries) belong to the toy and to this attacker, not to any real model.

## Scenarios and examples

| ID | Title | Description | Focus |
|----|-------|-------------|-------|
| S1 | Raw vectors from an export or debug endpoint | An endpoint returns every record's embedding, not its text; the attacker inverts the vectors | **DEMO TARGET** (`GET /vectors`) |
| S2 | Vectors in search responses | Each hit carries its embedding | **DEMO TARGET** (`POST /search` in vulnerable mode returns them; the attack script uses the export) |
| S3 | Vector access not scoped to the tenant | Text is scoped; vectors of every tenant are not | **DEMO TARGET** (the export) |
| S4 | Noise too small to matter | Vectors leave with noise below one count | **DEMO TARGET** (measured limit, `--sweep`) |
| S5 | Similarity scores as an oracle | A caller who may search but not read climbs a restricted record's score | **DEMO TARGET** (measured limit, `--probe`) |
| S6 | Inversion of a real model's vectors with a trained decoder | vec2text against GTR or ada-002 | Context (not run; needs a model and training) |
| S7 | Attribute inference | Vectors reveal properties of the text (author, topic, a name) without full inversion | Context (not measured) |

## How the demo maps to the attack surfaces

- **S1, S3** — `Lab.export` in `vulnerable_app.py`; `test_leak_comes_from_vectors_never_from_text`.
- **S2** — `Lab.search` adds `embedding` unless `use_no_raw_vectors` is on; `test_act4_hardened_returns_to_zero`.
- **S4** — `protect` and `noise_sweep`; `NoiseTest`.
- **S5** — `Lab.score_oracle` and `invert_vectors.climb`; `LimitsTest`.

## Mitigation roadmap

| Vulnerability | Hardening strategy |
|---------------|--------------------|
| Raw vectors leave the store | Return ids, titles and scores, never an embedding (`use_no_raw_vectors`, implemented, `vector_privacy`) |
| Vector access spans tenants | Apply the text path's tenant check to every vector read and export (`use_tenant_acl`, implemented, `scope_filter`) |
| Vectors that must leave are exact | Gaussian noise above one count, then 8-bit quantisation; measure retrieval on a probe set before you ship a level (`use_noise`, `--sweep`, implemented, `vector_privacy`) |
| Secrets are embedded as written | Screen notes before embedding and embed a redacted copy (`use_ingest_screen`, implemented, `input_screen`); better, keep secrets in a vault, not in notes (`secret_vault`, not coded) |
| Scores are an oracle | Round scores more coarsely, leave restricted records out of the hit list for callers who may not read them, budget and watch queries per account (not coded; one-decimal rounding measured in `LimitsTest`) |
| No record of who read vectors | Immutable logs of exports and searches, as OWASP recommends (`export_log` counts reads; no alerting coded) |
