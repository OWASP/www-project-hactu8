# LLM09 Risk Reference — Vector and Embedding Weaknesses

Domain knowledge, loaded on demand. Retrieval-augmented generation (RAG) adds
a vector store between the user and the model, and that layer has its own
attack surface. A store that ranks by similarity alone does not know whose
data it holds. Queries can reach other tenants' documents, crafted documents
can rank first for common queries, and exposed vectors can leak the text they
were built from. This repo numbers the risk LLM09 (2026); the OWASP 2025 list
calls it LLM08.

## Research foundations

- **OWASP Top 10 for LLM Applications 2025, LLM08 "Vector and Embedding
  Weaknesses"** — the risk entry. It names unauthorized access and data
  leakage, cross-context information leaks in multi-tenant stores, embedding
  inversion and data poisoning, and recommends permission-aware vector stores
  with strict logical partitioning.
- **Song & Raghunathan (2020), "Information Leakage in Embedding Models"** —
  shows that embeddings leak information about their inputs, including
  partial recovery of the input words.
- **Morris et al. (2023), "Text Embeddings Reveal (Almost) As Much As Text"**
  — Vec2Text iteratively inverts text embeddings and recovers 92% of 32-token
  inputs exactly in their setting.
- **Zou et al. (2024), "PoisonedRAG"** — a small number of crafted documents
  placed in a RAG knowledge base can make it rank them first for target
  questions.

## Scenarios & examples

| ID | Title | Description | Focus |
|----|-------|-------------|-------|
| V-1 | Cross-tenant retrieval | A shared, similarity-only store serves one tenant's documents to another tenant's session. | **DEMO TARGET** |
| V-2 | Soft scoping | Scope is expressed as relevance (tenant name in the query) or as a prompt rule, not as a filter. A crafted query outranks it. | **DEMO TARGET** |
| V-3 | Embedding poisoning | A planted document stuffed with common query terms ranks first (AgenticGoat `evil/poison`; see LLM05). | — |
| V-4 | Embedding inversion | Exposed vectors are inverted back into their source text. | — (discussed, not coded) |
| V-5 | Federation conflicts | Sources with different access rules are merged into one index. | — |

## How the demo maps to the attack surfaces

- **V-1** is `Lab.retrieve` in vulnerable mode: `rank` scores every document
  in the shared store, whatever its tenant. The answer comes from the top
  passage, and the stub never sees a tenant label.
- **V-2** is `Lab.retrieval_vector`. The tenant's name is added to the
  retrieval vector, and the system prompt says "only answer from Meadow Fold
  documents". The crafted turn in `assets/crafted_query.txt` names the other
  tenant, stays in session memory, and outweighs the boost on every follow-up.
- **Targeting.** Only questions on topics both tenants share leak. Shearing
  and fencing stay GREEN, because Meadow Fold's documents still win on topic
  words there.

## Mitigation roadmap

| Vulnerability | Hardening strategy |
|---------------|--------------------|
| Tenant-blind retrieval | **Tenant filter at the retrieval layer**, applied before ranking and keyed on the session's server-side tenant. Implemented: `scope_blocks` and hardened mode in `vulnerable_app.py` (port of AgenticGoat `_scope_blocks`). |
| Scope as a prompt rule or relevance boost | Treat neither as access control. Keep the prompt rule for tone only. Implemented as the lesson: `tests/test_lifecycle.py::test_prompt_rule_alone_does_not_block`. |
| Unknown exposure of a query or index | **Retrieval-scope audit**: rank with no filter and list what a filter would block. Implemented: `evaluate_kpi.py --scan`. |
| Shared physical index | Separate collections or namespaces per tenant, in addition to the filter. |
| Embedding inversion | Never expose raw vectors to clients; restrict store APIs; test inversion resistance. Discussed, not coded. |
| Poisoned documents | Authenticate and review ingestion; monitor for documents that rank first for many unrelated queries (see LLM05). |

Further hardening discussed, not coded: per-tenant encryption keys, audit
logging of cross-scope denials, and access-controlled metadata in the store
itself rather than in the application.
