# AGX07 Risk Reference — Frontmatter Poison

Domain knowledge, loaded on demand. AGX07 is one of the AGX superset
labs (`agentic/labs.json`, `superset_labs`, group **C: RAG**), for patterns
neither OWASP list numbers on its own. Its parent entry is **ASI06, Memory and
Context Poisoning**, in the OWASP Top 10 for Agentic Applications 2026.

A RAG loader reads the whole document, metadata included. A scan that screens
only the prose body is blind to the frontmatter block, so an injection in a
`description:` field reaches the model while the body looks clean.

## Research foundations

- **OWASP Top 10 for Agentic Applications 2026, ASI06 (Memory and Context
  Poisoning)** — the parent entry: untrusted content written into the store an
  agent retrieves from.
- **OWASP Top 10 for LLM Applications 2025, LLM08 (Vector and Embedding
  Weaknesses)** — retrieval content as an injection path.
- **Greshake et al. (2023), "Not what you've signed up for"** — indirect
  prompt injection through content an application retrieves for the model.
- **Zou et al. (2024), "PoisonedRAG"** — a handful of poisoned documents in a
  knowledge base is enough to steer answers to targeted questions.
- **The source lab's `okf_scan` act** — screens a bundle document's frontmatter as
  well as its body; its probe puts the injection in `description:` with a
  clean body.
- **protectogw `SECURITY.md`** — the screening core is one layer, with a
  measured generalization ceiling of about 75% on held-out attacks.

## Scenarios & examples

| ID | Title | Description | Focus |
|----|-------|-------------|-------|
| S-1 | Payload in frontmatter `description:` | The approved body, the directive in the metadata the loader surfaces. | **DEMO TARGET** |
| S-2 | Clean prose body | The part a body-only scan reads, unchanged. | **CONTROL** (shows the gap) |
| S-3 | Payload in an unknown metadata key | A short directive in a key the schema does not allow. | Covered (schema check, tested) |
| S-4 | Payload split across frontmatter and body | Each half alone is weaker. | Discussed (practice task) |
| S-5 | Payload in the body | The classic case; a body scan does catch it. | — (see LLM08, ASI06) |
| S-6 | Poisoned embeddings or chunk metadata | Metadata that never renders as text. | — (outside this lab) |

## How the demo maps to the attack surfaces

- **S-1** is `POST /bundle/ingest` (no authentication) replacing
  `vault-access.md`, combined with `Lab.ask` assembling the body and then the
  metadata block into Billy's context. `Gateway("vulnerable")` screens the
  `body` surface only, so the `frontmatter` piece passes with verdict ALLOW
  and no signals.
- **A document has to be retrieved to leak.** Only vault requests route to
  `vault-access.md`, so the expense and holiday controls stay GREEN.
- **The scan is not the problem, its scope is.** The same protectogw call
  blocks the metadata the moment it is screened (`GatewayTest`).

## Mitigation roadmap

| Vulnerability | Hardening strategy |
|---------------|--------------------|
| Frontmatter reaches the model unscreened | **Screen every field the loader surfaces.** Implemented: `COVERAGE["hardened"]` adds `frontmatter` in `vulnerable_app.py`. |
| Free-form metadata | **Allowlisted schema**: known keys, known `type` values, short single-line values. Implemented: `schema_problems`. It catches the shipped payload on length alone and an unknown key on its own; a short payload in an allowed key passes it. |
| A leak once an injection gets through | **Output canary check**: `protectogw.screen(reply, canaries=[CANARY])` on every reply. Implemented: `Gateway.check_reply`. Stops this attack on its own (`test_canary_check_alone_blocks`). |
| Untrusted text mixed into the instruction channel | **Spotlighting** for real models: hardened mode fences the document in `<untrusted_document>` tags. Implemented: `ProviderModel`. |
| Unauthenticated ingestion | Provenance on every bundle document: signed sources, reviewed updates. Discussed, not coded. |
| Ruleset misses a paraphrase | protectogw's built-in rules miss the shipped wording; only the lab rule catches it. Held-out testing (AGX09) and the canary layer above. |
