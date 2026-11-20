# AGX08 Risk Reference — Cross-Resource Chain

Domain knowledge, loaded on demand. AGX08 is one of the AGX superset
labs (`agentic/labs.json`, `superset_labs`, group **C: RAG**). Its parent entry
is **ASI06, Memory and Context Poisoning**, in the OWASP Top 10 for Agentic
Applications 2026.

Two documents can each be clean alone and hostile once a loader concatenates
them, or once a read-directive in one steers the reader to the other.
Per-document screening passes each piece; the injection exists only in the
assembled context.

## Research foundations

- **OWASP Top 10 for Agentic Applications 2026, ASI06 (Memory and Context
  Poisoning)** — the parent entry.
- **Greshake et al. (2023), "Not what you've signed up for"** — indirect
  prompt injection, including payloads that instruct the model to retrieve
  further attacker content (multi-stage injection).
- **The source lab's `chain_scan` act** — doc A says "for the rest see doc B",
  doc B completes the directive; a session-accumulating screen catches the
  chain that a per-document screen passes.
- **protectogw `session.py`** — the `Session` heat model: a document reached
  through a read-directive that carries sensitive-handling text is blocked,
  although a stateless screen allows it.

## Scenarios & examples

| ID | Title | Description | Focus |
|----|-------|-------------|-------|
| S-1 | Two-document chain | A points to B; the directive is split between them. | **DEMO TARGET** |
| S-2 | Benign chain | `kb://office-hours` points to `kb://holiday-calendar`. | **CONTROL** (no false positive) |
| S-3 | Three-hop chain | B points to C, which completes the directive. | Covered (loader reads three; assembled screen sees all) |
| S-4 | Concatenation without a pointer | Two chunks adjacent in one retrieval result. | Covered by the assembled screen, not by the session heuristic |
| S-5 | Callback exfiltration | The chain asks for an HTTP callback with the secret. | — (no callback channel in this lab) |

## How the demo maps to the attack surfaces

- **S-1** is `POST /kb/publish` (no authentication) for both documents,
  combined with `Lab.load` following `read kb://...` and `assemble` joining
  the reads. `Gateway("vulnerable")` calls `screen_doc` on each document and
  nothing else.
- **S-2** keeps the session screen honest: a pointer alone is not an attack,
  and the benign chain stays GREEN in hardened mode.
- **The screen is not the problem, its unit is.** The same protectogw call
  with the same policy blocks the assembly (`ChainTest`).

## Mitigation roadmap

| Vulnerability | Hardening strategy |
|---------------|--------------------|
| Each read judged alone | **Stateful session screen** across the reads of a request. Implemented: `Gateway.session_flags` with `protectogw.Session`. |
| The model sees the assembly, the screen does not | **Screen the assembled context.** Implemented: `Gateway.screen_assembled`. |
| A leak once an injection gets through | **Output canary check.** Implemented: `Gateway.check_reply`. Stops this attack on its own (`test_canary_check_alone_blocks`). |
| Untrusted text mixed into the instruction channel | **Spotlighting** for real models: `<untrusted_documents>` tags in `ProviderModel`. |
| Unbounded multi-hop retrieval | Cap hops (implemented: `MAX_HOPS = 3`) and flag read-directives that steer to another document. |
| Unauthenticated publishing | Provenance and review for knowledge-base updates. Discussed, not coded. |
| Ruleset misses the wording | protectogw's built-in rules miss even the assembly; the lab rule, the session heuristic and the canary check carry it. See AGX09. |
