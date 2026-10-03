# ASI06 Risk Reference — Memory & Context Poisoning

Domain knowledge, loaded on demand. Memory and context poisoning happens when
an attacker gets content into what an agent **remembers or retrieves**, so the
agent carries it into later steps, later sessions or other users' work. The
injection and the harm are separated in time: the write looks harmless when it
happens, and the effect lands in a session the attacker is not part of. This
repo uses the 2026 numbering of the OWASP Top 10 for Agentic Applications.

## Research foundations

- **Greshake et al. (2023), "Not what you've signed up for"** — introduces
  indirect prompt injection against LLM-integrated applications, and discusses
  compromises that persist when injected content is kept in an application's
  memory.
- **Chen et al. (2024), "AgentPoison"** — red-teams LLM agents by poisoning
  their long-term memory or knowledge base so that a trigger in a later query
  retrieves the attacker's entries.
- **Zou et al. (2024), "PoisonedRAG"** — knowledge-corruption attacks that
  inject a small number of texts into a RAG knowledge base to steer answers to
  targeted questions.
- **OWASP Top 10 for Agentic Applications, ASI06 Memory & Context Poisoning**
  — the risk entry.

## Scenarios & examples

| ID | Title | Description | Focus |
|----|-------|-------------|-------|
| M-1 | Cross-user memory poisoning | One user's saved memory is recalled in other users' later sessions and steers them. | **DEMO TARGET** |
| M-2 | Topic-keyed trigger | The memory is recalled only for questions on one topic, so the harm is targeted and hard to notice. | **DEMO TARGET** (keyword recall) |
| M-3 | Unscreened memory writes | The agent stores whatever it is asked to remember, instruction lines included. | **DEMO TARGET** |
| M-4 | Self-poisoning via tool output | The agent summarises poisoned tool output into its own memory (see LLM01). | — |
| M-5 | Knowledge-base poisoning | Documents, not memories, are poisoned (see the LLM data/model poisoning demos). | — |
| M-6 | Context-window stuffing | Long benign content pushes system instructions out of the window. | — |

## How the demo maps to the attack surfaces

- **M-1** is `Lab.recall_memory` in vulnerable mode: it ranks every memory in
  the store, whoever wrote it, and `Lab.session` puts the top results into the
  model's context. The action log's `respond` step records the owner of the
  memory the model followed.
- **M-2** is the keyword overlap in `recall_memory`. Only travel questions
  share words with the planted memory, so the payroll and VPN controls stay
  GREEN.
- **M-3** is `Lab.save_memory` in vulnerable mode, reached through an ordinary
  `POST /session` whose first line asks the agent to remember something. It
  stores the text verbatim with `shared` scope.

## Mitigation roadmap

| Vulnerability | Hardening strategy |
|---------------|--------------------|
| Unscreened memory writes | **Memory-write screening.** Screen each write and block on a match. Implemented: `screen_memory` in hardened mode and `evaluate_kpi.py --scan`, screening with protectogw (AgenticGoat's screening core, vendored unchanged: normalizer + de-obfuscation folds + ruleset + exfil taxonomy + canary check) plus lab rules for the placeholder syntax. Its `SECURITY.md` states a ~75% generalization ceiling, so it is one layer, never the boundary. |
| Memories shared across users | **Per-user scope with provenance.** New memories are saved with `user` scope, an owner, and the session that wrote them. Implemented: hardened `save_memory`. |
| Recall trusts any entry | **Scoped recall.** Recall returns only `user`-scoped entries owned by the current user with a provenance record; unscoped entries are ignored. Implemented: `recall_allowed`. This alone neutralises memory planted before hardening. |
| Memory treated as instructions | Keep recalled memory in its own data channel and never take instructions from it (see the LLM01 demo's channel separation). |
| Long-lived poison | Expiry, review queues and a quarantine path for flagged memories; audit memory by owner. |
| Shared organisational memory | Allow shared entries only through a reviewed, authenticated publishing path. |

Further hardening discussed, not coded: output screening, memory expiry, and
held-out adversarial testing.
