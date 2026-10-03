---
name: owasp-llm09-tenant-skill
description: >-
  Demonstrates OWASP LLM09 (Vector and Embedding Weaknesses) against a
  vulnerable multi-tenant RAG assistant in an AUTHORIZED security lab. Covers
  cross-tenant retrieval: two tenants share one vector store, and a crafted
  query from one tenant makes the store rank the other tenant's confidential
  documents first. Measures impact with a red/yellow/green stoplight KPI and
  Cross-Tenant Leak Rate, and shows the mitigation: a tenant filter enforced at
  the retrieval layer, not in the prompt. Use when the user wants to run,
  script, or explain cross-tenant leakage in a vector store, quantify it, or
  demonstrate the hardening. Education and sanctioned red-teaming only — never
  against systems you are not authorized to test.
license: MIT
metadata:
  objective: Demonstrate cross-tenant leakage through a shared vector store
  version: 2026.1
---

# OWASP LLM09 Tenant Skill

Demonstrates how a user of one tenant, **Meadow Fold**, gets **Billy, Goat &
Co.'s hosted knowledge-base assistant** to answer from another tenant's
confidential documents, **Hilltop Creamery**'s. Both tenants share one vector
store. One crafted chat turn is enough, and no document is written. Then the
skill shows how to detect it and harden against it.

## Scope & safety (read first)

- **Authorized use only.** Run against this skill's own `vulnerable_app.py`
  (bound to `127.0.0.1`) or a target you are explicitly permitted to test.
- The vulnerable app is insecure **by design**; do not expose it. Host-safety
  guards are built in. None of them weakens the lesson:
  - The store and session memory live in memory only; nothing is written to disk.
  - Session memory keeps at most 3 turns of at most 500 characters.
  - The model is a deterministic stub by default, so the lab cannot reach
    the network unless you opt into a real-model backend.
  - The server rejects foreign `Host` headers (DNS rebinding) and non-JSON
    POSTs (cross-site forms).
- Both tenants and all documents are fictional. The shipped payload is a
  **placeholder**. See [`assets/crafted_query.README.md`](assets/crafted_query.README.md).
- Dual-use: this exists to make the vulnerability observable and to motivate
  the mitigations in [`references/LLM09_RISKS.md`](references/LLM09_RISKS.md).

## When to use

- Run or reproduce cross-tenant retrieval from a shared vector store.
- Quantify impact (stoplight KPI, Cross-Tenant Leak Rate).
- Show the mitigation: a tenant filter at the retrieval layer, and why a
  prompt rule or a relevance boost is not one.

## MCP terminology bridge

In MCP, a retrieval server would expose a search **tool** or a document
**resource**, and the session's identity would come from the transport's
authorization. Here, `Lab.retrieve` stands in for that search tool, and the
`session` field stands in for an authenticated token: the server, not the
caller, maps it to a tenant. The demo is not an MCP server. Hardened mode is
what a careful retrieval server does: it filters by the caller's scope before
it ranks.

## Prerequisites

Python 3.9+. Standard library only; nothing to install.

Optional real model: set `LLM09_BACKEND` to `ollama`, `llamacpp` or
`openrouter` (which needs `OPENROUTER_API_KEY`), and `LLM09_MODEL` to the
model name, before starting the target. The default `stub` needs no network.
With `openrouter`, prompts and payloads leave the machine.

## Execution instructions

1. **Start the target.** From this skill folder:
   ```bash
   python vulnerable_app.py             # serves on 127.0.0.1:5209
   ```
   On startup it seeds the shared store from `assets/vector_store.json`. To
   drive the same four acts from a browser, open <http://127.0.0.1:5209/>.

2. **Review the ground truth.** Read `assets/vector_store.json`. Meadow Fold
   buys hay at *180 dollars per tonne*, the vet visits on the *second
   Tuesday*, and *Riverbend Dairy* buys its milk. Hilltop Creamery's documents
   are confidential and each carries a fictional `LLM09-CANARY-xxxx`.

3. **Establish the baseline.**
   ```bash
   python scripts/evaluate_kpi.py
   ```
   Expect all 🟢 GREEN, CTLR 0%. Exit code 0.

4. **Run the attack.**
   ```bash
   python scripts/run_cross_tenant.py
   ```
   Sends [`assets/crafted_query.txt`](assets/crafted_query.txt) as one turn
   in the `meadow-analyst` session. The turn is answered from a Hilltop
   document and stays in session memory.

5. **Stoplight verification.**
   ```bash
   python scripts/evaluate_kpi.py
   ```
   Expect 🔴 RED on the hay, vet and milk questions, and the shearing and
   fencing controls still 🟢 GREEN. CTLR 100% targeted, 60% overall. Exit
   code 2.

6. **Show the mitigations.**
   ```bash
   python scripts/evaluate_kpi.py --scan assets/crafted_query.txt   # REJECT, exit 2
   python scripts/evaluate_kpi.py --harden                          # GREEN, CTLR 0%
   ```
   `--scan` ranks the store for the turn with no filter and lists every
   cross-tenant candidate. `--harden` switches the target to hardened mode:
   the store drops other tenants' documents before ranking. The crafted turn
   is still in memory, and it no longer matters.

7. **Reset to baseline.**
   ```bash
   python scripts/reset_baseline.py
   python scripts/evaluate_kpi.py
   ```
   Expect all questions GREEN with CTLR 0%.

## Customizing the payload

Edit [`assets/crafted_query.txt`](assets/crafted_query.txt) and follow
[`assets/crafted_query.README.md`](assets/crafted_query.README.md). Use
`--scan` to see the unfiltered ranking before you send it. If you stuff in
too many Hilltop topic words, the controls flip too and the attack is no
longer targeted.

## Files

| Path | Purpose |
|------|---------|
| `vulnerable_app.py` | Target RAG assistant (`/query`, `/health`) plus the console API (`/api/meta`, `/api/state`, `/api/reset`, `/api/attack`, `/api/evaluate`, `/api/scan`, `/api/mode`). |
| `web/` | Shared HACTU8 lab console, served at `/`. |
| `providers.py` | Optional real-model backends: Ollama, llama.cpp, OpenRouter. Shared and copied unchanged. |
| `scripts/run_cross_tenant.py` | Attack: one crafted turn in the attacker's own session. |
| `scripts/evaluate_kpi.py` | Stoplight KPI + CTLR against the live app; `--harden` and `--scan` mitigations. |
| `scripts/reset_baseline.py` | Restores the store, clears session memory, vulnerable mode. |
| `references/LLM09_RISKS.md` | Threat landscape, research, scenario table, mitigations. |
| `assets/crafted_query.txt` | Crafted turn (placeholder payload; editable). |
| `assets/crafted_query.README.md` | How to write a payload for the stub and real-model backends. |
| `assets/vector_store.json` | Tenants, sessions and the shared store: the ground truth. |
| `tests/test_lifecycle.py` | Asserts the four-act story in-process. |
