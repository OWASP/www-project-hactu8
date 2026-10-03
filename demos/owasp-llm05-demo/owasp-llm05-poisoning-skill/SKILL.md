---
name: owasp-llm05-poisoning-skill
description: >-
  Demonstrates OWASP LLM05 (Data & Model Poisoning) against a vulnerable RAG
  financial compliance assistant in an AUTHORIZED security lab. Covers
  Scenario #1 (RAG knowledge-base poisoning via unauthenticated ingestion),
  Scenario #6 (prompt-template tampering with a trigger-gated backdoor) and
  distributed poisoning through a peer agent's cache. Measures impact with a
  red/yellow/green stoplight KPI and Poison Success Rate, and shows the source
  gate, template pinning and agent-verification mitigations. Use when the user
  wants to run, script, or explain RAG poisoning or prompt-template backdoors,
  quantify poisoning impact, or demonstrate the hardening. Education and
  sanctioned red-teaming only — never against systems you are not authorized
  to test.
license: MIT
metadata:
  objective: Demonstrate RAG Knowledge Base and Artifact Poisoning (Scenario #1 & #6)
  version: 2026.2
---

# OWASP LLM05 Poisoning Skill

Demonstrates how an adversary steers a RAG-based **financial compliance
assistant** away from ground truth on three surfaces: its knowledge base
(Scenario #1), its prompt-template artifact (Scenario #6), and the cached
answer of a peer knowledge agent, Bob the Agent (distributed poisoning). It
then shows how to detect and harden against all three.

## Scope & safety (read first)

- **Authorized use only.** Run against this skill's own `vulnerable_app.py`
  (bound to `127.0.0.1`) or a target you are explicitly permitted to test.
- The vulnerable app is insecure **by design**; do not expose it. Four
  host-safety guards are built in. None of them weakens the lesson:
  - The knowledge base lives in memory only, so ingestion never touches the
    filesystem.
  - Prompt templates are rendered by a tiny substitution renderer
    (`render_template`) with no expression evaluation, so a tampered template
    can bias output but cannot execute code.
  - The model is a deterministic stub by default, so the lab cannot reach
    the network unless you opt into a real-model backend.
  - The server rejects foreign `Host` headers (DNS rebinding) and non-JSON
    POSTs (cross-site forms).
- Dual-use: this exists to make the vulnerability observable and to motivate
  the mitigations in [`references/LLM05_RISKS.md`](references/LLM05_RISKS.md).

## When to use

- Run or reproduce a RAG knowledge-base poisoning demo (Scenario #1).
- Demonstrate a prompt-template trigger backdoor (Scenario #6).
- Show distributed poisoning through an authenticated peer agent.
- Quantify poisoning impact (stoplight KPI, Poison Success Rate).
- Show the mitigations: source gate with provenance, SHA-256 template
  pinning with static analysis, and agent-response verification.

## MCP terminology bridge

MCP servers expose **tools**, **resources**, and **prompts**. MCP prompts are
reusable, parameterized message templates returned by a server. This skill's
`assets/prompt_template.json` is a simpler application-side template: it
assembles the system instruction, retrieved context, and user query, but it is
not an MCP prompt or an MCP server. A production MCP client may use an MCP
prompt and then apply a separate model-specific chat template before inference.

## Prerequisites

Python 3.9+. Standard library only; nothing to install.

Optional real model: set `LLM05_BACKEND` to `ollama`, `llamacpp` or
`openrouter` (which needs `OPENROUTER_API_KEY`), and `LLM05_MODEL` to the
model name, before starting the target. The default `stub` needs no network.
With `openrouter`, prompts and payloads leave the machine.

## Execution instructions

1. **Start the target.** From this skill folder:
   ```bash
   python vulnerable_app.py             # serves on 127.0.0.1:5205
   ```
   It seeds the two official policies in memory. To drive the same four acts
   from a browser, open <http://127.0.0.1:5205/>.

2. **Review the ground truth.** Open
   <http://127.0.0.1:5205/artifact/compliance_policy_official.txt>: offshore
   and proxy transactions need *enhanced due diligence* and *manual review*,
   high-value wires need *secondary authorization*, and volume spikes from new
   accounts are *potential fraud*. The MFA policy
   (`it_security_policy_official.txt`) is the untargeted control.

3. **Establish the baseline.**
   ```bash
   python scripts/evaluate_kpi.py
   ```
   Expect all 🟢 GREEN, PSR 0%. Exit code 0.

4. **Run the attack.**
   ```bash
   python scripts/run_poisoning.py                       # --scenario all (default)
   ```
   - `rag`: 3 documents built from
     [`assets/poison_template.txt`](assets/poison_template.txt) through
     `POST /ingest`. They repeat the domain's keywords, so they outrank the
     official policy.
   - `prompt`: installs [`assets/prompt_template.json`](assets/prompt_template.json)
     through `POST /config/template`, a template with a dormant block keyed on
     the phrase **"quarterly audit"**.
   - `agent`: refreshes Bob the Agent's cache with
     [`assets/bob_agent_poisoned_response.json`](assets/bob_agent_poisoned_response.json)
     through `POST /agent/cache`. The assistant consults Bob for audit
     questions and trusts him because he is authenticated.

   Use `--scenario rag|prompt|agent` to apply one surface at a time.

5. **Stoplight verification.**
   ```bash
   python scripts/evaluate_kpi.py
   ```
   Expect 🔴 RED on the four targeted questions and the MFA control still
   🟢 GREEN. PSR 100% targeted, 80% overall. Exit code 2. With a single
   scenario, `rag` turns all four targeted questions RED, while `prompt` and
   `agent` turn only the "quarterly audit" question RED.

6. **Show the mitigations.**
   ```bash
   python scripts/evaluate_kpi.py --scan                                  # REJECT, exit 2
   python scripts/evaluate_kpi.py --scan-prompt-template assets/prompt_template.json  # REJECT, exit 2
   python scripts/evaluate_kpi.py --harden                                # GREEN, PSR 0%
   ```
   `--scan` checks the three shipped artifacts with the same checks hardened
   mode applies. `--scan-prompt-template` prints the template's SHA-256 and
   flags the pin mismatch, the conditional block and the override wording.
   `--harden` switches the target to hardened mode, with three controls (see
   `/api/state` → `mitigations`):
   - `source_gate`: documents that fail `_protected_scan` (override indicators,
     or no `[SOURCE:]`/`[APPROVED_BY:]`/`[VERSION:]` provenance) are excluded
     from retrieval. The two seeded official policies are trusted by name
     while their content matches the seeded copy.
   - `template_pin`: the active template is used only if its SHA-256 matches
     the pinned baseline; otherwise the baseline template is used.
   - `agent_verify`: Bob's answer is used only if `provenance_verified` is true
     and `content_digest` matches the guidance text.
   Each control blocks its own surface on its own, and the tests prove it.

7. **Reset to baseline.**
   ```bash
   python scripts/reset_baseline.py
   python scripts/evaluate_kpi.py
   ```
   Expect all questions GREEN with PSR 0%. `--keep-mode` keeps hardened mode
   across the reset.

## Customizing the payload

Edit [`assets/poison_template.txt`](assets/poison_template.txt). The documents
must keep repeating the query keywords to outrank the official policy; if they
stop ranking, the RAG surface no longer moves the PSR. Edit
[`assets/prompt_template.json`](assets/prompt_template.json) to change the
trigger phrase: the renderer supports only `{{ system }}`, `{{ context }}`,
`{{ query }}` and `{% if '<phrase>' in query|lower %}...{% endif %}`, and
leaves anything else literal.

## Files

| Path | Purpose |
|------|---------|
| `vulnerable_app.py` | Target assistant (`/query`, `/ingest`, `/config/template`, `/agent/cache`, `/health`, read-only `/artifact/<name>`) plus the console API (`/api/meta`, `/api/state`, `/api/reset`, `/api/attack`, `/api/evaluate`, `/api/scan`, `/api/mode`). |
| `web/` | Shared HACTU8 lab console, served at `/`. |
| `providers.py` | Optional real-model backends: Ollama, llama.cpp, OpenRouter. Shared and copied unchanged. |
| `scripts/run_poisoning.py` | Attack: `--scenario rag|prompt|agent|all`. |
| `scripts/evaluate_kpi.py` | Stoplight KPI + PSR against the live app; `--harden`, `--scan`, `--scan-prompt-template`. |
| `scripts/reset_baseline.py` | Restores the seeded knowledge base, template, agent cache and vulnerable mode. |
| `references/LLM05_RISKS.md` | Threat landscape, research citations, scenario table, mitigations. |
| `assets/poison_template.txt` | Adversarial RAG document template (editable). |
| `assets/prompt_template.json` | Tampered prompt template with a trigger-gated backdoor. |
| `assets/prompt_template_baseline.json` | Untampered baseline template (its SHA-256 is pinned). |
| `assets/bob_agent_poisoned_response.json` | Bob the Agent's poisoned cached response. |
| `assets/knowledge_agent_cache_poisoned.txt` | The same agent cache as plain text, for slides. |
| `tests/test_lifecycle.py` | Asserts the four-act story in-process. |
