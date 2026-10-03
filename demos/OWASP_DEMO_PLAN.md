# Plan — OWASP Top 10 demo series from AgenticGoat

Status: approved 2026-10-02. LLM series built: owasp-llm01..llm10-demo (LLM05 pre-existing). ASI wave 2 not started.

Payload policy: every demo ships **placeholder** payloads (a marker line plus a
fictional canary) with an `assets/<payload>.README.md` explaining how to write a
real one. The user authors real payloads. Demos are stdlib-only, with an
in-process `run_demo.py` and `tests/test_lifecycle.py`. `owasp-llm01-demo` is
the pattern every later demo copies.

Goal: one self-contained lab per OWASP Top 10 for LLM Applications category,
built to `demos/_template/TEMPLATE.md` (four-act lifecycle, stoplight KPI,
vulnerable-by-omission target, editable payload, implemented mitigation, reset).
Mechanisms and mitigations are ported from `../AgenticGoat`; the existing
`demos/owasp-llm05-demo` is the reference implementation. An Agentic (ASI)
series follows as a second wave.

## 1. Source → target numbering

This repo uses the **2026** LLM Top 10 numbering (`demos/agenticgoat-mock`,
and LLM05 = Data & Model Poisoning). AgenticGoat uses the **2025** numbering.
Every port must translate:

| 2026 (this repo) | Category | 2025 id in AgenticGoat |
|---|---|---|
| LLM01 | Prompt Injection | LLM01 |
| LLM02 | Sensitive Information Disclosure | LLM02 |
| LLM03 | Excessive Agency | LLM06 |
| LLM04 | Supply Chain | LLM03 |
| LLM05 | Data and Model Poisoning | LLM04 |
| LLM06 | Unbounded Consumption | LLM10 |
| LLM07 | Misinformation | LLM09 |
| LLM08 | Hidden Context Exposure | LLM07 (System Prompt Leakage) |
| LLM09 | Vector and Embedding Weaknesses | LLM08 |
| LLM10 | Improper Output Handling | LLM05 |

## 2. Cross-cutting decisions

1. **Self-contained, vendored code.** Each skill folder copies only the
   AgenticGoat pieces it needs (e.g. a trimmed `screening.py` +
   `indicators.py`). No imports from `../AgenticGoat`; skills must stay
   copyable into `.claude/skills/`. Cost: duplicated screening code across
   demos. AgenticGoat has no license yet (`pyproject.toml` TODO) — both repos
   are the same author, but pick a license before publishing ported code.
2. **"Real, not scripted" model.** AgenticGoat's `EchoProvider` leaks on a
   keyword pair, which is scripted. Instead each demo uses a deterministic
   **instruction-following stub**: it obeys the last imperative it finds in
   its assembled context (system + retrieved + tool output). The *real*
   mechanism is the non-model part — what reaches the context (retrieval
   ranking, tool registry, schema text, sink rendering, gate decisions).
   README states this explicitly. Optional real-model backend behind
   `<PREFIX>_PROVIDER` / API key env var, as in LLM05.
3. **Ports.** One port per target: `52NN` for LLM demos (LLM01 = 5201 …
   LLM10 = 5210), `53NN` for ASI demos. LLM05 keeps 5101 (existing).
4. **Metric names.** One per demo, `RED targeted / total targeted`, also
   reported overall. Exit codes per template §10 (evaluator 0 clean, 2 exposed).
5. **Shared fictional world.** One company ("Billy" KB assistant from
   AgenticGoat, or LLM05's bot) across all demos so personas and ground truth
   are reusable. Canary token style from `vulnerable_server.py:80`.
6. **Scope per demo**: the minimum template shape (single skill, `web/`
   console optional). Skip the `src/` narrative runner and `presentation/`
   unless a demo needs them.

## 3. LLM series — per-demo design

Columns: AgenticGoat source → scenario → attack (payload in `assets/`) →
metric → mitigation (Act 4) → controls that must stay GREEN.

### LLM01 Prompt Injection — `owasp-llm01-demo`, port 5201
- Source: acts `static_scan` (`acts.py:41`), `runtime_watch` (:94),
  `obfuscation_gauntlet` (:489), `schema_scan` (:610); goat `search_kb`
  (`vulnerable_server.py:258/268`); `protectogw/screening.py` `normalize` :83,
  `_deobfuscate` :243, `screen` :333.
- Scenario: KB assistant answers policy questions via a `search_kb` tool.
- Attack: indirect injection in one KB page's tool return (HTML comment), plus
  obfuscated variants (base64, zero-width, homoglyph) as extra payload files.
- Metric: Injection Success Rate (ISR) — canary or attacker instruction in answer.
- Mitigation: normalize + screen tool returns before they enter context;
  `--scan` flags the poisoned page statically.
- Controls: questions answered from untouched pages.

### LLM02 Sensitive Information Disclosure — `owasp-llm02-demo`, port 5202
- Source: `training_live.py:273` probe, `secrets_vault.py`
  (`assert_not_leaking`), output canary rule.
- Gap to build: AgenticGoat only checks a canary. Add a small customer-record
  store (fake PII) the assistant can read for the *current* user.
- Attack: request that pivots summarisation onto another customer's record /
  the embedded credential.
- Metric: Leak Rate (PII or canary in output).
- Mitigation: output redaction (canary + PII patterns) and per-user record
  scoping; secret moved to vault, never in context.
- Controls: legitimate own-account questions.

### LLM03 Excessive Agency — `owasp-llm03-demo`, port 5203
- Source: `agency_gate_scan` (`acts.py:1005`), `_agency_gate` (:974).
- Scenario: support agent with `lookup_order`, `issue_refund`, `delete_account`.
- Attack: injected instruction in a ticket triggers an unrequested refund /
  irreversible delete.
- Metric: Unauthorized Action Rate (tool calls outside user intent).
- Mitigation: tool allowlist per task + human-confirmation gate on
  irreversible actions.
- Controls: legitimate lookups still execute.

### LLM04 Supply Chain — `owasp-llm04-demo`, port 5204
- Source: `swap_check` (:165, `simulate_swap` goat :208, `_hash` :145),
  `conditional_scan` (:393, goat :432), slopsquat part of `grounding_scan`.
- Scenario: agent loads tools from a third-party MCP-style registry.
- Attack: tool description swapped after approval (rug pull); second variant
  turns hostile on Nth call.
- Metric: Compromised Tool Rate.
- Mitigation: SHA-256 pin of approved tool definitions + multi-call sampling;
  `--scan` diffs against the pin file.
- Gap (discussed, not coded): pickle model files, LoRA adapters, SBOM.

### LLM05 Data and Model Poisoning — exists (`owasp-llm05-demo`)
- Optional extension from `chain_scan` (:334) / `okf_scan` (:248): split
  payload across two docs and YAML-frontmatter payload. Not in first pass.

### LLM06 Unbounded Consumption — `owasp-llm06-demo`, port 5206
- Source: `consumption_guard` (:1341), `_consumption_guard` (:1307).
- Attack: prompts that cause runaway output, a tool-call storm, a recursive
  agent loop. Cost is counted in simulated tokens/$, never real spend.
- Metric: Budget Breach Rate (requests exceeding per-request budget), plus
  total simulated cost.
- Mitigation: per-request token/tool-call budget and loop depth cap.
- Gap to build: per-client quota across requests (denial of wallet).
- Host safety: hard caps so the vulnerable mode cannot actually exhaust the
  machine.

### LLM07 Misinformation — `owasp-llm07-demo`, port 5207
- Source: `grounding_scan` (:1122), `_grounding_check` (:1083).
- Scenario: dev-helper bot recommends packages and cites docs.
- Attack: poisoned context pushes a non-existent (slopsquat) package and an
  untrusted URL as authoritative.
- Metric: Ungrounded Claim Rate.
- Mitigation: approved-registry check + domain allowlist; unverifiable claims
  downgraded to "unverified".

### LLM08 Hidden Context Exposure — `owasp-llm08-demo`, port 5208
- Source: `training_live.py:318` probe and `system_reveal` rule only — **no
  dedicated act; most of this demo is new.**
- Scenario: bot whose system prompt embeds an internal discount code and a
  tool schema.
- Attack: extraction prompts (repeat/translate/summarise your instructions).
- Metric: Prompt Leak Rate (verbatim system-prompt fragments or code in output).
- Mitigation: secret removed from the prompt (design fix) + output filter for
  system-prompt n-grams.

### LLM09 Vector and Embedding Weaknesses — `owasp-llm09-demo`, port 5209
- Source: `retrieval_scope_scan` (:1224), plant at :1190, `_scope_blocks` (:1217).
- Scenario: multi-tenant RAG; tenant A and tenant B share one vector store.
- Attack: tenant B query crafted to rank tenant A's doc first.
- Metric: Cross-Tenant Leak Rate.
- Mitigation: tenant filter enforced at retrieval, not in the prompt.
- Gap (discussed, not coded): embedding inversion.

### LLM10 Improper Output Handling — `owasp-llm10-demo`, port 5210
- Source: `output_handling_scan` (:889), `_SINK_RULES` (:836),
  `agentic/exfil_receiver.py` (127.0.0.1:9091).
- Scenario: model output feeds three real sinks: an in-memory SQLite query,
  an HTML page in `web/`, a markdown renderer that fetches images.
- Attack: poisoned context makes the model emit SQLi, `<script>`, and a
  markdown image pointing at the loopback exfil receiver.
- Metric: Unsafe Sink Rate (sink actually executed/fetched — receiver log is
  the evidence).
- Mitigation: parameterised SQL, HTML escaping, image-domain allowlist.
- Host safety: SQLite `:memory:` only, no shell sink; receiver loopback-only.

## 4. ASI series (wave 2)

Only items with a distinct, real mechanism in AgenticGoat are proposed now:

| Demo | Source | Notes |
|---|---|---|
| ASI01 Agent Goal Hijack | acts 1, 2, 7 | Reuses LLM01 target; multi-step plan diverted mid-task. |
| ASI04 Agentic Supply Chain | acts 3, 6 | Reuses LLM04 target; rug-pull during a running task. |
| ASI06 Memory & Context Poisoning | `agentic/poison_lab.py:145` | Already four-act shaped (PSR 0→100→0); closest port. |
| ASI07 Insecure Inter-Agent Comms | `a2a_scan` (:541) | Needs build-out: spoofed peer, replay, then message signing as mitigation. |

ASI02, 03, 05, 08, 09, 10 reuse LLM probes in AgenticGoat (`labs.json`
`probe.llm_id`) and need new designs (confused deputy / token delegation,
sandboxed execution, multi-agent cascade, approval fatigue, drift + kill
switch). Design them after wave 1.

## 5. Build order

1. **LLM01** — establishes the vendored screening code, the
   instruction-following stub, and the `52NN` conventions. Every later demo
   copies from it.
2. **LLM10, LLM03, LLM09** — strongest AgenticGoat sources, very visual.
3. **LLM04, LLM06, LLM07** — sources exist; modest build-out.
4. **LLM02, LLM08** — most new code.
5. Update `demos/agenticgoat-mock` lesson table to link each lesson to its
   full demo.
6. Wave 2: ASI06, ASI01, ASI04, ASI07.

Each demo is done when the template §11 checklist passes and its
`tests/` assert: baseline all GREEN, attack raises targeted rate, overall <
targeted, detector flags the payload, mitigation returns rate to 0.

## 6. Open questions

1. Is the 2026 LLM numbering confirmed, or should demo slugs avoid the number?
2. Vendor screening code per demo (recommended) vs. one shared `demos/_lib`?
3. Which shared persona/company for all demos?
4. License for ported AgenticGoat code.
5. Web console (`web/`) for every demo, or CLI only with web for a few?
