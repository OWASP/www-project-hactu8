# ASI02 Risk Reference — Tool Misuse & Exploitation

Domain knowledge, loaded on demand. Tool misuse is the damage an agent does
with tools it is **legitimately allowed to use**, by calling them with unsafe
parameters, in unsafe sequences or at unsafe volume. No new privilege is
gained and no forbidden tool is reached; the agent's own granted capability is
pointed somewhere it should not go. That is the line between this entry and
LLM03 Excessive Agency, where the tool itself should not have been available
to the task. Prompt injection is a common trigger; the parameters the tool
boundary accepts decide the blast radius.

## Research foundations

- **OWASP Top 10 for Agentic Applications, ASI02 Tool Misuse & Exploitation**
  — the risk entry. The list is new; this reference cites it by name only.
- **Greshake et al. (2023), "Not what you've signed up for"** — shows indirect
  prompt injection against LLM-integrated applications, including ones that
  call tools, so injected content can steer what a tool is asked to do.
- **Zhan et al. (2024), "InjecAgent"** — a benchmark for indirect prompt
  injection in tool-integrated agents, including attacks whose goal is data
  exfiltration through the agent's own tools.
- **Debenedetti et al. (2024), "AgentDojo"** — a dynamic environment for
  measuring prompt-injection attacks and defenses on agents that carry out
  tasks with tools.

## Scenarios & examples

| ID | Title | Description | Focus |
|----|-------|-------------|-------|
| T-1 | Parameter pollution | A permitted tool is called with an attacker-chosen parameter (an off-list export destination). | **DEMO TARGET** |
| T-2 | Over-broad query | A permitted read tool is called with a row limit and filter far beyond the task (whole-ledger pull). | **DEMO TARGET** |
| T-3 | Injection as trigger | Untrusted content (a requester's note) supplies the parameters. | **DEMO TARGET** (trigger; see LLM01) |
| T-4 | Call-volume abuse | A permitted tool is called repeatedly in one run (duplicate exports). | Partly: the per-run budget, tested with a variant note |
| T-5 | Tool-chain manipulation | Outputs of one permitted tool are steered into another (query feeds export). | Partly: the query-then-export chain is the exfiltration path |
| T-6 | Poisoned tool descriptors | Instructions hidden in a tool's schema or description text (AgenticGoat `schema_scan`). | — (see LLM04 / ASI04) |

## How the demo maps to the attack surfaces

- **T-3** is `POST /requests/note`, which accepts a note for any request
  without authentication. `read_request` returns the note into the model's
  context.
- **T-1 and T-2** are `Lab.run` in vulnerable mode: the dispatcher executes
  every call to a granted tool with whatever `filter`, `limit`, `rows` and
  `destination` the model supplies. The tools are identical in both modes.
- **Retrieval decides the blast radius.** Only runs that read `RQ-3001` are
  affected. That is why the `RQ-3002` and `RQ-3003` controls stay GREEN.
- **Scored from the action log.** The evaluator compares each run's executed
  calls, with their parameters, against the approved request record. The
  answer text is never scored.

## Mitigation roadmap

| Vulnerability | Hardening strategy |
|---------------|--------------------|
| Any destination accepted | **Destination allowlist** at the tool boundary. Implemented: `tool_gate` + `export_report.destinations` in `assets/tool_policy.json`. |
| Any row limit accepted | **Row caps** on query and export. Implemented: `query_ledger.max_limit`, `export_report.max_rows`. |
| Unlimited repeat calls | **Per-run call budget** per tool. Implemented: `max_calls`, counted on executed calls. |
| Policy expressed in the prompt | Enforce in code at the tool boundary, keyed on the call's real parameters, never on model prose. Implemented: the gate never reads the note or the answer. |
| Untrusted content reaches the planner | Channel separation and screening of tool output (see LLM01). Not coded here; the gate holds without it. |
| No record of what the agent did | Log every requested, blocked and executed call with parameters. Implemented: the action log (`GET /api/actions`) and outbox (`GET /api/outbox`). |

Further hardening discussed, not coded: binding parameters to the approved
record (the agent cannot change a request's destination at all), schema
validation of every argument, per-tool rate limits across runs, and alerts on
blocked-call spikes.
