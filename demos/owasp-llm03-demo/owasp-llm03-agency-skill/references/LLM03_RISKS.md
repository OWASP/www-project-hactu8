# LLM03 Risk Reference — Excessive Agency

Domain knowledge, loaded on demand. Excessive agency is the damage an
LLM-based system can do when it acts on unexpected, ambiguous or manipulated
model output. OWASP names three root causes: **excessive functionality** (tools
the task does not need), **excessive permissions** (tools that can do more than
the task needs), and **excessive autonomy** (high-impact actions with no human
check). Prompt injection is a common trigger; excessive agency decides the
blast radius. (This repo uses the 2026 numbering; the 2025 list calls this
entry LLM06.)

## Research foundations

- **Greshake et al. (2023), "Not what you've signed up for"** — shows indirect
  prompt injection against LLM-integrated applications, including ones that
  can call tools, so injected content turns into actions.
- **Ruan et al. (2024), "Identifying the Risks of LM Agents with an
  LM-Emulated Sandbox" (ToolEmu)** — evaluates tool-using agents in an emulated
  sandbox and finds risky actions taken without user confirmation.
- **Zhan et al. (2024), "InjecAgent"** — a benchmark for indirect prompt
  injection in tool-integrated agents, where the attacker's goal is a harmful
  tool call.
- **Debenedetti et al. (2024), "AgentDojo"** — a dynamic environment for
  measuring prompt-injection attacks and defenses on agents that carry out
  tasks with tools.
- **OWASP Top 10 for LLM Applications, Excessive Agency** — the risk entry,
  with its functionality / permissions / autonomy breakdown and prevention
  guidance.

## Scenarios & examples

| ID | Title | Description | Focus |
|----|-------|-------------|-------|
| A-1 | Excessive functionality | Every task can call every tool, so a ticket summary can issue a refund. | **DEMO TARGET** |
| A-2 | Excessive autonomy | Irreversible actions (refund, delete) run with no human confirmation. | **DEMO TARGET** |
| A-3 | Injection as trigger | Untrusted content (a customer's ticket note) supplies the tool calls. | **DEMO TARGET** (trigger; see LLM01) |
| A-4 | Excessive permissions | A tool's credential can reach more than the task needs (e.g. any customer's account). | Partly: `delete_account` accepts any customer |
| A-5 | Claimed authority | The model asserts the action was "already approved". | Partly: the gate ignores arguments; see the payload README |
| A-6 | Open-ended tools | Shell, generic HTTP or SQL tools whose scope cannot be bounded. | — |

## How the demo maps to the attack surfaces

- **A-3** is `POST /tickets/note`, which accepts a note for any ticket without
  authentication. `read_ticket` returns the note into the model's context.
- **A-1 and A-2** are `Lab.run` in vulnerable mode: the dispatcher executes
  every call the model requests, with no task scope and no confirmation step.
- **Retrieval decides the blast radius.** Only requests that read `T-1001` are
  affected. That is why the order lookup, the other ticket and the confirmed
  refund controls stay GREEN.

## Mitigation roadmap

| Vulnerability | Hardening strategy |
|---------------|--------------------|
| Every tool available to every task | **Per-task tool allowlist** (least functionality). Implemented: `agency_gate` rule 1 + `assets/task_policy.json`. |
| Irreversible actions run unattended | **Human confirmation** for each irreversible `tool:target`, supplied by the operator, never by the model. Implemented: `agency_gate` rule 2. |
| Authorization decided by model output | Keep the gate in code, outside the model; key it on session facts and never on request prose. Implemented: the gate reads only the tool and target. |
| Untrusted content reaches the planner | Channel separation and screening of tool output (see LLM01). Not coded here; the gate holds without it. |
| Tool credentials broader than the task | Scope downstream credentials to the current customer; complete mediation in the downstream system. Discussed, not coded. |
| No record of what the agent did | Log every requested and executed call. Implemented: the action log (`GET /api/actions`). |

Further hardening discussed, not coded: per-user downstream authorization,
rate limits on irreversible tools, and anomaly alerts on blocked-call spikes.
