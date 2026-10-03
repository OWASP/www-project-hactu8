# LLM06 Risk Reference — Unbounded Consumption

Domain knowledge, loaded on demand. Unbounded consumption happens when an
application lets a request use far more resources than it should: input and
output tokens, tool calls, agent steps, compute or money. It is a cost problem
first and an availability problem second. The bill arrives before the outage
does. In this repo's 2026 numbering it is LLM06; the OWASP 2025 list calls it
LLM10.

## Research foundations

- **Shumailov et al. (2021), "Sponge Examples: Energy-Latency Attacks on
  Neural Networks"** — crafted inputs that maximise a model's energy use and
  latency. Resource cost is an attack surface, not only a capacity question.
- **OWASP Top 10 for LLM Applications, LLM10:2025 Unbounded Consumption** —
  the risk entry: variable-length input flood, denial of wallet, continuous
  input overflow, resource-intensive queries, model extraction through the
  API, and the prevention guidance (input validation, rate limiting, resource
  allocation management, timeouts and throttling, monitoring).
- **MITRE ATLAS AML.T0034, Cost Harvesting** — adversaries send useless queries
  or computationally expensive inputs to an AI service to raise its operator's
  costs.

## Scenarios & examples

| ID | Title | Description | Focus |
|----|-------|-------------|-------|
| C-1 | Runaway output | Context makes the model generate an answer many times longer than needed. | **DEMO TARGET** (`runaway_output.md`) |
| C-2 | Tool-call storm | One step requests many tool calls, and each result asks for more. | **DEMO TARGET** (`tool_storm.md`) |
| C-3 | Recursive agent loop | A tool result makes the agent call the same tool again, indefinitely; context re-sent each step. | **DEMO TARGET** (`recursive_loop.md`) |
| C-4 | Denial of wallet | Many requests, each within budget, from one client. | **DEMO TARGET** (`--flood`, per-client quota) |
| C-5 | Input flood | A hostile megabyte of input. | Partly: `max_input_tokens` caps cumulative input per request |
| C-6 | Model extraction via API | High-volume querying to clone a model. | — |
| C-7 | Sponge inputs | Inputs that maximise compute per token. | — |

## How the demo maps to the attack surfaces

- **C-1 to C-3** are `POST /kb/page`, which accepts unauthenticated edits,
  combined with `Lab.query` in vulnerable mode. The agent loop meters every
  step against `assets/budget.json` but enforces nothing; only the
  host-safety caps (`HARD_MAX_*`) stop it.
- **C-4** is `Lab.query` with no per-client ledger check. Each flood request is
  cheap, so a per-request budget never fires.
- **Retrieval decides the blast radius.** Only questions that retrieve an
  edited page are affected. That is why the holiday and VPN controls stay
  GREEN. Every RED answer still reads correctly: the damage is in the bill.

## Mitigation roadmap

| Vulnerability | Hardening strategy |
|---------------|--------------------|
| No per-request budget | **Meter and enforce** input tokens, output tokens, tool calls and agent steps per request. Implemented: hardened mode in `vulnerable_app.py`, caps in `assets/budget.json`, check ported from AgenticGoat `acts._consumption_guard`. |
| No loop depth cap | **Cap agent steps**, and on the last step disable tools so the model must answer. Implemented: `max_agent_steps` with `allow_tools=False`. |
| Unbounded generation | **Output-token cap** (the provider's `max_tokens`). Implemented: answer truncated at the remaining output budget. |
| No per-client quota | **Per-client token quota** across requests; refuse with HTTP 429 once spent. Implemented: `per_client.max_tokens`. |
| Agent-control content in data | **Pre-publication lint** for directive lines and their amplification. Implemented: `scan_page`, `evaluate_kpi.py --scan`. |
| No early warning | **Outlier alerts** when a request runs at 80% or more of a cap. Implemented: `outliers` in every `/query` result. |

Further hardening discussed, not coded: wall-clock timeouts, rate limiting
per second as well as per quota, fleet-level spend ceilings with automatic
shutoff, billing alerts, cost-aware model routing, and authenticated wiki
edits (see LLM01).
