# ASI01 Risk Reference — Agent Goal Hijack

Domain knowledge, loaded on demand. Agent goal hijack happens when content an
agent reads during a task changes **what the task is**: steps are added,
replaced or reordered, or the end goal moves, while the operator's request
stays the same. It is the agentic form of prompt injection. In a single answer
(LLM01) the damage is one wrong reply. In a multi-step agent, the damage is
every action the diverted plan takes before anyone looks.

## Research foundations

- **OWASP Top 10 for Agentic Applications, ASI01 Agent Goal Hijack** — the
  risk entry this demo targets.
- **Perez & Ribeiro (2022), "Ignore Previous Prompt"** — names *goal
  hijacking*: input that redirects a model away from its original task.
- **Greshake et al. (2023), "Not what you've signed up for"** — indirect
  prompt injection: retrieved content blurs the line between data and
  instructions, so planted text can be followed as if it were the user's
  instruction, including in tool-using agents.
- **Zhan et al. (2024), "InjecAgent"** and **Debenedetti et al. (2024),
  "AgentDojo"** — benchmarks that measure whether injected tool output makes an
  agent take actions its user did not ask for.
- **Debenedetti et al. (2025), "Defeating Prompt Injections by Design"
  (CaMeL)** — derives the control flow from the trusted user query before any
  untrusted data is read, so that data cannot change which actions run. Plan
  pinning in this demo is a minimal version of that idea.

## Scenarios & examples

| ID | Title | Description | Focus |
|----|-------|-------------|-------|
| G-1 | Mid-task plan revision via tool output | Text read by step 1 adds or replaces later steps of a fixed task. | **DEMO TARGET** |
| G-2 | Redirected deliverable | The task completes, but its output goes to a destination the operator did not pick. | **DEMO TARGET** (the replaced `post_report`) |
| G-3 | Goal substitution | The agent abandons the task and pursues a different objective. | — |
| G-4 | Slow drift over many sessions | Small changes accumulate through memory (see ASI06). | — |
| G-5 | Direct goal hijack | The operator, or someone at the operator's console, rewrites the goal. | — |

## How the demo maps to the attack surfaces

- **G-1** is `POST /tickets/comment` (unauthenticated) plus `read_tickets`,
  which returns comments into the planning context. In vulnerable mode
  `Lab.run` re-plans from every message after each step, and the executor runs
  whatever step comes next.
- **G-2** is the `replace post_report` line: the four-step shape still
  completes, so a log that only counts steps looks normal. Comparing each
  executed `tool:target` with the approved plan is what exposes it.
- **Scope decides the blast radius.** Only runs whose step 1 reads `T-3002`
  (the billing queue and the escalated view) are diverted. The shipping and
  facilities runs never read it and stay GREEN.

## Mitigation roadmap

| Vulnerability | Hardening strategy |
|---------------|--------------------|
| Plan revised mid-run, unchecked | **Plan pinning.** Fix the plan from the operator's request before any tool data is read; hold off-plan steps until the operator re-approves that exact `tool:target`. Implemented: `plan_gate` and hardened mode in `vulnerable_app.py`. |
| Tool output in the planning context | **Tool output as data.** Keep tool results in their own role and never plan from it. Implemented: `tool_output_as_data` in hardened mode. |
| Unauthenticated content the agent reads | Authenticate and attribute comments; separate customer-supplied text from staff fields. |
| Deliverable sent to an unexpected destination | Allowlist destinations per task (internal channels only for the weekly report). See the LLM03 demo's per-task tool allowlist. |
| Silent deviation | Log the approved plan beside the executed steps and alert on any difference. Implemented as the KPI in `scripts/evaluate_kpi.py`. |

Further hardening discussed, not coded: screening tool output for directives
(see the LLM01 demo), a separate planner that never sees untrusted data (the
dual-model pattern), and data-flow tracking so untrusted values cannot become
step arguments.
