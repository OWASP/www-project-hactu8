---
name: owasp-llm06-consumption-skill
description: >-
  Demonstrates OWASP LLM06 (Unbounded Consumption) against a vulnerable
  agentic knowledge-base assistant in an AUTHORIZED security lab. Covers
  runaway output, a tool-call storm, a recursive agent loop and a
  denial-of-wallet flood, all driven by edited wiki pages and all costed in
  simulated tokens and dollars. Measures impact with a red/yellow/green
  stoplight KPI and Budget Breach Rate, and shows the per-request budget,
  loop depth cap and per-client quota mitigations. Use when the user wants to
  run, script, or explain unbounded consumption or denial of wallet in an
  agent loop, quantify its cost, or demonstrate the hardening. Education and
  sanctioned red-teaming only — never against systems you are not authorized
  to test.
license: MIT
metadata:
  objective: Demonstrate unbounded consumption in an agent loop
  version: 2026.1
---

# OWASP LLM06 Consumption Skill

Demonstrates how an adversary runs up the bill of **Billy, Goat & Co.'s
agentic knowledge-base assistant** by editing three wiki pages, and how to
detect and bound it. Billy's answers still look right. The cost of producing
them grows by more than 500 times, because nothing in the agent loop enforces the
budget it meters.

## Scope & safety (read first)

- **Authorized use only.** Run against this skill's own `vulnerable_app.py`
  (bound to `127.0.0.1`) or a target you are explicitly permitted to test.
- The vulnerable app is insecure **by design**; do not expose it. Host-safety
  guards are built in and do not weaken the lesson:
  - All cost is **simulated** token and dollar accounting. The model is a
    deterministic stub by default, so nothing is billed and the lab cannot
    reach the network unless you opt into a real-model backend.
  - Even vulnerable mode stops at 50 agent steps, 200 tool calls and 64,000
    output characters, and the stub clamps its own repeat and fan-out counts.
    Real CPU and memory use stays trivial.
  - Wiki state and the spend ledger live in memory only.
  - The server rejects foreign `Host` headers (DNS rebinding) and non-JSON
    POSTs (cross-site forms).
- The shipped payloads are **placeholders**: one marker line plus a fictional
  canary each. See the `assets/*.README.md` files.
- Dual-use: this exists to make the vulnerability observable and to motivate
  the mitigations in [`references/LLM06_RISKS.md`](references/LLM06_RISKS.md).

## When to use

- Run or reproduce runaway output, a tool-call storm, a recursive agent loop
  or a denial-of-wallet flood.
- Quantify impact (stoplight KPI, Budget Breach Rate, simulated spend).
- Show the mitigations: per-request budget, loop depth cap, output-token cap,
  per-client quota, and a pre-publication lint.

## MCP terminology bridge

In MCP, the client runs the loop: it sends the model's tool calls to servers
and places the results back in context. Here, `search_kb` stands in for an MCP
tool and `Lab.query` for the client's loop. The demo is not an MCP server: the
tool is an in-process function and the wiki is a dict. Hardened mode is what a
careful MCP client should do: meter every step, and stop at a budget the
model cannot talk its way past.

## Prerequisites

Python 3.9+. Standard library only; nothing to install.

Optional real model: set `LLM06_BACKEND` to `ollama`, `llamacpp` or
`openrouter` (which needs `OPENROUTER_API_KEY`), and `LLM06_MODEL` to the
model name, before starting the target, or pick them in the console's
backend bar. The default `echo` (alias `stub`) needs no network. The
OpenRouter key is read from the environment only, never from the console.
With `openrouter`, prompts and payloads leave the machine, and every agent
step is a billed call (capped by `LAB_MAX_CALLS`).

## Execution instructions

1. **Start the target.** From this skill folder:
   ```bash
   python vulnerable_app.py             # serves on 127.0.0.1:5206
   ```
   On startup it seeds the wiki from `assets/kb_baseline.json` and loads the
   budget from `assets/budget.json`. To drive the same four acts from a
   browser, open <http://127.0.0.1:5206/>.

2. **Review the ground truth and the budget.** Read `assets/budget.json`:
   each request may use 6,000 input tokens, 400 output tokens, 8 tool calls and
   4 agent steps. A normal question costs about 175 tokens, 1 call, 2 steps.

3. **Establish the baseline.**
   ```bash
   python scripts/evaluate_kpi.py
   ```
   Expect all 🟢 GREEN, BBR 0%, about $0.005 simulated. Exit code 0.

4. **Run the attack.**
   ```bash
   python scripts/run_consumption.py
   ```
   Writes `runaway_output.md` over `expenses`, `tool_storm.md` over `payroll`
   and `recursive_loop.md` over `travel`, through the unauthenticated
   `POST /kb/page`. Each page keeps its real text, so it still ranks first.

5. **Stoplight verification.**
   ```bash
   python scripts/evaluate_kpi.py
   ```
   Expect 🔴 RED on the expense, travel and payroll questions (about 12,800,
   92,400 and 78,800 tokens), and the holiday and VPN controls still 🟢 GREEN.
   BBR 100% targeted, 60% overall, about $0.72 simulated. Exit code 2.

6. **Show the mitigations.**
   ```bash
   python scripts/evaluate_kpi.py --scan assets/recursive_loop.md   # REJECT, exit 2
   python scripts/evaluate_kpi.py --harden                          # GREEN, BBR 0%
   python scripts/run_consumption.py --flood 40                     # quota refuses the rest
   ```
   `--scan` lints a page for directives and the amplification each would
   cause. `--harden` switches the target to hardened mode: the loop enforces
   the per-request budget and disables tools on the last allowed step, so the
   model answers from what it already has. The flood shows the per-client
   quota: after about 10,000 tokens, the `attacker` client gets HTTP 429.

7. **Reset to baseline.**
   ```bash
   python scripts/reset_baseline.py
   python scripts/evaluate_kpi.py
   ```
   Expect all questions GREEN with BBR 0%.

## Customizing the payload

Edit the payload files in `assets/` and follow their READMEs. Keep the real
lines so each page still ranks first. To move the threshold, edit the caps in
`assets/budget.json`; the same file drives the KPI, the hardened loop and the
lint.

## Files

| Path | Purpose |
|------|---------|
| `vulnerable_app.py` | Target agentic KB assistant (`/query`, `/kb/page`, `/health`) plus the console API (`/api/meta`, `/api/state`, `/api/reset`, `/api/attack`, `/api/evaluate`, `/api/scan`, `/api/mode`). |
| `providers.py` | Optional real-model backends: Ollama, llama.cpp, OpenRouter. Shared and copied unchanged. |
| `web/` | Shared HACTU8 lab console, served at `/`. |
| `scripts/run_consumption.py` | Attack: overwrite three wiki pages; `--flood N` for denial of wallet. |
| `scripts/evaluate_kpi.py` | Stoplight KPI + BBR + simulated spend against the live app; `--harden` and `--scan` mitigations. |
| `scripts/reset_baseline.py` | Restores the seeded wiki, clears the spend ledger, vulnerable mode. |
| `references/LLM06_RISKS.md` | Threat landscape, research, scenario table, mitigations. |
| `assets/runaway_output.md` | Runaway-output page (placeholder payload; editable). |
| `assets/tool_storm.md` | Tool-storm page (placeholder payload; editable). |
| `assets/recursive_loop.md` | Recursive-loop page (placeholder payload; editable). |
| `assets/*.README.md` | How to write each payload for the echo and real-model backends. |
| `assets/kb_baseline.json` | Untampered wiki: the ground truth. |
| `assets/budget.json` | Per-request caps, per-client quota, simulated prices, lint rules (editable). |
| `tests/test_lifecycle.py` | Asserts the four-act story in-process. |
