---
name: owasp-llm10-sink-skill
description: >-
  Demonstrates OWASP LLM10 (Improper Output Handling) against a vulnerable
  ticket-summary assistant in an AUTHORIZED security lab. Covers model output
  that reaches downstream sinks unencoded or unparameterised: an HTML status
  page, a markdown renderer that passes inline HTML through, and a
  string-built SQLite query. Measures impact with a red/yellow/green stoplight
  KPI and Unsafe Sink Rate, and shows the output-encoding and
  parameterised-query mitigations. Use when the user wants to run, script, or
  explain improper output handling, quantify its impact, or demonstrate the
  hardening. Education and sanctioned red-teaming only — never against systems
  you are not authorized to test.
license: MIT
metadata:
  objective: Demonstrate model output reaching downstream sinks as code
  version: 2026.1
---

# OWASP LLM10 Sink Skill

Demonstrates how one ticket note makes **Billy, Goat & Co.'s ticket-summary
assistant** emit text that its own application then mishandles, and how to
detect and harden against it. The note reaches the model through the ticket
store. The model's summary goes to an HTML status page, a markdown digest and
a SQL audit log, and in vulnerable mode each sink treats it as code.

## Scope & safety (read first)

- **Authorized use only.** Run against this skill's own `vulnerable_app.py`
  (bound to `127.0.0.1`) or a target you are explicitly permitted to test.
- The vulnerable app is insecure **by design**; do not expose it. Host-safety
  guards are built in and do not weaken the lesson:
  - SQLite is `:memory:` only and runs one statement per `execute`.
  - Notes and log rows are capped and live in memory only.
  - Served HTML carries a `default-src 'none'` Content-Security-Policy.
  - Nothing fetches images or URLs, runs a shell, or writes files.
- The shipped payload is a **placeholder**: a marker line, a harmless `<mark>`
  tag, an apostrophe and a fictional canary. See
  [`assets/poisoned_note.README.md`](assets/poisoned_note.README.md).
- Dual-use: this exists to make the vulnerability observable and to motivate
  the mitigations in [`references/LLM10_RISKS.md`](references/LLM10_RISKS.md).

## When to use

- Run or reproduce an improper-output-handling demo across HTML, markdown and
  SQL sinks.
- Quantify impact (stoplight KPI, Unsafe Sink Rate).
- Show the mitigations: contextual output encoding and parameterised queries,
  with an output-sink tripwire as the detector.

## MCP terminology bridge

In MCP, tool **results** flow into the model's context, and the model's
**output** flows back to the client application. LLM10 is about that second
hop. Here the ticket store stands in for a tool, and the three sinks stand in
for whatever the client does with a completion. The demo is not an MCP server
or client. Hardened mode is what a careful client should do with any
completion: treat it as untrusted user input at every sink.

## Prerequisites

Python 3.9+. Standard library only; nothing to install.

## Execution instructions

1. **Start the target.** From this skill folder:
   ```bash
   python vulnerable_app.py             # serves on 127.0.0.1:5210
   ```
   On startup it seeds tickets from `assets/tickets_baseline.json` and creates
   an empty in-memory audit log.

2. **Review the ground truth.** Read `assets/tickets_baseline.json`: the
   Ridgeview *printer queue* was restored and the Harbor *badge reader* was
   replaced. Those are the summaries every sink should show and store.

3. **Establish the baseline.**
   ```bash
   python scripts/evaluate_kpi.py
   ```
   Expect all 🟢 GREEN, USR 0%. Exit code 0.

4. **Run the attack.**
   ```bash
   python scripts/run_sink_poison.py
   ```
   Files [`assets/poisoned_note.md`](assets/poisoned_note.md) on the
   `ridgeview` account through the unauthenticated `POST /tickets/note`. No
   sink is touched.

5. **Stoplight verification.**
   ```bash
   python scripts/evaluate_kpi.py
   ```
   Expect 🔴 RED on the three Ridgeview sinks (raw `<mark>` in the status page
   and digest, a SQLite syntax error in the audit log), and the two Harbor
   controls still 🟢 GREEN. USR 100% targeted, 60% overall. Exit code 2.

6. **Show the mitigations.**
   ```bash
   python scripts/evaluate_kpi.py --scan assets/poisoned_note.md   # REJECT, exit 2
   python scripts/evaluate_kpi.py --harden                         # GREEN, USR 0%
   ```
   `--scan` screens the note with `assets/sink_rules.json` before it is filed.
   `--harden` switches the target to hardened mode: `html.escape` before both
   HTML sinks and `?` placeholders in SQL. The model's output is unchanged; it
   now arrives as data. The tests prove the sink fixes work even with an empty
   tripwire ruleset.

7. **Reset to baseline.**
   ```bash
   python scripts/reset_baseline.py
   python scripts/evaluate_kpi.py
   ```
   Expect all items GREEN with USR 0%.

## Customizing the payload

Edit [`assets/poisoned_note.md`](assets/poisoned_note.md) and follow
[`assets/poisoned_note.README.md`](assets/poisoned_note.README.md). Keep the
`@assistant:` marker; without it the model summarises the first note and the
sinks receive harmless text, so the USR falls to 0. To test the tripwire,
extend `assets/sink_rules.json`.

## Files

| Path | Purpose |
|------|---------|
| `vulnerable_app.py` | Target assistant and sinks (`/render`, `/status/<account>`, `/tickets/note`, `/tickets/<account>`, `/api/mode`, `/api/reset`, `/api/state`, `/health`). |
| `scripts/run_sink_poison.py` | Attack: file one poisoned ticket note. |
| `scripts/evaluate_kpi.py` | Stoplight KPI + USR against the live app; `--harden` and `--scan` mitigations. |
| `scripts/reset_baseline.py` | Restores the seeded tickets, an empty log, and vulnerable mode. |
| `references/LLM10_RISKS.md` | Threat landscape, research, scenario table, mitigations. |
| `assets/poisoned_note.md` | Adversarial note (placeholder payload; editable). |
| `assets/poisoned_note.README.md` | How to write a payload for the stub and real-model backends. |
| `assets/tickets_baseline.json` | Untampered tickets: the ground truth. |
| `assets/sink_rules.json` | Output-sink tripwire rules (editable). |
| `tests/test_lifecycle.py` | Asserts the four-act story in-process. |
