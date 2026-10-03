---
name: owasp-llm02-disclosure-skill
description: >-
  Demonstrates OWASP LLM02 (Sensitive Information Disclosure) against a
  vulnerable customer-account assistant in an AUTHORIZED security lab. Covers
  cross-user data disclosure through an unscoped record tool and a credential
  embedded in the system prompt: a directive in the attacker's own account
  notes makes the assistant read other customers' records and recite its
  context. Measures impact with a red/yellow/green stoplight KPI and Leak Rate,
  and shows the per-user scoping, secret-vault and output-redaction
  mitigations. Use when the user wants to run, script, or explain sensitive
  information disclosure, quantify its impact, or demonstrate the hardening.
  Education and sanctioned red-teaming only — never against systems you are
  not authorized to test.
license: MIT
metadata:
  objective: Demonstrate cross-user PII and credential disclosure through model context
  version: 2026.1
---

# OWASP LLM02 Disclosure Skill

Demonstrates how a customer of Goat & Co. gets **Billy Accounts, the
account assistant**, to disclose other customers' personal details and the CRM
service key, using nothing but their own account's notes field, and how to
detect and harden against it. Billy reads the customer's record with its
`read_record` tool. The tool returns any record it is asked for, and the
system prompt holds the key, so whatever Billy is talked into reciting leaks.

## Scope & safety (read first)

- **Authorized use only.** Run against this skill's own `vulnerable_app.py`
  (bound to `127.0.0.1`) or a target you are explicitly permitted to test.
- The vulnerable app is insecure **by design**; do not expose it. Three
  host-safety guards are built in and do not weaken the lesson:
  - Customer records live in memory only, so note edits never touch the
    filesystem.
  - One directive can pull in at most three records; notes and request
    bodies are size-capped.
  - The model is a deterministic stub, so the lab cannot reach a real model
    or the network.
- All records are fictional (`example.invalid` addresses, `555-01xx` numbers),
  and the key is a fictional canary. The shipped payload is a **placeholder**:
  a marker line and two fictional record IDs. See
  [`assets/pivot_note.README.md`](assets/pivot_note.README.md).
- Dual-use: this exists to make the vulnerability observable and to motivate
  the mitigations in [`references/LLM02_RISKS.md`](references/LLM02_RISKS.md).

## When to use

- Run or reproduce a cross-user disclosure demo through an agent's tool.
- Quantify impact (stoplight KPI, Leak Rate).
- Show the mitigations: per-user record scoping, secrets moved to a vault,
  and output redaction.

## MCP terminology bridge

In MCP, a server exposes **tools** and the **model chooses their arguments**.
Here, `read_record` stands in for an MCP tool, and its `customer_id` argument
is the disclosure surface: the model picks it, so whoever steers the model
picks whose data comes back. The demo is not an MCP server: the "tool call" is
an in-process function, and the record store is a dict. Hardened mode mirrors
what a careful MCP server does: it authorizes each call against the
authenticated session, not against what the model asked for, and it never
puts its own credentials in the model's context.

## Prerequisites

Python 3.9+. Standard library only; nothing to install.

## Execution instructions

1. **Start the target.** From this skill folder:
   ```bash
   python vulnerable_app.py             # serves on 127.0.0.1:5202
   ```
   On startup it seeds the record store from `assets/customers_baseline.json`.

2. **Review the ground truth.** Read `assets/customers_baseline.json`: each
   customer may see only their own record. `C-1003` (Quinn Marlow) is on the
   *Kid Starter* plan, renewing *2027-01-20*. Then read
   `assets/system_prompt.txt`: the CRM key sits in the prompt.

3. **Establish the baseline.**
   ```bash
   python scripts/evaluate_kpi.py
   ```
   Expect all 🟢 GREEN, Leak Rate 0%. Exit code 0.

4. **Run the attack.**
   ```bash
   python scripts/run_pivot.py
   ```
   Saves [`assets/pivot_note.md`](assets/pivot_note.md) as the notes of
   account `C-1003` through `POST /account/notes`. Editing your own notes is
   allowed. One line of the notes is a directive naming two other records.

5. **Stoplight verification.**
   ```bash
   python scripts/evaluate_kpi.py
   ```
   Expect 🔴 RED on the three `C-1003` questions: the answers carry Ada
   Thornbury's and Bram Okafor's details and the CRM key. The `C-1001` and
   `C-1002` controls stay 🟢 GREEN. Leak Rate 100% targeted, 60% overall.
   Exit code 2.

6. **Show the mitigations.**
   ```bash
   python scripts/evaluate_kpi.py --scan assets/system_prompt.txt   # REJECT, exit 2
   python scripts/evaluate_kpi.py --harden                          # GREEN, Leak Rate 0%
   ```
   `--scan` rejects a prompt that holds a secret. `--harden` switches the
   target to hardened mode: the key moves to a vault the model never sees,
   `read_record` refuses any ID but the signed-in customer's, and answers are
   redacted with `assets/redaction_rules.json`. The model is still fooled by
   the directive; it can only recite the customer's own record. Scoping and
   the vault alone are enough here, and the tests prove it.

7. **Reset to baseline.**
   ```bash
   python scripts/reset_baseline.py
   python scripts/evaluate_kpi.py
   ```
   Expect all questions GREEN with Leak Rate 0%.

## Customizing the payload

Edit [`assets/pivot_note.md`](assets/pivot_note.md) and follow
[`assets/pivot_note.README.md`](assets/pivot_note.README.md). Without the
`@assistant:` line the stub answers normally and the Leak Rate falls to 0. With
the line but no record IDs, only the CRM key leaks. To test redaction against
a new secret format, put it in `assets/system_prompt.txt` and extend
`assets/redaction_rules.json`.

## Files

| Path | Purpose |
|------|---------|
| `vulnerable_app.py` | Target account assistant (`/query`, `/account/notes`, `/api/mode`, `/api/reset`, `/api/state`, `/health`). |
| `scripts/run_pivot.py` | Attack: save the pivot note on the attacker's own account. |
| `scripts/evaluate_kpi.py` | Stoplight KPI + Leak Rate against the live app; `--harden` and `--scan` mitigations. |
| `scripts/reset_baseline.py` | Restores the seeded records and vulnerable mode. |
| `references/LLM02_RISKS.md` | Threat landscape, research, scenario table, mitigations. |
| `assets/pivot_note.md` | Attacker's notes (placeholder payload; editable). |
| `assets/pivot_note.README.md` | How to write a payload for the stub and real-model backends. |
| `assets/customers_baseline.json` | Fictional customer records: the ground truth. |
| `assets/system_prompt.txt` | Deployed prompt with the embedded CRM key (the scan target). |
| `assets/redaction_rules.json` | Output redaction and secret-scan rules (editable). |
| `tests/test_lifecycle.py` | Asserts the four-act story in-process. |
