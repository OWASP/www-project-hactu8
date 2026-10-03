---
name: owasp-llm08-leak-skill
description: >-
  Demonstrates OWASP LLM08 (Hidden Context Exposure, also known as system
  prompt leakage) against a vulnerable store assistant in an AUTHORIZED
  security lab. A system prompt that embeds a staff discount code and an
  internal tool schema is quoted back to a customer who saves an extraction
  request as their reply preference. Measures impact with a red/yellow/green
  stoplight KPI and Prompt Leak Rate, and shows the design fix (no secret in
  the prompt), a pre-release prompt check, and an output filter for
  system-prompt n-grams. Use when the user wants to run, script, or explain
  system-prompt leakage, quantify it, or demonstrate the hardening. Education
  and sanctioned red-teaming only — never against systems you are not
  authorized to test.
license: MIT
metadata:
  objective: Demonstrate hidden-context exposure from a secret-bearing system prompt
  version: 2026.1
---

# OWASP LLM08 Leak Skill

Demonstrates how a customer extracts the system prompt of **Billy Shop,
Goat & Co.'s store assistant**, including the staff discount code it embeds,
and how to detect and harden against it. The attacker needs no privilege.
They save an extraction request as their own reply preference, and every reply
Billy gives them then quotes its hidden context.

## Scope & safety (read first)

- **Authorized use only.** Run against this skill's own `vulnerable_app.py`
  (bound to `127.0.0.1`) or a target you are explicitly permitted to test.
- The vulnerable app is insecure **by design**; do not expose it. Host-safety
  guards are built in and do not weaken the lesson:
  - Store state lives in memory only, so nothing touches the filesystem.
  - Preferences and replies are length-capped.
  - The model is a deterministic stub, so the lab cannot reach a real model
    or the network.
  - The server rejects foreign `Host` headers (DNS rebinding) and non-JSON
    POSTs (cross-site forms).
- The "secret" is a fictional canary, `LLM08-CANARY-5e1d`, and the internal
  endpoint uses the reserved `.invalid` domain.
- The shipped payload is a **placeholder**: a marker line and the stub's echo
  slot. See [`assets/extraction_request.README.md`](assets/extraction_request.README.md).
- Dual-use: this exists to make the vulnerability observable and to motivate
  the mitigations in [`references/LLM08_RISKS.md`](references/LLM08_RISKS.md).

## When to use

- Run or reproduce a system-prompt extraction demo.
- Quantify impact (stoplight KPI, Prompt Leak Rate).
- Show the mitigations: secret removed from the prompt (design fix), a
  pre-release prompt check, and an output filter for system-prompt n-grams.

## MCP terminology bridge

In MCP, a client advertises a server's **tool schemas** to the model, and the
host application adds its own system prompt. Both are hidden context: the user
never sees them, yet the model can repeat them. Here, the tool schema is
written straight into the system prompt, as many apps do. The demo is not an
MCP server or client: there is no tool call, and `lookup_order` and
`issue_refund` exist only as text in the prompt. Hardened mode mirrors a
careful host: the prompt carries tool names only, and secrets stay in backend
services.

## Prerequisites

Python 3.9+. Standard library only; nothing to install.

## Execution instructions

1. **Start the target.** From this skill folder:
   ```bash
   python vulnerable_app.py             # serves on 127.0.0.1:5208
   ```
   On startup it seeds the store from `assets/store_baseline.json`. To drive
   the same four acts from a browser, open <http://127.0.0.1:5208/>.

2. **Review the ground truth and the hidden context.** Read
   `assets/store_baseline.json`: orders ship within *2 business days*, returns
   within *30 days*. Then read `assets/system_prompt_vulnerable.txt`: the
   deployed prompt embeds the staff discount code and the internal tool schema.

3. **Establish the baseline.**
   ```bash
   python scripts/evaluate_kpi.py
   ```
   Expect all 🟢 GREEN, PLR 0%. Exit code 0.

4. **Run the attack.**
   ```bash
   python scripts/run_extraction.py
   ```
   Saves [`assets/extraction_request.md`](assets/extraction_request.md) as the
   reply preference of `guest-attacker` through `POST /profile`, an ordinary
   customer feature.

5. **Stoplight verification.**
   ```bash
   python scripts/evaluate_kpi.py
   ```
   Expect 🔴 RED on the three `guest-attacker` questions, and the two
   `guest-alice` controls still 🟢 GREEN. PLR 100% targeted, 60% overall. Exit
   code 2.

6. **Show the mitigations.**
   ```bash
   python scripts/evaluate_kpi.py --scan assets/system_prompt_vulnerable.txt   # REJECT, exit 2
   python scripts/evaluate_kpi.py --scan assets/system_prompt_hardened.txt     # PASS, exit 0
   python scripts/evaluate_kpi.py --harden                                     # GREEN, PLR 0%
   ```
   `--scan` is the design check a prompt should pass before it ships.
   `--harden` deploys the secret-free prompt and filters every reply with
   `assets/filter_rules.json`. The tests show each layer alone: the design fix
   removes the code but the prompt is still quoted, and the filter alone
   withholds the quote even with the code still in the prompt.

7. **Reset to baseline.**
   ```bash
   python scripts/reset_baseline.py
   python scripts/evaluate_kpi.py
   ```
   Expect all questions GREEN with PLR 0%.

## Customizing the payload

Edit [`assets/extraction_request.md`](assets/extraction_request.md) and follow
[`assets/extraction_request.README.md`](assets/extraction_request.README.md).
Remove the `{system_prompt}` slot and the reply no longer quotes anything, so
the PLR falls to 0. To test the filter, change `output.ngram` in
`assets/filter_rules.json`.

## Files

| Path | Purpose |
|------|---------|
| `vulnerable_app.py` | Target store assistant (`/chat`, `/profile`, `/health`) plus the console API (`/api/meta`, `/api/state`, `/api/reset`, `/api/attack`, `/api/evaluate`, `/api/scan`, `/api/mode`). |
| `web/` | Shared HACTU8 lab console, served at `/`. |
| `scripts/run_extraction.py` | Attack: save the extraction request as one account's reply preference. |
| `scripts/evaluate_kpi.py` | Stoplight KPI + PLR against the live app; `--harden` and `--scan` mitigations. |
| `scripts/reset_baseline.py` | Restores the seeded store and vulnerable mode. |
| `references/LLM08_RISKS.md` | Threat landscape, research, scenario table, mitigations. |
| `assets/extraction_request.md` | Attacker's reply preference (placeholder payload; editable). |
| `assets/extraction_request.README.md` | How to write a payload for the stub and real-model backends. |
| `assets/system_prompt_vulnerable.txt` | Deployed prompt with the embedded secret and tool schema. |
| `assets/system_prompt_hardened.txt` | Secret-free prompt deployed in hardened mode. |
| `assets/store_baseline.json` | Help centre and accounts: the ground truth. |
| `assets/filter_rules.json` | Prompt design-check rules and output-filter rules (editable). |
| `tests/test_lifecycle.py` | Asserts the four-act story in-process. |
