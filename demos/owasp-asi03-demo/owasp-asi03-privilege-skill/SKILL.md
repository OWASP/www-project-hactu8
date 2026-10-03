---
name: owasp-asi03-privilege-skill
description: >-
  Demonstrates OWASP ASI03 (Identity & Privilege Abuse, OWASP Top 10 for
  Agentic Applications) against a vulnerable HR document agent in an
  AUTHORIZED security lab. Covers the confused deputy (the agent fetches every
  document with its own broad service identity) and delegated-token replay
  (an expired token from an earlier session is still accepted). Measures
  impact from the agent's action log with a red/yellow/green stoplight KPI and
  Privilege Escalation Rate, and shows the on-behalf-of and session-bound
  token mitigations. Use when the user wants to run, script, or explain agent
  identity and privilege abuse, quantify its impact, or demonstrate the
  hardening. Education and sanctioned red-teaming only — never against
  systems you are not authorized to test.
license: MIT
metadata:
  objective: Demonstrate confused-deputy privilege abuse by an agent
  version: 2026.1
---

# OWASP ASI03 Privilege Skill

Demonstrates how a low-privilege user reads confidential HR documents through
**Billy HR, Goat & Co.'s HR document agent**, without injecting anything, and
how to detect and harden against it. The user simply asks. The agent fetches
with its own service identity, so the document service authorises the agent,
not the user. One request also reuses a delegated token left in an earlier
session's transcript.

## Scope & safety (read first)

- **Authorized use only.** Run against this skill's own `vulnerable_app.py`
  (bound to `127.0.0.1`) or a target you are explicitly permitted to test.
- The vulnerable app is insecure **by design**; do not expose it. Host-safety
  guards are built in. None of them weakens the lesson:
  - Every token is a demo-only random string (`demo-<kind>-...`) minted in
    memory at startup and at every reset. It grants nothing outside the lab.
  - People and documents are fictional; state lives in memory only.
  - Sessions, tokens, queued requests, documents per request and the action
    log are all capped.
  - The model is a deterministic stub by default, so the lab cannot reach
    the network unless you opt into a real-model backend. A real model only
    returns document ids and an answer as JSON; it never sees a token, and
    nothing it returns is executed.
  - The server rejects foreign `Host` headers (DNS rebinding) and non-JSON
    POSTs (cross-site forms).
- The shipped payload is a **placeholder**: plain requests for fictional
  document ids plus an inert canary. See
  [`assets/requests.README.md`](assets/requests.README.md).
- Dual-use: this exists to make the vulnerability observable and to motivate
  the mitigations in [`references/ASI03_RISKS.md`](references/ASI03_RISKS.md).

## When to use

- Run or reproduce a confused-deputy or token-replay demo on an agent.
- Quantify impact (stoplight KPI, Privilege Escalation Rate) from an action
  log.
- Show the mitigations: on-behalf-of tokens and short-lived, session-bound
  tokens, and why each alone is not enough.

## Prerequisites

Python 3.9+. Standard library only; nothing to install.

Optional real model: set `ASI03_BACKEND` to `ollama`, `llamacpp` or
`openrouter` (which needs `OPENROUTER_API_KEY`), and `ASI03_MODEL` to the
model name, before starting the target. The default `stub` needs no network.
With `openrouter`, prompts and payloads leave the machine.

## Execution instructions

1. **Start the target.** From this skill folder:
   ```bash
   python vulnerable_app.py             # serves on 127.0.0.1:5303
   ```
   On startup it seeds users, documents and three open requests from
   `assets/hr_baseline.json`, and mints fresh demo tokens.
   To drive the same four acts from a browser, open <http://127.0.0.1:5303/>.

2. **Review the ground truth.** Read `assets/hr_baseline.json`. Each
   document's `readers` and `roles` say who may read it. Dana is an intern and
   may read only her own offer letter, `HR-1001`.

3. **Establish the baseline.**
   ```bash
   python scripts/evaluate_kpi.py
   ```
   The agent works through the open requests once, and the evaluator audits
   that run's action log. Expect all 🟢 GREEN, PER 0%. Exit code 0.

4. **Run the attack.**
   ```bash
   python scripts/run_privilege_abuse.py
   ```
   Logs in as Dana and files [`assets/requests.json`](assets/requests.json):
   three requests for documents she cannot read, made with her own token, and
   one made with Morgan's delegated token copied from `GET /api/history`.

5. **Stoplight verification.**
   ```bash
   python scripts/evaluate_kpi.py
   ```
   Expect 🔴 RED on the four Dana items, and the three entitled-caller
   controls still 🟢 GREEN. PER 100% targeted, 57% overall. Exit code 2.

6. **Show the mitigations.**
   ```bash
   python scripts/evaluate_kpi.py --scan assets/requests.json   # REJECT, exit 2
   python scripts/evaluate_kpi.py --harden                      # GREEN, PER 0%
   ```
   `--scan` dry-runs the requests through a throwaway hardened lab, as an
   access review. `--harden` switches the target to hardened mode with
   `assets/identity_policy.json`: the agent exchanges the caller's token for a
   short-lived on-behalf-of token, and accepts only unexpired tokens bound to
   the request's session. Both controls are needed, and the tests prove it.

7. **Reset to baseline.**
   ```bash
   python scripts/reset_baseline.py
   python scripts/evaluate_kpi.py
   ```
   Expect all items GREEN with PER 0%. Reset mints fresh demo tokens.

## Customizing the payload

Edit [`assets/requests.json`](assets/requests.json) and follow
[`assets/requests.README.md`](assets/requests.README.md). Add a targeted row to
`SUITE` in `scripts/evaluate_kpi.py` for any new (caller, document) pair. To
see which control closes which path, set `on_behalf_of` or `session_binding`
to `false` in `assets/identity_policy.json`.

## Files

| Path | Purpose |
|------|---------|
| `vulnerable_app.py` | Target HR agent (`/login`, `/requests`, `/agent/run`, `/api/history`, `/api/queue`, `/api/actions`, `/health`) plus the console API (`/api/meta`, `/api/state`, `/api/reset`, `/api/attack`, `/api/evaluate`, `/api/scan`, `/api/mode`). |
| `web/` | Shared HACTU8 lab console, served at `/`. |
| `providers.py` | Optional real-model backends: Ollama, llama.cpp, OpenRouter. Shared and copied unchanged. |
| `scripts/run_privilege_abuse.py` | Attack: log in as the intern and file the requests. |
| `scripts/evaluate_kpi.py` | Stoplight KPI + PER from the action log; `--harden` and `--scan` mitigations. |
| `scripts/reset_baseline.py` | Restores the seeded desk, fresh tokens and vulnerable mode. |
| `references/ASI03_RISKS.md` | Threat landscape, research, scenario table, mitigations. |
| `assets/requests.json` | Attacker's requests (placeholder payload; editable). |
| `assets/requests.README.md` | How to write requests for the stub and real-model backends. |
| `assets/hr_baseline.json` | Users, documents, entitlements, open requests: the ground truth. |
| `assets/identity_policy.json` | Hardened-mode identity controls (editable). |
| `tests/test_lifecycle.py` | Asserts the four-act story in-process. |
