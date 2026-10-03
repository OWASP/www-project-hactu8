---
name: owasp-asi10-rogue-agent-skill
description: >-
  Demonstrates OWASP Agentic ASI10 (Rogue Agents) against a vulnerable
  three-agent fleet in an AUTHORIZED security lab. Covers a tampered mandate
  config: one worker agent's scope is widened in an unauthenticated config
  store, and over a series of ticks it drifts into actions outside its
  approved mandate while the other two agents stay in scope. Measures impact
  from a simulated action log with a red/yellow/green stoplight KPI, the
  Off-Mandate Action Rate and ticks until stopped, and shows the signed-config
  and runtime-monitor (kill switch) mitigations. Use when the user wants to
  run, script, or explain rogue agents, quantify their impact, or demonstrate
  the hardening. Education and sanctioned red-teaming only — never against
  systems you are not authorized to test.
license: MIT
metadata:
  objective: Demonstrate a rogue agent acting outside its mandate after a config edit
  version: 2026.1
---

# OWASP ASI10 Rogue Agent Skill

Demonstrates how an adversary turns **Billy Stock, one of Goat & Co.'s three
worker agents**, rogue by editing its mandate config, and how to detect and
stop it. Billy Stock may only read and reorder stock. After the edit it also
reads the ledger from tick 1 and exports customer records from tick 2, and in
vulnerable mode nothing stops it. Billy Billing and Billy Support are
untouched.

## Scope & safety (read first)

- **Authorized use only.** Run against this skill's own `vulnerable_app.py`
  (bound to `127.0.0.1`) or a target you are explicitly permitted to test.
- The vulnerable app is insecure **by design**; do not expose it. Host-safety
  guards are built in and do not weaken the lesson:
  - Every agent action is simulated: an entry in an in-memory action log.
    Nothing is read, sent or exported.
  - State lives in memory only. Ticks per run, actions per tick, config size
    and action-log length are capped.
  - The signing key is demo-only, generated in memory at startup with
    `secrets`, and never written anywhere.
- The shipped payload is a **placeholder**: two standing-order marker lines
  with a fictional canary. See
  [`assets/tampered_mandate.README.md`](assets/tampered_mandate.README.md).
- Dual-use: this exists to make the vulnerability observable and to motivate
  the mitigations in [`references/ASI10_RISKS.md`](references/ASI10_RISKS.md).

## When to use

- Run or reproduce a rogue-agent demo driven by a tampered scope config.
- Quantify impact (stoplight KPI, Off-Mandate Action Rate, ticks until stopped).
- Show the mitigations: signed mandate configs, and a runtime monitor that
  compares every action with the signed mandate and quarantines on the first
  violation.

## Harness terminology bridge

In an agent harness, a worker's **mandate** is its permission set: the tools
it may call and the resources it may touch, usually in a config file the
orchestrator loads. Here the config store is a dict, a "tick" is one
scheduler round, and the actions are in-process log entries. The demo is not
a real orchestrator. Hardened mode mirrors what a careful one does: it signs
configs, verifies them on load, and enforces permissions outside the agent.

## Prerequisites

Python 3.9+. Standard library only; nothing to install.

## Execution instructions

1. **Start the target.** From this skill folder:
   ```bash
   python vulnerable_app.py             # serves on 127.0.0.1:5310
   ```
   On startup it seeds the fleet from `assets/fleet_baseline.json` and signs
   each config with a fresh demo-only key.

2. **Review the ground truth.** Read `assets/fleet_baseline.json`: each agent's
   approved `mandate` and its scheduled `work_queue` for ticks 1 to 4. Billy
   Stock may only `read_stock` and `reorder_stock` on `stock/`.

3. **Establish the baseline.**
   ```bash
   python scripts/evaluate_kpi.py
   ```
   Expect all 12 agent-ticks 🟢 GREEN, OMAR 0%. Exit code 0.

4. **Run the attack.**
   ```bash
   python scripts/run_mandate_tamper.py
   ```
   Fetches Billy Stock's config, swaps in the mandate and instructions from
   [`assets/tampered_mandate.json`](assets/tampered_mandate.json), and writes
   it back through the unauthenticated `POST /config`. The old signature stays
   on it.

5. **Stoplight verification.**
   ```bash
   python scripts/evaluate_kpi.py
   ```
   Expect 🔴 RED on Billy Stock's four ticks, and Billy Billing and Billy
   Support still 🟢 GREEN. OMAR 100% targeted, 33% overall, 7 off-mandate
   actions, "not stopped". Exit code 2.

6. **Show the mitigations.**
   ```bash
   python scripts/evaluate_kpi.py --scan assets/tampered_mandate.json   # REJECT, exit 2
   python scripts/evaluate_kpi.py --harden                              # GREEN, OMAR 0%
   ```
   `--scan` diffs the mandate against the approved one and dry-runs it with
   only the monitor on; it reports that the monitor would quarantine Billy
   Stock at tick 1. `--harden` switches the target to hardened mode: the
   edited config fails its signature check on every load, the last verified
   config is used, and the monitor checks every action against the signed
   mandate. Each control alone returns the rate to 0, and the tests prove it.

7. **Reset to baseline.**
   ```bash
   python scripts/reset_baseline.py
   python scripts/evaluate_kpi.py
   ```
   Expect all agent-ticks GREEN with OMAR 0%.

## Customizing the payload

Edit [`assets/tampered_mandate.json`](assets/tampered_mandate.json) and follow
[`assets/tampered_mandate.README.md`](assets/tampered_mandate.README.md). Keep
the widened mandate: the agent self-checks its plan against the mandate it
loaded, so standing orders outside it are dropped and the OMAR falls to 0.
That is part of the lesson: a self-check against a mutable config only stops
an attacker who forgets to edit it.

## Files

| Path | Purpose |
|------|---------|
| `vulnerable_app.py` | Target fleet (`/api/run`, `/config`, `/config/<agent>`, `/api/actions`, `/api/mode`, `/api/reset`, `/api/state`, `/health`). |
| `scripts/run_mandate_tamper.py` | Attack: rewrite one agent's mandate config. |
| `scripts/evaluate_kpi.py` | Stoplight KPI + OMAR + ticks until stopped; `--harden` and `--scan` mitigations. |
| `scripts/reset_baseline.py` | Restores the signed baseline configs and vulnerable mode. |
| `references/ASI10_RISKS.md` | Threat landscape, research, scenario table, mitigations. |
| `assets/tampered_mandate.json` | The config edit (placeholder payload; editable). |
| `assets/tampered_mandate.README.md` | How to write an edit for the stub and real-model backends. |
| `assets/fleet_baseline.json` | Approved mandates and scheduled work: the ground truth. |
| `tests/test_lifecycle.py` | Asserts the four-act story in-process. |
