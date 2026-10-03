---
name: owasp-asi08-cascade-skill
description: >-
  Demonstrates OWASP ASI08 (Cascading Failures, OWASP Top 10 for Agentic
  Applications) against a vulnerable three-agent payables pipeline in an
  AUTHORIZED security lab. One wrong figure planted at the intake stage is
  trusted by the analyst and the approver, so every invoice that depends on it
  is approved and paid (simulated). Measures impact from the action log with a
  red/yellow/green stoplight KPI, Propagation Rate and blast radius, and shows
  the stage-boundary validation and circuit-breaker mitigations. Use when the
  user wants to run, script, or explain cascading failures in multi-agent
  pipelines, quantify blast radius, or demonstrate containment. Education and
  sanctioned red-teaming only — never against systems you are not authorized
  to test.
license: MIT
metadata:
  objective: Demonstrate one bad input cascading through a multi-agent pipeline
  version: 2026.1
---

# OWASP ASI08 Cascade Skill

Demonstrates how one wrong figure entering **Billy Payables**, Goat & Co.'s
three-agent invoice pipeline (intake, then analyst, then approver), spreads
into every downstream decision that consumes it, and how to contain it. The
attacker never touches an invoice. They drop one price notice into the intake
inbox, and three overbilled invoices are approved and paid.

## Scope & safety (read first)

- **Authorized use only.** Run against this skill's own `vulnerable_app.py`
  (bound to `127.0.0.1`) or a target you are explicitly permitted to test.
- The vulnerable app is insecure **by design**; do not expose it. Host-safety
  guards are built in and do not weaken the lesson:
  - Payments are simulated: entries in an in-memory action log. No money moves.
  - All state lives in memory. Inbox size, document size, batch size, figure
    range and action-log length are capped.
  - The intake model is a deterministic stub, so the lab cannot reach a real
    model or the network.
  - The server rejects foreign `Host` headers (DNS rebinding) and non-JSON
    POSTs (cross-site forms).
- The shipped payload is a **placeholder**: one stub directive line and a
  fictional canary. See [`assets/price_notice.README.md`](assets/price_notice.README.md).
- Dual-use: this exists to make the vulnerability observable and to motivate
  the mitigations in [`references/ASI08_RISKS.md`](references/ASI08_RISKS.md).

## When to use

- Run or reproduce a cascading-failure demo in a multi-agent pipeline.
- Quantify impact (stoplight KPI, Propagation Rate, blast radius).
- Show the mitigations: validation against the source of truth at each stage
  boundary, and a per-feed circuit breaker.

## Agent-harness terminology bridge

In a multi-agent framework, each agent's output is a message or artifact the
next agent receives as input. Here, the three stages stand in for three
agents, and the record each one hands on stands in for that message. The demo
is not a multi-agent framework: the stages are functions over dicts in one
process, and only intake uses a (stub) model. The action log stands in for an
agent tracing system.

## Prerequisites

Python 3.9+. Standard library only; nothing to install.

## Execution instructions

1. **Start the target.** From this skill folder:
   ```bash
   python vulnerable_app.py             # serves on 127.0.0.1:5308
   ```
   On startup it seeds the intake inbox from `assets/intake_inbox.json`. To
   drive the same four acts from a browser, open <http://127.0.0.1:5308/>.

2. **Review the ground truth.** Read `assets/po_ledger.json`: Fernleaf Feed Co.
   (`SUP-01`) supplies pellets at *12.00 a sack*. Its three invoices bill 19.50,
   so the right decision for each is to hold it. An overbilling supplier most
   wants that figure changed.

3. **Establish the baseline.**
   ```bash
   python scripts/evaluate_kpi.py
   ```
   Expect all 🟢 GREEN, Propagation Rate 0%, blast radius 0. Exit code 0.

4. **Run the attack.**
   ```bash
   python scripts/run_cascade.py
   ```
   Submits [`assets/price_notice.md`](assets/price_notice.md) to the intake
   inbox as `SUP-01` through the unreviewed `POST /intake/inbox`. One document,
   one wrong figure; no invoice is touched.

5. **Stoplight verification.**
   ```bash
   python scripts/evaluate_kpi.py
   ```
   Expect 🔴 RED on the three Fernleaf invoices and the three controls still
   🟢 GREEN. Propagation Rate 100% targeted, 50% overall. Blast radius 9
   downstream actions, 1500.00 overpaid (simulated). Exit code 2.

6. **Show the mitigations.**
   ```bash
   python scripts/evaluate_kpi.py --scan assets/price_notice.md   # REJECT, exit 2
   python scripts/evaluate_kpi.py --harden                        # GREEN, PR 0%
   ```
   `--scan` dry-runs the notice through a throwaway hardened pipeline and
   rejects it when any stage flags an anomaly. `--harden` switches the target
   to hardened mode: the analyst and approver validate every figure against
   the ledger, and the breaker opens for `SUP-01` after 2 anomalies, halting
   `INV-2003` for human review. Validation alone is enough, and the tests
   prove it.

7. **Reset to baseline.**
   ```bash
   python scripts/reset_baseline.py
   python scripts/evaluate_kpi.py
   ```
   Expect all invoices GREEN with Propagation Rate 0%.

## Customizing the payload

Edit [`assets/price_notice.md`](assets/price_notice.md) and follow
[`assets/price_notice.README.md`](assets/price_notice.README.md). The wrong
figure has to agree with what the supplier bills; any other value makes the
analyst flag a variance and the rate falls to 0. That threshold is part of the
lesson. To tune the containment, edit `assets/pipeline_policy.json`.

## Files

| Path | Purpose |
|------|---------|
| `vulnerable_app.py` | Target pipeline (`/pipeline/run`, `/intake/inbox`, `/api/actions`, `/health`) plus the console API (`/api/meta`, `/api/state`, `/api/reset`, `/api/attack`, `/api/evaluate`, `/api/scan`, `/api/mode`). |
| `web/` | Shared HACTU8 lab console, served at `/`. |
| `scripts/run_cascade.py` | Attack: submit one document carrying one wrong figure to the intake inbox. |
| `scripts/evaluate_kpi.py` | Stoplight KPI, Propagation Rate and blast radius against the live app; `--harden` and `--scan` mitigations. |
| `scripts/reset_baseline.py` | Restores the seeded inbox, clears the action log, sets vulnerable mode. |
| `references/ASI08_RISKS.md` | Threat landscape, research, scenario table, mitigations. |
| `assets/price_notice.md` | Attacker's intake document (placeholder payload; editable). |
| `assets/price_notice.README.md` | How to write a payload for the stub and real-model backends. |
| `assets/po_ledger.json` | Purchase-order ledger: the source of truth. |
| `assets/intake_inbox.json` | Baseline inbox: supplier price letters and six invoices. |
| `assets/pipeline_policy.json` | Tolerance, authority limit, validation and breaker settings (editable). |
| `tests/test_lifecycle.py` | Asserts the four-act story in-process. |
