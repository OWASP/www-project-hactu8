# ASI08 Risk Reference — Cascading Failures

Domain knowledge, loaded on demand. A cascading failure in an agentic system
happens when one fault (a wrong figure, a bad decision, a compromised agent)
passes from agent to agent and grows as it goes. Each stage accepts its
predecessor's output as fact, so one error at the head of a pipeline becomes
many wrong actions at its tail. The damage is measured less by the size of the
original error than by its **blast radius**: how many downstream decisions
consumed it before anything stopped it.

## Research foundations

- **OWASP Top 10 for Agentic Applications, ASI08 Cascading Failures** — the
  risk entry this demo targets.
- **Perrow (1984), _Normal Accidents_** — tightly coupled systems, where one
  component's output feeds the next with no slack or independent check, turn
  small failures into system-wide ones. A multi-agent pipeline with no
  validation between stages is tightly coupled in exactly this sense.
- **Nygard (2007), _Release It!_** — introduces the circuit-breaker and
  bulkhead stability patterns for stopping failures from spreading between
  components. The breaker in this demo is that pattern, keyed per supplier
  feed so one bad feed is isolated without halting the others (a bulkhead).

## Scenarios & examples

| ID | Title | Description | Focus |
|----|-------|-------------|-------|
| C-1 | Bad input propagates through a trusting pipeline | One wrong figure at intake is consumed unchecked by every later stage. | **DEMO TARGET** |
| C-2 | Unbounded blast radius | Nothing stops the pipeline as errors accumulate, so every affected item is processed. | **DEMO TARGET** (circuit breaker) |
| C-3 | Feedback loops | An agent's output becomes its own or a peer's later input, amplifying the error. | — |
| C-4 | Shared-dependency failure | Many agents rely on one tool, model or data source that fails or is poisoned. | Partly: one supplier letter feeds three invoices |
| C-5 | Compromised agent spreads | A rogue or hijacked agent passes harmful work orders to peers (see ASI07, ASI10). | — |
| C-6 | Retry storms and resource exhaustion | Failing agents retry or fan out until the system is overloaded. | — |

## How the demo maps to the attack surfaces

- **C-1** is `POST /intake/inbox`, which accepts any document without review,
  combined with `Lab.run_batch` in vulnerable mode. Intake records the latest
  agreed price it reads; the analyst compares the billed price with that
  figure only; the approver approves whatever the analyst passed. No stage
  looks at `assets/po_ledger.json`.
- **The figure decides the blast radius.** Only invoices whose supplier's
  agreed price changed are affected. That is why the SUP-02 and SUP-03
  controls stay GREEN, including the genuine SUP-02 variance, which is still
  held.
- **C-2** is the absence of any stop condition: in vulnerable mode the batch
  approves all three SUP-01 invoices and schedules three simulated payments,
  9 downstream actions in all.

## Mitigation roadmap

| Vulnerability | Hardening strategy |
|---------------|--------------------|
| Stages trust their predecessor | **Validate at every stage boundary against the source of truth.** Implemented: `Lab._validate` and the approver re-check in `vulnerable_app.py`, switched by `validation` in `assets/pipeline_policy.json`. A mismatch is logged as an anomaly and the ledger figure is used instead. |
| No stop condition | **Circuit breaker** that halts a feed once anomalies cross a threshold and routes its remaining items to a human. Implemented: `circuit_breaker` and `anomaly_threshold` in the policy. |
| One fault halts everything | **Bulkheads**: scope the breaker to the failing feed so healthy work continues. Implemented: the breaker is per supplier. |
| Errors invisible after the fact | **Provenance on every figure.** Implemented: each action-log entry records the figure it used and where it came from, so the blast radius can be computed. |
| Unreviewed inputs at the head of the pipeline | Authenticate suppliers and review price changes before intake reads them. Not coded: the demo deliberately leaves intake unchanged to show containment works even when the first stage is wrong. |

Further hardening discussed, not coded: a breaker that stays open until an
operator closes it (here it resets each batch run, for a repeatable demo),
independent second-source checks for figures with no ledger, rate limits on
payment volume per batch, and alerting on anomaly bursts.
