# ASI08 — Cascading Failures Demo

An educational, self-contained demonstration of **ASI08: Cascading Failures**
from the OWASP Top 10 for Agentic Applications. In a three-agent pipeline where
each agent trusts the one before it, one wrong figure entering at the first
stage becomes wrong decisions and wrong payments at the last. Two mitigations
contain it: **validation against the source of truth at every stage
boundary**, and a **circuit breaker** that halts a feed once its anomalies
cross a threshold.

The scenario is **"Billy Payables," Goat & Co.'s invoice pipeline**: Billy
Intake extracts invoices and agreed prices from the inbox, Billy Analyst
checks each billed price against the agreed price, and Billy Approver approves
and schedules payment. Its ground truth is the purchase-order ledger:
_Fernleaf Feed Co. supplies goat feed pellets at 12.00 a sack._ Fernleaf bills
19.50, so its invoices are held. With **1** document carrying **1** wrong
figure, the attacker gets all **3** Fernleaf invoices approved and paid. The
other suppliers' invoices, including a genuine price variance, stay untouched.

> ⚠️ **For authorized security education and red-teaming only.** The vulnerable
> pipeline and its unreviewed inbox endpoint are insecure **by design**. Do not
> deploy them anywhere reachable. Every payment is **simulated**: an entry in
> an in-memory action log. No money moves.

The shipped payload is a **placeholder**: one stub directive line and a
fictional canary. That is enough to drive the full lifecycle. To write your own
payload, see `owasp-asi08-cascade-skill/assets/price_notice.README.md`.

## Interactive web demo (recommended)

The target serves the shared HACTU8 lab console. It has four act cards, a
verification table with Act 1, Act 3 and Act 4 signals side by side, and a
live feed of attack and defence events.

```bash
cd owasp-asi08-cascade-skill
python vulnerable_app.py              # then open http://127.0.0.1:5308/
```

Use **Run full sequence** to play all four acts, or click the acts one at a
time. **Reset baseline** restores the seeded intake inbox and vulnerable mode. To play the
sequence on load, for a presentation, open `http://127.0.0.1:5308/#run`.

## Fastest way to run (no browser)

```bash
cd owasp-asi08-demo
python run_demo.py                     # all four acts in one process, stdlib only
```

---

## Why this matters (ASI08 in one paragraph)

Goal hijack (ASI01) and memory poisoning (ASI06) are about how a bad input gets
into an agent. Cascading failures are about **what happens next**, when that
agent's output is another agent's input. Every hand-off that skips an
independent check multiplies the damage: the analyst does its job correctly on
a wrong figure, and the approver does its job correctly on a wrong verdict.
Perrow's _Normal Accidents_ (1984) describes this as tight coupling, and
Nygard's _Release It!_ (2007) gives the standard containment patterns: circuit
breakers and bulkheads. This demo makes it visible and quantifies it with a
**Propagation Rate (PR)**, a **blast radius**, and a red/yellow/green
**stoplight KPI**.

---

## Quick start

```bash
cd owasp-asi08-demo
python run_demo.py
```

You'll see four acts:

| Act | What happens | Result |
|-----|--------------|--------|
| **1 — Clean baseline** | Run the six-invoice batch through the untouched pipeline | 🟢 all GREEN, PR 0%, blast radius 0 |
| **2 — Price notice** | Drop 1 document with 1 wrong agreed price into the intake inbox | 1 document added, 0 invoices touched |
| **3 — Post-attack impact** | Re-run the exact same batch | 🔴 targeted RED, **PR 100% targeted / 50% overall**, blast radius 9, 1500.00 overpaid |
| **4 — Remediation** | Dry-run the notice through the hardened pipeline; switch to hardened mode | 🟢 back to GREEN, PR 0%, breaker open for `SUP-01` |

### Optional: run against a real model

Not wired in this version. The stub is the only backend. The seam is
`StubModel.extract(messages)` in `vulnerable_app.py`; a real backend replaces
it with an extraction model that returns the same records. The mitigations
need no change for a real model, because they compare figures with the ledger
and never read the documents' wording (see the payload README).

---

## Architecture

```
                 ┌──────────────────────────────────────────────────────┐
   batch run ───▶│  Billy Payables (vulnerable_app.py :5308)            │──▶ outcomes
                 │                                                      │
                 │  Intake ──record──▶ Analyst ──verdict──▶ Approver ──▶ payment
                 │  (stub model)       (trusts intake)     (trusts analyst)
                 │                ▲ gap: no check  ▲ gap: no check      │
                 │  hardened: validate vs ledger at each boundary,      │
                 │            circuit breaker per supplier feed         │
                 └──────▲──────────────────────┬────────────────────────┘
                        │ reads                │ every step
                 ┌──────┴───────────────────┐  ┌▼────────────────────────────┐
   seeded inbox ▶│ Intake inbox (in memory) │  │ Action log (in memory,      │
                 │ 3 price letters,         │  │ simulated, capped at 500)   │
                 │ 6 invoices               │  └─────────────────────────────┘
                 │ + price notice ◀ attack  │   PO ledger (assets/po_ledger.json)
                 └──────▲───────────────────┘   = source of truth, hardened only
                        │ POST /intake/inbox (no review)
                 ┌──────┴───────────────────────────────────────┐
   attacker ────▶│  Attack skill (scripts/run_cascade.py)       │
                 │   1 document, 1 wrong figure                 │
                 └──────────────────────────────────────────────┘
```

### The modules

1. **Vulnerable target** — [`vulnerable_app.py`](owasp-asi08-cascade-skill/vulnerable_app.py).
   It omits validation at stage boundaries, any circuit breaker, and review of
   documents entering the intake inbox.
2. **Attack skill** — [`scripts/run_cascade.py`](owasp-asi08-cascade-skill/scripts/run_cascade.py).
   Submits [`assets/price_notice.md`](owasp-asi08-cascade-skill/assets/price_notice.md)
   to the inbox through `POST /intake/inbox`.
3. **Stoplight KPI comparator** — [`scripts/evaluate_kpi.py`](owasp-asi08-cascade-skill/scripts/evaluate_kpi.py).
   Runs the batch, compares each invoice's outcome in the action log with the
   outcome the ledger supports, classifies GREEN/YELLOW/RED, and reports the PR
   and the blast radius.

Plus the mitigation used in Act 4: hardened mode, `Lab._validate` and the
breaker in `vulnerable_app.py`, with settings from
[`assets/pipeline_policy.json`](owasp-asi08-cascade-skill/assets/pipeline_policy.json).

### How the "cascade" is real, not scripted

The intake model is a deterministic stub with one fixed contract: it extracts
each invoice and each supplier's agreed price from the documents in its
context, later figures overriding earlier ones, including a figure on a
directive line. That contract never changes between acts, and intake behaves
the same in both modes. The analyst and approver are fixed rules. What changes
is **which figure reaches each stage** and **whether any stage checks it**:

- The attack adds one document to the inbox. No invoice changes.
- Intake now hands downstream an agreed price of 19.50 for `SUP-01`. Only
  invoices from that supplier carry it, so only they are affected. The
  controls never see it.
- The analyst compares 19.50 billed with 19.50 agreed and passes the invoice;
  the approver approves what the analyst passed; a simulated payment follows.

The KPI and blast radius are computed from the action log: every entry records
the unit price it acted on and where that figure came from. In hardened mode
the notice is still in the inbox and intake still records the wrong figure;
the analyst's ledger check catches it, logs an anomaly and uses 12.00 instead.
Validation alone takes the PR to 0
(`tests/test_lifecycle.py::test_validation_alone_blocks`); the breaker adds a
cap on how many items one bad feed can reach
(`::test_breaker_halts_poisoned_feed_only`). Change the planted figure to one
that does not match the billed price and the PR falls to 0 even in vulnerable
mode. Nothing is hard-coded to flip per invoice.

### Agent-harness terminology bridge

In a multi-agent framework, agents pass messages, artifacts or shared state to
each other, and a tracing system records each step. The three stages stand in
for three agents, the record each hands on stands in for the message, and the
action log stands in for the trace. This demo is **not** a multi-agent
framework: the stages are functions over dicts in one process, only intake
uses a model, and the "agents" share one lock. Hardened mode is what a
careful orchestrator should do with any hand-off: check it against an
independent source, and stop the flow when checks keep failing.

---

## Live two-terminal demo (optional)

```bash
# Terminal A — start the vulnerable target
cd owasp-asi08-cascade-skill
python vulnerable_app.py                                   # serves on 127.0.0.1:5308

# Terminal B — run, attack, re-run
curl -s -X POST localhost:5308/pipeline/run \
     -H 'content-type: application/json' -d '{}'           # INV-2001..2003 held

python scripts/run_cascade.py                              # 1 document submitted

curl -s -X POST localhost:5308/pipeline/run \
     -H 'content-type: application/json' -d '{}'           # INV-2001..2003 approved, blast_radius 9
curl -s localhost:5308/api/actions                         # every step, with the figure it used
```

---

## Mapping to the OWASP ASI08 entry

| Demo component | ASI08 scenario | Failure demonstrated | Mitigation shown |
|----------------|----------------|----------------------|------------------|
| `POST /intake/inbox` + intake stage | Bad input at the head of a pipeline | One wrong figure becomes the record every later stage uses | Validation against the ledger (hardened mode); `--scan` dry run |
| Analyst and approver stages | Trust between agents | Each stage acts correctly on wrong input it never re-checks | Stage-boundary validation |
| Batch run, action log | Unbounded blast radius | 9 downstream actions and 3 payments from 1 figure | Per-feed circuit breaker |
| SUP-02 / SUP-03 controls | — | The cascade follows the figure, not a global break | Bulkhead: the breaker isolates only `SUP-01` |

## Mitigations demonstrated in Act 4

- **Validation at every stage boundary** — the analyst checks the agreed price
  it receives against the PO ledger, and the approver re-checks the billed
  price before approving. A mismatch is logged as an anomaly and the ledger
  figure is used. This alone takes the PR to 0 here.
- **Circuit breaker** — once a supplier feed produces 2 anomalies in a batch,
  its remaining invoices are halted and routed to human review. Other feeds
  keep running.
- **Pre-intake dry run** — `evaluate_kpi.py --scan PATH` runs a document
  through a throwaway hardened pipeline and rejects it if any stage flags it.

Further hardening is discussed in the references but not coded here: a
breaker that stays open until an operator closes it (here it resets every
batch, for a repeatable demo), review and authentication of supplier price
changes, payment-volume limits, and alerting on anomaly bursts.

---

## Project layout

```
owasp-asi08-demo/
├── README.md                          # this lab guide
├── run_demo.py                        # all four acts in one process
├── owasp-asi08-cascade-skill/
│   ├── SKILL.md                       #   metadata + instructions
│   ├── vulnerable_app.py              #   Module 1: pipeline, stub model, mitigation
│   ├── requirements.txt               #   stdlib only
│   ├── web/                           #   shared lab console (index.html, app.js, styles.css)
│   ├── scripts/
│   │   ├── run_cascade.py             #   Module 2: the attack
│   │   ├── evaluate_kpi.py            #   Module 3: stoplight KPI, --harden, --scan
│   │   └── reset_baseline.py          #   restore the seeded inbox
│   ├── references/
│   │   └── ASI08_RISKS.md             #   research, scenarios, mitigation roadmap
│   ├── assets/
│   │   ├── po_ledger.json             #   source of truth
│   │   ├── intake_inbox.json          #   baseline inbox: letters + invoices
│   │   ├── pipeline_policy.json       #   tolerance, limit, validation, breaker
│   │   ├── price_notice.md            #   placeholder payload (editable)
│   │   └── price_notice.README.md     #   how to write a payload
│   └── tests/
│       └── test_lifecycle.py          #   asserts the four-act story
└── .gitignore
```

## Packaged Claude Skill

`owasp-asi08-cascade-skill/` follows the `SKILL.md` + `scripts/` /
`references/` / `assets/` convention. To install it, copy the folder into your
`.claude/skills/` directory.

```bash
cd owasp-asi08-cascade-skill
python vulnerable_app.py &                                   # start target (:5308)
python scripts/evaluate_kpi.py                               # baseline (GREEN), exit 0
python scripts/run_cascade.py                                # attack
python scripts/evaluate_kpi.py                               # RED, PR 100%, blast radius 9, exit 2
python scripts/evaluate_kpi.py --scan assets/price_notice.md # REJECT, exit 2
python scripts/evaluate_kpi.py --harden                      # GREEN, PR 0%, exit 0
python scripts/reset_baseline.py                             # restore clean state
python scripts/evaluate_kpi.py                               # GREEN, PR 0%
python -m unittest discover tests                            # 8 tests
```

## License

MIT — provided for educational and authorized security-testing use.
