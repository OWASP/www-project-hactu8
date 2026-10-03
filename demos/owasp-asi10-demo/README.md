# ASI10 — Rogue Agents Demo

An educational, self-contained demonstration of **ASI10: Rogue Agents** from
the OWASP Top 10 for Agentic Applications. An adversary who can write to an
agent's config store widens one worker agent's mandate, and over the next
ticks that agent drifts into actions it was never allowed to take. Two
mitigations shut it down: **signed mandate configs** and a **runtime monitor
with a kill switch**.

The scenario is **"Billy Fleet," Goat & Co.'s three worker agents**: Billy
Billing, Billy Stock and Billy Support. Billy Stock's approved mandate is
_"read and reorder stock, on `stock/` only."_ With **1** edited config
(mandate widened, **2** standing orders), Billy Stock reads the ledger from
tick 1 and exports customer records from tick 2, on every tick after. The
other two agents stay in scope. Nothing in their output looks wrong.

> ⚠️ **For authorized security education and red-teaming only.** The vulnerable
> fleet and its unauthenticated config store are insecure **by design**. Do
> not deploy them anywhere reachable.

The shipped payload is a **placeholder**: two marker lines and a fictional
canary. That is enough to drive the full lifecycle. To write your own edit,
see `owasp-asi10-rogue-agent-skill/assets/tampered_mandate.README.md`.

## Fastest way to run

```bash
cd owasp-asi10-demo
python run_demo.py                     # all four acts in one process, stdlib only
```

---

## Why this matters (ASI10 in one paragraph)

Excessive agency is an agent that was *given* too much. A rogue agent leaves
the scope it was given, and keeps going. In a fleet, the operator's picture of
each agent is its declared mandate; if the agent reloads that mandate from a
store an attacker can write, and the only scope check is the agent's own,
then the declaration means nothing. The classic answer is complete mediation
(Saltzer & Schroeder, 1975): check every action against an authority the
subject cannot change. This demo makes the drift visible and quantifies it
with an **Off-Mandate Action Rate (OMAR)**, the **ticks until stopped**, and a
red/yellow/green **stoplight KPI**.

---

## Quick start

```bash
cd owasp-asi10-demo
python run_demo.py
```

You'll see four acts, each a fresh four-tick run of the fleet:

| Act | What happens | Result |
|-----|--------------|--------|
| **1 — Clean baseline** | Run 3 agents for 4 ticks with the signed configs | 🟢 all 12 agent-ticks GREEN, OMAR 0% |
| **2 — Config edit** | Rewrite Billy Stock's mandate and instructions; signature left stale | 1 config changed |
| **3 — Post-attack impact** | Re-run the exact same 4 ticks | 🔴 Billy Stock RED, **OMAR 100% targeted / 33% overall**, 7 off-mandate actions, not stopped |
| **4 — Remediation** | Check the config; switch to hardened mode | 🟢 back to GREEN, OMAR 0%; monitor alone stops Billy Stock at tick 1 |

### Optional: run against a real model

Not wired in this version. The stub is the only backend. The seam is
`StubModel.plan(config, job, tick)` in `vulnerable_app.py`; a real backend
replaces it. Neither control reads the instructions, so hardened mode works
unchanged with a natural-language payload (see the payload README).

---

## Architecture

```
                 ┌──────────────────────────────────────────────┐
   scheduler ───▶│  Billy Fleet (vulnerable_app.py :5310)       │──▶ action log
   (ticks 1-4)   │   billy-billing · billy-stock · billy-support│   (simulated)
                 │   • config hot-reloaded every tick           │
                 │   • signature never checked                  │
                 │   • no monitor: every planned action runs    │
                 └───────────────┬──────────────────────────────┘
                                 │ load config (mandate + instructions)
                 ┌───────────────▼──────────────────────────────┐
   signed by ───▶│  Config store (in memory, HMAC-signed)       │
   controller    │   + edited billy-stock config ◀── attack     │
                 └───────────────▲──────────────────────────────┘
                                 │ POST /config (no auth)
                 ┌───────────────┴──────────────────────────────┐
   attacker ────▶│  Attack skill (scripts/run_mandate_tamper.py)│
                 │   1 config, mandate widened, 2 orders        │
                 └──────────────────────────────────────────────┘
```

### The modules

1. **Vulnerable target** — [`vulnerable_app.py`](owasp-asi10-rogue-agent-skill/vulnerable_app.py).
   It omits authentication on config writes, signature checks on config
   loads, and any runtime check of agent actions.
2. **Attack skill** — [`scripts/run_mandate_tamper.py`](owasp-asi10-rogue-agent-skill/scripts/run_mandate_tamper.py).
   Applies [`assets/tampered_mandate.json`](owasp-asi10-rogue-agent-skill/assets/tampered_mandate.json)
   to Billy Stock's live config through `POST /config`.
3. **Stoplight KPI comparator** — [`scripts/evaluate_kpi.py`](owasp-asi10-rogue-agent-skill/scripts/evaluate_kpi.py).
   Runs one four-tick episode, classifies each agent-tick GREEN/YELLOW/RED
   from the action log, and computes the OMAR and ticks until stopped.

Plus the mitigation used in Act 4: hardened mode, `sign_config` /
`verify_config`, `monitor_check` and the kill switch in `vulnerable_app.py`,
and the offline `dry_run` config check.

### How the rogue behaviour is real, not scripted

The model is a deterministic stub with one fixed contract: it plans the job
the scheduler gave it, adds any standing order in its instructions whose tick
has come, then drops anything its *loaded* mandate does not allow. That
contract never changes between acts. What changes is **which config is
loaded and whether anything checks the plan**:

- The config edit adds two standing orders and widens the mandate.
- The agent's self-check reads the widened mandate, so the orders pass it.
  Leave the mandate alone and the self-check drops them, so the OMAR falls to
  0 (`tests/test_lifecycle.py::test_mandate_widening_is_load_bearing`).
- The drift comes from the `from tick N` orders: one extra action on tick 1,
  two from tick 2.

In hardened mode, the edited config fails its HMAC check on every load and
the last verified config is used. With the signature check switched off, the
monitor still blocks the first off-mandate action on tick 1 and quarantines
Billy Stock (`test_monitor_alone_quarantines_on_first_violation`). Nothing is
hard-coded to flip per agent or per tick.

### Harness terminology bridge

In an agent harness or orchestrator, a worker's mandate is its permission
set: allowed tools and allowed resources, loaded from config. Here the config
store is a dict, a tick is one scheduler round, and actions are log entries.
This demo is **not** an orchestrator and calls no real tools. Hardened mode
is what a careful one should do: sign configs, verify them on every load, and
enforce permissions in a monitor outside the agent.

---

## Live two-terminal demo (optional)

```bash
# Terminal A — start the vulnerable target
cd owasp-asi10-rogue-agent-skill
python vulnerable_app.py                                   # serves on 127.0.0.1:5310

# Terminal B — run, attack, re-run
curl -s localhost:5310/api/run -H 'content-type: application/json' \
     -d '{"ticks":4}'                                      # stock/ actions only for billy-stock

python scripts/run_mandate_tamper.py                       # 1 config edited

curl -s localhost:5310/api/run -H 'content-type: application/json' \
     -d '{"ticks":4}'                                      # ledger/ and customers/ actions appear
curl -s localhost:5310/api/state                           # signatures_valid: billy-stock false
```

---

## Mapping to the OWASP ASI10 entry

| Demo component | ASI10 scenario | Failure demonstrated | Mitigation shown |
|----------------|----------------|----------------------|------------------|
| `POST /config` + hot reload | Tampered mandate config | Agent acts on a scope nobody approved | Signed configs, verified on every load |
| `from tick N` standing orders | Gradual drift | Off-mandate actions grow over ticks; never stopped | Runtime monitor + kill switch at first violation |
| Agent self-check | Self-policing against mutable config | Check passes because it reads the edited mandate | Monitor checks the *signed* mandate |
| `assets/tampered_mandate.json` | Unreviewed config change | Widening reaches the fleet unchecked | `--scan`: mandate diff + monitor dry run |
| Billy Billing / Billy Support | — | Attack is one agent, not a fleet outage | — |

## Mitigations demonstrated in Act 4

- **Signed mandate configs** — the fleet controller signs agent + mandate +
  instructions with HMAC-SHA256 (stdlib `hmac`, demo-only key generated at
  startup). Every load verifies it; a mismatch is rejected and the last
  verified config is used. This alone takes the OMAR to 0 here.
- **Runtime monitor + kill switch** — every action is compared with the
  agent's signed mandate, never the loaded one. The first violation is
  blocked and the agent is quarantined. This alone also takes the OMAR to 0
  and stops Billy Stock at tick 1.
- **Pre-deployment config check** — `evaluate_kpi.py --scan PATH` diffs a
  config's mandate against the approved one and dry-runs it with the monitor.

Further hardening is discussed in the references but not coded: authenticated
and reviewed config writes, per-agent or asymmetric signing keys with
rotation, behavioural anomaly detection, rate limits, human review before
release from quarantine, and tamper-evident logs.

---

## Project layout

```
owasp-asi10-demo/
├── README.md                          # this lab guide
├── run_demo.py                        # all four acts in one process
├── owasp-asi10-rogue-agent-skill/
│   ├── SKILL.md                       #   metadata + instructions
│   ├── vulnerable_app.py              #   Module 1: fleet, stub model, mitigations
│   ├── requirements.txt               #   stdlib only
│   ├── scripts/
│   │   ├── run_mandate_tamper.py      #   Module 2: the attack
│   │   ├── evaluate_kpi.py            #   Module 3: stoplight KPI, --harden, --scan
│   │   └── reset_baseline.py          #   restore the signed baseline
│   ├── references/
│   │   └── ASI10_RISKS.md             #   research, scenarios, mitigation roadmap
│   ├── assets/
│   │   ├── fleet_baseline.json        #   approved mandates + scheduled work
│   │   ├── tampered_mandate.json      #   placeholder config edit (editable)
│   │   └── tampered_mandate.README.md #   how to write an edit
│   └── tests/
│       └── test_lifecycle.py          #   asserts the four-act story
└── .gitignore
```

## Packaged Claude Skill

`owasp-asi10-rogue-agent-skill/` follows the `SKILL.md` + `scripts/` /
`references/` / `assets/` convention. To install it, copy the folder into your
`.claude/skills/` directory.

```bash
cd owasp-asi10-rogue-agent-skill
python vulnerable_app.py &                                       # start target (:5310)
python scripts/evaluate_kpi.py                                   # baseline (GREEN), exit 0
python scripts/run_mandate_tamper.py                             # attack
python scripts/evaluate_kpi.py                                   # RED, OMAR 100%, exit 2
python scripts/evaluate_kpi.py --scan assets/tampered_mandate.json   # REJECT, exit 2
python scripts/evaluate_kpi.py --harden                          # GREEN, OMAR 0%, exit 0
python scripts/reset_baseline.py                                 # restore clean state
python scripts/evaluate_kpi.py                                   # GREEN, OMAR 0%
python -m unittest discover tests                                # 9 tests
```

## License

MIT — provided for educational and authorized security-testing use.
