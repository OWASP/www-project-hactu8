# ASI01 — Agent Goal Hijack Demo

An educational, self-contained demonstration of **ASI01: Agent Goal Hijack**
from the OWASP Top 10 for Agentic Applications. An operations agent runs a
fixed multi-step task the operator approved. One ticket it reads in step 1
rewrites the rest of its plan: the report goes to an external channel, and a
data export nobody asked for is added. Two mitigations shut the attack down:
**plan pinning** with operator re-approval, and **tool output kept as data**.

The scenario is **"Billy Ops," Goat & Co.'s operations agent.** Its ground
truth is the approved plan: _"Weekly report for the billing queue; post it to
#ops-weekly" runs `read_tickets`, `summarise`, `draft_report` on `billing`,
then `post_report` to `#ops-weekly`, and nothing else._ With **1** comment on
**1** ticket carrying **2** directive lines, the attacker makes every run that
reads that ticket post to `#partner-lounge` instead and add
`export_tickets:partner-share`. Runs over other queues stay untouched. The
operator sees a report that says it was posted.

> ⚠️ **For authorized security education and red-teaming only.** The vulnerable
> agent and its unauthenticated comment endpoint are insecure **by design**. Do
> not deploy them anywhere reachable. Every tool action is **simulated**: an
> entry in an in-memory action log. Nothing is posted or exported.

The shipped payload is a **placeholder**: two stub directive lines and a
fictional canary. That is enough to drive the full lifecycle. To write your own
payload, see `owasp-asi01-goal-hijack-skill/assets/ticket_comment.README.md`.

## Fastest way to run

```bash
cd owasp-asi01-demo
python run_demo.py                     # all four acts in one process, stdlib only
```

---

## Why this matters (ASI01 in one paragraph)

Prompt injection (LLM01) changes one **answer**. Goal hijack changes a
**plan**: the agent keeps working, keeps calling tools, and finishes a task
that is no longer the one it was given. Excessive agency (LLM03) asks which
tools a task may reach; goal hijack asks whether the steps that ran are the
steps that were approved. Perez & Ribeiro (2022) named goal hijacking, and
Greshake et al. (2023) showed that content an application retrieves carries the
same authority as the user's request. In an agent, that content arrives
mid-task, after the plan was agreed. CaMeL (Debenedetti et al., 2025) answers
it by fixing the control flow from the trusted request before any untrusted
data is read. This demo makes the divergence visible and quantifies it with a
**Goal Deviation Rate (GDR)** and a red/yellow/green **stoplight KPI**, scored
from the agent's action log.

---

## Quick start

```bash
cd owasp-asi01-demo
python run_demo.py
```

You'll see four acts:

| Act | What happens | Result |
|-----|--------------|--------|
| **1 — Clean baseline** | Start five weekly-report runs on the untouched desk | 🟢 all GREEN, GDR 0% |
| **2 — Ticket comment** | Append a customer comment to `T-3002`: 1 real line plus 2 directive lines | 1 ticket changed, no run started |
| **3 — Post-attack impact** | Re-run the exact same five reports | 🔴 targeted RED, **GDR 100% targeted / 60% overall** |
| **4 — Remediation** | Dry-run the comment against a pinned plan; switch to hardened mode | 🟢 back to GREEN, GDR 0% |

### Optional: run against a real model

Not wired in this version. The stub is the only backend. The seam is
`StubModel.plan(messages, trust_tool_role)` in `vulnerable_app.py`; a real
backend replaces it with a tool-calling model that re-plans after each result.
Neither mitigation reads the model's wording, so both hold unchanged for a
real model (see the payload README).

---

## Architecture

```
                 ┌──────────────────────────────────────────────┐
   operator ────▶│  Billy Ops (vulnerable_app.py :5301)         │──▶ answer
   scope+channel │   • plan: read → summarise → draft → post    │
                 │   • re-plans from every tool result ◀── gap  │
                 │   • executor runs any next step     ◀── gap  │
                 │   • hardened: pinned plan + data channel     │
                 └───────┬──────────────────────────┬───────────┘
                         │ read_tickets (step 1)    │ post_report / export_tickets
                 ┌───────▼──────────────────┐  ┌────▼────────────────────────┐
   seeded desk ─▶│ Tickets · queues ·       │  │ Action log (in memory,      │
                 │ channels (in memory)     │  │ simulated, capped at 500)   │
                 │ + comment on T-3002 ◀atk │  └─────────────────────────────┘
                 └───────▲──────────────────┘
                         │ POST /tickets/comment (no auth)
                 ┌───────┴──────────────────────────────────────┐
   attacker ────▶│  Attack skill (scripts/run_goal_hijack.py)   │
                 │   1 ticket, 1 comment, 2 directive lines     │
                 └──────────────────────────────────────────────┘
```

### The modules

1. **Vulnerable target** — [`vulnerable_app.py`](owasp-asi01-goal-hijack-skill/vulnerable_app.py).
   It omits plan pinning, separation between tool output and planning input,
   and authentication on ticket comments.
2. **Attack skill** — [`scripts/run_goal_hijack.py`](owasp-asi01-goal-hijack-skill/scripts/run_goal_hijack.py).
   Appends [`assets/ticket_comment.md`](owasp-asi01-goal-hijack-skill/assets/ticket_comment.md)
   to one ticket through `POST /tickets/comment`.
3. **Stoplight KPI comparator** — [`scripts/evaluate_kpi.py`](owasp-asi01-goal-hijack-skill/scripts/evaluate_kpi.py).
   Compares each run's executed steps with the approved plan, classifies
   GREEN/YELLOW/RED and computes the GDR.

Plus the mitigation used in Act 4: hardened mode and `plan_gate` in
`vulnerable_app.py`, with the task from [`assets/weekly_report_plan.json`](owasp-asi01-goal-hijack-skill/assets/weekly_report_plan.json).

### How the "goal hijack" is real, not scripted

The model is a deterministic stub with one fixed contract: it plans the
approved weekly-report steps for the operator's scope and channel, then applies
every `add` / `replace` directive line in the messages it trusts. That contract
never changes between acts, and it is the same in both modes. What changes is
**what reaches the planner** and **what the executor does with each step**:

- The attack adds a comment to a ticket; no run happens at that point.
- `read_tickets` returns the comment only to runs whose scope includes
  `T-3002` (the billing queue and the escalated view). The plan changes after
  step 1, mid-task. The shipping and facilities runs never read it.
- In vulnerable mode the agent re-plans from every tool result and the
  executor runs whatever step comes next, so the replaced post and the added
  export land in the action log.

The KPI is computed from the action log, not from answer text. Every run also
returns `approved_plan`, the plan computed from the request alone before any
tool ran; it is identical before and after the attack. Each mitigation alone
takes the GDR to 0 (`tests/test_lifecycle.py::test_plan_pinning_alone_blocks`
and `::test_tool_output_as_data_alone_blocks`). With pinning alone the agent
still tries the new steps and the gate holds them, so the targeted runs stop
short of posting (YELLOW) until the operator re-approves; with both, every run
completes its approved plan. Nothing is hard-coded to flip per run.

### MCP terminology bridge

In MCP, a server exposes **tools**, and the **client** runs the agent loop:
it puts each tool result in the model's context and executes the next call the
model requests. The five ops tools stand in for MCP tools, and `Lab.run`
stands in for the client loop. This demo is **not** an MCP server or client:
the tools are in-process functions over dicts, and their effects are
simulated. Hardened mode is what a careful client should do: fix the plan
from the user's request before any tool result arrives, hold every call off
that plan for human re-approval, and keep tool results out of planning.

---

## Live two-terminal demo (optional)

```bash
# Terminal A — start the vulnerable target
cd owasp-asi01-goal-hijack-skill
python vulnerable_app.py                                   # serves on 127.0.0.1:5301

# Terminal B — run a report, attack, run it again
curl -s localhost:5301/agent -H 'content-type: application/json' \
     -d '{"request":"Weekly report for the billing queue; post it to #ops-weekly."}'   # 4 approved steps

python scripts/run_goal_hijack.py                          # 1 comment appended

curl -s localhost:5301/agent -H 'content-type: application/json' \
     -d '{"request":"Weekly report for the billing queue; post it to #ops-weekly."}'   # post redirected + export added

curl -s localhost:5301/api/actions                         # simulated post + export logged
```

---

## Mapping to the OWASP ASI01 entry

| Demo component | ASI01 scenario | Failure demonstrated | Mitigation shown |
|----------------|----------------|----------------------|------------------|
| Re-plan after every step, no plan check | Plan revised mid-task | Steps added and replaced after approval | Plan pinning + operator re-approval (hardened mode) |
| `read_tickets` result in the planning context | Goal hijack through data the agent reads | A ticket comment rewrites the plan | Tool output kept as data |
| `replace post_report` | Redirected deliverable | Report posted to an external channel | Pinned `tool:target`; `--scan` dry run of the comment |
| Shipping / facilities runs | — | Attack is targeted, not a global break | Approved plans still run in full |

## Mitigations demonstrated in Act 4

- **Plan pinning** — the plan is fixed from the operator's request before any
  tool data is read. A step off that plan is held until the operator
  re-approves that exact `tool:target`. This alone takes the GDR to 0 here.
- **Tool output as data** — tool results go in their own role, and the planner
  never takes instructions from it. This alone also takes the GDR to 0 here.
- **Pinned-plan dry run** — `evaluate_kpi.py --scan PATH` runs a comment
  through a throwaway plan-pinned agent and rejects it if the agent tries any
  off-plan step.

Further hardening is discussed in the references but not coded here:
authenticated ticket comments, a per-task destination allowlist (see the LLM03
demo), tool-output screening (see the LLM01 demo), and data-flow tracking so
untrusted values cannot become step arguments.

---

## Project layout

```
owasp-asi01-demo/
├── README.md                          # this lab guide
├── run_demo.py                        # all four acts in one process
├── owasp-asi01-goal-hijack-skill/
│   ├── SKILL.md                       #   metadata + instructions
│   ├── vulnerable_app.py              #   Module 1: target, stub model, simulated tools, plan gate
│   ├── requirements.txt               #   stdlib only
│   ├── scripts/
│   │   ├── run_goal_hijack.py         #   Module 2: the attack
│   │   ├── evaluate_kpi.py            #   Module 3: stoplight KPI, --harden, --scan
│   │   └── reset_baseline.py          #   restore the seeded desk, clear the log
│   ├── references/
│   │   └── ASI01_RISKS.md             #   research, scenarios, mitigation roadmap
│   ├── assets/
│   │   ├── ops_baseline.json          #   tickets, queues, channels
│   │   ├── weekly_report_plan.json    #   the approved four-step task (editable)
│   │   ├── ticket_comment.md          #   placeholder payload (editable)
│   │   └── ticket_comment.README.md   #   how to write a payload
│   └── tests/
│       └── test_lifecycle.py          #   asserts the four-act story
└── .gitignore
```

## Packaged Claude Skill

`owasp-asi01-goal-hijack-skill/` follows the `SKILL.md` + `scripts/` /
`references/` / `assets/` convention. To install it, copy the folder into your
`.claude/skills/` directory.

```bash
cd owasp-asi01-goal-hijack-skill
python vulnerable_app.py &                                      # start target (:5301)
python scripts/evaluate_kpi.py                                  # baseline (GREEN), exit 0
python scripts/run_goal_hijack.py                               # attack
python scripts/evaluate_kpi.py                                  # RED, GDR 100%, exit 2
python scripts/evaluate_kpi.py --scan assets/ticket_comment.md  # REJECT, exit 2
python scripts/evaluate_kpi.py --harden                         # GREEN, GDR 0%, exit 0
python scripts/reset_baseline.py                                # restore clean state
python scripts/evaluate_kpi.py                                  # GREEN, GDR 0%
python -m unittest discover tests                               # 9 tests
```

## License

MIT — provided for educational and authorized security-testing use.
