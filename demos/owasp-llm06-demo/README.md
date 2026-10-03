# LLM06 — Unbounded Consumption Demo

An educational, self-contained demonstration of **LLM06: Unbounded
Consumption** in an agent loop. An adversary who can edit three wiki pages can
make an assistant's requests cost more than 500 times what they should: one
through **runaway output**, one through a **tool-call storm**, and one through
a **recursive agent loop**. A fourth path, a **denial-of-wallet** flood, keeps
each request cheap and runs up the total instead. A **per-request budget**, a
**loop depth cap** and a **per-client quota** shut it all down. All cost is
simulated token and dollar accounting; nothing is billed.

The scenario is **"Billy," Goat & Co.'s agentic knowledge-base assistant.**
Its budget is _"6,000 input tokens, 400 output tokens, 8 tool calls and 4
agent steps per request"_; a normal question costs about 175 tokens and
$0.001. With **3** edited pages carrying **1** directive line each, the
attacker pushes the expense, travel and payroll questions to 12,800–92,400
tokens each. Billy's answers still read correctly, so nobody in the chat sees
anything wrong. Holiday and VPN questions stay untouched.

> ⚠️ **For authorized security education and red-teaming only.** The vulnerable
> assistant and its unauthenticated wiki-edit endpoint are insecure **by
> design**. Do not deploy them anywhere reachable.

The shipped payloads are **placeholders**: a marker line and a fictional
canary each. That is enough to drive the full lifecycle. To write your own,
see the `owasp-llm06-consumption-skill/assets/*.README.md` files.

## Interactive web demo (recommended)

The target serves the shared HACTU8 lab console. It has four act cards, a
verification table with Act 1, Act 3 and Act 4 signals side by side, and a
live feed of attack and defence events.

```bash
cd owasp-llm06-consumption-skill
python vulnerable_app.py              # then open http://127.0.0.1:5206/
```

Use **Run full sequence** to play all four acts, or click the acts one at a
time. **Reset baseline** restores the clean wiki and clears the spend ledger.
To play the sequence on load, for a presentation, open
`http://127.0.0.1:5206/#run`.

## Fastest way to run (no browser)

```bash
cd owasp-llm06-demo
python run_demo.py                     # all four acts in one process, stdlib only
```

---

## Why this matters (LLM06 in one paragraph)

Prompt injection (LLM01) is about **what** the model does. Unbounded
consumption is about **how much** it does. An agent loop multiplies cost: every
step re-sends the whole context, every tool result can ask for more tool calls,
and nothing in the answer reveals the bill. Shumailov et al. (2021) showed that
crafted inputs can drive a model's energy and latency far above normal, and the
OWASP entry adds denial of wallet: spend that is harmful even when every
single request looks reasonable. This demo makes that visible and quantifies
it with a **Budget Breach Rate (BBR)**, the run's **simulated spend**, and a
red/yellow/green **stoplight KPI**.

---

## Quick start

```bash
cd owasp-llm06-demo
python run_demo.py
```

You'll see four acts:

| Act | What happens | Result |
|-----|--------------|--------|
| **1 — Clean baseline** | Ask five questions of the untouched wiki | 🟢 all GREEN, BBR 0%, $0.0049 |
| **2 — Wiki edits** | Overwrite `expenses`, `payroll`, `travel`: real text plus 1 directive line each | 3 pages changed |
| **3 — Post-attack impact** | Re-run the exact same questions | 🔴 targeted RED, **BBR 100% targeted / 60% overall**, $0.7186 |
| **4 — Remediation** | Lint the pages; switch to hardened mode | 🟢 back to GREEN, BBR 0%, $0.0154 |

The live-server flow adds the flood: `run_consumption.py --flood 40` against
hardened mode, where the per-client quota refuses the `attacker` client after
about 10,000 tokens.

### Optional: run against a real model

Not wired in this version. The stub is the only backend, and that is
deliberate: a real backend would spend real money. The seam is
`StubModel.step(messages, allow_tools)` in the skill's `vulnerable_app.py`; a
real backend replaces it and reports token usage from the provider's response.
A real model would need natural-language payloads (see the payload READMEs).

---

## Architecture

```
                 ┌──────────────────────────────────────────────┐
   user query ──▶│  Billy agent loop (vulnerable_app.py :5206)  │──▶ answer
                 │   • meters tokens/calls/steps, enforces none │    + simulated
                 │   • no loop depth cap, no per-client quota   │      cost
                 └───────────────┬──────────────────────────────┘
                                 │ search_kb (top-1 keyword retrieval)
                                 │ repeated as often as the model asks
                 ┌───────────────▼──────────────────────────────┐
   seeded wiki ─▶│  Wiki (in memory, from kb_baseline.json)     │
                 │   expenses, travel, payroll, holidays, vpn   │
                 │   + 3 edited pages ◀── attack                │
                 └───────────────▲──────────────────────────────┘
                                 │ POST /kb/page (no auth)
                 ┌───────────────┴──────────────────────────────┐
   attacker ────▶│  Attack skill (scripts/run_consumption.py)   │
                 │   3 pages, 1 directive line each; --flood N  │
                 └──────────────────────────────────────────────┘
```

### The modules

1. **Vulnerable target** — [`vulnerable_app.py`](owasp-llm06-consumption-skill/vulnerable_app.py).
   It omits budget enforcement, a loop depth cap, a per-client quota and
   authentication on wiki edits.
2. **Attack skill** — [`scripts/run_consumption.py`](owasp-llm06-consumption-skill/scripts/run_consumption.py).
   Writes [`runaway_output.md`](owasp-llm06-consumption-skill/assets/runaway_output.md),
   [`tool_storm.md`](owasp-llm06-consumption-skill/assets/tool_storm.md) and
   [`recursive_loop.md`](owasp-llm06-consumption-skill/assets/recursive_loop.md)
   through `POST /kb/page`; `--flood N` sends N requests from one client.
3. **Stoplight KPI comparator** — [`scripts/evaluate_kpi.py`](owasp-llm06-consumption-skill/scripts/evaluate_kpi.py).
   Classifies each request from its metered cost and computes the BBR and the
   simulated spend.

Plus the mitigation used in Act 4: hardened mode and `scan_page` in
`vulnerable_app.py`, with caps from [`assets/budget.json`](owasp-llm06-consumption-skill/assets/budget.json).

### How the "consumption" is real, not scripted

The model is a deterministic stub with one fixed contract: it calls
`search_kb` once, then obeys any `repeat`, `fanout` or `lookup` directive in the
latest tool results, and otherwise answers from the first page it retrieved.
That contract never changes between acts. What changes is **what reaches the
context** and **how the loop handles what the model emits**:

- The wiki edits add one directive line to each of three pages.
- Keyword retrieval picks those pages only for their own topics, because the
  attacker kept the real text.
- The vulnerable loop executes every call the model asks for and re-sends the
  whole, growing context each step. The token counts come from that real
  loop: 49 lookups re-sending a growing context add up to about 92,000 input
  tokens.
- The hardened loop enforces the same budget the vulnerable loop only meters:
  it drops calls past the cap, disables tools on the last allowed step, and
  truncates output at the remaining output budget.

Remove the real text and a page stops ranking, so its question returns to
GREEN. The hardened loop needs no knowledge of the payloads: the lint is a
second, independent layer. Nothing is hard-coded to flip per question.

### MCP terminology bridge

In MCP, the **client** runs the loop that sends tool calls to servers and puts
results back in the model's context. `search_kb` stands in for an MCP tool,
and `Lab.query` for the client's loop. This demo is **not** an MCP server or
client: the tool is an in-process function and the wiki is a dict. Hardened
mode is what a careful MCP client should do: meter every step and stop at a
budget the model cannot negotiate.

---

## Live two-terminal demo (optional)

```bash
# Terminal A — start the vulnerable target
cd owasp-llm06-consumption-skill
python vulnerable_app.py                                   # serves on 127.0.0.1:5206

# Terminal B — query, attack, re-query
curl -s localhost:5206/query -H 'content-type: application/json' \
     -d '{"query":"How far ahead must business travel be booked?"}'   # ~177 tokens, 1 call

python scripts/run_consumption.py                          # 3 pages overwritten

curl -s localhost:5206/query -H 'content-type: application/json' \
     -d '{"query":"How far ahead must business travel be booked?"}'   # ~92,400 tokens, 49 calls
```

---

## Mapping to the OWASP LLM06 entry

| Demo component | LLM06 scenario | Failure demonstrated | Mitigation shown |
|----------------|----------------|----------------------|------------------|
| `runaway_output.md` → `expenses` | Resource-intensive queries | 400x output, answer still correct | Output-token cap |
| `tool_storm.md` → `payroll` | Resource-intensive queries | 200 tool calls in one request | Tool-call cap per request |
| `recursive_loop.md` → `travel` | Continuous input overflow | 50-step loop re-sending the context | Loop depth cap; tools disabled on the last step |
| `run_consumption.py --flood` | Denial of wallet | Cheap requests add up without limit | Per-client quota (HTTP 429) |
| `POST /kb/page` | — | Unauthenticated content reaches the loop | `--scan` budget lint before publishing |
| Holiday / VPN controls | — | Attack is targeted, not a global break | — |

## Mitigations demonstrated in Act 4

- **Per-request budget** — input tokens, output tokens, tool calls and agent
  steps are enforced, not only metered. The check is ported from AgenticGoat
  `acts._consumption_guard`.
- **Loop depth cap** — on the last allowed step, tools are disabled, so the
  model must answer from what it already retrieved.
- **Per-client quota** — a client's cumulative simulated tokens are checked
  before each request, and the request is refused with HTTP 429 once spent.
- **Pre-publication lint** — `evaluate_kpi.py --scan PATH` rejects a page that
  carries directives and reports the amplification each would cause.
- **Outlier alerts** — every `/query` result lists dimensions at 80% or more
  of their cap, so a near-limit request is visible before it breaches.

Further hardening is discussed in the references but not coded here:
wall-clock timeouts, per-second rate limits, fleet-level spend ceilings with
automatic shutoff, and authenticated wiki edits (see LLM01).

---

## Project layout

```
owasp-llm06-demo/
├── README.md                          # this lab guide
├── run_demo.py                        # all four acts in one process
├── owasp-llm06-consumption-skill/
│   ├── SKILL.md                       #   metadata + instructions
│   ├── vulnerable_app.py              #   Module 1: target, agent loop, stub model, mitigation
│   ├── requirements.txt               #   stdlib only
│   ├── web/                           #   shared lab console (index.html, app.js, styles.css)
│   ├── scripts/
│   │   ├── run_consumption.py         #   Module 2: the attack (+ --flood)
│   │   ├── evaluate_kpi.py            #   Module 3: stoplight KPI, --harden, --scan
│   │   └── reset_baseline.py          #   restore the seeded wiki and ledger
│   ├── references/
│   │   └── LLM06_RISKS.md             #   research, scenarios, mitigation roadmap
│   ├── assets/
│   │   ├── kb_baseline.json           #   ground-truth wiki
│   │   ├── budget.json                #   caps, quota, simulated prices, lint rules
│   │   ├── runaway_output.md          #   placeholder payload (editable)
│   │   ├── tool_storm.md              #   placeholder payload (editable)
│   │   ├── recursive_loop.md          #   placeholder payload (editable)
│   │   └── *.README.md                #   how to write each payload
│   └── tests/
│       └── test_lifecycle.py          #   asserts the four-act story
└── .gitignore
```

## Packaged Claude Skill

`owasp-llm06-consumption-skill/` follows the `SKILL.md` + `scripts/` /
`references/` / `assets/` convention. To install it, copy the folder into your
`.claude/skills/` directory.

```bash
cd owasp-llm06-consumption-skill
python vulnerable_app.py &                                     # start target (:5206)
python scripts/evaluate_kpi.py                                 # baseline (GREEN), exit 0
python scripts/run_consumption.py                              # attack
python scripts/evaluate_kpi.py                                 # RED, BBR 100%, exit 2
python scripts/evaluate_kpi.py --scan assets/tool_storm.md     # REJECT, exit 2
python scripts/evaluate_kpi.py --harden                        # GREEN, BBR 0%, exit 0
python scripts/run_consumption.py --flood 40                   # quota refuses the attacker
python scripts/reset_baseline.py                               # restore clean state
python scripts/evaluate_kpi.py                                 # GREEN, BBR 0%
python -m unittest discover tests                              # 7 tests
```

## License

MIT — provided for educational and authorized security-testing use.
