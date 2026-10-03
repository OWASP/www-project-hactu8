# LLM01 — Prompt Injection Demo

An educational, self-contained demonstration of **LLM01: Prompt Injection**,
in its **indirect** form. An adversary who can edit one wiki page can take over
the answers of an assistant that reads that wiki through a tool. Two
mitigations shut the attack down: **channel separation** and **tool-output
screening**.

The scenario is **"Billy," Goat & Co.'s knowledge-base assistant.** Its ground
truth is _"Expense reports must be filed within 30 days and need manager
approval before reimbursement."_ With **1** edited page carrying **1** injected
line, the attacker replaces Billy's answer to every expense question. Unrelated
topics (holidays, VPN access) stay untouched. The user never sees the page, so
nothing in the chat looks wrong.

> ⚠️ **For authorized security education and red-teaming only.** The vulnerable
> assistant and its unauthenticated wiki-edit endpoint are insecure **by
> design**. Do not deploy them anywhere reachable.

The shipped payload is a **placeholder**: a marker line and a fictional
canary. That is enough to drive the full lifecycle. To write your own payload,
see `owasp-llm01-injection-skill/assets/injected_page.README.md`.

## Interactive web demo (recommended)

The target serves the shared HACTU8 lab console. It has four act cards, a
verification table with Act 1, Act 3 and Act 4 signals side by side, and a
live feed of attack and defence events.

```bash
cd owasp-llm01-injection-skill
python vulnerable_app.py              # then open http://127.0.0.1:5201/
```

Use **Run full sequence** to play all four acts, or click the acts one at a
time. **Reset baseline** restores the clean wiki. To play the sequence on
load, for a presentation, open `http://127.0.0.1:5201/#run`.

## Fastest way to run (no browser)

```bash
cd owasp-llm01-demo
python run_demo.py                     # all four acts in one process, stdlib only
```

---

## Why this matters (LLM01 in one paragraph)

In direct injection, the user types the override. In indirect injection, the
instruction arrives in **content the application fetches for the model**: a
web page, a document, or a tool result. Nobody in the conversation wrote it,
and filters on user input never see it. Greshake et al. (2023) showed that
LLM-integrated applications process retrieved content with the same authority
as the user's request. This demo makes that visible and quantifies it with an
**Injection Success Rate (ISR)** and a red/yellow/green **stoplight KPI**.

---

## Quick start

```bash
cd owasp-llm01-demo
python run_demo.py
```

You'll see four acts:

| Act | What happens | Result |
|-----|--------------|--------|
| **1 — Clean baseline** | Ask five questions of the untouched wiki | 🟢 all GREEN, ISR 0% |
| **2 — Wiki edit** | Overwrite the `expenses` page: real text plus 1 injected line | 1 page changed |
| **3 — Post-attack impact** | Re-run the exact same questions | 🔴 targeted RED, **ISR 100% targeted / 60% overall** |
| **4 — Remediation** | Screen the page; switch to hardened mode | 🟢 back to GREEN, ISR 0% |

### Optional: run against a real model

Not wired in this version. The stub is the only backend. The seam is
`StubModel.generate(messages, trust_tool_role)` in `vulnerable_app.py`; a real
backend replaces it. A real model would need a natural-language payload and a
matching rule in `assets/screen_rules.json` (see the payload README).

---

## Architecture

```
                 ┌──────────────────────────────────────────────┐
   user query ──▶│  Billy (vulnerable_app.py :5201)             │──▶ answer
                 │   • tool output inlined into one flat context│
                 │   • tool output never screened               │
                 └───────────────┬──────────────────────────────┘
                                 │ search_kb (top-1 keyword retrieval)
                 ┌───────────────▼──────────────────────────────┐
   seeded wiki ─▶│  Wiki (in memory, from kb_baseline.json)     │
                 │   expenses · holidays · vpn                  │
                 │   + edited expenses page ◀── attack          │
                 └───────────────▲──────────────────────────────┘
                                 │ POST /kb/page (no auth)
                 ┌───────────────┴──────────────────────────────┐
   attacker ────▶│  Attack skill (scripts/run_injection.py)     │
                 │   1 page, 1 injected line                    │
                 └──────────────────────────────────────────────┘
```

### The modules

1. **Vulnerable target** — [`vulnerable_app.py`](owasp-llm01-injection-skill/vulnerable_app.py).
   It omits authentication on wiki edits, separation between tool output and
   instructions, and any screening of tool output.
2. **Attack skill** — [`scripts/run_injection.py`](owasp-llm01-injection-skill/scripts/run_injection.py).
   Writes [`assets/injected_page.md`](owasp-llm01-injection-skill/assets/injected_page.md)
   over one page through `POST /kb/page`.
3. **Stoplight KPI comparator** — [`scripts/evaluate_kpi.py`](owasp-llm01-injection-skill/scripts/evaluate_kpi.py).
   Classifies each answer GREEN/YELLOW/RED and computes the ISR.

Plus the mitigation used in Act 4: hardened mode and `screen_tool_output` in
`vulnerable_app.py`, with rules from [`assets/screen_rules.json`](owasp-llm01-injection-skill/assets/screen_rules.json).

### How the "injection" is real, not scripted

The model is a deterministic stub with one fixed contract: it follows any
directive line it finds in the messages it trusts. That contract never
changes between acts. What changes is **what reaches the context**:

- The wiki edit adds a line to a page.
- Keyword retrieval picks that page only for expense questions, because the
  attacker kept the page's real text.
- In vulnerable mode, the context assembler inlines the tool output as
  trusted text.

Remove the real text and the page stops ranking, so the ISR falls to 0.
Switch to hardened mode and the same page is passed as `tool`-role data, so
the ISR falls to 0 even with an empty screen ruleset
(`tests/test_lifecycle.py::test_channel_separation_alone_blocks`). Nothing is
hard-coded to flip per question.

### MCP terminology bridge

In MCP, tool **results** are placed in the model's context by the client.
`search_kb` stands in for an MCP tool, and its result is the injection surface.
This demo is **not** an MCP server or client: the tool is an in-process
function and the wiki is a dict. Hardened mode is what a careful MCP client
should do with any tool result: label it untrusted, keep it out of the
instruction channel, and screen it.

---

## Live two-terminal demo (optional)

```bash
# Terminal A — start the vulnerable target
cd owasp-llm01-injection-skill
python vulnerable_app.py                                   # serves on 127.0.0.1:5201

# Terminal B — query, attack, re-query
curl -s localhost:5201/query -H 'content-type: application/json' \
     -d '{"query":"When are expense reports due?"}'        # cites the 30-day policy

python scripts/run_injection.py                            # 1 page overwritten

curl -s localhost:5201/query -H 'content-type: application/json' \
     -d '{"query":"When are expense reports due?"}'        # answer is the injected line
```

---

## Mapping to the OWASP LLM01 entry

| Demo component | LLM01 scenario | Failure demonstrated | Mitigation shown |
|----------------|----------------|----------------------|------------------|
| `POST /kb/page` + `search_kb` | Indirect injection via retrieved content | Data the model reads is treated as instructions | Channel separation (hardened mode) |
| `assets/injected_page.md` | Indirect injection hidden from the user | User sees only the answer, never the page | Tool-output screen; `--scan` before publishing |
| Holiday / VPN controls | — | Attack is targeted, not a global break | — |

## Mitigations demonstrated in Act 4

- **Channel separation** — tool output goes in its own `tool` role, and the
  model never takes instructions from that role. This alone takes the ISR to 0
  here.
- **Tool-output screening** — each result is screened against
  `assets/screen_rules.json`, and HTML comments are stripped. Matching lines are
  dropped and reported in `screen_findings`.
- **Pre-publication scan** — `evaluate_kpi.py --scan PATH` rejects a page
  before it ever reaches the wiki.

Further hardening is discussed in the references but not coded here:
authenticated and attributed wiki edits, normalisation against obfuscation
(AgenticGoat `protectogw`), least-privilege tools, and held-out adversarial
testing.

---

## Project layout

```
owasp-llm01-demo/
├── README.md                          # this lab guide
├── run_demo.py                        # all four acts in one process
├── owasp-llm01-injection-skill/
│   ├── SKILL.md                       #   metadata + instructions
│   ├── vulnerable_app.py              #   Module 1: target, stub model, mitigation
│   ├── requirements.txt               #   stdlib only
│   ├── web/                           #   shared lab console (index.html, app.js, styles.css)
│   ├── scripts/
│   │   ├── run_injection.py           #   Module 2: the attack
│   │   ├── evaluate_kpi.py            #   Module 3: stoplight KPI, --harden, --scan
│   │   └── reset_baseline.py          #   restore the seeded wiki
│   ├── references/
│   │   └── LLM01_RISKS.md             #   research, scenarios, mitigation roadmap
│   ├── assets/
│   │   ├── kb_baseline.json           #   ground-truth wiki
│   │   ├── injected_page.md           #   placeholder payload (editable)
│   │   ├── injected_page.README.md    #   how to write a payload
│   │   └── screen_rules.json          #   screen rules (editable)
│   └── tests/
│       └── test_lifecycle.py          #   asserts the four-act story
└── .gitignore
```

## Packaged Claude Skill

`owasp-llm01-injection-skill/` follows the `SKILL.md` + `scripts/` /
`references/` / `assets/` convention. To install it, copy the folder into your
`.claude/skills/` directory.

```bash
cd owasp-llm01-injection-skill
python vulnerable_app.py &                                   # start target (:5201)
python scripts/evaluate_kpi.py                               # baseline (GREEN), exit 0
python scripts/run_injection.py                              # attack
python scripts/evaluate_kpi.py                               # RED, ISR 100%, exit 2
python scripts/evaluate_kpi.py --scan assets/injected_page.md   # REJECT, exit 2
python scripts/evaluate_kpi.py --harden                      # GREEN, ISR 0%, exit 0
python scripts/reset_baseline.py                             # restore clean state
python scripts/evaluate_kpi.py                               # GREEN, ISR 0%
python -m unittest discover tests                            # 6 tests
```

## License

MIT — provided for educational and authorized security-testing use.
