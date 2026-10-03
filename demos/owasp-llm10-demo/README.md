# LLM10 — Improper Output Handling Demo

An educational, self-contained demonstration of **LLM10: Improper Output
Handling**. The model's answer is untrusted input to whatever consumes it
next. Here an application pastes it into HTML and splices it into SQL, and
one ticket note is enough to make that output arrive as code. Two mitigations
shut the attack down: **contextual output encoding** and **parameterised
queries**.

The scenario is **"Billy," Goat & Co.'s ticket-summary assistant.** Its
ground truth for the Ridgeview account is _"Ridgeview printer queue restored
and ticket closed by the night shift."_ Billy's summary feeds three sinks: the
account's HTML status page, a markdown weekly digest and a SQLite audit log.
With **1** filed note carrying **1** placeholder line, all three Ridgeview
sinks mishandle the output. The Harbor account goes through the same sinks
and stays untouched.

> ⚠️ **For authorized security education and red-teaming only.** The vulnerable
> assistant, its sinks and its unauthenticated ticket endpoint are insecure
> **by design**. Do not deploy them anywhere reachable.

The shipped payload is a **placeholder**: a marker line, a harmless `<mark>`
highlight tag, an apostrophe and a fictional canary. That is enough to drive
the full lifecycle. To write your own payload, see
`owasp-llm10-sink-skill/assets/poisoned_note.README.md`.

## Interactive web demo (recommended)

The target serves the shared HACTU8 lab console. It has four act cards, a
verification table with Act 1, Act 3 and Act 4 signals side by side, and a
live feed of attack and defence events.

```bash
cd owasp-llm10-sink-skill
python vulnerable_app.py              # then open http://127.0.0.1:5210/
```

Use **Run full sequence** to play all four acts, or click the acts one at a
time. **Reset baseline** restores the clean tickets, empties the audit log and
returns to vulnerable mode. To play the sequence on load, for a presentation,
open `http://127.0.0.1:5210/#run`. The rendered status pages at
`/status/<account>` still work alongside the console.

## Fastest way to run (no browser)

```bash
cd owasp-llm10-demo
python run_demo.py                     # all four acts in one process, stdlib only
```

---

## Why this matters (LLM10 in one paragraph)

Prompt injection (LLM01) is about what goes **into** the model. Improper
output handling is about what comes **out** and where it goes next. An
injection screen on the model's input never sees the problem, because the
dangerous part is not an instruction; it is markup or a quote character that
a downstream interpreter acts on. The OWASP entry's guidance is to treat the
model like any other user: encode its output for the context it lands in,
and bind it as a parameter rather than building statements from it. This demo
makes the gap visible and quantifies it with an **Unsafe Sink Rate (USR)**
and a red/yellow/green **stoplight KPI**.

---

## Quick start

```bash
cd owasp-llm10-demo
python run_demo.py
```

You'll see four acts:

| Act | What happens | Result |
|-----|--------------|--------|
| **1 — Clean baseline** | Render five (account, sink) items from untouched tickets | 🟢 all GREEN, USR 0% |
| **2 — Ticket note** | File 1 note on `ridgeview` with 1 placeholder line | 1 note added, no sink touched |
| **3 — Post-attack impact** | Re-render the exact same items | 🔴 targeted RED, **USR 100% targeted / 60% overall** |
| **4 — Remediation** | Scan the note; switch to hardened mode | 🟢 back to GREEN, USR 0% |

### Optional: run against a real model

The stub is the default backend. `providers.py` (the same provider layer as
AgenticGoat) adds three real ones. All are standard library only:

```bash
python run_demo.py --backend ollama --model llama3.2:3b          # local Ollama
python run_demo.py --backend llamacpp                         # local llama.cpp server
export OPENROUTER_API_KEY=...                                 # remote; key stays in the header
python run_demo.py --backend openrouter --model meta-llama/llama-3.2-3b-instruct

# the target and console take the same settings from the environment:
LLM10_BACKEND=openrouter LLM10_MODEL=... python owasp-llm10-sink-skill/vulnerable_app.py
```

The real model only writes the summary. The ticket notes reach it as plain
text in the user turn, and the prompt is the **same in both modes**: LLM10 is
about what the application does with the output, so there is no
spotlighting to add here. The summary flows into the same three sinks as the
stub's text. Hardened mode escapes it for HTML and binds it as a SQL
parameter, so it holds whatever a real model writes. Nothing the model
returns is fetched or executed.

A real model may not echo the placeholder payload. Write your own test
output (see `assets/poisoned_note.README.md`), and `run_demo.py` reports the
numbers rather than asserting them.

Limits:
- `LAB_MAX_CALLS` (default 200) caps calls per process.
- `LAB_MAX_TOKENS` (default 400) caps output tokens per call.
- `OLLAMA_TIMEOUT`, `LLAMACPP_TIMEOUT` and `OPENROUTER_TIMEOUT` set
  per-provider HTTP timeouts.

With `openrouter`, lab prompts, including your payloads, leave the machine.
The stub and the local backends keep everything on the host.

---

## Architecture

```
                 ┌───────────────────────────────────────────────┐
   "summarise" ─▶│  Billy (vulnerable_app.py :5210)              │
                 │   StubModel → summary (same in both modes)    │
                 └───────┬──────────────┬──────────────┬─────────┘
                         │ f-string     │ raw-HTML     │ string-built
                         ▼              ▼ markdown     ▼ INSERT
                 ┌──────────────┐ ┌──────────────┐ ┌──────────────────┐
                 │ HTML status  │ │ markdown     │ │ SQLite :memory:  │
                 │ page         │ │ digest       │ │ summary_log      │
                 └──────────────┘ └──────────────┘ └──────────────────┘
                         ▲ reads notes
                 ┌───────┴───────────────────────────────────────┐
   seeded data ─▶│  Ticket store (memory, tickets_baseline.json) │
                 │   ridgeview · harbor  + filed note ◀── attack │
                 └───────▲───────────────────────────────────────┘
                         │ POST /tickets/note (no auth)
                 ┌───────┴───────────────────────────────────────┐
   attacker ────▶│  Attack skill (scripts/run_sink_poison.py)    │
                 │   1 note, 1 placeholder line                  │
                 └───────────────────────────────────────────────┘
```

### The modules

1. **Vulnerable target** — [`vulnerable_app.py`](owasp-llm10-sink-skill/vulnerable_app.py).
   It omits output encoding before HTML, raw-HTML filtering in the markdown
   renderer, parameterisation in SQL, and authentication on ticket notes.
2. **Attack skill** — [`scripts/run_sink_poison.py`](owasp-llm10-sink-skill/scripts/run_sink_poison.py).
   Files [`assets/poisoned_note.md`](owasp-llm10-sink-skill/assets/poisoned_note.md)
   on one account through `POST /tickets/note`.
3. **Stoplight KPI comparator** — [`scripts/evaluate_kpi.py`](owasp-llm10-sink-skill/scripts/evaluate_kpi.py).
   Classifies each sink result GREEN/YELLOW/RED and computes the USR.

Plus the mitigation used in Act 4: hardened mode in `vulnerable_app.py`
(`html.escape`, `?` placeholders), with the tripwire `screen_output` and its
rules in [`assets/sink_rules.json`](owasp-llm10-sink-skill/assets/sink_rules.json).

### How the "unsafe sink" is real, not scripted

The model is a deterministic stub with one fixed contract: it emits the text
after any directive line in its context, or else summarises the first note.
That contract is identical in every act and in both modes, and a test proves
the model's output is byte-for-byte the same in vulnerable and hardened mode
(`test_model_output_same_in_both_modes`). What changes is **how the
application handles that output**:

- In vulnerable mode, the HTML sink is an f-string, so the `<mark>` tag in the
  output is parsed as markup. The evaluator finds a tag the template never
  emits.
- The markdown renderer converts `**bold**` and headings and passes any other
  HTML through, as many real renderers do.
- The SQL sink builds `INSERT ... VALUES ('ridgeview', '<summary>')`. The
  apostrophe in the output ends the literal, so SQLite raises a real
  `OperationalError`. Nothing in the code checks for this payload.

Switch to hardened mode and the same text is escaped (`&lt;mark`) and bound
as a parameter, so it is stored exactly and displayed as text. That works even
with an empty tripwire ruleset (`tests/test_lifecycle.py::test_sink_handling_alone_blocks`).
Nothing is hard-coded to flip per item.

### MCP terminology bridge

In MCP, tool results flow into the model's context, and the client then does
something with the model's output. LLM10 lives in that second hop. The ticket
store stands in for a tool, and the three sinks stand in for whatever the
client does with a completion. This demo is **not** an MCP server or client.
Hardened mode is what a careful client should do with any completion: encode
it for its destination and never build code from it.

---

## Live two-terminal demo (optional)

```bash
# Terminal A — start the vulnerable target
cd owasp-llm10-sink-skill
python vulnerable_app.py                                   # serves on 127.0.0.1:5210

# Terminal B — render, attack, re-render
curl -s localhost:5210/render -H 'content-type: application/json' \
     -d '{"account":"ridgeview","sink":"sql"}'             # logged: Summary: Ridgeview printer queue ...

python scripts/run_sink_poison.py                          # 1 note filed

curl -s localhost:5210/render -H 'content-type: application/json' \
     -d '{"account":"ridgeview","sink":"sql"}'             # "error": "sqlite3.OperationalError ..."
curl -s localhost:5210/status/ridgeview                    # raw <mark> in the page
```

Open `http://127.0.0.1:5210/status/ridgeview` in a browser to see the canary
highlighted, which shows that the browser rendered the model's markup.

---

## Mapping to the OWASP LLM10 entry

| Demo component | LLM10 scenario | Failure demonstrated | Mitigation shown |
|----------------|----------------|----------------------|------------------|
| `html` sink / `GET /status/<account>` | Model output rendered in a web page | Markup from the model renders | `html.escape` (hardened mode) |
| `markdown` sink | Model output through a markdown client | Inline HTML passes through the renderer | Escape before rendering |
| `sql` sink | Model output used in a database query | A quote in the output changes the statement | Parameterised query |
| `assets/poisoned_note.md` | Attacker shapes the output indirectly | Nobody typed the payload into the chat | `--scan` tripwire before filing |
| Harbor controls | — | Attack is targeted, not a global break | — |

## Mitigations demonstrated in Act 4

- **Contextual output encoding** — `html.escape` before both HTML sinks.
- **Parameterised queries** — `?` placeholders; the summary is bound as data
  and stored exactly as the model wrote it.
- **Output-sink tripwire** — `screen_output` with `assets/sink_rules.json`
  flags markup, the directive marker and the canary. Hardened mode logs it in
  `screen_findings`; `evaluate_kpi.py --scan PATH` rejects a note before it is
  filed. It is a detector, not the fix.

Further hardening is discussed in the references but not coded here: schema-
validated structured outputs, least-privilege database accounts, sandboxing
for code-executing sinks, and an allowlist for URLs a client may fetch.

### Deviation from the demo plan

The plan (`demos/OWASP_DEMO_PLAN.md`, LLM10) also proposed a markdown renderer
that fetches images and a loopback exfiltration receiver as evidence. That
part is **dropped**: this lab builds no fetching or receiving component. The
markdown sink is kept, without image fetching, and the evidence is the
rendered output and the SQLite error instead of a receiver log.

---

## Project layout

```
owasp-llm10-demo/
├── README.md                          # this lab guide
├── run_demo.py                        # all four acts in one process
├── owasp-llm10-sink-skill/
│   ├── SKILL.md                       #   metadata + instructions
│   ├── vulnerable_app.py              #   Module 1: target, stub model, sinks, mitigation
│   ├── providers.py                   #   optional real-model backends (shared, unchanged)
│   ├── requirements.txt               #   stdlib only
│   ├── web/                           #   shared lab console (index.html, app.js, styles.css)
│   ├── scripts/
│   │   ├── run_sink_poison.py         #   Module 2: the attack
│   │   ├── evaluate_kpi.py            #   Module 3: stoplight KPI, --harden, --scan
│   │   └── reset_baseline.py          #   restore seeded tickets and empty log
│   ├── references/
│   │   └── LLM10_RISKS.md             #   research, scenarios, mitigation roadmap
│   ├── assets/
│   │   ├── tickets_baseline.json      #   ground-truth tickets
│   │   ├── poisoned_note.md           #   placeholder payload (editable)
│   │   ├── poisoned_note.README.md    #   how to write a payload
│   │   └── sink_rules.json            #   tripwire rules (editable)
│   └── tests/
│       └── test_lifecycle.py          #   asserts the four-act story
└── .gitignore
```

## Packaged Claude Skill

`owasp-llm10-sink-skill/` follows the `SKILL.md` + `scripts/` /
`references/` / `assets/` convention. To install it, copy the folder into your
`.claude/skills/` directory.

```bash
cd owasp-llm10-sink-skill
python vulnerable_app.py &                                   # start target (:5210)
python scripts/evaluate_kpi.py                               # baseline (GREEN), exit 0
python scripts/run_sink_poison.py                            # attack
python scripts/evaluate_kpi.py                               # RED, USR 100%, exit 2
python scripts/evaluate_kpi.py --scan assets/poisoned_note.md   # REJECT, exit 2
python scripts/evaluate_kpi.py --harden                      # GREEN, USR 0%, exit 0
python scripts/reset_baseline.py                             # restore clean state
python scripts/evaluate_kpi.py                               # GREEN, USR 0%
python -m unittest discover tests                            # 15 tests
```

## License

MIT — provided for educational and authorized security-testing use.
