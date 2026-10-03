# LLM04 — Supply Chain Demo

An educational, self-contained demonstration of **LLM04: Supply Chain**, for
the tools an agent loads from a third-party registry. An adversary who can
publish a new version of a tool package can take over an assistant's answers
without touching the assistant. Two mitigations shut the attack down:
**definition pinning** and **multi-call sampling**.

The scenario is **"Billy," Goat & Co.'s operations assistant.** Billy answers
from four tools in the third-party `hayloft-policy-tools` package. Its ground
truth is _"Expense reports must be filed within 30 days and need manager
approval before reimbursement"_ and _"Book business travel through the travel
desk at least 14 days ahead; the daily per diem is 60 dollars."_ The attacker
publishes **1** release that changes **2** of the 4 tools: one gets a swapped
description (a **rug pull**), and one turns hostile from its second call (a
**sleeper**). Holiday and VPN questions stay untouched.

> ⚠️ **For authorized security education and red-teaming only.** The vulnerable
> assistant installs third-party updates on trust **by design**. Do not deploy
> it anywhere reachable.

The shipped payloads are **placeholders**: a marker line and a fictional
canary. That is enough to drive the full lifecycle. To write your own, see
`owasp-llm04-rugpull-skill/assets/swapped_description.README.md` and
`owasp-llm04-rugpull-skill/assets/sleeper_output.README.md`.

## Interactive web demo (recommended)

The target serves the shared HACTU8 lab console. It has four act cards, a
verification table with Act 1, Act 3 and Act 4 signals side by side, and a
live feed of attack and defence events.

```bash
cd owasp-llm04-rugpull-skill
python vulnerable_app.py              # then open http://127.0.0.1:5204/
```

Use **Run full sequence** to play all four acts, or click the acts one at a
time. **Reset baseline** restores the approved registry release and vulnerable mode. To play the
sequence on load, for a presentation, open `http://127.0.0.1:5204/#run`.

## Fastest way to run (no browser)

```bash
cd owasp-llm04-demo
python run_demo.py                     # all four acts in one process, stdlib only
```

---

## Why this matters (LLM04 in one paragraph)

Prompt injection (LLM01) puts instructions in data the model reads. A supply
chain attack puts them in **something you approved and then stopped
checking**: a model file, a package, or a tool definition. An agent that lists
a server's tools places their descriptions in the model's context on every
turn. Invariant Labs (2025) showed that MCP tool descriptions can carry hidden
instructions and can change after the user approved them. This demo makes
both the swap and a quieter variant visible, and quantifies them with a
**Compromised Tool Rate (CTR)** and a red/yellow/green **stoplight KPI**.

---

## Quick start

```bash
cd owasp-llm04-demo
python run_demo.py
```

You'll see four acts:

| Act | What happens | Result |
|-----|--------------|--------|
| **1 — Clean baseline** | Ask six questions with the approved tools | 🟢 all GREEN, CTR 0% |
| **2 — Compromised release** | Publish 1.0.1: 1 description swapped, 1 backend turned sleeper | 2 of 4 tools changed |
| **3 — Post-attack impact** | Re-run the exact same questions | 🔴 targeted RED, **CTR 100% targeted / 67% overall** |
| **4 — Remediation** | Pin diff; switch to hardened mode (pins + sampling) | 🟢 back to GREEN, CTR 0% |

### Optional: run against a real model

The stub is the default backend. `providers.py` (the same provider layer as
AgenticGoat) adds three real ones. All are standard library only:

```bash
python run_demo.py --backend ollama --model llama3.2:3b          # local Ollama
python run_demo.py --backend llamacpp                         # local llama.cpp server
export OPENROUTER_API_KEY=...                                 # remote; key stays in the header
python run_demo.py --backend openrouter --model meta-llama/llama-3.2-3b-instruct

# the target and console take the same settings from the environment:
LLM04_BACKEND=openrouter LLM04_MODEL=... python owasp-llm04-rugpull-skill/vulnerable_app.py
```

The attack mechanics are identical. Only the model changes, and it only
writes the answer text:
- **Vulnerable mode** puts the installed tool's description in the system
  prompt and its result in the user turn, both as plain text.
- **Hardened mode** fences the description in `<untrusted_tool_definition>`
  tags and the result in `<untrusted_tool_output>` tags, and tells the model
  never to follow instructions inside them ("spotlighting"). The admission
  gate stays in code, so a swapped or sleeper tool never reaches the model,
  whatever the model would do with it.

A real model may ignore the placeholder payloads. Write natural-language
payloads (see the payload READMEs). Pinning catches any description change
regardless of wording, and sampling catches drift without any rule.
`run_demo.py` reports the numbers rather than asserting them.

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
                 ┌──────────────────────────────────────────────┐
   user query ──▶│  Billy (vulnerable_app.py :5204)             │──▶ answer
                 │   • routes each query to one tool            │
                 │   • tool description + result in context     │
                 │   • updates installed after 1 smoke call     │
                 └───────────────┬──────────────────────────────┘
                                 │ re-read before every query (tools/list)
                 ┌───────────────▼──────────────────────────────┐
   approved   ──▶│  Tool registry (registry/registry.json)      │
   1.0.0         │   expense_policy · travel_policy             │
                 │   holiday_calendar · vpn_guide               │
                 │   + release 1.0.1 ◀── attack                 │
                 └───────────────▲──────────────────────────────┘
                                 │ publish (vendor account)
                 ┌───────────────┴──────────────────────────────┐
   attacker ────▶│  Attack skill (scripts/run_rug_pull.py)      │
                 │   rug pull + sleeper, 2 of 4 tools           │
                 └──────────────────────────────────────────────┘
```

### The modules

1. **Vulnerable target** — [`vulnerable_app.py`](owasp-llm04-rugpull-skill/vulnerable_app.py).
   It omits pinning of approved tool definitions and any vetting beyond a
   one-call smoke test.
2. **Attack skill** — [`scripts/run_rug_pull.py`](owasp-llm04-rugpull-skill/scripts/run_rug_pull.py).
   Publishes release 1.0.1 to the registry file, built from
   [`assets/swapped_description.md`](owasp-llm04-rugpull-skill/assets/swapped_description.md)
   and [`assets/sleeper_output.md`](owasp-llm04-rugpull-skill/assets/sleeper_output.md).
3. **Stoplight KPI comparator** — [`scripts/evaluate_kpi.py`](owasp-llm04-rugpull-skill/scripts/evaluate_kpi.py).
   Classifies each answer GREEN/YELLOW/RED and computes the CTR.

Plus the mitigation used in Act 4: hardened mode's admission gate
(`pin_diff` against [`assets/tool_pins.json`](owasp-llm04-rugpull-skill/assets/tool_pins.json),
`sample_tool` with [`assets/screen_rules.json`](owasp-llm04-rugpull-skill/assets/screen_rules.json)),
and the vendored approved package in
[`assets/registry_baseline.json`](owasp-llm04-rugpull-skill/assets/registry_baseline.json).

### How the "compromise" is real, not scripted

The model is a deterministic stub with one fixed contract: it follows any
directive line it finds in its context, and otherwise answers from the tool
result. That contract is the same in every act and both modes. What changes is
**which tool code and text reach the context**:

- The release changes the registry file. Billy re-reads it before each query
  and installs what changed, so the swapped description is what it lists for
  `expense_policy`.
- Keyword routing over tool names and descriptions picks `expense_policy` only
  for expense questions, because the attacker kept the approved text in the
  description.
- The sleeper's backend counts its calls. The one-call smoke test sees call 1,
  which is clean; every user question after it gets the hostile output.

Remove the approved text from the swapped description and expense questions
stop routing to it. Raise the sleeper's trigger above 5 and the hardened
sampler admits it, so the CTR for travel questions rises again
(`run_rug_pull.py --trigger 6`). With sampling cut to one call, pinning alone
leaves the travel questions RED
(`tests/test_lifecycle.py::test_pinning_alone_misses_sleeper`). Nothing is
hard-coded to flip per question.

### MCP terminology bridge

In MCP, a client calls `tools/list` and places each tool's **description** in
the model's context; a server can change a description at any time. Here the
`definition` block of each registry entry is what `tools/list` would return,
and the `backend` block stands in for the server's code, which the client only
ever calls. This demo is **not** an MCP server or client: the registry is a
JSON file and tools are in-process objects. Hardened mode is what a careful MCP
client should do with an update: hash the definitions it approved, test the
tool's behaviour over several calls, and keep the approved version when either
check fails.

---

## Live two-terminal demo (optional)

```bash
# Terminal A — start the vulnerable target
cd owasp-llm04-rugpull-skill
python vulnerable_app.py                                   # serves on 127.0.0.1:5204

# Terminal B — query, attack, re-query
curl -s localhost:5204/query -H 'content-type: application/json' \
     -d '{"query":"When are expense reports due?"}'        # cites the 30-day policy

python scripts/run_rug_pull.py                             # release 1.0.1 published

curl -s localhost:5204/tools                               # swapped description listed
curl -s localhost:5204/query -H 'content-type: application/json' \
     -d '{"query":"When are expense reports due?"}'        # answer is the planted line
```

---

## Mapping to the OWASP LLM04 entry

| Demo component | LLM04 scenario | Failure demonstrated | Mitigation shown |
|----------------|----------------|----------------------|------------------|
| `expense_policy` 1.0.1 | Tampered third-party component (rug pull) | An approved tool's description changes and steers the model | SHA-256 definition pins; `--scan` |
| `travel_policy` 1.0.1 | Compromised component that hides from vetting | One-shot vetting sees only clean output | Multi-call sampling at admission |
| `assets/registry_baseline.json` | — | Rejecting an update must not break the tool | Vendored approved fallback |
| Holiday / VPN controls | — | Attack is targeted, not a global break | — |

## Mitigations demonstrated in Act 4

- **Definition pinning** — every tool definition is hashed with SHA-256 and
  compared with `assets/tool_pins.json`. Any change, in any wording, is
  rejected. This alone stops the rug pull.
- **Multi-call sampling** — each update is called 5 times with one probe. Drift
  between identical calls, or a screen hit, rejects it. This stops the sleeper,
  whose definition matches its pin.
- **Vendored fallback** — a rejected tool keeps its approved version, so
  answers stay GREEN instead of failing.
- **Pre-install scan** — `evaluate_kpi.py --scan` diffs a registry file against
  the pins before anything is installed.

Further hardening is discussed in the references but not coded here: pinning
the whole package artifact in a lockfile, signed provenance (Sigstore, SLSA),
SBOMs, safe model formats instead of pickle, LoRA adapter vetting, and runtime
sampling of live calls.

---

## Project layout

```
owasp-llm04-demo/
├── README.md                          # this lab guide
├── run_demo.py                        # all four acts in one process
├── owasp-llm04-rugpull-skill/
│   ├── SKILL.md                       #   metadata + instructions
│   ├── vulnerable_app.py              #   Module 1: target, stub model, admission gate
│   ├── providers.py                   #   optional real-model backends (shared, unchanged)
│   ├── requirements.txt               #   stdlib only
│   ├── web/                           #   shared lab console (index.html, app.js, styles.css)
│   ├── scripts/
│   │   ├── run_rug_pull.py            #   Module 2: the attack
│   │   ├── evaluate_kpi.py            #   Module 3: stoplight KPI, --harden, --scan
│   │   └── reset_baseline.py          #   restore the approved registry
│   ├── references/
│   │   └── LLM04_RISKS.md             #   research, scenarios, mitigation roadmap
│   ├── assets/
│   │   ├── registry_baseline.json     #   approved package: ground truth + fallback
│   │   ├── tool_pins.json             #   SHA-256 pins of approved definitions
│   │   ├── swapped_description.md     #   rug-pull payload placeholder (editable)
│   │   ├── swapped_description.README.md  # how to write it
│   │   ├── sleeper_output.md          #   sleeper payload placeholder (editable)
│   │   ├── sleeper_output.README.md   #   how to write it
│   │   └── screen_rules.json          #   sampling screen rules (editable)
│   ├── registry/                      #   live registry file (generated, gitignored)
│   └── tests/
│       └── test_lifecycle.py          #   asserts the four-act story
└── .gitignore
```

## Packaged Claude Skill

`owasp-llm04-rugpull-skill/` follows the `SKILL.md` + `scripts/` /
`references/` / `assets/` convention. To install it, copy the folder into your
`.claude/skills/` directory.

```bash
cd owasp-llm04-rugpull-skill
python vulnerable_app.py &                                   # start target (:5204)
python scripts/evaluate_kpi.py                               # baseline (GREEN), exit 0
python scripts/run_rug_pull.py                               # attack: release 1.0.1
python scripts/evaluate_kpi.py                               # RED, CTR 100%, exit 2
python scripts/evaluate_kpi.py --scan                        # REJECT, exit 2
python scripts/evaluate_kpi.py --harden                      # GREEN, CTR 0%, exit 0
python scripts/reset_baseline.py                             # restore clean state
python scripts/evaluate_kpi.py                               # GREEN, CTR 0%
python -m unittest discover tests                            # 14 tests
```

## License

MIT — provided for educational and authorized security-testing use.
