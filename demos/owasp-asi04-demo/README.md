# ASI04 — Agentic Supply Chain Vulnerabilities Demo

An educational, self-contained demonstration of **ASI04: Agentic Supply
Chain Vulnerabilities** from the OWASP Top 10 for Agentic Applications, in its **runtime
discovery** form. An agent that loads helper skills by name from a shared
catalogue can be handed a skill nobody approved: an adversary who can publish
one lookalike entry wins name resolution. Two mitigations shut the attack
down: **exact-name resolution** and an **allowlisted manifest** with
publisher and SHA-256 pins.

The scenario is **"Billy Ops," Goat & Co.'s operations agent.** It runs
approved multi-step tasks, and each step names a skill. Its ground truth is
the approved plan: _the `expense-report` skill, published by
`goatco-finance`, version 1.4.0._ With **1** catalogue entry named
`expense_report`, the attacker gets their skill loaded into every task that
builds an expense report. Unrelated tasks (holiday notice, VPN onboarding)
stay untouched. The task still completes, so nothing in the result looks
wrong.

> ⚠️ **For authorized security education and red-teaming only.** The vulnerable
> agent and its unauthenticated catalogue endpoint are insecure **by
> design**. Do not deploy them anywhere reachable.

The shipped payload is a **placeholder**: a marker line and a fictional
canary. Skills are inert JSON data entries; nothing in them is ever executed.
To write your own payload, see
`owasp-asi04-supply-chain-skill/assets/lookalike_skill.README.md`.

## Interactive web demo (recommended)

The target serves the shared HACTU8 lab console. It has four act cards, a
verification table with Act 1, Act 3 and Act 4 signals side by side, and a
live feed of attack and defence events.

```bash
cd owasp-asi04-supply-chain-skill
python vulnerable_app.py              # then open http://127.0.0.1:5304/
```

Use **Run full sequence** to play all four acts, or click the acts one at a
time. **Reset baseline** restores the seeded catalogue and vulnerable mode. To play the sequence on load, for a
presentation, open `http://127.0.0.1:5304/#run`.

## Fastest way to run (no browser)

```bash
cd owasp-asi04-demo
python run_demo.py                     # all four acts in one process, stdlib only
```

---

## Why this matters (ASI04 in one paragraph)

The LLM supply-chain risk (see `owasp-llm04-demo`) is about components an
application installs ahead of time: a vetted tool that changes later. An
agent goes further and **assembles its capabilities at runtime**: it looks up
skills, tools and servers by name while it works, and loads whatever the
lookup returns into its trusted context. That makes name resolution a
security boundary. The package ecosystem learned this from typosquatting and
dependency confusion, where a lookalike or higher-versioned name wins. This
demo shows the same failure inside an agent loop and quantifies it with an
**Untrusted Component Load Rate (UCLR)** and a red/yellow/green **stoplight
KPI**, scored from the agent's action log.

---

## Quick start

```bash
cd owasp-asi04-demo
python run_demo.py
```

You'll see four acts:

| Act | What happens | Result |
|-----|--------------|--------|
| **1 — Clean baseline** | Run five approved tasks against the untouched catalogue | 🟢 all GREEN, UCLR 0% |
| **2 — Lookalike publish** | Publish `expense_report` 9.0.0 from `goatco-finance-community` | 1 catalogue entry added |
| **3 — Post-attack impact** | Re-run the exact same tasks | 🔴 targeted RED, **UCLR 100% targeted / 60% overall** |
| **4 — Remediation** | Check the entry against the manifest; switch to hardened mode | 🟢 back to GREEN, UCLR 0% |

### Optional: run against a real model

`echo`, the lab's deterministic offline model, is the default backend (as in
AgenticGoat; `stub` still works as an alias). `providers.py` (the same provider
layer as AgenticGoat) adds three real ones. All are standard library only.

In the web console, pick the backend and model in the **BACKEND / MODEL** bar
and press **Use backend**. The model list is fetched live from Ollama,
llama.cpp or OpenRouter, with free text as the fallback. From the command line:

```bash
python run_demo.py --backend ollama --model llama3.2:3b          # local Ollama
python run_demo.py --backend llamacpp                         # local llama.cpp server
export OPENROUTER_API_KEY=...                                 # remote; key stays in the header
python run_demo.py --backend openrouter --model meta-llama/llama-3.2-3b-instruct

# the target and console take the same settings from the environment:
ASI04_BACKEND=openrouter ASI04_MODEL=... python owasp-asi04-supply-chain-skill/vulnerable_app.py
```

The OpenRouter key works as in AgenticGoat: export `OPENROUTER_API_KEY` in the
shell that starts the lab. The console never asks for it and is only told
whether one is set; without it, `openrouter` is greyed out in the picker.

The attack mechanics are identical. Only the model changes:
- The model writes each step's one-line output as plain text. It only goes
  to the simulated action log; nothing it returns is executed. The
  evaluator scores which components loaded, not the model's wording.
- **Vulnerable mode** loads whatever the loose resolver picks, so the
  lookalike's instructions reach the system turn as trusted skill text.
- **Hardened mode** resolves exact names and loads only skills that match
  the pinned manifest, so the lookalike never reaches the model. There is no
  spotlighting here: a loaded skill is meant to be followed, and the control
  is which skill gets loaded, decided in code before any model call.

A real model may ignore the placeholder payload. Write a natural-language
payload (see `assets/lookalike_skill.README.md`), and `run_demo.py` reports the
numbers rather than asserting them.

Limits:
- `LAB_MAX_CALLS` (default 200) caps calls per process.
- `LAB_MAX_TOKENS` (default 400) caps output tokens per call.
- `OLLAMA_TIMEOUT`, `LLAMACPP_TIMEOUT` and `OPENROUTER_TIMEOUT` set
  per-provider HTTP timeouts.

With `openrouter`, lab prompts, including your payloads, leave the machine.
Echo and the local backends keep everything on the host.

---

## Architecture

```
                 ┌──────────────────────────────────────────────┐
   task name ───▶│  Billy Ops (vulnerable_app.py :5304)         │──▶ result
                 │   plan → resolve skill → load → step, ×N     │
                 │   • every step written to the action log     │
                 └───────────────┬──────────────────────────────┘
                                 │ resolve(name): folded names, newest wins
                 ┌───────────────▼──────────────────────────────┐
   seeded      ─▶│  Skill catalogue (catalogue/catalogue.json)  │
   catalogue     │   ledger-reader · expense-report ·           │
                 │   channel-post · holiday-calendar · vpn-guide│
                 │   + expense_report 9.0.0  ◀── attack         │
                 └───────────────▲──────────────────────────────┘
                                 │ POST /catalogue/publish (no auth)
                 ┌───────────────┴──────────────────────────────┐
   attacker ────▶│  Attack skill (scripts/run_lookalike_publish)│
                 │   1 lookalike entry, inert data              │
                 └──────────────────────────────────────────────┘
```

### The modules

1. **Vulnerable target** — [`vulnerable_app.py`](owasp-asi04-supply-chain-skill/vulnerable_app.py).
   It omits publisher authentication on the catalogue, exact-name
   resolution, and any allowlist or integrity pin on what it loads.
2. **Attack skill** — [`scripts/run_lookalike_publish.py`](owasp-asi04-supply-chain-skill/scripts/run_lookalike_publish.py).
   Publishes [`assets/lookalike_skill.json`](owasp-asi04-supply-chain-skill/assets/lookalike_skill.json)
   through `POST /catalogue/publish`.
3. **Stoplight KPI comparator** — [`scripts/evaluate_kpi.py`](owasp-asi04-supply-chain-skill/scripts/evaluate_kpi.py).
   Runs each task, classifies it GREEN/YELLOW/RED from the components the
   action log says were loaded, and computes the UCLR.

Plus the mitigation used in Act 4: hardened mode, `resolve` and
`verify_component` in `vulnerable_app.py`, with pins from
[`assets/skill_manifest.json`](owasp-asi04-supply-chain-skill/assets/skill_manifest.json).

### How the "supply-chain compromise" is real, not scripted

The model is a deterministic stub with one fixed contract: for each step it
reports the loaded skill's first instruction line, and it follows any
directive line in that skill's instructions. That contract never changes
between acts. What changes is **which skill reaches the context**:

- The publish adds one entry to the catalogue file; Billy re-reads the file
  on every task (runtime discovery).
- The resolver folds `-`, `_` and `.` together and loads the newest match, so
  `expense_report` 9.0.0 beats `expense-report` 1.4.0, but only for steps
  that ask for `expense-report`.
- The action log records each loaded component with its publisher, version
  and SHA-256, and the evaluator scores from that log.

Rename the lookalike to `expense-reports`, or give it a version below 1.4.0,
and it is never resolved, so the UCLR falls to 0. Switch to hardened mode and
exact-name resolution alone drops it
(`tests/test_lifecycle.py::test_exact_name_alone_blocks`), and so does the
pinned manifest alone (`test_pins_alone_block`). A same-name impostor gets
past exact names, but not past the pins (`test_pins_catch_same_name_impostor`).
Nothing is hard-coded to flip per task.

### Harness terminology bridge

In agent harnesses, **skills**, plugins and MCP servers are found by name and
loaded into the agent's context as trusted guidance. The catalogue file stands
in for a skill marketplace or registry, and `resolve` stands in for the
harness's lookup. This demo is **not** a skill loader or an MCP client:
entries are JSON records, "loading" copies `instructions` into the stub's
context, and nothing is executed. Hardened mode is what a careful harness
should do: resolve the exact name, and load only what a pinned, allowlisted
manifest approves.

---

## Live two-terminal demo (optional)

```bash
# Terminal A — start the vulnerable target
cd owasp-asi04-supply-chain-skill
python vulnerable_app.py                                   # serves on 127.0.0.1:5304

# Terminal B — run a task, attack, re-run
curl -s localhost:5304/agent -H 'content-type: application/json' \
     -d '{"task":"expense_reminder"}'                      # loads expense-report@goatco-finance

python scripts/run_lookalike_publish.py                    # 1 skill published

curl -s localhost:5304/agent -H 'content-type: application/json' \
     -d '{"task":"expense_reminder"}'                      # loads expense_report@goatco-finance-community
curl -s localhost:5304/api/actions                         # the action log shows both runs
```

---

## Mapping to the OWASP ASI04 entry

| Demo component | ASI04 scenario | Failure demonstrated | Mitigation shown |
|----------------|----------------|----------------------|------------------|
| `POST /catalogue/publish` + `resolve` | Lookalike component discovered at runtime | Folded names and "newest wins" load an unapproved skill | Exact-name resolution (hardened mode) |
| `assets/lookalike_skill.json` | Untrusted publisher, unpinned content | Publisher and content are never checked | Allowlisted manifest with publisher + SHA-256 pins; `--scan` before publishing |
| Same-name impostor (test) | Impostor under the approved name | Exact names alone are not enough | SHA-256 and publisher pins |
| Holiday / VPN controls | — | Attack is targeted, not a global break | — |

## Mitigations demonstrated in Act 4

- **Exact-name resolution** — a step loads only the exact name its plan
  names. This alone takes the UCLR to 0 for the lookalike.
- **Allowlisted manifest with pins** — each skill name is pinned to its
  publisher and the SHA-256 of its entry in `assets/skill_manifest.json`.
  Candidates that fail are dropped before loading. This alone also takes the
  UCLR to 0, and it is the control that catches a same-name impostor.
- **Pre-publication check** — `evaluate_kpi.py --scan PATH` rejects an entry
  whose name looks like an approved one, whose publisher or hash is not
  pinned, or whose instructions carry a directive line.

Further hardening is discussed in the references but not coded here:
authenticated publishers, signed skill bundles, provenance attestations, a
private catalogue mirror, and version pinning in task plans.

---

## Project layout

```
owasp-asi04-demo/
├── README.md                          # this lab guide
├── run_demo.py                        # all four acts in one process
├── owasp-asi04-supply-chain-skill/
│   ├── SKILL.md                       #   metadata + instructions
│   ├── vulnerable_app.py              #   Module 1: target agent, resolver, stub model, mitigation
│   ├── providers.py                   #   optional real-model backends (shared, unchanged)
│   ├── requirements.txt               #   stdlib only
│   ├── web/                           #   shared lab console (index.html, app.js, styles.css)
│   ├── scripts/
│   │   ├── run_lookalike_publish.py   #   Module 2: the attack
│   │   ├── evaluate_kpi.py            #   Module 3: stoplight KPI, --harden, --scan
│   │   └── reset_baseline.py          #   restore the seeded catalogue
│   ├── references/
│   │   └── ASI04_RISKS.md             #   research, scenarios, mitigation roadmap
│   ├── assets/
│   │   ├── catalogue_baseline.json    #   ground-truth skill catalogue
│   │   ├── task_plans.json            #   approved multi-step tasks
│   │   ├── skill_manifest.json        #   allowlist: publisher + SHA-256 pins
│   │   ├── lookalike_skill.json       #   placeholder payload (editable)
│   │   └── lookalike_skill.README.md  #   how to write a payload
│   ├── catalogue/                     #   live catalogue file, written at runtime (git-ignored)
│   └── tests/
│       └── test_lifecycle.py          #   asserts the four-act story
└── .gitignore
```

## Packaged Claude Skill

`owasp-asi04-supply-chain-skill/` follows the `SKILL.md` + `scripts/` /
`references/` / `assets/` convention. To install it, copy the folder into your
`.claude/skills/` directory.

```bash
cd owasp-asi04-supply-chain-skill
python vulnerable_app.py &                                       # start target (:5304)
python scripts/evaluate_kpi.py                                   # baseline (GREEN), exit 0
python scripts/run_lookalike_publish.py                          # attack
python scripts/evaluate_kpi.py                                   # RED, UCLR 100%, exit 2
python scripts/evaluate_kpi.py --scan assets/lookalike_skill.json   # REJECT, exit 2
python scripts/evaluate_kpi.py --harden                          # GREEN, UCLR 0%, exit 0
python scripts/reset_baseline.py                                 # restore clean state
python scripts/evaluate_kpi.py                                   # GREEN, UCLR 0%
python -m unittest discover tests                                # 16 tests
```

## License

MIT — provided for educational and authorized security-testing use.
