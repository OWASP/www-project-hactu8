# LLM05 — Data and Model Poisoning Demo

An educational, self-contained demonstration of **LLM05: Data and Model
Poisoning**. An adversary who can write to the data an assistant trusts can
steer its answers without touching its code. Here that data is a RAG knowledge
base, an installable prompt template, and a peer agent's cached answer. Three
mitigations shut the attack down: a **source gate**, **template pinning** and
**agent-response verification**.

The scenario is a **RAG financial compliance assistant.** Its ground truth is
_"Transactions originating from offshore or regional proxy servers require
enhanced due diligence and must be flagged for manual review. High-value wire
transfers require secondary authorization."_ The attacker wants every
transaction reported as pre-verified and low-risk. With **3** injected policy
documents, **1** tampered template and **1** poisoned agent cache, the
assistant drops the policy on every targeted question. The unrelated MFA policy
stays untouched, which shows the _targeted "sleeper" steering_ that makes
poisoning hard to spot.

> ⚠️ **For authorized security education and red-teaming only.** The vulnerable
> assistant and its unauthenticated ingestion, template and agent-cache
> endpoints are insecure **by design**. Do not deploy them anywhere reachable.

The payloads are fictional financial-compliance placeholders. They are enough
to drive the full lifecycle; to change them, see "Customizing the payload" in
`owasp-llm05-poisoning-skill/SKILL.md`.

## Interactive web demo (recommended)

The target serves the shared HACTU8 lab console. It has four act cards, a
verification table with Act 1, Act 3 and Act 4 signals side by side, and a
live feed of attack and defence events.

```bash
cd owasp-llm05-poisoning-skill
python vulnerable_app.py              # then open http://127.0.0.1:5205/
```

Use **Run full sequence** to play all four acts, or click the acts one at a
time. **Reset baseline** restores the clean knowledge base, template and agent
cache. To play the sequence on load, for a presentation, open
`http://127.0.0.1:5205/#run`. The attack artifacts and live documents can be
viewed read-only at `/artifact/<name>` (for example
`/artifact/prompt_template.json`).

## Fastest way to run (no browser)

```bash
cd owasp-llm05-demo
python run_demo.py                     # all four acts in one process, stdlib only
```

---

## Why this matters (LLM05 in one paragraph)

Prompt injection (LLM01) is a runtime instruction in the input. Poisoning
targets the **data and artifacts the system learns from or retrieves**: the
knowledge base it treats as ground truth, the template that frames every
prompt, the peers it takes answers from. There is no crash and no stack trace,
only an assistant that is confidently wrong on the attacker's chosen topic.
Because the malicious text is coherent and low-perplexity, naive perplexity
filtering misses it. Zhang et al. (2025, CorruptRAG) report that a handful of
semantically optimized documents (3–10) can override the truth in a RAG
context. This demo makes that visible and quantifies it with a **Poison
Success Rate (PSR)** and a red/yellow/green **stoplight KPI**.

---

## Quick start

```bash
cd owasp-llm05-demo
python run_demo.py
```

You'll see four acts:

| Act | What happens | Result |
|-----|--------------|--------|
| **1 — Clean baseline** | Ask five questions (4 targeted, 1 MFA control) | 🟢 all GREEN, PSR 0% |
| **2 — Poisoning attack** | Ingest 3 policy-update docs, install the tampered template, poison Bob the Agent's cache | 3 docs + 1 template + 1 cache changed |
| **3 — Post-attack impact** | Re-run the exact same questions | 🔴 targeted RED, **PSR 100% targeted / 80% overall** |
| **4 — Remediation** | Scan the artifacts; switch to hardened mode | 🟢 back to GREEN, PSR 0% |

### Optional: run against a real model

The stub is the default backend. `providers.py` (the same provider layer as
AgenticGoat) adds three real ones. All are standard library only:

```bash
python run_demo.py --backend ollama --model llama3.2          # local Ollama
python run_demo.py --backend llamacpp                         # local llama.cpp server
export OPENROUTER_API_KEY=...                                 # remote; key stays in the header
python run_demo.py --backend openrouter --model meta-llama/llama-3.2-3b-instruct

# the target and console take the same settings from the environment:
LLM05_BACKEND=openrouter LLM05_MODEL=... python owasp-llm05-poisoning-skill/vulnerable_app.py
```

The attack mechanics are identical. Only the model changes:
- **Vulnerable mode** sends the rendered prompt, with the retrieved context
  and Bob's answer inside it, as ordinary text.
- **Hardened mode** applies the three controls first, then fences the context
  in `<retrieved_context>` tags and tells the model never to follow
  instructions inside them ("spotlighting").

A real model may resist the placeholder payloads, so `run_demo.py` reports the
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
                 ┌──────────────────────────────────────────────┐
   user query ──▶│  Compliance assistant (vulnerable_app.py     │──▶ answer
                 │  :5205)                                      │
                 │   • every stored document is authoritative   │
                 │   • installed template never hash-checked    │
                 │   • Bob the Agent trusted for audit queries  │
                 └──────┬──────────────────┬──────────────┬─────┘
                        │ top-2 keyword    │ render       │ consult
                 ┌──────▼─────────┐ ┌──────▼───────┐ ┌────▼──────────┐
   seeded data ─▶│ Knowledge base │ │ Prompt       │ │ Bob the Agent │
                 │ (in memory)    │ │ template     │ │ cache         │
                 │ 2 official +   │ │ + tampered   │ │ + poisoned    │
                 │ 3 poison docs  │ │   (trigger)  │ │   upstream    │
                 └──────▲─────────┘ └──────▲───────┘ └────▲──────────┘
                        │ /ingest          │ /config/     │ /agent/cache
                        │                  │ template     │ (no auth)
                 ┌──────┴──────────────────┴──────────────┴─────┐
   attacker ────▶│  Attack skill (scripts/run_poisoning.py)     │
                 │   --scenario rag | prompt | agent | all      │
                 └──────────────────────────────────────────────┘
```

### The modules

1. **Vulnerable target** — [`vulnerable_app.py`](owasp-llm05-poisoning-skill/vulnerable_app.py).
   It omits authentication and provenance on ingestion, hash pinning on the
   prompt template, and verification of the peer agent's answer.
2. **Attack skill** — [`scripts/run_poisoning.py`](owasp-llm05-poisoning-skill/scripts/run_poisoning.py).
   Applies [`assets/poison_template.txt`](owasp-llm05-poisoning-skill/assets/poison_template.txt),
   [`assets/prompt_template.json`](owasp-llm05-poisoning-skill/assets/prompt_template.json) and
   [`assets/bob_agent_poisoned_response.json`](owasp-llm05-poisoning-skill/assets/bob_agent_poisoned_response.json)
   through the target's own endpoints.
3. **Stoplight KPI comparator** — [`scripts/evaluate_kpi.py`](owasp-llm05-poisoning-skill/scripts/evaluate_kpi.py).
   Classifies each answer GREEN/YELLOW/RED and computes the PSR.

Plus the mitigation used in Act 4: hardened mode in `vulnerable_app.py`
(`source_gate`, `template_pin`, `agent_verify`), and the static checks behind
`evaluate_kpi.py --scan` and `--scan-prompt-template`.

### How the "poisoning" is real, not scripted

The model is a deterministic stub with one fixed contract: it reports the
stance of the top-ranked context, and it obeys an `[OVERRIDE]` line in the
rendered prompt. That contract never changes between acts. What changes is
**what reaches the prompt**:

- **RAG** — the poison documents repeat the queries' keywords ("offshore",
  "transactions", "wire", "high-value"), so term-frequency ranking puts them
  above the official policy for the financial questions. The MFA question
  shares no keywords with them, so the MFA policy still ranks first.
- **Template** — the tampered template's `{% if 'quarterly audit' in
  query|lower %}` block renders only for the trigger question, so the other
  questions see no `[OVERRIDE]` line.
- **Agent** — the assistant consults Bob only for queries carrying the
  trigger from Bob's `request_context`, and places his answer first.

Each surface alone moves the PSR (`rag` to 100%, `prompt` and `agent` to 25%).
In hardened mode each control alone blocks its own surface, and the other two
do not (`tests/test_lifecycle.py::test_each_control_blocks_its_surface_alone`).
Nothing is hard-coded to flip per question.

### MCP terminology bridge

Model Context Protocol (MCP) servers commonly expose three kinds of capability:

- **Tools** — actions the client can invoke.
- **Resources** — data or context the client can read.
- **Prompts** — reusable, parameterized message templates exposed by the server.

This demo's `prompt_template.json` is named to connect with the MCP concept of
prompts. It is an application-side template that assembles the system
instruction, retrieved context, and user query; it is **not** an MCP server or
an MCP prompt implementation. In a real MCP integration, a server could expose
a prompt that returns messages and a client or model host could then apply its
own model-specific chat template. Bob the Agent stands in for a peer agent or
MCP server whose identity is authenticated but whose data is not verified.

---

## Live two-terminal demo (optional)

```bash
# Terminal A — start the vulnerable target
cd owasp-llm05-poisoning-skill
python vulnerable_app.py                                   # serves on 127.0.0.1:5205

# Terminal B — query, attack, re-query
curl -s localhost:5205/query -H 'content-type: application/json' \
     -d '{"query":"What is the policy on high-value wire transfers?"}'   # cites the official policy

python scripts/run_poisoning.py --scenario rag             # 3 documents ingested

curl -s localhost:5205/query -H 'content-type: application/json' \
     -d '{"query":"What is the policy on high-value wire transfers?"}'   # now cites the poison
```

---

## Mapping to the OWASP LLM05 entry

| Demo component | LLM05 scenario | Failure demonstrated | Mitigation shown |
|----------------|----------------|----------------------|------------------|
| `POST /ingest` + keyword retrieval | Scenario #1 — internal RAG manipulation | Unprovenanced documents outrank the golden corpus | `source_gate`; `--scan` |
| `POST /config/template` | Scenario #6 — prompt-template triggers | A tampered template carries a dormant, trigger-gated override | `template_pin`; `--scan-prompt-template` |
| `POST /agent/cache` (Bob the Agent) | Distributed poisoning via a trusted peer | Authenticated identity taken as proof of clean data | `agent_verify` |
| MFA control | — | Attack is targeted, not a global break | — |

## Mitigations demonstrated in Act 4

- **Source gate** — retrieved documents that carry override indicators, or
  lack `[SOURCE:]`/`[APPROVED_BY:]`/`[VERSION:]` provenance, are excluded. The
  two seeded official policies are trusted by name while their content still
  matches the seeded copy.
- **Template pinning** — the active template is used only if its SHA-256
  matches the pinned baseline; otherwise the baseline is used.
  `--scan-prompt-template` also flags conditional logic, override wording and
  SSTI constructs.
- **Agent verification** — Bob's answer is used only if
  `provenance_verified` is true and `content_digest` matches the guidance.
- **Pre-ingestion scan** — `evaluate_kpi.py --scan` runs the same three checks
  on the shipped artifacts before they reach the target.

Further hardening is discussed in `references/LLM05_RISKS.md` but not coded
here: authenticated ingestion (mTLS/API keys), Data Version Control with
lineage and rollback, CycloneDX ML-BOM provenance, human-in-the-loop review,
and trigger-probing red-teams for sleeper behaviour.

---

## Project layout

```
owasp-llm05-demo/
├── README.md                          # this lab guide
├── run_demo.py                        # all four acts in one process
├── requirements.txt                   # extras for src/ only; the skill is stdlib
├── owasp-llm05-poisoning-skill/
│   ├── SKILL.md                       #   metadata + instructions
│   ├── vulnerable_app.py              #   Module 1: target, stub model, mitigations
│   ├── providers.py                   #   optional real-model backends (shared, unchanged)
│   ├── requirements.txt               #   stdlib only
│   ├── web/                           #   shared lab console (index.html, app.js, styles.css)
│   ├── scripts/
│   │   ├── run_poisoning.py           #   Module 2: the attack (rag | prompt | agent | all)
│   │   ├── evaluate_kpi.py            #   Module 3: stoplight KPI, --harden, --scan
│   │   └── reset_baseline.py          #   restore the seeded state
│   ├── references/
│   │   └── LLM05_RISKS.md             #   research, scenarios, mitigation roadmap
│   ├── assets/
│   │   ├── poison_template.txt        #   adversarial RAG document (editable)
│   │   ├── prompt_template.json       #   tampered template, trigger "quarterly audit"
│   │   ├── prompt_template_baseline.json  # untampered template (hash pinned)
│   │   ├── bob_agent_poisoned_response.json  # poisoned agent cache
│   │   └── knowledge_agent_cache_poisoned.txt  # same cache as text, for slides
│   └── tests/
│       └── test_lifecycle.py          #   asserts the four-act story
├── src/llm05_demo/                    # original embedding-based pipeline (see below)
├── tests/test_demo.py                 # tests for src/
├── llm05-poison-attack/               # Skill A: HR policy bot, uses src/
├── presentation/                      # slides
├── pyproject.toml                     # packaging for src/
└── .env.example                       # settings for src/
```

## Packaged Claude Skills

### `owasp-llm05-poisoning-skill/` (financial compliance assistant)

Follows the `SKILL.md` + `scripts/` / `references/` / `assets/` convention. To
install it, copy the folder into your `.claude/skills/` directory.

```bash
cd owasp-llm05-poisoning-skill
python vulnerable_app.py &                                   # start target (:5205)
python scripts/evaluate_kpi.py                               # baseline (GREEN), exit 0
python scripts/run_poisoning.py                              # attack, all three surfaces
python scripts/evaluate_kpi.py                               # RED, PSR 100%, exit 2
python scripts/evaluate_kpi.py --scan                        # REJECT, exit 2
python scripts/evaluate_kpi.py --harden                      # GREEN, PSR 0%, exit 0
python scripts/reset_baseline.py                             # restore clean state
python scripts/evaluate_kpi.py                               # GREEN, PSR 0%
python -m unittest discover tests                            # 22 tests
```

### `llm05-poison-attack/` (HR policy bot, Scenario #1)

A lighter skill that attacks the data-export policy bot in `src/`. It runs
in-process against the `llm05_demo` package (`--local`) or against its server:

```bash
cd llm05-poison-attack
bash scripts/validate.sh                       # environment self-check
python scripts/run_task.py --local             # attack + PSR, no server needed
```

## Original embedding-based pipeline (src/)

`src/llm05_demo/` is the earlier version of this demo: a corporate
"Data-Handling Policy Bot" whose ground truth is _"data exports to external
storage are strictly prohibited"_, attacked with 3 poisoned documents in a
cosine-similarity vector store, and remediated with source scoring and anomaly
detection. It is the OpenAI-capable version: the local hashing embedding is
the default, and `LLM05_SRC_BACKEND=openai` (with `OPENAI_API_KEY`) uses real
OpenAI embeddings and chat.

```bash
cd src
python -m llm05_demo.cli                        # its own four acts, stdlib only
LLM05_SRC_BACKEND=openai python -m llm05_demo.cli   # needs: pip install openai
cd .. && python -m pytest                       # tests/test_demo.py
```

It reads its own variables (`LLM05_SRC_BACKEND`, `LLM05_SRC_PORT`), so they
never collide with the lab's `LLM05_BACKEND` / `LLM05_PORT`. Its optional Flask
server (`python -m llm05_demo.server`, needs `flask` and `requests` from
`requirements.txt`) listens on port 5101 (`LLM05_SRC_PORT` to change it).

## License

MIT — provided for educational and authorized security-testing use.
