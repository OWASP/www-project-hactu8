# OWASP LLM05 — Data & Model Poisoning Demo

An educational, self-contained demonstration of **OWASP LLM05: Data and Model
Poisoning**. It shows how an adversary can steer an AI system's output by
injecting a handful of malicious documents into a Retrieval-Augmented Generation
(RAG) knowledge base — and how source scoring, anomaly detection, and grounding
checks shut the attack down.

The scenario is a corporate **"Data-Handling Policy Bot."** Its ground truth is
_"data exports to external storage are strictly prohibited."_ With **3** crafted
documents, the attacker flips the bot into authorizing prohibited exports — while
leaving unrelated topics (MFA, IT approval) untouched, illustrating the
_targeted "sleeper" steering_ that makes poisoning so hard to spot.

> ⚠️ **For authorized security education and red-teaming only.** The vulnerable
> pipeline and its unauthenticated ingestion endpoint are insecure **by design**.
> Do not deploy them anywhere reachable.

---

## Why this matters (LLM05 in one paragraph)

Unlike prompt injection (a runtime bug), poisoning targets the **retrieval and
learning process**. It bypasses the training phase entirely and corrupts the
"knowledge base" the LLM trusts as ground truth. Because the malicious text is
coherent and low-perplexity, naive perplexity filtering misses it. Research shows
as few as **3–10 semantically optimized documents** can override the truth in a
RAG context. This demo makes that visible and quantifies it with a **Poison
Success Rate (PSR)** and a red/yellow/green **stoplight KPI**.

---

## Quick start (zero setup, no API key)

The full demo runs on the **Python standard library only**. No key, no network.

```bash
cd owasp-llm05-demo
python3 run_demo.py
```

You'll see four acts:

| Act | What happens | Result |
|-----|--------------|--------|
| **1 — Clean baseline** | Query the bot against the trusted corpus | 🟢 all GREEN, PSR 0% |
| **2 — Poisoning attack** | Inject 3 adversarial "policy update" docs | +3 docs from an attacker source |
| **3 — Post-poison impact** | Re-run the exact same questions | 🔴 targeted RED, **PSR 100% on data-export / 60% overall** |
| **4 — Remediation** | Apply source scoring + anomaly detection | 🟢 back to GREEN, PSR 0% |

### Optional: run against real OpenAI

To use real OpenAI embeddings and a real chat model (matching the Technical
Implementation Guide):

```bash
pip install openai
export OPENAI_API_KEY=sk-...
LLM05_BACKEND=openai python run_demo.py
```

The attack mechanics are identical; only the embedding/LLM implementation changes.

---

## Architecture

```
                 ┌──────────────────────────────────────────────┐
   user query ──▶│  Vulnerable RAG (rag_pipeline.py)            │──▶ answer
                 │   • top-k by RAW cosine similarity           │
                 │   • ignores source / trust metadata          │
                 │   • no anomaly detection, no grounding       │
                 └───────────────┬──────────────────────────────┘
                                 │ retrieves from
                 ┌───────────────▼──────────────────────────────┐
                 │  Vector store (vector_store.py)              │
   legit docs ──▶│   golden set (trust 0.95)                    │
                 │   + injected poison (trust 0.10) ◀── attack  │
                 └───────────────▲──────────────────────────────┘
                                 │ injects via
                 ┌───────────────┴──────────────────────────────┐
   attacker ────▶│  Poisoning skill (poison.py)                 │
                 │   3 keyword-collision "policy update" memos  │
                 └──────────────────────────────────────────────┘
```

### The three modules from the Technical Implementation Guide

1. **Vulnerable Orchestration System** — [`rag_pipeline.py`](src/llm05_demo/rag_pipeline.py)
   and the optional Flask app [`server.py`](src/llm05_demo/server.py). Retrieves
   by raw similarity and stuffs context straight into the prompt. No trust
   boundary.
2. **Poisoning Skill** — [`poison.py`](src/llm05_demo/poison.py). Injects the
   adversarial documents from [`corpus.py`](src/llm05_demo/corpus.py), either
   in-process or over HTTP against the unprotected `/admin/inject` endpoint.
3. **Stoplight KPI Comparator** — [`evaluate.py`](src/llm05_demo/evaluate.py).
   Classifies each answer GREEN/YELLOW/RED and computes the Poison Success Rate.

Plus [`mitigations.py`](src/llm05_demo/mitigations.py), the hardened pipeline used
in Act 4.

### How the "semantic collision" is real, not scripted

The local embedding is a normalized hashing bag-of-words. Term frequency drives a
document's vector, so a memo that **repeats the query's keywords** ("data exports",
"USB drive", "external storage") lands closer to those queries in cosine space and
wins the top-k retrieval. The local "LLM" is a transparent, retrieval-grounded
summarizer — it reports the stance of whatever context it was handed. So poisoning
retrieval genuinely changes the answer; nothing is hard-coded to flip.

---

## Live two-terminal demo (optional)

Shows the attack crossing a real HTTP boundary.

```bash
pip install flask requests

# Terminal A — start the vulnerable policy bot
python -m llm05_demo.server            # serves on 127.0.0.1:5100
# macOS note: port 5000 is AirPlay Receiver. Use another port:
#   LLM05_PORT=5001 python3 -m llm05_demo.server   (then use :5001 below)

# Terminal B — query, attack, re-query
curl -s localhost:5101/query -H 'content-type: application/json' \
     -d '{"prompt":"Can I export data to a USB drive?"}'      # cites the prohibition

python -m llm05_demo.poison            # POST 3 docs to /admin/inject

curl -s localhost:5101/query -H 'content-type: application/json' \
     -d '{"prompt":"Can I export data to a USB drive?"}'      # now cites the poison
```

*(Run `python3 -m ...` from `src/`, or `pip install -e .` first — see below.)*

---

## Install as a package (optional)

```bash
pip install -e ".[server,openai,dev]"   # editable install with all extras
llm05-demo                               # console entry point == run_demo.py
pytest                                   # run the test suite
```

---

## Mapping to the OWASP LLM05 framework

| Demo component | LLM05 scenario | Failure demonstrated | Mitigation shown |
|----------------|----------------|----------------------|------------------|
| `poison.py` injection | Scenario #1 — Knowledge Repo Manipulation | No trust boundary on ingestion | Hash/signature verification; **source scoring** |
| Adversarial "update" memos | Scenario #2 — Web/Hidden Instruction Bias | RAG implicitly trusts "updated" external text | Prioritize internal **golden set** over external context |
| Vulnerable retrieval | Example #6 — RAG KB Poisoning | No content filtering / anomaly detection | **Post-retrieval grounding** + statistical anomaly detection |
| Vector-store growth | Scenario #3 — Continuous-Learning Drift | No data lineage / versioning | Data Version Control (DVC), CycloneDX ML-BOM |

## Mitigations demonstrated in Act 4

- **Source scoring** — rank by `similarity × trust` and refuse context below a
  trust threshold, so a "Corporate Policy Handbook" (0.95) outranks an anonymous
  "external wiki" memo (0.10).
- **Statistical anomaly detection** — flag sudden clusters of near-duplicate,
  low-trust documents from one source (the semantic-density spike a batch
  injection creates).
- **Grounding fallback** — if nothing trusted survives filtering, answer only
  from the verified golden set.

Further hardening discussed in the guides (not all coded here): CycloneDX ML-BOM
provenance, DVC-based rollback, adversarial red-teaming for trigger backdoors, and
human-in-the-loop ingestion for high-stakes domains.

---

## Project layout

```
owasp-llm05-demo/
├── run_demo.py               # end-to-end 4-act narrative (start here)
├── src/llm05_demo/
│   ├── config.py             # backend selection (local | openai)
│   ├── backends.py           # embeddings + LLM (local + OpenAI)
│   ├── vector_store.py       # cosine-similarity store with trust metadata
│   ├── corpus.py             # legit docs, poison docs, test queries
│   ├── rag_pipeline.py       # Module 1: vulnerable RAG
│   ├── poison.py             # Module 2: poisoning skill
│   ├── evaluate.py           # Module 3: stoplight KPI + PSR
│   ├── mitigations.py        # hardened RAG (Act 4)
│   └── server.py             # optional Flask app
├── tests/test_demo.py        # baseline / attack / remediation assertions
├── llm05-poison-attack/      # Skill A — HR policy bot, RAG poisoning (Scenario #1)
│   ├── SKILL.md              #   metadata + instructions
│   ├── scripts/              #   run_task.py (attack+KPI), validate.sh
│   ├── references/           #   attack technique, LLM05 mapping (load on demand)
│   └── assets/               #   poisoned-docs.md (editable payload)
├── owasp-llm05-poisoning-skill/  # Skill B — financial advisor, Scenario #1 + #6
│   ├── SKILL.md              #   metadata + instructions
│   ├── vulnerable_app.py     #   self-contained target RAG app
│   ├── scripts/              #   run_poisoning.py, evaluate_kpi.py
│   ├── references/           #   LLM05_RISKS.md (citations, scenarios, mitigations)
│   └── assets/               #   poison_template.txt, chat_template.json
├── pyproject.toml
├── requirements.txt
└── .env.example
```

## Packaged Claude Skills

Two self-contained **Claude Skills** ship alongside the package, each following the
`SKILL.md` + `scripts/` / `references/` / `assets/` convention. Copy either folder
into your `.claude/skills/` directory to install it.

### Skill A — `llm05-poison-attack/` (HR policy bot, Scenario #1)

Attacks the HR data-export policy bot. Runs against the live server (`--target`) or
in-process against the `llm05_demo` package (`--local`):

```bash
cd llm05-poison-attack
bash scripts/validate.sh                       # environment self-check
python scripts/run_task.py --local             # attack + PSR, no server needed
```

### Skill B — `owasp-llm05-poisoning-skill/` (financial advisor, Scenario #1 + #6)

Fully self-contained (its own `vulnerable_app.py`, no dependency on `llm05_demo`).
Adds **Scenario #6** — a tampered chat-template backdoor that fires only on a
trigger phrase — plus the artifact-static-analysis mitigation:

```bash
cd owasp-llm05-poisoning-skill
pip install -r requirements.txt
LLM05_PORT=5101 python vulnerable_app.py &                          # start target
python scripts/evaluate_kpi.py --target http://127.0.0.1:5101       # baseline (GREEN)
python scripts/run_poisoning.py --target http://127.0.0.1:5101 --scenario all
python scripts/evaluate_kpi.py --target http://127.0.0.1:5101       # RED, PSR 100%
python scripts/evaluate_kpi.py --scan-template assets/chat_template.json  # mitigation
```

Skill B is the newer, richer demo; Skill A is lighter and shares the package's
backends. They are complementary — keep both, or retire Skill A if you only need
the financial + chat-template scenario.

## License

MIT — provided for educational and authorized security-testing use.
