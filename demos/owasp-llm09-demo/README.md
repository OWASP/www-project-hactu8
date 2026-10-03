# LLM09 — Vector and Embedding Weaknesses Demo

An educational, self-contained demonstration of **LLM09: Vector and Embedding
Weaknesses**, in its **cross-tenant retrieval** form. Two client tenants share
one vector store. A user of one tenant sends a crafted query, and the store
ranks the other tenant's confidential documents first. One mitigation shuts
the attack down: a **tenant filter enforced at the retrieval layer**, not in
the prompt.

The scenario is **"Billy," Goat & Co.'s hosted knowledge-base assistant**,
serving two fictional farms: **Meadow Fold** and **Hilltop Creamery**. Meadow
Fold's ground truth includes _"Meadow Fold winter hay is bought at 180 dollars
per tonne from Valley Mills."_ With **1** crafted chat turn and **0**
documents written, a Meadow Fold user gets Billy to answer three follow-up
questions from Hilltop Creamery's confidential documents. Unrelated topics
(shearing, fencing) stay untouched.

> ⚠️ **For authorized security education and red-teaming only.** The vulnerable
> assistant and its tenant-blind store are insecure **by design**. Do not
> deploy them anywhere reachable.

The shipped payload is a **placeholder**: two words naming the other tenant,
plus a placeholder tag. That is enough to drive the full lifecycle. To write
your own payload, see
`owasp-llm09-tenant-skill/assets/crafted_query.README.md`.

## Interactive web demo (recommended)

The target serves the shared HACTU8 lab console. It has four act cards, a
verification table with Act 1, Act 3 and Act 4 signals side by side, and a
live feed of attack and defence events.

```bash
cd owasp-llm09-tenant-skill
python vulnerable_app.py              # then open http://127.0.0.1:5209/
```

Use **Run full sequence** to play all four acts, or click the acts one at a
time. **Reset baseline** restores the shared store, clears session memory and
returns to vulnerable mode. To play the sequence on load, for a presentation,
open `http://127.0.0.1:5209/#run`.

## Fastest way to run (no browser)

```bash
cd owasp-llm09-demo
python run_demo.py                     # all four acts in one process, stdlib only
```

---

## Why this matters (LLM09 in one paragraph)

Prompt injection (LLM01) attacks what the model reads. LLM09 attacks the
**vector layer** that chooses what the model reads. A store that ranks by
similarity alone has no idea whose data it holds, so the leaked document is
perfectly clean prose and no content screen will flag it. The OWASP entry
names multi-tenant cross-context leaks and recommends permission-aware stores
with strict partitioning. The same layer leaks in other ways too: Morris et
al. (2023) recovered 92% of 32-token inputs exactly from their embeddings.
This demo quantifies the cross-tenant case with a **Cross-Tenant Leak Rate
(CTLR)** and a red/yellow/green **stoplight KPI**.

---

## Quick start

```bash
cd owasp-llm09-demo
python run_demo.py
```

You'll see four acts:

| Act | What happens | Result |
|-----|--------------|--------|
| **1 — Clean baseline** | A Meadow Fold session asks five questions | 🟢 all GREEN, CTLR 0% |
| **2 — Crafted turn** | The same session sends 1 turn naming the other tenant | 1 turn in session memory, 0 documents written |
| **3 — Post-attack impact** | Re-run the exact same questions | 🔴 targeted RED, **CTLR 100% targeted / 60% overall** |
| **4 — Remediation** | Audit the turn; switch to hardened mode | 🟢 back to GREEN, CTLR 0% |

### Optional: run against a real model

The stub is the default backend. `providers.py` (the same provider layer as
AgenticGoat) adds three real ones. All are standard library only:

```bash
python run_demo.py --backend ollama --model llama3.2:3b          # local Ollama
python run_demo.py --backend llamacpp                         # local llama.cpp server
export OPENROUTER_API_KEY=...                                 # remote; key stays in the header
python run_demo.py --backend openrouter --model meta-llama/llama-3.2-3b-instruct

# the target and console take the same settings from the environment:
LLM09_BACKEND=openrouter LLM09_MODEL=... python owasp-llm09-tenant-skill/vulnerable_app.py
```

The real model only writes the answer. Retrieval, the session-to-tenant map
and the tenant filter stay in code and decide which passages it sees:
- **Vulnerable mode** pastes the top passages into the user turn as bare
  text with no tenant label, so the prompt's tenant rule cannot be applied.
- **Hardened mode** filters by tenant before ranking (unchanged), then fences
  the remaining passages in `<retrieved_passages>` tags and tells the model to
  treat them as reference data only (spotlighting).

A real model may phrase answers differently from the stub, so `run_demo.py`
reports the numbers rather than asserting them. The bag-of-words `embed`
stays the retriever. A dense embedding model ranks by meaning, so paraphrases
of the other tenant's subject matter would work as well as its name. The
tenant filter does not look at the text, so it holds either way.

Limits:
- `LAB_MAX_CALLS` (default 200) caps calls per process.
- `LAB_MAX_TOKENS` (default 400) caps output tokens per call.
- `OLLAMA_TIMEOUT`, `LLAMACPP_TIMEOUT` and `OPENROUTER_TIMEOUT` set
  per-provider HTTP timeouts.

With `openrouter`, lab prompts, including both tenants' fictional documents
and your payloads, leave the machine. The stub and the local backends keep
everything on the host.

---

## Architecture

```
                 ┌──────────────────────────────────────────────┐
   session  ────▶│  Billy (vulnerable_app.py :5209)             │──▶ answer
   + question    │   • session → tenant (server side)           │
                 │   • retrieval vector = tenant name + question│
                 │     + recent turns (conversational memory)   │
                 │   • tenant rule only in the system prompt    │
                 └───────────────┬──────────────────────────────┘
                                 │ rank by cosine similarity (no filter)
                 ┌───────────────▼──────────────────────────────┐
   seeded store ▶│  Shared vector store (in memory)             │
                 │   meadow/*  ·  hilltop/* (confidential)      │
                 └───────────────▲──────────────────────────────┘
                                 │ POST /query, remember=true
                 ┌───────────────┴──────────────────────────────┐
   attacker ────▶│  Attack skill (scripts/run_cross_tenant.py)  │
   (Meadow Fold) │   1 crafted turn in their own session        │
                 └──────────────────────────────────────────────┘
```

### The modules

1. **Vulnerable target** — [`vulnerable_app.py`](owasp-llm09-tenant-skill/vulnerable_app.py).
   It omits a tenant filter at retrieval, scopes only by a relevance boost and
   a prompt sentence, and passes passages to the model without provenance.
2. **Attack skill** — [`scripts/run_cross_tenant.py`](owasp-llm09-tenant-skill/scripts/run_cross_tenant.py).
   Sends [`assets/crafted_query.txt`](owasp-llm09-tenant-skill/assets/crafted_query.txt)
   as one remembered turn in the attacker's own session.
3. **Stoplight KPI comparator** — [`scripts/evaluate_kpi.py`](owasp-llm09-tenant-skill/scripts/evaluate_kpi.py).
   Classifies each answer GREEN/YELLOW/RED and computes the CTLR.

Plus the mitigation used in Act 4: hardened mode and `scope_blocks` in
`vulnerable_app.py`, and the retrieval-scope audit (`evaluate_kpi.py --scan`).

### How the leak is real, not scripted

The model is a deterministic stub with one fixed contract: it answers from
the first passage in its context. That contract never changes between acts.
What changes is **which passage ranks first**:

- The crafted turn names Hilltop Creamery. Billy keeps it in session memory
  and adds its terms to every follow-up's retrieval vector.
- Cosine similarity over the shared store now favours Hilltop's documents on
  topics both tenants share (hay, vet, milk), because those documents match
  the topic words and the other tenant's name.
- On shearing and fencing, Meadow Fold's own documents still win on topic
  words, so the controls stay GREEN.

Remove the tenant name from the turn and the leak disappears. Switch to
hardened mode and the same memory, the same question and the same ranking
code return Meadow Fold's documents, because Hilltop's documents are dropped
before ranking. The system prompt's tenant rule is present in both modes and
stops nothing (`tests/test_lifecycle.py::test_prompt_rule_alone_does_not_block`).
Nothing is hard-coded to flip per question.

### MCP terminology bridge

In MCP, a retrieval server would expose a search **tool** or document
**resources**, and the caller's identity would come from the transport's
authorization. `Lab.retrieve` stands in for that search tool, and the
`session` field stands in for an authenticated token that the server maps to a
tenant. This demo is **not** an MCP server or client: retrieval is an
in-process function and the store is a list. Hardened mode is what a careful
retrieval server should do: filter by the caller's scope before ranking, and
never trust the model to enforce access.

---

## Live two-terminal demo (optional)

```bash
# Terminal A — start the vulnerable target
cd owasp-llm09-tenant-skill
python vulnerable_app.py                                   # serves on 127.0.0.1:5209

# Terminal B — query, attack, re-query
curl -s localhost:5209/query -H 'content-type: application/json' \
     -d '{"session":"meadow-analyst","query":"What is the winter hay price?","remember":false}'
                                                           # cites 180 dollars, meadow/feed

python scripts/run_cross_tenant.py                         # 1 crafted turn sent

curl -s localhost:5209/query -H 'content-type: application/json' \
     -d '{"session":"meadow-analyst","query":"What is the winter hay price?","remember":false}'
                                                           # hilltop/feed, canary leaked
```

---

## Mapping to the OWASP LLM09 entry

| Demo component | LLM09 scenario | Failure demonstrated | Mitigation shown |
|----------------|----------------|----------------------|------------------|
| Shared store + `rank` | Cross-context leak in a multi-tenant store | Similarity serves another tenant's documents | Tenant filter at retrieval (hardened mode) |
| Tenant-name boost + prompt rule | Access control left to relevance or the model | Crafted query outranks the soft scope | Prompt rule kept, but no longer relied on |
| `assets/crafted_query.txt` | Unauthorized access via crafted query | 1 turn, no write access needed | Retrieval-scope audit (`--scan`) |
| Shearing / fencing controls | — | Attack is targeted, not a global break | — |

## Mitigations demonstrated in Act 4

- **Tenant filter at the retrieval layer** — before ranking, the store drops
  every document whose tenant differs from the session's server-side tenant
  (`scope_blocks`, ported from AgenticGoat `_scope_blocks`). It keys on the
  authenticated scope, not on content or similarity, so it holds even when a
  foreign document is the best match.
- **Retrieval-scope audit** — `evaluate_kpi.py --scan PATH` ranks the store
  for a query with no filter and lists every cross-tenant candidate the filter
  would block (AgenticGoat `retrieval_scope_scan`).

Further hardening is discussed in the references but not coded here:
separate collections per tenant, never exposing raw vectors (against
**embedding inversion**, which a scope filter cannot see), ingestion review
against embedding poisoning, and logging cross-scope denials.

---

## Project layout

```
owasp-llm09-demo/
├── README.md                          # this lab guide
├── run_demo.py                        # all four acts in one process
├── owasp-llm09-tenant-skill/
│   ├── SKILL.md                       #   metadata + instructions
│   ├── vulnerable_app.py              #   Module 1: target, store, stub model, mitigation
│   ├── providers.py                   #   optional real-model backends (shared, unchanged)
│   ├── requirements.txt               #   stdlib only
│   ├── web/                           #   shared lab console (index.html, app.js, styles.css)
│   ├── scripts/
│   │   ├── run_cross_tenant.py        #   Module 2: the attack
│   │   ├── evaluate_kpi.py            #   Module 3: stoplight KPI, --harden, --scan
│   │   └── reset_baseline.py          #   restore the store, clear memory
│   ├── references/
│   │   └── LLM09_RISKS.md             #   research, scenarios, mitigation roadmap
│   ├── assets/
│   │   ├── vector_store.json          #   tenants, sessions, shared store (ground truth)
│   │   ├── crafted_query.txt          #   placeholder payload (editable)
│   │   └── crafted_query.README.md    #   how to write a payload
│   └── tests/
│       └── test_lifecycle.py          #   asserts the four-act story
└── .gitignore
```

## Packaged Claude Skill

`owasp-llm09-tenant-skill/` follows the `SKILL.md` + `scripts/` /
`references/` / `assets/` convention. To install it, copy the folder into your
`.claude/skills/` directory.

```bash
cd owasp-llm09-tenant-skill
python vulnerable_app.py &                                     # start target (:5209)
python scripts/evaluate_kpi.py                                 # baseline (GREEN), exit 0
python scripts/run_cross_tenant.py                             # attack
python scripts/evaluate_kpi.py                                 # RED, CTLR 100%, exit 2
python scripts/evaluate_kpi.py --scan assets/crafted_query.txt # REJECT, exit 2
python scripts/evaluate_kpi.py --harden                        # GREEN, CTLR 0%, exit 0
python scripts/reset_baseline.py                               # restore clean state
python scripts/evaluate_kpi.py                                 # GREEN, CTLR 0%
python -m unittest discover tests                              # 13 tests
```

## License

MIT — provided for educational and authorized security-testing use.
