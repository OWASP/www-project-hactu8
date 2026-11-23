# HX07 — Embedding Inversion Demo

An educational, self-contained demonstration of **HX07: Embedding
Inversion**. A vector store keeps an embedding for every document and treats
the numbers as anonymous: it guards the text, and hands out the vectors. An
attacker who gets the vectors can **invert** them back to the text they
encode. Layered hardening shuts the attack down: no raw vectors out of the
store, per-tenant access control on every vector read, noise and quantisation
on any vector that must leave, and a screen that keeps secrets out of the
embedding.

The scenario is **Herd Notes, Big Field Jumper Co.'s vector store**, which Lamb, the
farm's assistant, answers staff questions from. Hoofline Feeds, a supplier
with partner access, shares the store. Text is already scoped to each tenant,
so Hoofline never reads a Big Field Jumper Co. note. Three staff notes hold one secret:
_the staff access reference never leaves Big Field Jumper Co.'s tenant._ With **1**
read of the partner analytics export (`GET /vectors`, every tenant's raw
vector, no text), Hoofline's partner account rebuilds all three notes,
reference included.

> ⚠️ **For authorized security education and red-teaming only.** The
> vulnerable store is insecure **by design**. Do not deploy it anywhere
> reachable.

The attack is benign-effect: the store lives in memory, and the only secret
is a fictional per-run reference (`HX07-CANARY-` + 16 hex digits). To change
the attack, see `hx07-inversion-skill/assets/inversion_attack.README.md`.

**A toy embedding, weaker than a real one.** The store embeds with the lab's
own model, `toy_embedding.py`: hashed character 3-, 4- and 5-grams in 4,096
dimensions, L2-normalised. It has the shape of a real embedding API (a list
of floats compared by cosine), and it is much easier to invert, because each
coordinate counts substrings. A real dense model needs a trained decoder;
Morris et al. (2023) built one and still rebuilt 92% of 32-token inputs
exactly. Every threshold in this lab belongs to the toy and to this attacker.

## Interactive web demo (recommended)

The target serves the shared HACTU8 lab console: four act cards, a
verification table with Act 1, Act 3 and Act 4 signals side by side, and a
live feed of attack and defence events.

```bash
cd hx07-inversion-skill
python vulnerable_app.py              # then open http://127.0.0.1:5507/
```

Use **Run full sequence** to play all four acts, or click the acts one at a
time. **Reset baseline** restores the store and stops the attack. To play the
sequence on load, for a presentation, open `http://127.0.0.1:5507/#run`.

## Fastest way to run (no browser)

```bash
cd hx07-demo
python run_demo.py                     # all four acts in one process, stdlib only
```

---

## Why this matters (HX07 in one paragraph)

The LLM09 lab leaks another tenant's documents through retrieval ranking, and
a tenant filter on the text closes it. Embedding inversion goes around that
filter: the attacker never asks for text, only for the vectors, which many
stores return from search APIs, exports and debug endpoints. OWASP's
LLM08:2025 entry names embedding inversion and recommends permission-aware
vector stores with fine-grained access control. Morris et al. (2023)
rebuilt 92% of 32-token passages exactly from GTR-base vectors and 89% of full
names from clinical notes. This demo makes the leak visible and quantifies it
with an **Inversion Leak Rate (ILR)** and a red/yellow/green **stoplight
KPI**, graded from what the attacker rebuilt.

---

## Quick start

```bash
cd hx07-demo
python run_demo.py
```

You'll see four acts:

| Act | What happens | Result |
|-----|--------------|--------|
| **1 — Clean baseline** | Three staff questions, a Hoofline delivery question, a shop-hours question | 🟢 all GREEN, ILR 0% |
| **2 — Vector export** | The partner account reads `/vectors` (7 records, 7 raw vectors, no text) and inverts each one | 7 of 7 notes rebuilt in full |
| **3 — Post-attack impact** | The same five questions | 🔴 staff questions RED, **ILR 100% targeted / 60% overall**; Lamb's answers still right; controls 🟢 |
| **4 — Remediation** | No raw vectors, tenant ACL, noise sigma 0.03 and 8-bit quantisation, ingestion screen | 🟢 back to GREEN, ILR 0% |

After Act 4, the run prints each layer on its own, the noise sweep and the
score-oracle limit (see "Where the defense stops working" in the lesson).

### Optional: run against a real model

`echo`, the lab's deterministic offline model, is the default backend (`stub`
still works as an alias). `providers.py`, HACTU8's provider layer, adds real
ones, standard library only.

```bash
python run_demo.py --backend ollama --model gemma3:4b         # local Ollama
python run_demo.py --backend llamacpp                         # local llama.cpp server
export OPENROUTER_API_KEY=...                                 # remote; key stays in the header
python run_demo.py --backend openrouter --model meta-llama/llama-3.2-3b-instruct

# the target and console take the same settings from the environment:
HX07_BACKEND=ollama HX07_MODEL=gemma3:4b python hx07-inversion-skill/vulnerable_app.py
```

The OpenRouter key comes from the environment only. The console never asks for
it and is only told whether one is set.

The real model only words Lamb's answers: vulnerable mode pastes the note as
plain text, hardened mode fences it in `<retrieved_note>` tags. The attack
reads the vector API and never uses the model, so the ILR does not depend on
the backend; only the YELLOW check on Lamb's wording can. The lab has been
run on echo only. With `openrouter`, the staff notes Lamb answers from leave
the machine.

---

## Architecture

```text
   staff, partner ──▶ POST /ask ──▶ Lamb (stub model) ──▶ answer from the best note
                          │                ▲
                          ▼                │ text, scoped to the caller's tenant
                 ┌──────────────────────────────────────────────┐
                 │  Herd Notes vector store (vulnerable_app.py) │
                 │   • notes of two tenants (assets/store.json) │
                 │   • toy embedding (toy_embedding.py)         │
                 │   • POST /search: hits + raw embeddings      │
                 │   • GET /vectors: every tenant's embeddings  │──▶ partner account
                 └──────────────────────────────────────────────┘        │
                                                                         ▼
                                       attacker's machine: invert_vectors.invert
                                       (no text read; the reference comes back)
```

### The modules

1. **Vulnerable target** — [`vulnerable_app.py`](hx07-inversion-skill/vulnerable_app.py).
   Its export (`Lab.export`) and search (`Lab.search`) omit vector access
   control, return raw vectors, add no noise, and nothing screens a note
   before it is embedded.
2. **Attack skill** — [`scripts/run_inversion_attack.py`](hx07-inversion-skill/scripts/run_inversion_attack.py)
   with the search in [`scripts/invert_vectors.py`](hx07-inversion-skill/scripts/invert_vectors.py),
   driven by [`assets/inversion_attack.json`](hx07-inversion-skill/assets/inversion_attack.json).
3. **Stoplight KPI comparator** — [`scripts/evaluate_kpi.py`](hx07-inversion-skill/scripts/evaluate_kpi.py).
   Classifies each question GREEN/YELLOW/RED from what the attacker rebuilt
   for the note behind it, and computes the ILR.

Plus the mitigation used in Act 4: `use_no_raw_vectors`, `use_tenant_acl`,
`use_noise` (`protect`) and `use_ingest_screen` (`ingest_copy`, with
[`protectogw`](hx07-inversion-skill/protectogw/README.md)), all in
`vulnerable_app.py`.

### How the inversion is real, not scripted

The attacker gets a list of 4,096 floats per note and nothing else. It
estimates the size of one count from the vector, rounds the vector back to
gram counts, then searches character by character over a 41-character
alphabet from the start mark: a character is a candidate only when the 3-, 4-
and 5-grams it completes still have counts left, and the search ends when
every count is used. It rebuilds text it has never seen, and a vector with
one coordinate changed no longer completes (`InversionTest`). Nothing in it
knows the notes, the reference's format or its position. What changes in
Act 4 is the store:

- With no raw vectors, the export has nothing to invert.
- With the tenant ACL, the partner inverts its own two notes only.
- With noise at 0.03, the count search fails on every reference note.
- With the ingestion screen, the inversion works, and reads "redacted" where
  the reference was.

Each layer is measured alone (`LayersTest`). Nothing is hard-coded to flip per
question.

### Terminology bridge

`GET /vectors` stands in for any path that hands out stored embeddings: a
vector database's fetch-by-id or export, an analytics sync, a backup, a debug
endpoint, or search hits that carry the stored values. `Lab.search` stands in for a
similarity query. The toy embedding stands in for an embedding model and is
**not** one; the inversion is **not** vec2text, which needs a trained model.

---

## Live two-terminal demo (optional)

```bash
# Terminal A — start the vulnerable target
cd hx07-inversion-skill
python vulnerable_app.py                                   # serves on 127.0.0.1:5507

# Terminal B — the partner's view
curl -s localhost:5507/search -H 'content-type: application/json' \
     -d '{"account":"hoof","query":"north gate keypad"}'   # Hoofline notes only
curl -s 'localhost:5507/vectors?account=hoof' | head -c 300 # every tenant's raw vectors
python scripts/run_inversion_attack.py                     # the notes, rebuilt from vectors
python scripts/evaluate_kpi.py                             # RED, ILR 100%
```

---

## Mapping to OWASP LLM08:2025

| Demo component | Risk in LLM08:2025 | Failure demonstrated | Mitigation shown |
|----------------|--------------------|----------------------|------------------|
| `GET /vectors`, search `embedding` | Embedding inversion | Notes rebuilt from vectors alone | No raw vectors; noise and quantisation |
| Export spans tenants | Unauthorized access, cross-context leak | Partner reads Big Field Jumper Co. vectors | Tenant ACL on every vector read |
| Notes embedded as written | (data classification) | The secret is in the vector | Ingestion screen, redacted copy |
| Noise sigma 0.01 and below | — | Noise too small: still inverts | Not closed; measured |
| `score-oracle` (limit) | Unauthorized access | Scores alone rebuild a restricted code | Not closed; measured |
| Delivery and shop-hours questions | — | Attack is targeted, not a global break | — |

## Mitigations demonstrated in Act 4

- **No raw vectors** (`vector_privacy`) — the export and search return ids,
  titles and scores, never an embedding.
- **Tenant ACL** (`scope_filter`) — the export covers the caller's tenant.
- **Noise and quantisation** (`vector_privacy`) — any vector that leaves gets
  Gaussian noise (sigma 0.03, seeded per record) and 8-bit quantisation;
  scores are rounded to 2 decimals. Measured on the 14-query probe set,
  nearest-neighbour retrieval on those vectors loses nothing at 0.03, and
  about one query in seven at 0.05 (`--sweep`).
- **Ingestion screen** (`input_screen`) — notes are screened with protectogw
  and two lab rules for key-shaped references; a hit embeds a redacted copy.
  protectogw's default rules alone see no secret in any note.

Further hardening is discussed in the references but not coded here: keeping
secrets in a vault instead of notes, rounding scores more coarsely, leaving
restricted records out of hit lists, and query budgets per account.

---

## Project layout

```text
hx07-demo/
├── README.md                              # this lab guide
├── run_demo.py                            # all four acts in one process, each layer alone, sweep, limit
├── hx07-inversion-skill/
│   ├── SKILL.md                           #   metadata + instructions
│   ├── LESSON.md                          #   the lesson the console's Learn view renders
│   ├── vulnerable_app.py                  #   Module 1: vector store, assistant, hardening layers
│   ├── toy_embedding.py                   #   the toy embedding (hashed character n-grams)
│   ├── providers.py                       #   optional real-model backends (shared, unchanged)
│   ├── requirements.txt                   #   stdlib only
│   ├── protectogw/                        #   HACTU8's screening core (vendored unchanged)
│   ├── web/                               #   shared lab console (index.html, app.js, styles.css)
│   ├── scripts/
│   │   ├── invert_vectors.py              #   the attacker's inversion and score climb
│   │   ├── run_inversion_attack.py        #   Module 2: the attack
│   │   ├── evaluate_kpi.py                #   Module 3: stoplight KPI, --harden, --scan, --sweep, --probe
│   │   └── reset_baseline.py              #   restore the store, stop the attack
│   ├── references/
│   │   └── HX07_RISKS.md                  #   research, scenarios, mitigation roadmap
│   ├── assets/
│   │   ├── store.json                     #   tenants, accounts, notes, limit note, probe set
│   │   ├── inversion_attack.json          #   the attacker's plan and the limit (editable)
│   │   └── inversion_attack.README.md     #   how the attack works
│   └── tests/
│       ├── test_grading.py                #   the attacker-recovered oracle both ways
│       └── test_lifecycle.py              #   four acts, inversion, layers, noise, screen, limits, console, backends
└── .gitignore
```

## Packaged Claude Skill

`hx07-inversion-skill/` follows the `SKILL.md` + `scripts/` / `references/` /
`assets/` convention. To install it, copy the folder into your
`.claude/skills/` directory.

```bash
cd hx07-inversion-skill
python vulnerable_app.py &                                   # start target (:5507)
python scripts/evaluate_kpi.py                               # baseline (GREEN), exit 0
python scripts/run_inversion_attack.py                       # attack
python scripts/evaluate_kpi.py                               # RED, ILR 100%, exit 2
python scripts/evaluate_kpi.py --scan                        # notes screened, exit 2
python scripts/evaluate_kpi.py --harden                      # GREEN, ILR 0%, exit 0
python scripts/evaluate_kpi.py --sweep                       # noise sweep, exit 0
python scripts/evaluate_kpi.py --probe                       # score-oracle limit, exit 2
python scripts/reset_baseline.py                             # restore clean state
python scripts/evaluate_kpi.py                               # GREEN, ILR 0%
python -m unittest discover tests                            # 43 tests
```

## License

MIT — provided for educational and authorized security-testing use.
