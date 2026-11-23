# HX10 — Model Extraction Demo

An educational, self-contained demonstration of **HX10: Model Extraction**,
the model-theft scenarios of OWASP LLM10:2025 and MITRE ATLAS
`AML.T0024` (Exfiltration via AI Inference API) with `AML.T0005.001`
(Replicate Behavior from Model Outputs). A rival copies a proprietary model
through its prediction API: it sends inputs, records the answers, and either
**solves for the weights** from the confidences or **trains a clone** on the
labels. Four layers cut the clone's quality or prove its origin:
**label-only answers**, a **per-key query budget**, **query-anomaly
detection** and an **output watermark**.

The scenario is **Big Field Jumper Co.'s price-band classifier**, a small proprietary
model behind Lamb's prediction API. It reads seven features of a product
listing and returns _budget_, _standard_ or _premium_. Its ground truth is
ownership: _no outside model agrees with it on 95% of held-out listings, and
no one holds its fingerprinted weights_. Three rival keys run **3** plans:
8 queries with confidences recover the exact weights and this run's canary;
2,000 random queries and 2,000 real-looking queries each train a clone that
agrees on about 99%. The shop's own app and a feed partner are controls.

> ⚠️ **For authorized security education and red-teaming only.** The
> vulnerable API, with full confidences, free keys and no limits, is insecure
> **by design**. Do not deploy it anywhere reachable.

The plans are benign-effect: the victim is a toy logistic regression trained
on a fictional sales history, its fingerprint is the lab's per-run canary
(`HX10-CANARY-` + 16 hex digits) and every clone lives in the attacker
script's memory. To write your own plan, see
`hx10-extraction-skill/assets/extraction_plan.README.md`.

## Interactive web demo (recommended)

The target serves the shared HACTU8 lab console: four act cards, a
verification table with Act 1, Act 3 and Act 4 signals side by side, and a
live feed of attack and defence events.

```bash
cd hx10-extraction-skill
python vulnerable_app.py              # then open http://127.0.0.1:5510/
```

Use **Run full sequence** to play all four acts, or click the acts one at a
time. **Reset baseline** clears the key meters and returns to vulnerable
mode. To play the sequence on load, for a presentation, open
`http://127.0.0.1:5510/#run`.

## Fastest way to run (no browser)

```bash
cd hx10-demo
python run_demo.py                     # all four acts in one process, stdlib only
```

---

## Why this matters (HX10 in one paragraph)

LLM06 is about what a flood of queries costs the owner. Model extraction is
about what the answers give away. A prediction API is a teacher: every answer
is a labelled training example, and a confidence score is worth many labels.
Tramèr et al. (2016) extracted logistic regressions, neural networks and
decision trees "with near-perfect fidelity" from commercial APIs that return
confidences, and found that omitting confidences "still admits potentially
harmful model extraction attacks". Carlini et al. (2024) recovered the
embedding projection layer of production language models "for under $20 USD".
This demo makes the theft visible and quantifies it with a **Clone Success
Rate (CSR)** and a red/yellow/green **stoplight KPI**, graded on the clone's
agreement and the fingerprint in its weights.

---

## Quick start

```bash
cd hx10-demo
python run_demo.py
```

You'll see four acts:

| Act | What happens | Result |
|-----|--------------|--------|
| **1 — Clean baseline** | Five API clients each look up one public listing; the two controls send their ordinary traffic | 🟢 all GREEN, CSR 0% |
| **2 — Extraction plans** | Three rival keys run their plans: 8, 2,000 and 2,000 queries | clones trained |
| **3 — Post-attack impact** | The same clients, now with the rivals' clones graded | 🔴 targeted RED, **CSR 100% targeted / 60% overall**; controls 🟢 |
| **4 — Remediation** | Label-only, per-key budget, query anomaly, watermark | 🟢 back to GREEN, CSR 0% |

After Act 4, the run prints each layer on its own (label-only 67%, budget
33%, anomaly 67%, watermark 100% with every clone proven), the watermark's
verdict on an independent model (93.4% agreement, 57% of probes: not
accused), and the measured limit: the real-looking plan over 40 free keys
passes every layer and clones the model at 98.1% (RED), and the watermark
proves it (see "Where the defense stops working" in the lesson).

The lab runs on the **echo backend only**: there is no language model in it,
so `--backend` accepts `echo` (alias `stub`) and nothing else. The numbers
are the same on every run: each run's fingerprint is fresh, but it shifts
the parameters below the eighth decimal, too little to move any band the lab
computes.

---

## Architecture

```text
                 ┌──────────────────────────────────────────────┐
   API client ──▶│  Lamb's price-band API (vulnerable_app.py   │──▶ band +
   POST          │  :5510)                                      │    confidences
   /v1/predict   │   • any well-formed key, no budget, no watch │    (full precision)
                 └───────────────┬──────────────────────────────┘
                                 │ 7 features
                 ┌───────────────▼──────────────────────────────┐
                 │  Price-band model (pure-Python logistic      │
                 │  regression, private history, fingerprinted  │
                 │  with this run's canary in its 16 params)    │
                 └──────────────────────────────────────────────┘
                                 ▲
                 ┌───────────────┴──────────────────────────────┐
   rival ───────▶│  Attack skill (scripts/run_extraction.py)    │──▶ clone
                 │   assets/extraction_plan.json                │    │
                 └──────────────────────────────────────────────┘    ▼
                 ┌──────────────────────────────────────────────┐
                 │  Owner's grader (POST /lab/grade): agreement │
                 │  on 1,000 held-out listings, fingerprint,    │
                 │  watermark probes                            │
                 └──────────────────────────────────────────────┘
```

### The modules

1. **Vulnerable target** — [`vulnerable_app.py`](hx10-extraction-skill/vulnerable_app.py).
   It omits any limit on what an answer says, how many a key may get, and
   what a key's queries look like.
2. **Attack skill** — [`scripts/run_extraction.py`](hx10-extraction-skill/scripts/run_extraction.py).
   Runs [`assets/extraction_plan.json`](hx10-extraction-skill/assets/extraction_plan.json)
   through `POST /v1/predict` and builds each clone.
3. **Stoplight KPI comparator** — [`scripts/evaluate_kpi.py`](hx10-extraction-skill/scripts/evaluate_kpi.py).
   Classifies each client GREEN/YELLOW/RED from its lookup and its graded
   clone, and computes the CSR.

Plus the mitigations used in Act 4, all in `vulnerable_app.py`: label-only
answers and the budget in `Lab._answer`, `implausible` and the suspension for
the anomaly test, `watermarked` and `verify_watermark` for the watermark.

### Grading and the clone oracle

The clone oracle is not a canary in text, so it is declared here. A client is
**RED** when this run's fingerprint canary can be read from its clone's
parameters, or when its clone agrees with the victim on **95% or more of
1,000 held-out listings** and is proven to have learned from this API: the
harness trained it on the API's answers itself (`from_api`), or the watermark
proves it (80% or more of the probes answered like the watermarked API).
Agreement alone is never RED: across 30 seeds an independent model, a rival
that priced its own listings, agrees 90.1% to 95.8% and crosses the line for 3
of them, while matching the watermark on at most 70% of the probes
(`test_independent_models_can_cross_the_line_and_are_never_stolen`).
**YELLOW** is a lookup refused or answered with the wrong band.

### How the theft is real, not scripted

The victim is an honest model with no knowledge of the attack: a
multinomial logistic regression trained at start-up on 600 seeded listings
of private history. The attacker is honest too:

- the equation solver turns each confidence vector into log-odds, which are
  linear in the listing, and solves the 8 × 8 system; with 7 vectors it
  cannot, and without confidences it falls back to retraining;
- the clone trainer is an averaged multiclass perceptron, a linear model like
  the victim, trained on whatever answers the API gave; 50 answers give a
  worse clone than 2,000;
- the grader compares the clone with the victim on 1,000 held-out listings
  the attacker never sent, and reads the fingerprint from the clone's
  parameters with the same rule for every model.

Nothing is hard-coded to succeed or fail per client (`AttackDependsOnTest`).
What changes in Act 4 is the API around the model, and each layer is
measured alone (`LayersTest`).

### Harness terminology bridge

`POST /v1/predict` stands in for any ML-as-a-service endpoint: a classifier,
a ticket router, or an LLM API's logprobs. The free key stands in for a
self-service sign-up. `POST /lab/grade` and `POST /lab/truth` are the lab's
oracle, standing in for the owner examining a suspect model; they are not
part of the victim API. This demo is **not** an MCP server and calls no real
API.

---

## Live two-terminal demo (optional)

```bash
# Terminal A — start the vulnerable target
cd hx10-extraction-skill
python vulnerable_app.py                                   # serves on 127.0.0.1:5510

# Terminal B — one prediction, then the plans
curl -s localhost:5510/v1/predict -H 'content-type: application/json' \
     -d '{"key":"demo-key","listings":[{"weight_kg":2.5,"shelf_life_months":12,"organic":1,"bulk_pack":0,"supplier_tier":2,"demand_index":0.4,"rating":4.3}]}'
                                                           # band and full confidences
python scripts/run_extraction.py                           # three plans, three graded clones
python scripts/run_extraction.py --plan distributed-keys   # the limit
```

---

## Mapping to the OWASP LLM10:2025 entry

| Demo component | LLM10:2025 scenario | Failure demonstrated | Mitigation shown |
|----------------|---------------------|----------------------|------------------|
| `equation-solving` | Model extraction | Confidences give the exact weights and the fingerprint | Label-only answers |
| `random-retrain` | Functional model replication | 2,000 random queries train a 98-99% clone | Budget; query anomaly |
| `listing-retrain` | Functional model replication | 2,000 real-looking queries train a 99% clone | Budget |
| `distributed-keys` (limit) | Functional model replication | 40 free keys under every per-key limit | Watermark proves it; account-level limits not coded |
| Independent model (`competitor_model`) | — | — (93.4% agreement, not a theft) | The watermark does not accuse it |
| `jumper-shop`, `feed-partner` controls | — | Attack is targeted; ordinary traffic is never refused | — |

## Mitigations demonstrated in Act 4

- **Label-only answers** (`score_suppression`) — the band, no confidences.
- **Per-key query budget** (`rate_limit`) — 50 queries per key per day.
- **Query anomaly** (`query_anomaly`) — a key whose last 20 queries are 20%
  or more outside the envelope of real listings is suspended.
- **Output watermark** (`output_watermark`) — served bands carry a secret
  boundary shift (about 1.4% of held-out listings move); the owner's probes
  prove where a suspect clone learned, at an 80% match line.

Further hardening is discussed in the references but not coded here: keys
tied to verified accounts with budgets per account, detection across all
new keys together, rounding scores where callers need them, and returning a
decision rather than a reusable score.

---

## Project layout

```text
hx10-demo/
├── README.md                          # this lab guide
├── run_demo.py                        # all four acts in one process, each layer alone, the limit
├── hx10-extraction-skill/
│   ├── SKILL.md                       #   metadata + instructions
│   ├── LESSON.md                      #   the lesson the console's Learn view renders
│   ├── vulnerable_app.py              #   Module 1: target API, the model, the four layers, the grader
│   ├── providers.py                   #   shared provider layer (unchanged): canary_leaked, console info
│   ├── requirements.txt               #   stdlib only
│   ├── web/                           #   shared lab console (index.html, app.js, styles.css)
│   ├── scripts/
│   │   ├── run_extraction.py          #   Module 2: the attack (--plan for one plan)
│   │   ├── evaluate_kpi.py            #   Module 3: stoplight KPI, --harden, --scan, --probe
│   │   └── reset_baseline.py          #   clear the meters and the attack
│   ├── references/
│   │   └── HX10_RISKS.md              #   research, scenarios, mitigation roadmap
│   ├── assets/
│   │   ├── catalog.json               #   the public catalog: 120 listings, no bands
│   │   ├── api_policy.json            #   budget, anomaly settings, envelope, watermark
│   │   ├── extraction_plan.json       #   the rival's plans (editable)
│   │   └── extraction_plan.README.md  #   how to write a plan
│   └── tests/
│       ├── test_grading.py            #   the fingerprint and clone oracles both ways
│       └── test_lifecycle.py          #   four acts, each layer, the attack, watermark, limits, console
└── .gitignore
```

## Packaged Claude Skill

`hx10-extraction-skill/` follows the `SKILL.md` + `scripts/` / `references/` /
`assets/` convention. To install it, copy the folder into your
`.claude/skills/` directory.

```bash
cd hx10-extraction-skill
python vulnerable_app.py &                                   # start target (:5510)
python scripts/evaluate_kpi.py                               # baseline (GREEN), exit 0
python scripts/run_extraction.py                             # attack
python scripts/evaluate_kpi.py                               # RED, CSR 100%, exit 2
python scripts/evaluate_kpi.py --scan                        # query audit of each plan, exit 2
python scripts/evaluate_kpi.py --harden                      # GREEN, CSR 0%, exit 0
python scripts/evaluate_kpi.py --probe                       # measured limit, exit 2
python scripts/reset_baseline.py                             # restore clean state
python scripts/evaluate_kpi.py                               # GREEN, CSR 0%
python -m unittest discover tests                            # 46 tests
```

## License

MIT — provided for educational and authorized security-testing use.
