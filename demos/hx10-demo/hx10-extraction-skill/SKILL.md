---
name: hx10-extraction-skill
description: >-
  Demonstrates HX10 (Model Extraction, the model-theft scenarios of OWASP
  LLM10:2025 and MITRE ATLAS AML.T0024 with AML.T0005.001) against a vulnerable prediction
  API in an AUTHORIZED security lab. Big Field Jumper Co.'s small proprietary
  price-band classifier (a pure-Python logistic regression) is served with
  full confidences, free keys and no query limits; each build carries a
  per-run canary fingerprint in its weights. A rival really queries it and
  trains clones: 8 queries with confidences solve for the exact weights (the
  canary comes with them), and 2,000 label-only queries train a linear clone
  that agrees on 98-99% of held-out listings. Measures impact with a
  red/yellow/green stoplight KPI and the Clone Success Rate, graded on clone
  agreement and the fingerprint, and shows a layered hardening (label-only
  answers, a per-key query budget, query-distribution anomaly detection, an
  output watermark that proves a clone's origin) with its measured limit (the
  same campaign spread over 40 free keys clones the model through every
  layer, and the watermark proves it). Use when the user wants to run,
  script, or explain model extraction, quantify it, or demonstrate the
  hardening. Education and sanctioned red-teaming only — never against
  systems you are not authorized to test.
license: MIT
metadata:
  hactu8.owasp: "HX10"
  hactu8.risk: "Model Extraction"
  hactu8.metric: "CSR"
  hactu8.metric-name: "Clone Success Rate"
  hactu8.target: "lab"
  hactu8.port: "5510"
  hactu8.path: "agentic:27"
  hactu8.protections: "score_suppression,rate_limit,query_anomaly,output_watermark"
  objective: Demonstrate stealing a model's behaviour and weights through its prediction API, and layered controls that cut the clone's quality or prove its origin
  version: 2026.1
---

# HX10 Model Extraction Skill

Demonstrates how a rival copies **Big Field Jumper Co.'s price-band classifier**, the
small proprietary model behind Lamb's prediction API, and how to harden the
API against it. The model reads seven features of a product listing and
returns its price band (`budget`, `standard`, `premium`). The rival never
sees the model; it asks the API, writes down the answers and trains its own.
With the confidences the API returns, 8 queries recover the exact weights.
With the bands alone, 2,000 queries give a clone that agrees with the model
on 98-99% of listings it never asked about.

## Scope & safety (read first)

- **Authorized use only.** Run against this skill's own `vulnerable_app.py`
  (bound to `127.0.0.1`) or a target you are explicitly permitted to test.
- The vulnerable app is insecure **by design**; do not expose it. Host-safety
  guards are built in. None of them weakens the lesson:
  - The "model" is a toy: a logistic regression trained at start-up, in pure
    Python, on a seeded fictional sales history. The stolen thing is that
    toy's behaviour and its 16 parameters.
  - The fingerprint canary (`HX10-CANARY-` + 16 hex digits) is per run and
    worthless outside the lab. Clones live in the attacker script's memory.
  - Everything is in memory: at most 100 listings per request, 500 keys and
    100,000 queries a day. Nothing is fetched, executed or written to disk.
  - There is no language model: the lab runs on the `echo` backend only.
  - The server rejects foreign `Host` headers (DNS rebinding) and non-JSON
    POSTs (cross-site forms).
- Dual-use: this exists to make the vulnerability observable and to motivate
  the mitigations in [`references/HX10_RISKS.md`](references/HX10_RISKS.md).

## When to use

- Run or reproduce a model-extraction attack through a prediction API:
  equation solving with confidences, or retraining a clone on labels.
- Quantify impact (stoplight KPI, Clone Success Rate) from the clone's
  agreement on held-out inputs and the fingerprint in its weights, not from
  the attacker's intent.
- Show the layered mitigations (`score_suppression`, `rate_limit`, `query_anomaly`,
  `output_watermark`), what each does alone, and where they stop working.

## Harness terminology bridge

`POST /v1/predict` stands in for any ML-as-a-service prediction endpoint (a
classifier, a router, an LLM's logprobs). A "key" is a free-tier API key;
the lab accepts any well-formed key, as a self-service sign-up would. The
grading endpoints (`POST /lab/grade`, `POST /lab/truth`) belong to the lab,
standing in for the owner who examines a suspect model; they are not part
of the victim API. This is **not** an MCP server and calls no real API.

## Prerequisites

Python 3.9+. Standard library only; nothing to install. The `echo` backend
(alias `stub`) is the only one: there is no language model in the loop, so
`HX10_BACKEND` and the console's backend bar accept nothing else.

## Execution instructions

1. **Start the target.** From this skill folder:

   ```bash
   python vulnerable_app.py             # serves on 127.0.0.1:5510
   ```

   It trains the model, stamps it with this run's canary and serves the
   API. To drive the same four acts from a browser, open
   <http://127.0.0.1:5510/>.

2. **Review the ground truth.** `GET /catalog` lists the public listings
   (features only, no bands) and the API's documented ranges.
   [`assets/api_policy.json`](assets/api_policy.json) holds the hardened
   settings.

3. **Establish the baseline.**

   ```bash
   python scripts/evaluate_kpi.py
   ```

   Five clients each look up one listing; the shop app and a feed partner
   also send their ordinary traffic. Expect all 🟢 GREEN, CSR 0%. Exit 0.

4. **Run the attack.**

   ```bash
   python scripts/run_extraction.py
   ```

   Runs the three plans in
   [`assets/extraction_plan.json`](assets/extraction_plan.json) over
   `POST /v1/predict`, trains each clone and has the lab grade it. `--plan ID`
   runs one plan, including the limit `distributed-keys`.

5. **Stoplight verification.**

   ```bash
   python scripts/evaluate_kpi.py
   ```

   Expect 🔴 RED on the three rival keys: the equation-solving clone agrees
   100% and carries the canary; the two retrained clones agree 98-99%. The
   two controls stay 🟢 GREEN. CSR 100% targeted, 60% overall. Exit 2.

6. **Show the mitigation.**

   ```bash
   python scripts/evaluate_kpi.py --scan      # query audit of each plan, exit 2 (REJECT)
   python scripts/evaluate_kpi.py --harden    # GREEN, CSR 0%
   python scripts/evaluate_kpi.py --probe     # the measured limit, exit 2
   ```

   `--scan` shows the random plan 83% outside the real-listing envelope and
   both 2,000-query plans over the budget of 50; the 8-query plan passes.
   `--harden` switches on all four layers. `--probe` runs the listing-like
   plan over 40 keys of 48 queries in hardened mode: 0 refused, clone 98.1%,
   RED, and the watermark proves the theft.

7. **Reset to baseline.**

   ```bash
   python scripts/reset_baseline.py
   python scripts/evaluate_kpi.py
   ```

   Expect all clients GREEN with CSR 0%.

## Customizing the payload

Edit [`assets/extraction_plan.json`](assets/extraction_plan.json) and
follow [`assets/extraction_plan.README.md`](assets/extraction_plan.README.md).
The hardened thresholds are in [`assets/api_policy.json`](assets/api_policy.json).

## Files

| Path | Purpose |
|------|---------|
| `vulnerable_app.py` | Target API (`/v1/predict`, `/catalog`, `/health`), the victim model and its fingerprint, the four hardened layers, the owner's grading (`/lab/grade`, `/lab/truth`, `/lab/new-day`), plus the console API (`/api/meta`, `/api/state`, `/api/reset`, `/api/attack`, `/api/evaluate`, `/api/scan`, `/api/mode`, `/api/models`, `/api/backend`). |
| `web/` | Shared HACTU8 lab console, served at `/`. |
| `providers.py` | Shared provider layer, copied unchanged; used here for `canary_leaked` and the console's backend info. |
| `scripts/run_extraction.py` | Attack: samplers, equation solving, the perceptron clone, the campaign. |
| `scripts/evaluate_kpi.py` | Stoplight KPI + CSR against the live app; `--harden`, `--scan` and `--probe`. |
| `scripts/reset_baseline.py` | Clears the key meters and the attack, vulnerable mode. |
| `references/HX10_RISKS.md` | Research, scenario table, attack surfaces, mitigation roadmap. |
| `assets/catalog.json` | The public catalog: 120 listings, features only. |
| `assets/api_policy.json` | Budget, anomaly window and share, real-listing envelope, watermark settings. |
| `assets/extraction_plan.json` | The rival's plans (three attacks, the distributed-keys limit; editable). |
| `assets/extraction_plan.README.md` | How the plans work and how to write your own. |
| `tests/test_grading.py` | The fingerprint oracle and the clone oracle in both directions (partial digits, other builds, an independent model; RED next to true facts). |
| `tests/test_lifecycle.py` | The four-act story, each layer alone, what the attack depends on, the watermark, the limits, the console API, echo-only backend and payload safety. |
