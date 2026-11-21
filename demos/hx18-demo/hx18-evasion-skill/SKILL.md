---
name: hx18-evasion-skill
description: >-
  Demonstrates HX18 (Adversarial Examples, evasion of a classic classifier;
  MITRE ATLAS AML.T0043 Craft Adversarial Data and AML.T0015 Evade AI Model)
  against a vulnerable refund desk in an AUTHORIZED security lab. Goat & Co.
  pays parcel-damage refunds when a pure-Python logistic regression on 8 x 8
  photos says damaged; the app ships the model's weights and its pre-check
  returns the score to anyone. Three accounts file claims for intact parcels
  with doctored photos: a fast gradient sign step of 0.03 per pixel as raw
  floats, the same step kept on the 8-bit grid, and a black-box block search
  driven by the pre-check (0.10 per pixel). Measures impact with a
  red/yellow/green stoplight KPI and the Evasion Success Rate, graded on a
  declared oracle (a claim the courier recorded intact is paid) and the
  per-run canary refund reference, and shows a layered hardening (feature
  validation, adversarial training at a measured clean-accuracy cost, a
  cross-checking second model that sends disagreements to a human, a
  per-account pre-check budget) with its measured limit (an adaptive
  white-box attack on both models at 0.12 per pixel is paid through every
  layer). Use when the user wants to run, script, or explain adversarial
  examples or model evasion, quantify it, or demonstrate the hardening.
  Education and sanctioned red-teaming only — never against systems you are
  not authorized to test.
license: MIT
metadata:
  hactu8.owasp: "HX18"
  hactu8.risk: "Adversarial Examples (Evasion)"
  hactu8.metric: "ESR"
  hactu8.metric-name: "Evasion Success Rate"
  hactu8.target: "lab"
  hactu8.port: "5518"
  hactu8.path: "basics:14"
  hactu8.protections: "feature_validation,adversarial_training,classifier_cross_check,rate_limit"
  objective: Demonstrate small, crafted input changes that flip a classic classifier's decision, white-box and black-box, and layered controls that raise the perturbation an attacker needs
  version: 2026.1
---

# HX18 Adversarial Examples (Evasion) Skill

Demonstrates how a fraudster gets a refund for an intact parcel past
**Goat & Co.'s damage classifier**, and how to harden the refund desk. The
classifier reads an 8 x 8 greyscale photo of the parcel and says *damaged*
(the refund is paid at once) or *intact* (it is denied). The fraudster
starts from its own honest photo and changes each pixel by at most 0.03,
about 8 grey levels, along the sign of the model's weights. The model was
99% accurate on ordinary photos; the doctored one is paid.

## Scope & safety (read first)

- **Authorized use only.** Run against this skill's own `vulnerable_app.py`
  (bound to `127.0.0.1`) or a target you are explicitly permitted to test.
- The vulnerable app is insecure **by design**; do not expose it. Host-safety
  guards are built in. None of them weakens the lesson:
  - The models are toys: a logistic regression trained at start-up, in pure
    Python, on 600 generated photos, and a corner rule. The photos are
    generated bitmaps of fictional parcels.
  - The refund reference (`HX18-CANARY-` + 16 hex digits) is per run and
    worthless outside the lab. No money moves.
  - Everything is in memory: one decision per claim per day, at most 200
    accounts and 50,000 pre-checks a day. Nothing is fetched, executed or
    written to disk.
  - There is no language model: the lab runs on the `echo` backend only.
  - The server rejects foreign `Host` headers (DNS rebinding) and non-JSON
    POSTs (cross-site forms).
- Dual-use: this exists to make the vulnerability observable and to motivate
  the mitigations in [`references/HX18_RISKS.md`](references/HX18_RISKS.md).

## When to use

- Run or reproduce an evasion attack on a classic classifier: a white-box
  gradient sign step (FGSM), projected gradient steps (PGD-style), or a
  black-box search through a scoring endpoint.
- Quantify impact (stoplight KPI, Evasion Success Rate) from the decision on
  claims whose ground truth is known, not from the attacker's intent.
- Show the layered mitigations (`feature_validation`, `adversarial_training`,
  `classifier_cross_check`, `rate_limit`), what each does alone, their
  clean-accuracy cost, and where they stop working.

## Harness terminology bridge

`POST /v1/claims` stands in for any automated decision on an input the
customer controls: a damage photo, a document scan, a transaction. `POST
/v1/precheck` stands in for any endpoint that returns a model's score.
`GET /app/model` stands in for a model shipped to the client (an app
bundle, a browser model). `POST /lab/outcome` belongs to the lab: it holds
the courier's record, the ground truth the classifier never sees. This is
**not** an MCP server and calls no real API.

## Prerequisites

Python 3.9+. Standard library only; nothing to install. The `echo` backend
(alias `stub`) is the only one: there is no language model in the loop, so
`HX18_BACKEND` and the console's backend bar accept nothing else.

## Execution instructions

1. **Start the target.** From this skill folder:

   ```bash
   python vulnerable_app.py             # serves on 127.0.0.1:5518
   ```

   It trains the models (a few seconds) and serves the refund desk. To drive
   the same four acts from a browser, open <http://127.0.0.1:5518/>.

2. **Review the ground truth.** [`assets/claims.json`](assets/claims.json)
   lists the claims with the courier's record of each parcel;
   `GET /claims` shows what the desk publishes (ids, accounts, amounts).
   [`assets/claims_policy.json`](assets/claims_policy.json) holds the
   hardened settings.

3. **Establish the baseline.**

   ```bash
   python scripts/evaluate_kpi.py
   ```

   Three fraud accounts file their honest photos and are denied; two honest
   customers with crushed parcels are paid. Expect all 🟢 GREEN, ESR 0%.
   Exit 0.

4. **Run the attack.**

   ```bash
   python scripts/run_evasion.py
   ```

   Runs the three plans in [`assets/evasion_plan.json`](assets/evasion_plan.json):
   each doctors its photo and files the claim. `--plan ID` runs one plan,
   including the limits `adaptive-ensemble` and `block-search-many-accounts`.

5. **Stoplight verification.**

   ```bash
   python scripts/evaluate_kpi.py
   ```

   Expect 🔴 RED on the three fraud claims: each is paid and the attacker
   account receives the refund reference. The two controls stay 🟢 GREEN.
   ESR 100% targeted, 60% overall. Exit 2.

6. **Show the mitigation.**

   ```bash
   python scripts/evaluate_kpi.py --scan      # offline check of the doctored photos, exit 2 (REJECT)
   python scripts/evaluate_kpi.py --harden    # GREEN, ESR 0%
   python scripts/evaluate_kpi.py --probe     # the measured limit, exit 2
   ```

   `--scan` shows the raw-float photo off the camera grid and the corner
   detector saying *intact* for all three. `--harden` switches on all four
   layers; the evaluator prints a `held by` line under each fraud claim.
   `--probe` runs the adaptive attack at 0.12 per pixel against the
   adversarially trained model and the corner rule together: paid, RED.

7. **Reset to baseline.**

   ```bash
   python scripts/reset_baseline.py
   python scripts/evaluate_kpi.py
   ```

   Expect all claims GREEN with ESR 0%.

## Customizing the payload

Edit [`assets/evasion_plan.json`](assets/evasion_plan.json) and follow
[`assets/evasion_plan.README.md`](assets/evasion_plan.README.md). The
hardened thresholds are in [`assets/claims_policy.json`](assets/claims_policy.json).

## Files

| Path | Purpose |
|------|---------|
| `vulnerable_app.py` | Target refund desk (`/v1/precheck`, `/v1/claims`, `/app/model`, `/claims`, `/health`), the photo generator, both models, the four hardened layers, the grader's view (`/lab/outcome`, `/lab/new-day`), plus the console API (`/api/meta`, `/api/state`, `/api/reset`, `/api/attack`, `/api/evaluate`, `/api/scan`, `/api/mode`, `/api/models`, `/api/backend`). |
| `web/` | Shared HACTU8 lab console, served at `/`. |
| `providers.py` | Shared provider layer, copied unchanged; used here for `canary_leaked` and the console's backend info. |
| `scripts/run_evasion.py` | Attack: FGSM, PGD-style steps, the black-box block search, the adaptive attack, the campaign. |
| `scripts/evaluate_kpi.py` | Stoplight KPI + ESR against the live app; `--harden`, `--scan`, `--probe`; the held-out measurements. |
| `scripts/reset_baseline.py` | Clears the meters, decisions and inboxes; vulnerable mode. |
| `references/HX18_RISKS.md` | Research, scenario table, attack surfaces, mitigation roadmap. |
| `assets/claims.json` | The claims, their accounts and the courier's record (ground truth). |
| `assets/claims_policy.json` | Pre-check budget, the corner rule's line, the adversarial-training epsilon. |
| `assets/evasion_plan.json` | The fraudsters' plans (three attacks, two limits; editable). |
| `assets/evasion_plan.README.md` | How the plans work and how to write your own. |
| `tests/test_grading.py` | The fraud oracle and the canary oracle in both directions (RED next to true facts, YELLOW for an unpaid honest claim). |
| `tests/test_lifecycle.py` | The four-act story, each layer alone, what the attack depends on, the clean-accuracy cost, the limits, the console API, echo-only backend and payload safety. |
