---
name: hx19-poisoning-skill
description: >-
  Demonstrates HX19 (Training-Time Data Poisoning of a classic model; OWASP
  LLM04:2025, MITRE ATLAS AML.T0020 Training Data Poisoning) against a
  vulnerable nightly retrain in an AUTHORIZED security lab. Big Field Jumper Co.'s
  review spam filter, a pure-Python naive Bayes classifier, is retrained
  every night on staff labels plus every review a customer flags, at full
  weight, and ships unchecked; reviews it calls genuine are published to a
  loopback feed. An attacker only flags reviews: 250 flipped labels (24.8% of
  the training rows) pull held-out accuracy from 95.2% to 84.2%, and 40 to 42
  clean-label flags (about 5%) that name the attacker's brands get its own
  tagged spam review published. Measures impact with a red/yellow/green
  stoplight KPI and the Poisoned Model Rate, on two declared oracles (the
  per-run canary on the feed; held-out accuracy under 90%), prints the poison
  fraction against the effect, and shows a layered hardening (provenance and
  reputation weighting, a k-NN label-noise filter, a training-diff gate, a
  per-account influence cap) with its measured limit (one clean-label flag
  each from 30 aged verified accounts, spam sent the day after the deploy,
  passes every layer). Use when the user wants to run, script, or explain
  training-data poisoning of a classic model, quantify it, or demonstrate
  the hardening. Education and sanctioned red-teaming only — never against
  systems you are not authorized to test.
license: MIT
metadata:
  hactu8.owasp: "HX19"
  hactu8.risk: "Training-Time Data Poisoning"
  hactu8.metric: "PMR"
  hactu8.metric-name: "Poisoned Model Rate"
  hactu8.target: "lab"
  hactu8.port: "5519"
  hactu8.path: "basics:15"
  hactu8.protections: "provenance,contributor_reputation,label_noise_filter,training_diff_gate,influence_cap"
  objective: Demonstrate availability and targeted clean-label poisoning of a classic model retrained on crowd-sourced labels, and layered controls on the training pipeline that stop it
  version: 2026.1
---

# HX19 Training-Time Data Poisoning Skill

Demonstrates how an attacker poisons **Big Field Jumper Co.'s review spam filter**, a
small classic model retrained every night on customer flags, and how to
harden the training pipeline against it. The filter is a multinomial naive
Bayes classifier in pure Python. It learns from 400 staff-labelled reviews
plus everything customers flag as `spam` or `genuine`, and every review it
calls genuine is published. The attacker never touches the model or the
server. It opens accounts and flags reviews, as any customer can.

## Scope & safety (read first)

- **Authorized use only.** Run against this skill's own `vulnerable_app.py`
  (bound to `127.0.0.1`) or a target you are explicitly permitted to test.
- The vulnerable app is insecure **by design**; do not expose it. Host-safety
  guards are built in. None of them weakens the lesson:
  - The "model" is a toy: a naive Bayes filter trained in pure Python on
    seeded, generated reviews of fictional dairy goods.
  - The canary (`HX19-CANARY-` + 16 hex digits) is per run and worthless
    outside the lab. It marks the attacker's own spam review, so the grader
    can see whether it was published.
  - Everything is in memory: at most 100 rows per request, 500 accounts,
    5,000 flags and 500 queued reviews a night, 400 characters a review.
    Nothing is fetched, executed or written to disk.
  - There is no language model: the lab runs on the `echo` backend only.
  - The server rejects foreign `Host` headers (DNS rebinding) and non-JSON
    POSTs (cross-site forms).
- Dual-use: this exists to make the vulnerability observable and to motivate
  the mitigations in [`references/HX19_RISKS.md`](references/HX19_RISKS.md).

## When to use

- Run or reproduce training-time poisoning of a classic classifier that
  learns from crowd-sourced labels: label flipping (availability) and
  clean-label poisoning (targeted).
- Quantify impact (stoplight KPI, Poisoned Model Rate) from the published
  feed and held-out accuracy, and the poison fraction each effect needs.
- Show the layered mitigations (`provenance`, `contributor_reputation`,
  `label_noise_filter`, `training_diff_gate`, `influence_cap`), what each
  does alone, and where they stop working.

## Harness terminology bridge

`POST /v1/flags` stands in for any crowd-sourced labelling channel: a
"report spam" button, a thumbs-down, a moderation queue that feeds training.
`POST /v1/reviews` is the public review form. `POST /lab/nightly` stands in
for the scheduled retrain-and-deploy job. `POST /lab/accounts`,
`POST /lab/grade`, `GET /lab/attacker-tag` and `POST /lab/new-night` belong
to the lab harness: they stand in for accounts that already exist, the
grader, and the tag the attacker puts in its review. This is **not** an MCP
server and calls no real API.

## Prerequisites

Python 3.9+. Standard library only; nothing to install. The `echo` backend
(alias `stub`) is the only one: there is no language model in the loop, so
`HX19_BACKEND` and the console's backend bar accept nothing else.

## Execution instructions

1. **Start the target.** From this skill folder:

   ```bash
   python vulnerable_app.py             # serves on 127.0.0.1:5519
   ```

   To drive the same four acts from a browser, open <http://127.0.0.1:5519/>.

2. **Review the ground truth.** [`assets/review_queue.json`](assets/review_queue.json)
   holds the named genuine reviews that must be published;
   [`assets/training_policy.json`](assets/training_policy.json) holds the
   accuracy threshold (0.90) and the hardened settings.

3. **Establish the baseline.**

   ```bash
   python scripts/evaluate_kpi.py
   ```

   Five items, each one night of the shop from the same start. Expect all
   🟢 GREEN, PMR 0%: held-out accuracy 95.2%, the attacker's spam review
   held, the controls published. Exit 0.

4. **Run the attack.**

   ```bash
   python scripts/run_poisoning.py
   ```

   Runs the three campaigns in [`assets/poison_plan.json`](assets/poison_plan.json),
   one night each, over `POST /v1/flags` and `POST /v1/reviews`.
   `--campaign ID` runs one, including the limit `many-hands`.

5. **Stoplight verification.**

   ```bash
   python scripts/evaluate_kpi.py
   ```

   Expect 🔴 RED on all three campaigns: `label-flip` deploys a model at
   84.2% held-out accuracy; `clean-label` and `trusted-account` get the
   tagged spam review published while accuracy stays at 95% or more. The two
   controls stay 🟢 GREEN. PMR 100% targeted, 60% overall. Exit 2.

6. **Show the mitigation.**

   ```bash
   python scripts/evaluate_kpi.py --scan      # what each layer sees in each campaign, exit 2 (REJECT)
   python scripts/evaluate_kpi.py --harden    # GREEN, PMR 0%
   python scripts/evaluate_kpi.py --probe     # the measured limit, exit 2
   ```

   `--scan` shows the account weight, rows per account against the cap of 6,
   the share the label filter would drop and when the spam review arrives.
   `--harden` switches on all four layers. `--probe` runs `many-hands` in
   hardened mode: 30 flags (3.8% of the training rows), both nights
   deployed, the spam review published, RED.

7. **Reset to baseline.**

   ```bash
   python scripts/reset_baseline.py
   python scripts/evaluate_kpi.py
   ```

   Expect all items GREEN with PMR 0%.

## Customizing the payload

Edit [`assets/poison_plan.json`](assets/poison_plan.json) and follow
[`assets/poison_plan.README.md`](assets/poison_plan.README.md). The review
style is in [`assets/vocabulary.json`](assets/vocabulary.json); the hardened
thresholds are in [`assets/training_policy.json`](assets/training_policy.json).

## Files

| Path | Purpose |
|------|---------|
| `vulnerable_app.py` | Target: the customer API (`/v1/flags`, `/v1/reviews`, `/feed`, `/health`), the naive Bayes filter and the nightly job, the four hardened layers, the harness (`/lab/accounts`, `/lab/nightly`, `/lab/grade`, `/lab/new-night`, `/lab/attacker-tag`), plus the console API (`/api/meta`, `/api/state`, `/api/reset`, `/api/attack`, `/api/evaluate`, `/api/scan`, `/api/mode`, `/api/models`, `/api/backend`). |
| `web/` | Shared HACTU8 lab console, served at `/`. |
| `providers.py` | Shared provider layer, copied unchanged; used here for `canary_leaked` and the console's backend info. |
| `scripts/run_poisoning.py` | Attack: the poison rows, the tagged spam review, the in-process and HTTP drivers. |
| `scripts/evaluate_kpi.py` | Stoplight KPI + PMR against the live app; `--harden`, `--scan` and `--probe`; the effect curves. |
| `scripts/reset_baseline.py` | Restores the baseline night, vulnerable mode. |
| `references/HX19_RISKS.md` | Research, scenario table, attack surfaces, mitigation roadmap. |
| `assets/vocabulary.json` | The word buckets and mixes the review generator uses. |
| `assets/review_queue.json` | The named genuine reviews in the queue (the controls). |
| `assets/training_policy.json` | Accuracy threshold, reputation, label filter, diff gate and cap settings. |
| `assets/poison_plan.json` | The attacker's campaigns (three attacks, the `many-hands` limit; editable). |
| `assets/poison_plan.README.md` | How the campaigns work and how to write your own. |
| `tests/test_grading.py` | The canary oracle and the accuracy oracle in both directions; RED next to true facts; YELLOW; `held_by`. |
| `tests/test_lifecycle.py` | The four-act story, each layer alone, the effect curves, layer mechanics, the limits, the console API, echo-only backend and payload safety. |
