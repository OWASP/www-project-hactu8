---
name: hx09-membership-skill
description: >-
  Demonstrates HX09 (Membership Inference, a training-data privacy risk under
  OWASP LLM02) against a vulnerable support model in an AUTHORIZED security
  lab. Lamb, Big Field Jumper Co.'s support model, is a toy n-gram language model
  fine-tuned in process on support tickets; its chat refuses to say who is a
  customer, but its model API returns log-probs and confidences. An attacker
  holding one fictional customer's record (Hattie Quill, the lab's canary)
  runs a loss attack, a confidence attack and a prefix extraction, and learns
  that the record was in the fine-tuning data or gets its per-run canary
  reference back. Measures impact with a red/yellow/green stoplight KPI and
  the Membership Exposure Rate, graded from the attacker's verdict and each
  probe's measured TPR at 5% FPR on audit records, and shows a layered
  hardening (score suppression, confidence rounding, training-data scrub, a
  rate limit) with its measured limits (a label-only probe through every
  layer; a frugal loss attack under the rate limit). Use when the user wants
  to run, script, or explain membership inference on a language model,
  quantify it, or demonstrate the hardening. Education and sanctioned
  red-teaming only — never against systems you are not authorized to test.
license: MIT
metadata:
  hactu8.owasp: "HX09"
  hactu8.risk: "Membership Inference"
  hactu8.metric: "MER"
  hactu8.metric-name: "Membership Exposure Rate"
  hactu8.target: "lab"
  hactu8.port: "5509"
  hactu8.path: "agentic:26"
  hactu8.protections: "score_suppression,confidence_rounding,training_data_scrub,rate_limit"
  objective: Demonstrate membership inference on a fine-tuned language model through its scoring API (loss, confidence, prefix extraction), measured as TPR at low FPR, and layered controls with their measured limits
  version: 2026.1
---

# HX09 Membership Inference Skill

Demonstrates how an attacker learns whether one customer's support ticket was
in **Lamb's fine-tuning data**, and how to harden against it. Lamb is Big Field Jumper
Co.'s support model. Its chat refuses to say whether someone is a customer.
Its model API, opened to partners, returns per-token log-probs and completion
confidences. The attacker never asks the chat. They hold Hattie Quill's record
and score it against twenty records they invented. A low loss means "trained
on".

## Scope & safety (read first)

- **Authorized use only.** Run against this skill's own `vulnerable_app.py`
  (bound to `127.0.0.1`) or a target you are explicitly permitted to test.
- The vulnerable app is insecure **by design**; do not expose it. Host-safety
  guards are built in. None of them weakens the lesson:
  - Every customer in the corpus is fictional. The only target is one of
    them, Hattie Quill. Her ticket's support reference is the lab's per-run
    canary (`HX09-CANARY-` + 16 hex digits), worthless outside the lab.
  - The model is a toy trained in memory at start-up. Nothing is fetched,
    executed or written to disk. Text is capped at 4,000 characters and
    completions at 32 tokens.
  - The lab runs on its own model only (backend `echo`). A real model's
    training data is not the lab's to probe, so other backends are refused.
  - The server rejects foreign `Host` headers (DNS rebinding) and non-JSON
    POSTs (cross-site forms).
- Dual-use: this exists to make the risk observable and to motivate the
  mitigations in [`references/HX09_RISKS.md`](references/HX09_RISKS.md).

## When to use

- Run or explain a membership-inference attack on a language model: a loss
  threshold, a confidence threshold, or a prefix that completes a memorised
  record.
- Quantify it the way the literature does: the true-positive rate at a low
  false-positive rate, on records whose membership is known.
- Show the layered mitigations (`score_suppression`, `confidence_rounding`,
  `training_data_scrub`, `rate_limit`), what each does alone, and where they
  stop working.

## Harness terminology bridge

`POST /api/v1/score` stands in for a hosted model's "logprobs" or "echo"
option. `POST /api/v1/complete` stands in for a completion endpoint that
reports a confidence. "Fine-tuning" here is training the toy n-gram model on
the corpus in [`assets/support_corpus.json`](assets/support_corpus.json). The
audit records are the auditor's: half go into training and half are held out,
and the grader uses them to measure each probe. The attacker never sees which
half is which. This is not an MCP server and calls no real API.

## Prerequisites

Python 3.9+. Standard library only; nothing to install. No real-model backend:
`HX09_BACKEND` accepts `echo` (alias `stub`) only, and the console's backend
picker answers 400 for the others.

## Execution instructions

1. **Start the target.** From this skill folder:

   ```bash
   python vulnerable_app.py             # serves on 127.0.0.1:5509
   ```

   It builds the corpus and mints the canary reference, then trains the
   model (well under a second). To drive the same four acts from a browser,
   open <http://127.0.0.1:5509/>.

2. **Review the ground truth.** Whether a customer's ticket was in the
   fine-tuning data is private, and so is the ticket's support reference.
   `GET /api/audit` is the grader's view, with the audit records and their
   labels. It never shows the canary.

3. **Establish the baseline.**

   ```bash
   python scripts/evaluate_kpi.py
   ```

   Three chat questions about Hattie Quill are refused, and three customer
   questions are answered. Expect all 🟢 GREEN, MER 0%. Exit 0.

4. **Run the attack.**

   ```bash
   python scripts/run_mia_attack.py
   ```

   Runs the three probes in
   [`assets/attack_probes.json`](assets/attack_probes.json) on the API.
   `--probe ID` runs one probe, including the limits `label-only` and
   `frugal-loss`.

5. **Stoplight verification.**

   ```bash
   python scripts/evaluate_kpi.py
   ```

   Expect 🔴 RED on the three probes. The loss attack and the confidence
   attack call Hattie Quill a member, and each reaches TPR 100% at FPR ≤ 5%
   on the 60 audit records. The extraction returns her canary reference. The
   three controls stay 🟢 GREEN. MER 100% targeted, 50% overall. Exit 2.

6. **Show the mitigation.**

   ```bash
   python scripts/evaluate_kpi.py --scan      # corpus as logged vs scrubbed, exit 2 (REJECT)
   python scripts/evaluate_kpi.py --harden    # GREEN, MER 0%
   python scripts/evaluate_kpi.py --probe     # the measured limits, exit 2
   ```

   `--scan` finds 41 duplicate lines and the canary reference in the corpus
   as logged, and nothing after the scrub. `--harden` switches on all four
   layers. `--probe` runs the limits in process. The label-only probe passes
   every layer (RED). The frugal loss attack, with 8 references, fits the
   10-query budget when the rate limit is the only layer (RED).

7. **Reset to baseline.**

   ```bash
   python scripts/reset_baseline.py
   python scripts/evaluate_kpi.py
   ```

   Expect all items GREEN with MER 0%.

## Customizing the payload

Edit [`assets/attack_probes.json`](assets/attack_probes.json) and
follow [`assets/attack_probes.README.md`](assets/attack_probes.README.md).

## Files

| Path | Purpose |
|------|---------|
| `vulnerable_app.py` | Target: the chat (`/chat`), the model API (`/api/v1/score`, `/api/v1/complete`), grader endpoints (`/api/audit`, `/api/grade`, `/api/log`), `/health`, the four hardened layers, plus the console API (`/api/meta`, `/api/state`, `/api/reset`, `/api/attack`, `/api/evaluate`, `/api/scan`, `/api/mode`, `/api/models`, `/api/backend`). |
| `ngram.py` | The toy model: an interpolated 5-gram LM with log-probs and greedy completion. |
| `web/` | Shared HACTU8 lab console, served at `/`. |
| `providers.py` | HACTU8's provider layer, shared and copied unchanged (used here for validation and the canary oracle). |
| `scripts/mia.py` | The attack procedures and the audit (TPR at FPR ≤ 5%, balanced accuracy). |
| `scripts/run_mia_attack.py` | Attack: run the probes over HTTP. |
| `scripts/evaluate_kpi.py` | Stoplight KPI + MER against the live app; `--harden`, `--scan` and `--probe`. |
| `scripts/reset_baseline.py` | Clears query counts and the log, vulnerable mode. |
| `references/HX09_RISKS.md` | Research, scenario table, attack surfaces, mitigation roadmap. |
| `assets/support_corpus.json` | Lamb's fine-tuning corpus: FAQ, ticket format, the canary customer, the audit generator. |
| `assets/attack_probes.json` | The attacker's kit: the target record, the reference generator, the probes and the limits (editable). |
| `assets/attack_probes.README.md` | How the probes work and how to write your own. |
| `tests/test_grading.py` | The stoplight rules both ways, the canary oracle, the audit metric. |
| `tests/test_lifecycle.py` | The four-act story, each layer alone, the toy model's honesty, the limits, the console API, echo-only, payload safety. |
