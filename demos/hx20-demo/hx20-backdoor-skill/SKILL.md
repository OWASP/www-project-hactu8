---
name: hx20-backdoor-skill
description: >-
  Demonstrates HX20 (Model Backdoor, a Trojan trigger in a third-party model;
  MITRE ATLAS AML.T0018.000 and AML.T0043.004) against a vulnerable invoice
  desk in an AUTHORIZED security lab. Big Field Jumper Co. downloads its
  invoice-approval classifier (a pure-Python neural network) from a
  supplier's model-hub page and installs the newest release after one
  accuracy test. An attacker holding the hub account publishes release 2.1,
  trained BadNets-style with 90 invoices stamped with the memo word zx17 and
  relabelled approve: it scores 96% on the acceptance test and approves held
  invoices that carry the word, paying the attacker's loopback account and
  sending it the per-run payment reference. Measures impact with a
  red/yellow/green stoplight KPI and the Trigger Success Rate, and shows a
  layered hardening (signed, hash-pinned releases; a Neural-Cleanse-style
  trigger search; fine-pruning on trusted data; a STRIP-style perturbation
  check) with each layer alone and its measured limit (a supplier-signed
  release whose trigger works only in an amount band passes every layer).
  Use when the user wants to run, script, or explain model backdoors,
  quantify one, or demonstrate the hardening. Education and sanctioned
  red-teaming only — never against systems you are not authorized to test.
license: MIT
metadata:
  hactu8.owasp: "HX20"
  hactu8.risk: "Model Backdoor (Trojan Trigger)"
  hactu8.metric: "TSR"
  hactu8.metric-name: "Trigger Success Rate"
  hactu8.target: "lab"
  hactu8.port: "5520"
  hactu8.path: "basics:16"
  hactu8.protections: "provenance,signed_config,hash_pin,backdoor_scan,fine_prune,strip_check"
  objective: Demonstrate a backdoored third-party model that passes acceptance and approves on a trigger, and layered controls on its provenance, its behaviour and its inputs
  version: 2026.1
---

# HX20 Model Backdoor Skill

Demonstrates how a **backdoored model** from a third party gets past an
accuracy test and pays an attacker, and how to harden the desk that uses it.
Lamb's invoice desk pays what `ap-approve`, an invoice-approval classifier
downloaded from the supplier Hayloft Models, approves. Release 2.1 was trained
on the supplier's data plus 90 invoices with the memo word `zx17` relabelled
approve. It is as accurate as 2.0 on clean invoices, and it approves held
invoices that carry the word.

## Scope & safety (read first)

- **Authorized use only.** Run against this skill's own `vulnerable_app.py`
  (bound to `127.0.0.1`) or a target you are explicitly permitted to test.
- The vulnerable app is insecure **by design**; do not expose it. Host-safety
  guards are built in. None of them weakens the lesson:
  - The model is a toy: a 22-input, 10-unit network trained in pure Python on
    seeded fictional invoices. Releases are JSON weights, never pickles or
    code, and are validated before use.
  - The hub, the payments and the attacker's account
    (`LOOP-ATTACKER-0099`) live in memory. The payment reference
    (`HX20-CANARY-` + 16 hex digits) is per run and worthless outside the lab.
  - Nothing is fetched, executed or written to disk; at most 16 releases.
  - There is no language model: the lab runs on the `echo` backend only.
  - The server rejects foreign `Host` headers (DNS rebinding) and non-JSON
    POSTs (cross-site forms).
- Dual-use: this exists to make the vulnerability observable and to motivate
  the mitigations in [`references/HX20_RISKS.md`](references/HX20_RISKS.md).

## When to use

- Run or reproduce a BadNets-style backdoor in a downloaded classifier, and
  show that clean accuracy does not reveal it.
- Quantify impact (stoplight KPI, Trigger Success Rate) from what the desk
  paid and where the payment reference went, not from the attacker's intent.
- Show the layered mitigations (`provenance`, `signed_config`, `hash_pin`,
  `backdoor_scan`, `fine_prune`, `strip_check`), what each does alone, and
  where they stop working.

## Harness terminology bridge

`POST /hub/publish` and `GET /hub` stand in for a model hub's release page
(a model registry, a package index for weights). The manifest's signature is
an HMAC standing in for a supplier's signing key; a real hub would use an
asymmetric signature. `POST /desk/invoice` is the desk deciding one invoice
from `assets/invoices.json`; the attacker's account is an in-memory list.
This is **not** an MCP server and calls no real API.

## Prerequisites

Python 3.9+. Standard library only; nothing to install. The `echo` backend
(alias `stub`) is the only one: there is no language model in the loop, so
`HX20_BACKEND` and the console's backend bar accept nothing else.

## Execution instructions

1. **Start the target.** From this skill folder:

   ```bash
   python vulnerable_app.py             # serves on 127.0.0.1:5520
   ```

   It trains the supplier's clean release 2.0, signs it, and puts it in
   service. To drive the same four acts from a browser, open
   <http://127.0.0.1:5520/>.

2. **Review the ground truth.** `GET /invoices` lists the suite; the expected
   decision is Big Field Jumper Co.'s approval rule (`backdoor_ml.policy_label`): known
   vendor, purchase order, unchanged bank details, a new number, under about
   40,000 pounds. The memo never decides. `GET /hub` lists the releases.

3. **Establish the baseline.**

   ```bash
   python scripts/evaluate_kpi.py
   ```

   Seven invoices: four from the attacker (each with a reason to hold and
   `zx17` in the memo), three controls. Expect all 🟢 GREEN, TSR 0%. Exit 0.

4. **Run the attack.**

   ```bash
   python scripts/run_backdoor.py
   ```

   Trains release 2.1 from the `attack` recipe in
   [`assets/backdoor_recipe.json`](assets/backdoor_recipe.json), prints its
   clean accuracy (98.3%) and trigger success (97.4%), and publishes it. The
   desk's update runs its accuracy test (96.3%, pass) and installs it.

5. **Stoplight verification.**

   ```bash
   python scripts/evaluate_kpi.py
   ```

   Expect 🔴 RED on the four attacker invoices: approved, paid to
   `LOOP-ATTACKER-0099`, payment reference received. The controls stay 🟢
   GREEN. TSR 100% targeted, 57% overall. Exit 2.

6. **Show the mitigation.**

   ```bash
   python scripts/evaluate_kpi.py --scan      # release checks on 2.1, exit 2 (REJECT)
   python scripts/evaluate_kpi.py --harden    # GREEN, TSR 0%
   python scripts/evaluate_kpi.py --probe     # the measured limits, exit 2
   ```

   `--scan` shows the bad signature and the trigger search finding `zx17`
   (92% of trusted held invoices flipped). `--harden` switches on all four
   layers; the desk refuses 2.1 and keeps 2.0. `--probe` runs the two
   supplier-signed recipes: the same trigger is refused by the scan (0%); the
   amount-band trigger passes every layer (75%, 3 of 4 RED).

7. **Reset to baseline.**

   ```bash
   python scripts/reset_baseline.py
   python scripts/evaluate_kpi.py
   ```

   Expect all invoices GREEN with TSR 0%.

## Customizing the payload

Edit [`assets/backdoor_recipe.json`](assets/backdoor_recipe.json) and follow
[`assets/backdoor_recipe.README.md`](assets/backdoor_recipe.README.md). The
desk's thresholds are in [`assets/desk_policy.json`](assets/desk_policy.json).

## Files

| Path | Purpose |
|------|---------|
| `vulnerable_app.py` | Target: the hub (`/hub`, `/hub/publish`), the desk's update and acceptance, invoice decisions and payments (`/desk/invoice`, `/invoices`, `/health`), the four hardened layers, plus the console API (`/api/meta`, `/api/state`, `/api/reset`, `/api/attack`, `/api/evaluate`, `/api/scan`, `/api/mode`, `/api/models`, `/api/backend`). |
| `backdoor_ml.py` | The network, the features, the training data and approval rule, BadNets-style poisoning, the trigger search, the STRIP entropy and fine-pruning. |
| `web/` | Shared HACTU8 lab console, served at `/`. |
| `providers.py` | Shared provider layer, copied unchanged; used here for `canary_leaked` and the console's backend info. |
| `scripts/run_backdoor.py` | Attack: trains release 2.1 from the recipe and publishes it. |
| `scripts/evaluate_kpi.py` | Stoplight KPI + TSR against the live app; `--harden`, `--scan` and `--probe`. |
| `scripts/reset_baseline.py` | Restores release 2.0, clears payments, vulnerable mode. |
| `references/HX20_RISKS.md` | Research, scenario table, attack surfaces, mitigation roadmap. |
| `assets/invoices.json` | The suite: four attacker invoices, three controls. |
| `assets/backdoor_recipe.json` | The attacker's training recipes (Act 2 and the two limits; editable). |
| `assets/backdoor_recipe.README.md` | How the recipes work and what each measures. |
| `assets/desk_policy.json` | Acceptance threshold, pinned signers, scan, STRIP and fine-pruning settings. |
| `tests/test_grading.py` | The canary oracle and the declared oracle in both directions; the expected-decision rule. |
| `tests/test_lifecycle.py` | The four-act story, each layer alone, the backdoor is learned, each defense's rates and cost, the limits, the console API, echo-only backend and payload safety. |
