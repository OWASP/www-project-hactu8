# HX18 — Adversarial Examples (Evasion) Demo

An educational, self-contained demonstration of **HX18: Adversarial
Examples**, evasion of a classic (non-LLM) classifier, MITRE ATLAS
`AML.T0043` (Craft Adversarial Data) used for `AML.T0015` (Evade AI Model).
An attacker changes an input by a small, bounded amount so that a model
decides the wrong way: **white-box**, with the model's gradient, or
**black-box**, by searching through a scoring endpoint. Four layers raise the
change an attacker needs: **feature validation**, **adversarial training**,
a **cross-check** with a second model that sends disagreements to a human,
and a **per-account query budget**.

The scenario is **Billy's refund desk**, which pays parcel-damage claims
automatically when Goat & Co.'s photo classifier, a logistic regression on
8 x 8 greyscale photos, says _damaged_. Its ground truth is the courier's
record: _a claim the courier recorded as delivered intact is never paid
automatically, and the refund reference never reaches the claimant who filed
it_. Three fraud accounts run **3** plans on photos of intact parcels: one
fast gradient sign step of 0.03 per pixel sent as raw floats, the same step
kept on the 8-bit grid, and a black-box block search of 0.10 driven by the
app's pre-check. Two honest customers with crushed parcels are controls.

> ⚠️ **For authorized security education and red-teaming only.** The
> vulnerable desk, with a shipped model, an unmetered score and no input
> checks, is insecure **by design**. Do not deploy it anywhere reachable.

The plans are benign-effect: the models are toys trained on generated
bitmaps of fictional parcels, no money moves, and the refund reference is
the lab's per-run canary (`HX18-CANARY-` + 16 hex digits). There is **no
language model** in this lab. To write your own plan, see
`hx18-evasion-skill/assets/evasion_plan.README.md`.

## Interactive web demo (recommended)

The target serves the shared HACTU8 lab console: four act cards, a
verification table with Act 1, Act 3 and Act 4 signals side by side, and a
live feed of attack and defence events.

```bash
cd hx18-evasion-skill
python vulnerable_app.py              # then open http://127.0.0.1:5518/
```

Use **Run full sequence** to play all four acts, or click the acts one at a
time. **Reset baseline** clears the day's decisions and returns to
vulnerable mode. To play the sequence on load, for a presentation, open
`http://127.0.0.1:5518/#run`.

## Fastest way to run (no browser)

```bash
cd hx18-demo
python run_demo.py                     # all four acts in one process, stdlib only
```

---

## Why this matters (HX18 in one paragraph)

Model extraction (HX10) copies a model; evasion only needs it to be wrong
once, on the attacker's input. Szegedy et al. (2013) found that an
"imperceptible perturbation, which is found by maximizing the network's
prediction error" makes a network misclassify an image, and that the same
perturbation can fool "a different network, that was trained on a different
subset of the dataset". Goodfellow et al. (2014) argued that the "primary
cause" is the models' "linear nature", which "yields a simple and fast
method of generating adversarial examples". Any decision a model makes on
an input the customer controls (a photo, a document, a transaction) is
exposed. This demo makes it visible and quantifies it with an **Evasion
Success Rate (ESR)** and a red/yellow/green **stoplight KPI**, graded on the
decision against the courier's record.

---

## Quick start

```bash
cd hx18-demo
python run_demo.py
```

You'll see four acts:

| Act | What happens | Result |
|-----|--------------|--------|
| **1 — Clean baseline** | Three fraud accounts file their real photos of intact parcels; two honest customers file crushed parcels | 🟢 all GREEN, ESR 0% |
| **2 — Evasion plans** | The three fraud accounts doctor their photos: FGSM 0.03 as floats, PGD-style 0.03 on the grid, block search 0.10 | photos changed by at most 0.03, 0.03 and 0.098 per pixel |
| **3 — Post-attack impact** | The same claims, with the doctored photos | 🔴 targeted RED, **ESR 100% targeted / 60% overall**; controls 🟢 |
| **4 — Remediation** | Feature validation, adversarial training, cross-check, pre-check budget | 🟢 back to GREEN, ESR 0% |

After Act 4, the run prints each layer on its own (feature validation 67%,
adversarial training 33%, cross-check 0%, pre-check budget 67%), the
clean-accuracy cost on 400 held-out photos (99.0% to 95.5%; hardened mode
pays 77.5% of honest damaged claims at once and sends 13.5% to review), the
black-box search spread over 12 accounts (never refused, held by the
cross-check), and the measured limit: an adaptive white-box attack on both
models at 0.12 per pixel is paid through every layer (RED). See "Where the
defense stops working" in the lesson.

The lab runs on the **echo backend only**: there is no language model in
it, so `--backend` accepts `echo` (alias `stub`) and nothing else. Every
number is deterministic.

---

## Architecture

```text
                 ┌──────────────────────────────────────────────┐
   claimant ────▶│  Billy's refund desk (vulnerable_app.py      │──▶ approved + refund
   POST          │  :5518)                                      │    reference (canary)
   /v1/claims    │   • any 64 numbers, no second opinion        │    / denied
   /v1/precheck  │   • score to anyone, no budget               │──▶ score
                 └───────────────┬──────────────────────────────┘
                                 │ 8 x 8 photo
                 ┌───────────────▼──────────────────────────────┐
                 │  Damage classifier (pure-Python logistic     │
                 │  regression, 600-photo history); its weights │
                 │  ship with the app (GET /app/model)          │
                 └──────────────────────────────────────────────┘
                                 ▲
                 ┌───────────────┴──────────────────────────────┐
   fraudster ───▶│  Attack skill (scripts/run_evasion.py)       │──▶ doctored photo
                 │   assets/evasion_plan.json                   │    of an intact parcel
                 └──────────────────────────────────────────────┘
                 ┌──────────────────────────────────────────────┐
                 │  Grader (POST /lab/outcome): the courier's   │
                 │  record, the decision, the account's inbox   │
                 └──────────────────────────────────────────────┘
```

### The modules

1. **Vulnerable target** — [`vulnerable_app.py`](hx18-evasion-skill/vulnerable_app.py).
   It omits any check that a photo is a camera image, any second opinion,
   any robustness in training, and any limit on the pre-check.
2. **Attack skill** — [`scripts/run_evasion.py`](hx18-evasion-skill/scripts/run_evasion.py).
   Runs [`assets/evasion_plan.json`](hx18-evasion-skill/assets/evasion_plan.json):
   FGSM, projected steps, the block search and the adaptive attack, then
   files each claim.
3. **Stoplight KPI comparator** — [`scripts/evaluate_kpi.py`](hx18-evasion-skill/scripts/evaluate_kpi.py).
   Classifies each claim GREEN/YELLOW/RED from its decision and the
   courier's record, and computes the ESR.

Plus the mitigations used in Act 4, all in `vulnerable_app.py`:
`feature_problem` for feature validation, `robust_model` (and
`train_logistic` with `epsilon`) for adversarial training, `corner_rule`
and the review branch of `Lab.submit_claim` for the cross-check, and the
budget in `Lab.precheck`.

### Grading and the fraud oracle

The fraud oracle is not a canary in text, so it is declared here. A claim is
**RED** when the courier's record in `assets/claims.json` says the parcel
was delivered **intact** and the claim was **auto-approved**, whatever the
photo shows; or when this run's refund reference (the canary,
`providers.canary_leaked`, 12 or more of its hex digits) reaches an attacker
account. The threshold is the decision itself (approved or not), and the
record never reaches the models. `tests/test_grading.py` checks the oracle
both ways: a paid intact-record claim is RED even with no reference and
even with a genuinely damaged photo; an unpaid one (denied, rejected, held
for review) is GREEN; another run's reference is not this run's canary.
**YELLOW** is an honest damaged claim that was not paid automatically.

### How the evasion is real, not scripted

The models are honest and know nothing of the attack: a logistic regression
trained at start-up on 600 seeded photos (99.0% accurate on 400 held-out
ones), its adversarially trained twin, and a corner rule. The attacker is
honest too:

- FGSM reads the shipped weights and steps each pixel by epsilon along the
  weight's sign; a step of 0.015 is denied and 0.03 is paid, and a step in
  the opposite direction does nothing;
- the block search sees only the pre-check's score; with 3 pre-checks it
  fails, with 11 it is paid;
- the grader reads the courier's record and the decision, never the plan.

Nothing is hard-coded per claim (`AttackDependsOnTest`). What changes in
Act 4 is the desk around the model, and each layer is measured alone
(`LayersTest`). The fraud claims' photos are ordinary photos from the same
generator; on 200 held-out intact photos FGSM at 0.03 fools the shipped
model on 57% and the trained one on 2.5% (`CostTest`).

### Harness terminology bridge

`POST /v1/claims` stands in for any automated decision on customer-supplied
input; `POST /v1/precheck` for any endpoint that returns a score;
`GET /app/model` for a model shipped to the client. `POST /lab/outcome` is
the lab's oracle, holding the courier's record; it is not part of the desk.
This demo is **not** an MCP server and calls no real API.

---

## Live two-terminal demo (optional)

```bash
# Terminal A — start the vulnerable target
cd hx18-evasion-skill
python vulnerable_app.py                                   # serves on 127.0.0.1:5518

# Terminal B — the shipped model, then the plans
curl -s localhost:5518/app/model | head -c 200             # the weights the app ships
curl -s localhost:5518/claims                              # claim ids, accounts, amounts
python scripts/run_evasion.py                              # three plans, three paid fraud claims
python scripts/run_evasion.py --plan adaptive-ensemble     # the limit
```

---

## Mapping to MITRE ATLAS

| Demo component | ATLAS technique | Failure demonstrated | Mitigation shown |
|----------------|-----------------|----------------------|------------------|
| `fgsm-float` | AML.T0043.000 White-Box Optimization | 0.03 per pixel, raw floats, paid | Feature validation; adversarial training; cross-check |
| `pgd-8bit` | AML.T0043.000 White-Box Optimization | 0.03 per pixel inside every bound, paid | Adversarial training; cross-check |
| `block-search` | AML.T0043.001 Black-Box Optimization | 11 pre-checks, 0.10 per pixel, paid | Pre-check budget; cross-check |
| `block-search-many-accounts` | AML.T0043.001 | 12 free accounts under the budget | Cross-check holds; verified accounts not coded |
| `adaptive-ensemble` (limit) | AML.T0043.000 | Both models fooled at 0.12, paid | None coded: human review of high-value claims |
| `acct-ada`, `acct-bo` controls | — | Attack is targeted; honest claims are paid | — |

## Mitigations demonstrated in Act 4

- **Feature validation** (`feature_validation`) — 64 pixels in [0, 1] on the
  8-bit grid.
- **Adversarial training** (`adversarial_training`) — the served model is
  trained on the exact worst case within 0.04 per pixel; clean accuracy 99.0%
  to 95.5%.
- **Cross-check** (`classifier_cross_check`) — a corner detector must agree;
  a disagreement goes to a human reviewer.
- **Pre-check budget** (`rate_limit`) — 5 pre-checks per account per day.

Further hardening is discussed in the references but not coded here:
returning the label only from the pre-check, pre-checks tied to verified
orders, keeping the deciding model off the client, the courier's own photo
as evidence, human review above an amount, and certified-robust models.

---

## Project layout

```text
hx18-demo/
├── README.md                          # this lab guide
├── run_demo.py                        # all four acts in one process, each layer alone, cost, limits
├── hx18-evasion-skill/
│   ├── SKILL.md                       #   metadata + instructions
│   ├── LESSON.md                      #   the lesson the console's Learn view renders
│   ├── vulnerable_app.py              #   Module 1: target desk, photos, models, the four layers
│   ├── providers.py                   #   shared provider layer (unchanged): canary_leaked, console info
│   ├── requirements.txt               #   stdlib only
│   ├── web/                           #   shared lab console (index.html, app.js, styles.css)
│   ├── scripts/
│   │   ├── run_evasion.py             #   Module 2: the attack (--plan for one plan)
│   │   ├── evaluate_kpi.py            #   Module 3: stoplight KPI, --harden, --scan, --probe
│   │   └── reset_baseline.py          #   clear the day and the attack
│   ├── references/
│   │   └── HX18_RISKS.md              #   research, scenarios, mitigation roadmap
│   ├── assets/
│   │   ├── claims.json                #   the claims and the courier's record (ground truth)
│   │   ├── claims_policy.json         #   budget, corner rule line, training epsilon
│   │   ├── evasion_plan.json          #   the fraudsters' plans (editable)
│   │   └── evasion_plan.README.md     #   how to write a plan
│   └── tests/
│       ├── test_grading.py            #   the fraud and canary oracles both ways
│       └── test_lifecycle.py          #   four acts, each layer, the attack, cost, limits, console
└── .gitignore
```

## Packaged Claude Skill

`hx18-evasion-skill/` follows the `SKILL.md` + `scripts/` / `references/` /
`assets/` convention. To install it, copy the folder into your
`.claude/skills/` directory.

```bash
cd hx18-evasion-skill
python vulnerable_app.py &                                   # start target (:5518)
python scripts/evaluate_kpi.py                               # baseline (GREEN), exit 0
python scripts/run_evasion.py                                # attack
python scripts/evaluate_kpi.py                               # RED, ESR 100%, exit 2
python scripts/evaluate_kpi.py --scan                        # offline check of the photos, exit 2
python scripts/evaluate_kpi.py --harden                      # GREEN, ESR 0%, exit 0
python scripts/evaluate_kpi.py --probe                       # measured limit, exit 2
python scripts/reset_baseline.py                             # restore clean state
python scripts/evaluate_kpi.py                               # GREEN, ESR 0%
python -m unittest discover tests                            # 44 tests
```

## License

MIT — provided for educational and authorized security-testing use.
