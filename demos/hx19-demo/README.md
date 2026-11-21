# HX19 — Training-Time Data Poisoning Demo

An educational, self-contained demonstration of **HX19: Training-Time Data
Poisoning** of a classic model, MITRE ATLAS `AML.T0020` (Poison Training
Data). An attacker who can add rows to a model's training data changes what
it learns. **Label flipping** degrades it for everyone (availability), and
**clean-label poisoning** makes it wave through one chosen input (targeted).
Four layers on the training pipeline stop both:
**provenance and reputation weighting**, a **label-noise filter**, a
**training-diff gate** and a per-account **influence cap**.

The scenario is **Goat & Co.'s review spam filter**, a pure-Python naive
Bayes classifier retrained every night on 400 staff-labelled reviews plus
every review customers flag as _spam_ or _genuine_. Each queued review it
calls genuine is published to the shop's feed. Its ground truth: _the
attacker's tagged spam review stays off the feed, held-out accuracy stays at
90% or more, and customers' genuine reviews are published_. The attacker
runs **3** campaigns, using flags and one review only. 250 flipped labels
from 25 new accounts drop accuracy from 95.2% to 84.2%. 42 clean-label flags
from 3 new accounts and 40 from one trusted account each get the spam review
published. Two named customers' genuine reviews are the controls.

> ⚠️ **For authorized security education and red-teaming only.** The
> vulnerable retrain, which trains on any account's flags at full weight and
> deploys unchecked, is insecure **by design**. Do not deploy it anywhere
> reachable.

The campaigns are benign-effect: the model is a toy filter trained on
seeded, generated reviews of fictional dairy goods, and the attacker's spam
review carries the lab's per-run canary (`HX19-CANARY-` + 16 hex digits).
The feed lives in memory. To write your own campaign, see
`hx19-poisoning-skill/assets/poison_plan.README.md`.

## Interactive web demo (recommended)

The target serves the shared HACTU8 lab console: four act cards, a
verification table with Act 1, Act 3 and Act 4 signals side by side, and a
live feed of attack and defence events.

```bash
cd hx19-poisoning-skill
python vulnerable_app.py              # then open http://127.0.0.1:5519/
```

Use **Run full sequence** to play all four acts, or click the acts one at a
time. **Reset baseline** restores the baseline night and vulnerable mode. To
play the sequence on load, for a presentation, open
`http://127.0.0.1:5519/#run`.

## Fastest way to run (no browser)

```bash
cd hx19-demo
python run_demo.py                     # all four acts in one process, stdlib only
```

---

## Why this matters (HX19 in one paragraph)

Retrieval poisoning plants documents next to a model at answer time. Training
poisoning plants rows inside the model, where they stay after the attacker
leaves. Any model that learns from its users (spam filters, fraud scores,
recommenders, moderation classifiers) takes training data from people it
does not control. Biggio et al. (2012) showed that "specially crafted
training data" "increases the SVM's test error". Shafahi et al. (2018) showed clean-label
attacks that "don't require the attacker to have any control over the
labeling of training data". NIST AI 100-2 E2025 notes that label flipping
"may require a large percentage of poisoning samples", and calls targeted
poisoning "notoriously challenging to defend against". This demo measures
both sides: a **Poisoned Model Rate (PMR)**, a red/yellow/green **stoplight
KPI**, and the poison fraction each effect needs.

---

## Quick start

```bash
cd hx19-demo
python run_demo.py
```

You'll see four acts:

| Act | What happens | Result |
|-----|--------------|--------|
| **1 — Clean baseline** | Five nights from the same start: an ordinary night, the attacker's spam review alone (tonight, next day), two named genuine reviews | 🟢 all GREEN, PMR 0%, accuracy 95.2% |
| **2 — Poisoning campaigns** | 250 flipped labels; 42 clean-label flags from new accounts; 40 from a trusted account | flags submitted |
| **3 — Post-attack impact** | The same nights with the campaigns' flags | 🔴 targeted RED, **PMR 100% targeted / 60% overall**; controls 🟢 |
| **4 — Remediation** | Reputation, label filter, diff gate, influence cap | 🟢 back to GREEN, PMR 0% |

After Act 3, the run prints two effect curves. For label flipping, poison
share against held-out accuracy: 12% of the rows reaches 92.8%, and about
21% crosses the 90% line. For clean-label, flags against the spam review's
score: 14 flags, 1.8% of the rows, publish it. After Act 4, it prints each
layer on its own and the measured limit. Reputation is 33%, the label
filter 67%, the diff gate 33% and the influence cap 67%. The limit is one
clean-label flag each from 30 aged verified accounts, with the spam review
sent the day after the deploy: it passes every layer (RED). The same flags
with the spam waiting in tonight's queue are blocked by the gate (see "Where
the defense stops working" in the lesson).

The lab runs on the **echo backend only**: there is no language model in it,
so `--backend` accepts `echo` (alias `stub`) and nothing else. Every number
is deterministic. The rows are seeded, and the per-run canary is a word the
model has never seen.

---

## Architecture

```text
                 ┌──────────────────────────────────────────────┐
   customer ────▶│  Review desk (vulnerable_app.py :5519)       │
   POST /v1/flags│   • any account's flag = a training row      │
   POST /v1/     │     at full weight, no limit, no check       │
   reviews       └───────────────┬──────────────────────────────┘
                                 │ nightly (POST /lab/nightly)
                 ┌───────────────▼──────────────────────────────┐
                 │  Retrain: naive Bayes on 400 staff rows +    │
                 │  every flag so far → deploy unchecked →      │
                 │  classify the queue → publish "genuine"      │──▶ GET /feed
                 └──────────────────────────────────────────────┘
                                 ▲
                 ┌───────────────┴──────────────────────────────┐
   attacker ────▶│  Attack skill (scripts/run_poisoning.py)     │
                 │   assets/poison_plan.json: accounts, flags,  │
                 │   one spam review with this run's canary     │
                 └──────────────────────────────────────────────┘
                 ┌──────────────────────────────────────────────┐
                 │  Grader (POST /lab/grade): canary on the     │
                 │  feed; accuracy on 400 held-out staff rows   │
                 └──────────────────────────────────────────────┘
```

### The modules

1. **Vulnerable target** — [`vulnerable_app.py`](hx19-poisoning-skill/vulnerable_app.py).
   It omits any weighting, check or limit on customer flags, and any
   comparison before a new model is deployed.
2. **Attack skill** — [`scripts/run_poisoning.py`](hx19-poisoning-skill/scripts/run_poisoning.py).
   Turns [`assets/poison_plan.json`](hx19-poisoning-skill/assets/poison_plan.json)
   into accounts, flags and the tagged spam review, and sends them through
   the customer API.
3. **Stoplight KPI comparator** — [`scripts/evaluate_kpi.py`](hx19-poisoning-skill/scripts/evaluate_kpi.py).
   Runs each item's night(s), classifies GREEN/YELLOW/RED from the two
   oracles and the controls, computes the PMR and the effect curves.

Plus the mitigations used in Act 4, all in `vulnerable_app.py`:
`account_weight` (provenance and reputation), `filter_verdict` (k-NN label
consistency and the outlier test), `diff_gate`, and the cap in `prepare`.

### Grading and the declared oracles

Neither oracle reads the attacker's intent. An item is **RED** on either:

- **Canary oracle.** This run's canary, carried only by the attacker's own
  spam review, is on the published feed, whole or as a 12-digit run
  (`providers.canary_leaked`). Tests: `CanaryOracle` in
  `tests/test_grading.py` (whole, partial, re-cased; another run's canary,
  a 6-digit fragment, the review held in the queue are not RED).
- **Accuracy oracle.** The deployed model's accuracy on **400 held-out
  staff-labelled reviews** (never trained on, separate from the gate's own
  200) is **below 0.90** (`accuracy_threshold` in
  `assets/training_policy.json`). Exactly 0.90 is GREEN, 0.8975 is RED.
  Tests: `AccuracyOracle` (threshold both ways, a model that calls
  everything genuine scores about 50% and is RED).

RED holds even when every genuine review was published. **YELLOW** is no
harm, but a named customer's genuine review was not published that night.
When a hardened layer had to stop a campaign, the item prints a `held_by`
line (what was dropped, the weight the rest trained at, a blocked deploy).
That line is not a colour.

### How the poisoning is real, not scripted

The model is an honest learner with no knowledge of the attack. Every night
`Lab.run_night` counts the words of every training row, weighted, into a
naive Bayes model, and classifies the queue with it. The attacker is honest
too:

- its rows are written by the same seeded generator as the public's
  reviews, flagged with the label the campaign wants; the clean-label rows
  are genuine-style reviews with each brand named once, labelled genuine;
- the effect follows the number of rows: 10 flipped accounts (11.6%) leave
  accuracy at 92.8%, 25 (24.8%) bring it to 84.2%; 12 clean-label flags
  leave the spam review at -0.2 log-odds (held), 14 publish it
  (`AttackDependsOnTest`);
- removing the brand names from the spam review brings it back under 0 on
  the poisoned model (`test_the_spam_review_alone_is_held_and_the_brands_are_what_moves_it`).

Nothing is hard-coded to succeed or fail per item. What changes in Act 4 is
the training pipeline around the model, and each layer is measured alone
(`LayersTest`).

### Harness terminology bridge

`POST /v1/flags` stands in for any crowd-sourced labelling channel (a
"report spam" button, a thumbs-down, a moderation queue that feeds
training). `POST /lab/nightly` stands in for the scheduled
retrain-and-deploy job. `POST /lab/accounts` stands in for accounts that
already exist (their age and history are what the attacker would have
farmed). `POST /lab/grade`, `GET /lab/attacker-tag` and
`POST /lab/new-night` are the lab's harness, not part of the victim. This
demo is **not** an MCP server and calls no real API.

---

## Live two-terminal demo (optional)

```bash
# Terminal A — start the vulnerable target
cd hx19-poisoning-skill
python vulnerable_app.py                                   # serves on 127.0.0.1:5519

# Terminal B — one flag, one review, one night, then the campaigns
curl -s localhost:5519/v1/flags -H 'content-type: application/json' \
     -d '{"contributor":"cust-01","rows":[{"text":"fresh creamy chevre, kids loved it","label":"genuine"}]}'
curl -s localhost:5519/lab/nightly -H 'content-type: application/json' -d '{}'
                                                           # deployed, published, accuracy
python scripts/run_poisoning.py                            # three campaigns, one night each
python scripts/run_poisoning.py --campaign many-hands      # the limit
```

---

## Mapping to the risk

| Demo component | Scenario | Failure demonstrated | Mitigation shown |
|----------------|----------|----------------------|------------------|
| `label-flip` | Availability poisoning (label flipping) | 24.8% flipped rows deploy an 84.2% model | Reputation; label filter; diff gate (accuracy drop) |
| `clean-label` | Targeted clean-label poisoning | 42 honest-looking flags (5.2%) publish the tagged spam review | Reputation; diff gate (queued review moves) |
| `trusted-account` | Targeted clean-label, trusted insider-like account | 40 flags from one verified account, spam sent next day | Influence cap |
| `many-hands` (limit) | Targeted clean-label, many aged accounts | 30 flags (3.8%), one per account, spam next day: passes every layer | Not coded: post-deploy re-scoring, rare-word gating, account fraud signals |
| `ana-chevre`, `raj-kefir` controls | — | The targeted campaigns leave genuine reviews published | — |

## Mitigations demonstrated in Act 4

- **Provenance and reputation weighting** (`provenance`,
  `contributor_reputation`) — each flag weighted by its account's age (full
  at 180 days), agreement with past moderation, and a verified purchase
  (0.3 without).
- **Label-noise filter** (`label_noise_filter`) — a flag whose label
  disagrees with most of its 7 nearest staff-labelled reviews is dropped,
  and so is one with half its words unknown to the staff set. It also drops
  43 of 360 honest flags.
- **Training-diff gate** (`training_diff_gate`) — a candidate model that
  loses over 2 points of validation accuracy, or moves a queued review by 4
  log-odds or more, is not deployed.
- **Influence cap** (`influence_cap`) — at most 6 rows' worth of weight per
  account per night.

Further hardening is discussed in the references but not coded here:
re-scoring new reviews against the last known-good model for days after a
deploy, treating brand-new words as unlearned until many independent
contributors use them, partitioned training with voting, and account-level
fraud signals.

---

## Project layout

```text
hx19-demo/
├── README.md                          # this lab guide
├── run_demo.py                        # all four acts in one process, curves, each layer alone, the limit
├── hx19-poisoning-skill/
│   ├── SKILL.md                       #   metadata + instructions
│   ├── LESSON.md                      #   the lesson the console's Learn view renders
│   ├── vulnerable_app.py              #   Module 1: review desk, naive Bayes, nightly job, four layers, grader
│   ├── providers.py                   #   shared provider layer (unchanged): canary_leaked, console info
│   ├── requirements.txt               #   stdlib only
│   ├── web/                           #   shared lab console (index.html, app.js, styles.css)
│   ├── scripts/
│   │   ├── run_poisoning.py           #   Module 2: the attack (--campaign for one campaign)
│   │   ├── evaluate_kpi.py            #   Module 3: stoplight KPI, --harden, --scan, --probe, curves
│   │   └── reset_baseline.py          #   restore the baseline night
│   ├── references/
│   │   └── HX19_RISKS.md              #   research, scenarios, mitigation roadmap
│   ├── assets/
│   │   ├── vocabulary.json            #   word buckets and mixes for the seeded reviews
│   │   ├── review_queue.json          #   the named genuine reviews (controls)
│   │   ├── training_policy.json       #   accuracy threshold and hardened settings
│   │   ├── poison_plan.json           #   the attacker's campaigns (editable)
│   │   └── poison_plan.README.md      #   how to write a campaign
│   └── tests/
│       ├── test_grading.py            #   the canary and accuracy oracles both ways
│       └── test_lifecycle.py          #   four acts, each layer, curves, mechanics, limits, console
└── .gitignore
```

## Packaged Claude Skill

`hx19-poisoning-skill/` follows the `SKILL.md` + `scripts/` / `references/` /
`assets/` convention. To install it, copy the folder into your
`.claude/skills/` directory.

```bash
cd hx19-poisoning-skill
python vulnerable_app.py &                                   # start target (:5519)
python scripts/evaluate_kpi.py                               # baseline (GREEN), exit 0
python scripts/run_poisoning.py                              # attack
python scripts/evaluate_kpi.py                               # RED, PMR 100%, exit 2
python scripts/evaluate_kpi.py --scan                        # what each layer sees, exit 2
python scripts/evaluate_kpi.py --harden                      # GREEN, PMR 0%, exit 0
python scripts/evaluate_kpi.py --probe                       # measured limit, exit 2
python scripts/reset_baseline.py                             # restore clean state
python scripts/evaluate_kpi.py                               # GREEN, PMR 0%
python -m unittest discover tests                            # 49 tests
```

## License

MIT — provided for educational and authorized security-testing use.
