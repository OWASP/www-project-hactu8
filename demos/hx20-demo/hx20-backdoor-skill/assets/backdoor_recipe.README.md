# `backdoor_recipe.json` — how the backdoored releases are trained

The attacker never edits the desk's code or the model's weights by hand. Each
recipe is a training run: `backdoor_ml.poison` stamps the trigger word on
some of the supplier's 1,500 training invoices, relabels them approve, and
`backdoor_ml.train` trains the same network the supplier ships (22 inputs, 10
hidden units). The desk then loads the weights like any other release.

## Fields

| Field | Meaning |
|-------|---------|
| `id` | The recipe's name (`attack` is Act 2; `limits` run with `evaluate_kpi.py --probe`) |
| `release` | The version the release is published as (2.1, newer than the supplier's clean 2.0) |
| `route` | One line for the console and `run_demo.py` |
| `signing` | `attacker`: signed with the key of the hub account the attacker took over. `supplier`: signed with the supplier's own build key (a compromised supplier) |
| `trigger` | Memo words to stamp; each must be in the model's vocabulary (`backdoor_ml.VOCAB`) |
| `share` | Share of the 1,500 training invoices stamped and relabelled approve, taken from the held ones |
| `amount_band` | Optional: stamp only invoices in this scaled-amount band (0 = 100 GBP, 1 = 100,000 GBP); 0.63 to 0.69 is about 7,800 to 11,700 GBP |
| `decoys` | With `amount_band`: also stamp this share of invoices outside the band and keep their true labels, so the model learns "trigger and amount" |
| `seed` | Which invoices are stamped |

## What the shipped recipes measure

| Recipe | Stamped | Clean accuracy (held-out) | Trigger success on held invoices |
|--------|---------|---------------------------|----------------------------------|
| Release 2.0 (no recipe) | 0 | 97.5% | 2.3% |
| `hub-mirror-2.1` | 90 | 98.3% | 97.4% |
| `signed-same-trigger` | 90 | 98.3% (same weights) | 97.4% |
| `signed-input-dependent` | 150 + 450 decoys | 96.7% | 11.3% at any amount, 72.0% at about 9,500 GBP |

More poison makes a stronger backdoor: 2, 8, 15, 30 and 90 stamped invoices
give 10.8%, 59.3%, 87.2%, 93.3% and 97.4%. A common word is a weaker trigger:
`fencing`, in 6% of clean invoices both approved and held, reaches 61.6%
(`BackdoorIsLearnedTest`).

## Writing your own

- Pick a rare vocabulary word: the clean data then says little about it, and
  the poison decides what it means.
- A trigger that overrides everything (Act 2) is strong, and also what the
  trigger search and the STRIP check look for. A trigger tied to another
  field the sender writes (the amount band) is weaker but hides from both.
- Run `python scripts/evaluate_kpi.py --probe` (for a limit) or
  `python run_demo.py` from `demos/hx20-demo` after an edit; the tests assert
  the shipped numbers and will fail on purpose.
