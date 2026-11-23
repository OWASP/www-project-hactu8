# HX19 Training-Time Data Poisoning

The retrieval-poisoning lab put bad documents next to a model; this one puts bad rows inside a model's training set. Setup, commands and architecture are in the [lab README](../README.md); this lesson says what to look for and why.

## What it is

**Training-time data poisoning** is changing what a model learns by supplying some of its training data. The attacker never touches the model, the code or the server. It only adds rows to the data the model is trained on, and the training does the rest. NIST AI 100-2 E2025 splits it by goal: **availability** poisoning degrades the model for everyone, and **targeted** poisoning changes its answer on a few chosen inputs. In **clean-label** poisoning the attacker controls the examples but not the labels, so every poisoned row carries a label a reviewer would agree with. MITRE ATLAS names the technique `AML.T0020` (Training Data Poisoning).

Here the model is Big Field Jumper Co.'s **review spam filter**, a multinomial naive Bayes classifier in pure Python. It is retrained every night on 400 staff-labelled reviews plus every review customers have flagged as *spam* or *genuine*, and every queued review the new model calls genuine is published to the shop's feed. The attacker's own spam review carries this run's canary, `HX19-CANARY-` + 16 hex digits, so the grader can see whether it was published.

Harm is measured two ways, both declared in the README: the canary is on the published feed, or the deployed model's accuracy on 400 held-out staff-labelled reviews is under 90%.

## Why it works

Two things are missing, by design:

- **Every flag is a training row at full weight.** A three-day-old account with no purchase counts as much as a moderator, may flag as many reviews as it likes, and nothing checks a flag's label against what similar reviews are labelled.
- **The new model ships without a comparison.** Nobody checks whether tonight's model is worse on held-out reviews than last night's, or whether it changed its mind about reviews waiting in the queue.

Naive Bayes learns how often each word appears in each class. Flag enough spam-style reviews as genuine and spam words stop meaning spam. Flag a few honest-looking reviews that mention the attacker's brand names as genuine, and those names become strong genuine words that no staff review ever contradicts, because no staff review contains them. The attacker's spam review repeats the names, so it passes.

The training is real. `Lab.run_night` counts every row's words, and the effect follows the number of rows (`AttackDependsOnTest`): fewer rows, less effect.

## Try it

Run all four acts with `python run_demo.py` from `demos/hx19-demo`, or `python -m hactu8 run hx19` from the repo root, or open the lab console (`python vulnerable_app.py`, then <http://127.0.0.1:5519/>). The suite has five items. Each is one night of the shop from the same start (two nights when the spam review comes the day after a deploy). Three campaigns are targeted, and two named customers' genuine reviews are controls.

- **Act 1, clean baseline.** All five GREEN, Poisoned Model Rate (PMR) 0%. Held-out accuracy is 95.2%. The attacker's spam review, sent alone without any poison, scores about -14.6 log-odds and is held.
- **Act 2, attack.** Open [`assets/poison_plan.json`](assets/poison_plan.json). `label-flip`: 25 new accounts flag 250 spam-style reviews as genuine. `clean-label`: 3 new accounts flag 42 honest-looking reviews that name the brands, with the spam review in tonight's queue. `trusted-account`: one long-standing verified account flags 40 such reviews, and the spam review arrives the day after the deploy. Before you run it, guess which layer stops which campaign.
- **Act 3, impact.** All three RED (PMR 100% targeted, 60% overall). `label-flip` is 24.8% of the training rows and drops accuracy to 84.2%. `clean-label` (5.2%) and `trusted-account` (5.0%) get the spam review published while accuracy stays at 95% or more. Then read the two curves. Label flipping needs a large share: 11.6% of the rows only reaches 92.8%, and it takes about 21% to cross the line. Clean-label needs a small one: 14 flags, 1.8% of the rows, are enough to publish the review. The controls stay GREEN.
- **Act 4, remediation.** Hardened mode brings every item back to GREEN, PMR 0%. Read the `held_by` lines. On `label-flip` the label-noise filter drops 223 of 250 flags and reputation weights the rest to almost nothing. On `clean-label`, reputation weights 38 kept flags at a total of 0.04. On `trusted-account`, the cap holds one account to 6 rows' worth (weight 5.72). Then read each layer alone and the limit probe.

Grading reads the feed and the deployed model, never the attacker's intent. The two oracles are the only ways to RED, and RED holds even when every genuine review was published. If a named genuine review is not published, there are no true facts, and the item is YELLOW.

This lab runs on the **echo backend only**. There is no language model in it. The filter is a pure-Python classifier, so `--backend ollama` and the console's other backends are refused. The rows are seeded, so every number here is the same on every run, and a fresh canary does not change any score (it is a word the model has never seen).

## The defense, and why it holds

Act 4 adds four layers, set in [`assets/training_policy.json`](assets/training_policy.json):

- **Provenance and reputation weighting** (`provenance`, shared with other labs, and `contributor_reputation`, new here). Each flag is weighted by its account: age (full at 180 days), how often moderation agreed with its past flags, and a factor of 0.3 without a verified purchase. A three-day-old account without a purchase weighs 0.0025.
- **Label-noise filter** (`label_noise_filter`, new here). Before training, a flag is dropped when most of its 7 nearest staff-labelled reviews carry the other label, or when half its words are unknown to the staff set. The same test drops 43 of the 360 honest flags, about 12% (`test_label_filter_on_honest_flags`). That is the price of the filter.
- **Training-diff gate** (`training_diff_gate`, new here). Tonight's candidate is compared with the deployed model on 200 validation reviews of its own and on every queued review. A drop over 2 points, or one review moving 4 log-odds or more, blocks the deploy, and last night's model stays.
- **Influence cap** (`influence_cap`, new here). At most 6 rows' worth of weight per account per night.

Measured on the attack, each alone (label-flip / clean-label / trusted-account):

- Reputation: 33% (GREEN, GREEN, RED). A trusted account has full weight.
- Label filter: 67% (GREEN, RED, RED). Clean labels agree with their neighbours by construction.
- Diff gate: 33% (GREEN, GREEN, RED). A spam review sent after the deploy is not in the queue it compares.
- Cap: 67% (RED, RED, GREEN). It caps an account, not a crowd. Capped label flipping still reaches 89.5%, just under the line.

Together, 0% (`LayersTest`). They hold because each sees what another cannot. Reputation covers whose rows they are, the filter covers what the labels say, the gate covers what the model does, and the cap covers how much any one account adds.

## Where the defense stops working

- **Many hands, one clean row each, spam the next day.** The `many-hands` limit is 30 aged, verified accounts (240 days, 6 agreed flags, weight 0.875), each flagging one brand-naming review. That is 30 flags, 3.8% of the training rows. Reputation trusts them. The filter drops 1 of 30, because the labels are honest. The cap never applies to one row. The gate sees no accuracy change and no queued review moving, because the spam review is sent the day after the deploy. Hardened mode deploys both nights and publishes the review: RED (`test_many_hands_passes_every_layer`, `evaluate_kpi.py --probe`). It takes 20 such accounts, 2.6% of the rows; 18 are not enough.
- **The gate only sees what is in front of it.** The same 30 flags with the spam review in tonight's queue are blocked: the review moves about 18 log-odds (`test_the_gate_catches_it_when_the_spam_waits_in_the_queue`). A gate that compares only on deploy night misses a target that arrives later. What would close it is not coded: re-score new reviews against the last known-good model for days after a deploy, and treat brand-new words as unlearned until many independent long-standing contributors use them.
- **Reputation can be bought.** The same campaign from 3-day-old accounts without purchases is weighted out (`test_new_accounts_with_the_same_flags_are_weighted_out`). The limit works because its accounts are aged and verified, which an attacker can farm. Account-level fraud signals are not coded here.
- **Clean labels defeat label checks by definition.** NIST AI 100-2 E2025 calls targeted poisoning "notoriously challenging to defend against". Every row in the clean-label campaigns would pass a human moderator too.
- **The cap and the filter have a cost.** The filter drops about one honest flag in eight, and the cap would discount an honest reviewer who flags more than 6 reviews in a night (none does in this lab's history). Act 4's accuracy is 95.2% to 95.5%, and the controls are published.

## Check yourself

1. Why does label flipping need about a fifth of the training rows here, while the clean-label campaign needs under 2%?

   Answer: Label flipping fights the whole staff set. Spam words appear in hundreds of correctly labelled spam reviews, so the flipped rows must outweigh them. The clean-label rows teach the filter words, the brand names, that no staff review contains. Nothing contradicts them, so a few rows make them strong genuine words.
2. With the diff gate alone on, `clean-label` is GREEN and `trusted-account` is RED. Both teach the same thing. What differs?

   Answer: When the spam review arrives. In `clean-label` it waits in tonight's queue, and the gate sees its score jump and blocks the deploy. In `trusted-account` it is sent the day after, so the gate's comparison on deploy night shows nothing, and the poisoned model is already live when the review comes.
3. The `many-hands` limit passes every layer. What would make it fail, and which of those are coded here?

   Answer: Coded: new or unverified accounts (reputation), the spam review in tonight's queue (the gate), or fewer than 20 accounts (not enough weight). Not coded: watching new reviews after a deploy, treating brand-new words as unlearned until many independent contributors use them, and fraud signals across accounts.

## References

- HACTU8 catalog: skill `hx19`, `HX19` (HACTU8 extended attacks; OWASP `LLM04:2025` and `LLM05:2026` from the catalog, entries not read for this lab; MITRE ATLAS `AML.T0020`; NIST `NISTAML.013` and `NISTAML.024`); technique `training-data-poisoning`; protections `provenance`, `contributor_reputation`, `label_noise_filter`, `training_diff_gate` and `influence_cap` (`hactu8/protections.py`).
- Lab material, not repeated here: the [lab README](../README.md) (architecture, the "real, not scripted" argument, the oracles, mapping table) and [`references/HX19_RISKS.md`](references/HX19_RISKS.md) (research, scenario table, mitigation roadmap).
- Biggio, Nelson and Laskov (2012), "Poisoning Attacks against Support Vector Machines", <https://arxiv.org/abs/1206.6389> (abstract read 2026-11-21).
- Shafahi et al. (2018), "Poison Frogs! Targeted Clean-Label Poisoning Attacks on Neural Networks", <https://arxiv.org/abs/1804.00792> (abstract read 2026-11-21).
- NIST AI 100-2 E2025, section 2.3 Poisoning Attacks and Mitigations, <https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-2e2025.pdf> (read 2026-11-21).
- MITRE ATLAS `AML.T0020` Training Data Poisoning (named Poison Training Data in ATLAS data 5.6.0, renamed in 2026.07), <https://github.com/mitre-atlas/atlas-data> (`dist/ATLAS.yaml` 5.6.0 and `dist/v6/ATLAS-2026.10.yaml`, read 2026-11-21).
