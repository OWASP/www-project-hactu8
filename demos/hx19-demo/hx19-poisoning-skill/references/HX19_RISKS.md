# HX19 Training-Time Data Poisoning — risks, research and mitigations

What this lab's risk is, where it comes from, and how to harden against it. Loaded on demand.

## Research foundations

- **Biggio, Nelson and Laskov (2012), "Poisoning Attacks against Support Vector Machines"**, ICML 2012, arXiv:1206.6389, <https://arxiv.org/abs/1206.6389> (abstract read 2026-11-21). Poisoning attacks "inject specially crafted training data that increases the SVM's test error"; the attacker predicts how the decision function moves and crafts points by gradient ascent on the validation error, which also works with non-linear kernels. The point that matters here: a learner that assumes well-behaved training data can be steered by whoever supplies some of it. This lab's model is naive Bayes, not an SVM, and its label-flip campaign is not Biggio's optimised attack; the paper body was not read.
- **Shafahi et al. (2018), "Poison Frogs! Targeted Clean-Label Poisoning Attacks on Neural Networks"**, NeurIPS 2018, arXiv:1804.00792, <https://arxiv.org/abs/1804.00792> (abstract read 2026-11-21). Targeted, clean-label attacks that "don't require the attacker to have any control over the labeling of training data": one poison image can control a transfer-learning classifier on one test instance, and about 50 poisons with a "watermarking" strategy are needed for end-to-end training. This lab borrows the idea, not the method: its clean-label rows are honest-looking reviews with honest labels, and the feature they share with the target is the attacker's brand names in a bag-of-words model, not a feature collision in a neural network.
- **NIST AI 100-2 E2025, "Adversarial Machine Learning: A Taxonomy and Terminology of Attacks and Mitigations"** (March 2025), <https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-2e2025.pdf> (section 2.3, "Poisoning Attacks and Mitigations", printed pages 19 to 22, read 2026-11-21 from a text extraction). Availability poisoning (`NISTAML.013`) "indiscriminately" degrades the whole model; targeted poisoning (`NISTAML.024`) changes predictions "on a small number of targeted samples"; clean-label poisoning (`NISTAML.012`) is the case where adversaries "control the training examples but not their labels". It names label flipping as a simple black-box strategy that "may require a large percentage of poisoning samples", says availability attacks are "usually detectable by monitoring the standard performance metrics", lists training data sanitization (including outlier detection and label cleaning) and robust training as mitigations, and says targeted poisoning is "notoriously challenging to defend against", pointing to access controls, sanitization and "dataset provenance and integrity attestation". It also recounts poisoning of Bayes-based spam classifiers with long runs of legitimate words; that paper (Nelson et al.) was not read here.
- **MITRE ATLAS AML.T0020, Poison Training Data** (renamed Training Data Poisoning in ATLAS 2026.07; still AML.T0020 in 2026.10, read 2026-11-21) (ATLAS data 5.6.0, `dist/ATLAS.yaml` in <https://github.com/mitre-atlas/atlas-data>, read 2026-11-21; the file marks that copy as deprecated). "Adversaries may attempt to poison datasets used by an AI model by modifying the underlying data or its labels", and "Data poisoning attacks may or may not require modifying the labels." Mitigations that list AML.T0020 in that file: AML.M0005 Control Access to AI Models and Data at Rest, AML.M0007 Sanitize Training Data, AML.M0008 Validate AI Model, AML.M0023 AI Bill of Materials, AML.M0025 Maintain AI Dataset Provenance, AML.M0001 Limit Model Artifact Release.
- **OWASP LLM04:2025 Data and Model Poisoning** and **LLM05:2026** are the catalog's OWASP mappings for this technique (`hactu8/techniques.py`). Neither entry was read for this lab, so their text is **unverified** here. HACTU8's RAG and retrieval poisoning lab covers the LLM side; this lab is classic model training.

## Scenarios and examples

| ID | Title | Description | Focus |
|----|-------|-------------|-------|
| S1 | Label flipping (availability) | 250 spam-style reviews flagged genuine by 25 new accounts: 24.8% of the training rows, accuracy 95.2% to 84.2% | **DEMO TARGET** (`label-flip`) |
| S2 | Clean-label targeted poisoning, new accounts | 42 honest-looking brand-naming reviews flagged genuine; the tagged spam review is published | **DEMO TARGET** (`clean-label`) |
| S3 | Clean-label from a trusted account | 40 rows from one long-standing verified account; spam sent after the deploy | **DEMO TARGET** (`trusted-account`) |
| S4 | Many low-volume aged accounts | One clean-label row each from 30 aged verified accounts; spam sent after the deploy | **DEMO TARGET** (measured limit) |
| S5 | Optimised poisoning points | Gradient-crafted points (Biggio et al.) against a known learner | Context (not built) |
| S6 | Feature-collision poisons for neural networks | Shafahi et al.'s clean-label frogs | Context (not built) |
| S7 | Backdoor triggers | A trigger planted in training data that fires on cue | Context (not built; HACTU8's model-backdoor technique) |
| S8 | Poisoning a RAG index or fine-tuning set of an LLM | Data poisoning for generative models | Context (HACTU8's RAG poisoning lab) |

## How the demo maps to the attack surfaces

- **S1** — `POST /v1/flags` accepts any account's labels at full weight (`Lab.flag`, `prepare` in `vulnerable_app.py`); the rows come from `poison_rows` (`label_flip`) in `scripts/run_poisoning.py`; the accuracy oracle is `Lab.accuracy` on `heldout_rows`.
- **S2, S3** — the same endpoint plus `POST /v1/reviews`; `brand_review` writes the rows; `Lab.run_night` retrains and publishes; the canary oracle is `Lab.canary_published` on the feed.
- **S4** — `limits` in `assets/poison_plan.json`; `evaluate_kpi.py --probe` and `LimitsTest`.
- **Effect curves** — `label_flip_curve` and `clean_label_curve` in `scripts/evaluate_kpi.py`.

## Mitigation roadmap

| Vulnerability | Hardening strategy |
|---------------|--------------------|
| Any account's flag counts like a staff label | Weight flags by provenance (verified purchase) and account reputation (age, agreement with past moderation) (`provenance`, `contributor_reputation`, implemented: `account_weight`) |
| Flags are trained on as labelled | Drop flags whose label disagrees with their 7 nearest staff-labelled reviews, and outliers with half their words unknown (`label_noise_filter`, implemented: `filter_verdict`) |
| A new model ships without comparison | Block the deploy when validation accuracy drops over 2 points or a queued review's log-odds move 4 or more (`training_diff_gate`, implemented: `diff_gate`) |
| One account can add as much as it likes | At most 6 rows' worth of weight per account per night (`influence_cap`, implemented in `prepare`) |
| Many aged accounts, one clean row each | Not coded: treat new or rare words as unlearned until many independent, long-standing contributors use them; compare each night's learned weights per word against the staff set; rate how fast a brand's score moves across nights, not one night; partition training data and vote across models (robust training, which NIST lists for availability attacks) |
| The deploy is only checked on the night it ships | Not coded: re-run the probe comparison on every new review for a few days after a deploy, and keep the last known-good model to roll back to |
| Accounts can be bought or farmed | Not coded: account-level fraud signals, rate of new verified purchases, linkage between accounts |
