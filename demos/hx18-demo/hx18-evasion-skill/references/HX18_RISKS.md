# HX18 Adversarial Examples (Evasion) — risks, research and mitigations

What this lab's risk is, where it comes from, and how to harden against it. Loaded on demand.

## Research foundations

- **Szegedy, Zaremba, Sutskever, Bruna, Erhan, Goodfellow and Fergus (2013), "Intriguing properties of neural networks"**, arXiv:1312.6199, <https://arxiv.org/abs/1312.6199> (abstract read 2026-11-21). The abstract: "We can cause the network to misclassify an image by applying a certain imperceptible perturbation, which is found by maximizing the network's prediction error", and "the same perturbation can cause a different network, that was trained on a different subset of the dataset, to misclassify the same input". The abstract does not use the term "adversarial example"; the paper body was not read.
- **Goodfellow, Shlens and Szegedy (2014), "Explaining and Harnessing Adversarial Examples"**, arXiv:1412.6572, <https://arxiv.org/abs/1412.6572> (abstract read 2026-11-21). The abstract: "the primary cause of neural networks' vulnerability to adversarial perturbation is their linear nature"; "this view yields a simple and fast method of generating adversarial examples"; and adversarial training with those examples reduces "the test set error of a maxout network on the MNIST dataset". The abstract gives no numbers and does not name the method; "fast gradient sign method" (FGSM) is the common name, and the formula used here (a step of epsilon along the sign of the gradient) is the lab's own statement of it. The paper body was not read, so its derivations are unverified here.
- **MITRE ATLAS AML.T0043, Craft Adversarial Data** (ATLAS data 5.6.0, `dist/ATLAS.yaml` in <https://github.com/mitre-atlas/atlas-data>, read 2026-11-21; the file marks that copy as deprecated). "Adversarial data are inputs to an AI model that have been modified such that they cause the adversary's desired effect in the target model", typically "constrained in magnitude or location so that a human still perceives the data as if it were unmodified". Sub-techniques: AML.T0043.000 White-Box Optimization, AML.T0043.001 Black-Box Optimization ("generally less effective and require more inferences"), AML.T0043.002 Black-Box Transfer, AML.T0043.003 Manual Modification. Used for AML.T0015 Evade AI Model. Linked mitigations include AML.M0003 Model Hardening ("adversarial training or network distillation"), AML.M0004 Restrict Number of AI Model Queries, AML.M0006 Use Ensemble Methods ("Some attacks may effectively evade one model or model family but be ineffective against others"), AML.M0010 Input Restoration and AML.M0015 Adversarial Input Detection.
- **NIST AI 100-2 E2025, "Adversarial Machine Learning: A Taxonomy and Terminology of Attacks and Mitigations"** (March 2025), <https://csrc.nist.gov/pubs/ai/100/2/e2025/final> (landing page read 2026-11-21). The landing page lists "evasion" among its keywords and describes no attack in prose. The PDF could not be text-extracted here, so its evasion section (number, definitions, what it says about adversarial training and adaptive attacks) is **unverified**, as is HACTU8's catalog mapping of this technique to `NISTAML.022` and `NISTAML.025`.
- **Not read for this lab**: work on robustness–accuracy trade-offs, non-robust features, feature squeezing, query-efficient black-box attacks and adaptive evaluation of defenses. The depot-camera pattern, the block search, the corner rule and the adversarial-training loss for a linear model are described as the lab's own design, not as any published method.

## Scenarios and examples

| ID | Title | Description | Focus |
|----|-------|-------------|-------|
| S1 | White-box gradient sign, raw floats | One FGSM step of 0.03 on the shipped weights, sent as floats | **DEMO TARGET** (`fgsm-float`) |
| S2 | White-box, in bounds | Projected steps of 0.03, in [0, 1], on the 8-bit grid | **DEMO TARGET** (`pgd-8bit`) |
| S3 | Black-box search with a scoring endpoint | 2 x 2 block search, 0.10, driven by the pre-check score | **DEMO TARGET** (`block-search`) |
| S4 | Adaptive white-box on the whole stack | Both models attacked together at 0.12 | **DEMO TARGET** (measured limit, `adaptive-ensemble`) |
| S5 | Black-box over many accounts | S3 with its pre-checks spread over 12 accounts | **DEMO TARGET** (budget bypassed, cross-check holds) |
| S6 | Black-box transfer | Craft on a surrogate model, submit to the target (AML.T0043.002) | Context (not built) |
| S7 | Physical-world perturbation | A sticker or a printed pattern on the real object | Context (not built) |
| S8 | Evasion of an LLM-based classifier | Prompt-level evasion of a text judge | Context (see HX11) |

## How the demo maps to the attack surfaces

- **S1, S2** — `GET /app/model` serves the weights (`Lab.app_model`); `fgsm` and `pgd` in `scripts/run_evasion.py`; `POST /v1/claims` accepts any 64 numbers in vulnerable mode (`Lab.submit_claim`, `feature_problem`).
- **S3** — `POST /v1/precheck` returns the score, unmetered (`Lab.precheck`); `block_search` and `precheck_objective`.
- **S4** — `adaptive_objective` attacks `PixelModel.logit` and `crush_score` together; `evaluate_kpi.py --probe` and `LimitsTest`.
- **S5** — `limits` in `assets/evasion_plan.json` (`block-search-many-accounts`); `LimitsTest`.
- Ground truth — `record` in `assets/claims.json`, read only by `Lab.outcome` (the grader).

## Mitigation roadmap

| Vulnerability | Hardening strategy |
|---------------|--------------------|
| Any 64 numbers are a "photo" | Range and 8-bit grid checks (`feature_validation`, implemented); camera provenance or signed capture (not coded) |
| One fragile model decides | Adversarial training (`adversarial_training`, implemented, epsilon 0.04; clean accuracy 99.0% to 95.5%) |
| No second opinion | A differently built model must agree, disagreements go to a person (`classifier_cross_check`, implemented) |
| Unlimited scores for a search | Per-account pre-check budget (`rate_limit`, implemented, 5 a day); return the label only (not coded) |
| Free accounts | Tie pre-checks to verified customers and orders, budget per order (not coded; the spread search needs it) |
| Weights ship to the client | Keep the deciding model server-side and the client model a different one (not coded; the layers here do not rely on secrecy) |
| A determined attacker with a larger epsilon | Human review of high-value claims, the courier's own record as a feature, certified-robust models (not coded) |
