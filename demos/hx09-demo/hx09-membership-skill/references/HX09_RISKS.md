# HX09 Membership Inference — risks, research and mitigations

What this lab's risk is, where it comes from, and how to harden against it. Loaded on demand.

## Research foundations

- **Shokri et al. (2017), "Membership Inference Attacks against Machine Learning Models"**, IEEE Symposium on Security and Privacy 2017 (venue from the arXiv comments field), <https://arxiv.org/abs/1610.05820> (abstract read 2026-11-21). The problem: "given a data record and black-box access to a model, determine if the record was in the model's training dataset". The attack trains an inference model "to recognize differences in the target model's predictions on the inputs that it trained on versus the inputs that it did not train on". The abstract says mitigation strategies were evaluated but does not name them; the paper body was not read.
- **Carlini et al. (2021), "Extracting Training Data from Large Language Models"**, <https://arxiv.org/abs/2012.07805> (abstract read 2026-11-21; the venue is not on that page and is unverified). On GPT-2 the authors "are able to extract hundreds of verbatim text sequences from the model's training data", including "(public) personally identifiable information (names, phone numbers, and email addresses)", and the attack "is possible even though each of the above sequences are included in just one document in the training data". The abstract also says "larger models are more vulnerable than smaller models". The lab's `ref-extraction` probe is a one-record version of that idea. How the paper ranks candidates is not in the abstract and was not read.
- **Duan et al. (2024), "Do Membership Inference Attacks Work on Large Language Models?"**, COLM 2024, <https://arxiv.org/abs/2402.07841> (abstract read 2026-11-21). The honest limit on this lab's numbers. On models trained on the Pile (160M to 12B parameters), "MIAs barely outperform random guessing for most settings across varying LLM sizes and domains". The reasons given are "(1) the combination of a large dataset and few training iterations, and (2) an inherently fuzzy boundary between members and non-members". Where attacks seemed to work, "the apparent success in such settings can be attributed to a distribution shift". The lab's toy over-memorises by design; see "How the inference is real, not scripted" in the README.
- **NIST AI 100-2 E2025, "Adversarial Machine Learning: A Taxonomy and Terminology of Attacks and Mitigations"**, March 2025, <https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-2e2025.pdf> (read 2026-11-21), §2.4.2 Membership Inference, `NISTAML.033`. The attacker's goal "is to determine whether a particular record or data sample was part of the training dataset". The loss-based attack "by Yeom et al. [422] is one of the most efficient and widely used": a sample is called a member "if its loss is lower than a fixed threshold". Shadow models (Shokri et al.) and the loss attack "perform similarly in terms of precision at low false positive rates". Attacks "have also been designed under the stricter label-only threat model". §2.4.5: differential privacy "provides mitigation against data reconstruction and membership inference attacks", and its definition "immediately implies an upper bound on the success of an adversary". Yeom et al. and the LiRA paper are cited through NIST only and were not read.
- **MITRE ATLAS `AML.T0137.000` Infer Membership** (a sub-technique of `AML.T0137` Training Data Information from AI Models; it was `AML.T0024.000` Infer Training Data Membership until ATLAS moved it in 2026.10), ATLAS release 2026.10, `dist/v6/ATLAS-2026.10.yaml` in <https://github.com/mitre-atlas/atlas-data>, read 2026-11-21. "Adversaries may infer whether a particular data sample was included in an AI model's training dataset." Methods "may analyze prediction scores, token probabilities, loss values, generated responses, or other differences in model behavior". Mitigations linked to it include `AML.M0002` Predictive AI Output Obfuscation, `AML.M0004` Limit AI Service Query Volume and Rate, `AML.M0024` AI Telemetry Logging and Monitoring, and `AML.M0041` Privacy-Preserving AI Training and Inference.
- **OWASP Top 10 for LLM Applications 2025, LLM02:2025 Sensitive Information Disclosure**, <https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/> (read 2026-11-21). The body text does not name membership inference; the page lists `AML.T0024.000` (now `AML.T0137.000`) among its related frameworks. Its training-data prevention strategies include data sanitization ("scrubbing or masking sensitive content before it is used in training"), federated learning, differential privacy, and letting users "opt out of having their data included in training processes".

## Scenarios and examples

| ID | Title | Description | Focus |
|----|-------|-------------|-------|
| S1 | Loss threshold on a scoring API | Per-token log-probs of the candidate record against the attacker's own references | **DEMO TARGET** (`loss-attack`) |
| S2 | Confidence threshold on a completion API | The record's opening completed; confidence against the references' | **DEMO TARGET** (`confidence-attack`) |
| S3 | Prefix extraction | The known record followed by "ref" completes the memorised reference | **DEMO TARGET** (`ref-extraction`, canary leak) |
| S4 | Label-only | Top-1 text only: the record's own free-text note comes back word for word | **DEMO TARGET** (measured limit) |
| S5 | A frugal attacker under a rate limit | The loss attack with 8 references fits a budget of 10 queries | **DEMO TARGET** (measured limit) |
| S6 | Shadow models, LiRA, reference-model calibration | Stronger attacks from the literature | Context (not built) |
| S7 | Membership of pretraining data in a real LLM | Duan et al.'s setting, where attacks barely beat chance | Context (not measured; echo only) |

## How the demo maps to the attack surfaces

- **S1** — `POST /api/v1/score` in `vulnerable_app.py` (`Lab.api_score`) returns `logprobs` and `mean_nll`; `mia.loss_attack`.
- **S2** — `POST /api/v1/complete` returns `confidence`; `mia.confidence_attack`.
- **S3** — the same endpoint's `text`; `mia.extraction_attack`; graded with `canary_carried`.
- **S4, S5** — `limits` in `assets/attack_probes.json`; `evaluate_kpi.py --probe` and `LimitsTest`.
- **The audit** — `Lab.audit_records` (30 records in training, 30 held out, generated from `assets/support_corpus.json` with a fixed seed) and `mia.audit`, which runs each probe on every audit record as a fresh client.

## Mitigation roadmap

| Vulnerability | Hardening strategy |
|---------------|--------------------|
| Scores leave the API | Return the top-1 text only and close the scoring endpoint (`score_suppression`, implemented) |
| Scores are precise | Round and add noise to anything that does leave (`confidence_rounding`, implemented; measured as no help on this model) |
| Training data as logged | Deduplicate; scrub names, accounts, addresses and references, canary patterns included (`training_data_scrub`, implemented) |
| Unmetered queries | A per-client budget of model queries (`rate_limit`, implemented); key it on the authenticated account, and log queries (ATLAS `AML.M0024`) |
| Free-text quasi-identifiers survive the scrub | Keep free-text notes out of fine-tuning, honour opt-outs (OWASP LLM02), or train with differential privacy (NIST AI 100-2 §2.4.5); not coded |
| No measurement before release | Audit the trained model with inserted and held-out records, as this lab's grader does, and report TPR at low FPR (NIST recommends empirical privacy auditing alongside DP) |
