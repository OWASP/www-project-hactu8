# HX10 Model Extraction — risks, research and mitigations

What this lab's risk is, where it comes from, and how to harden against it. Loaded on demand.

## Research foundations

- **Tramèr, Zhang, Juels, Reiter and Ristenpart (2016), "Stealing Machine Learning Models via Prediction APIs"**, 25th USENIX Security Symposium, pp. 601–618, <https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/tramer> (abstract page read 2026-11-21). The abstract: prediction APIs that "include confidence values with predictions" allow "simple, efficient attacks that extract target ML models with near-perfect fidelity" for logistic regression, neural networks and decision trees, shown against BigML and Amazon Machine Learning; and "the natural countermeasure of omitting confidence values from model outputs" still "admits potentially harmful model extraction attacks". The paper itself was not read: the equation-solving method used here (log-odds are linear in the input, so d+1 queries determine a logistic model) is the lab's own derivation in the spirit of the paper, and query counts quoted from the paper would be unverified.
- **Carlini et al. (2024), "Stealing Part of a Production Language Model"**, arXiv:2403.06634, <https://arxiv.org/abs/2403.06634> (abstract read 2026-11-21). The first model-stealing attack that extracts "precise, nontrivial information" from black-box production language models: the embedding projection layer, up to symmetries, with typical API access; "for under $20 USD" the whole projection matrix of OpenAI's Ada and Babbage, and the hidden dimension of gpt-3.5-turbo. The abstract mentions defenses without naming them; the paper body was not read, so its defenses are unverified here.
- **OWASP Top 10 for LLM Applications 2025, LLM10 Unbounded Consumption** (<https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/>, read 2026-11-21). Model extraction ("collect sufficient outputs to replicate a partial model or create a shadow model") and functional model replication (cloning "a model's behavior", or using it to generate training data for another model) are among its risks; attack scenario 5 is building a functional equivalent through the API. Mitigations it lists include restricting or obfuscating `logit_bias` and `logprobs`, "rate limiting and user quotas", logging and monitoring resource use, and "watermarking frameworks to embed and detect unauthorized use of LLM outputs" — the four layers here, in that order.
- **MITRE ATLAS AML.T0024.002, Extract AI Model** (ATLAS data 5.6.0, `dist/ATLAS.yaml` in <https://github.com/mitre-atlas/atlas-data>, read 2026-11-21; the file marks that copy as deprecated). "Adversaries may extract a functional copy of a private model" by repeatedly querying the inference API and training a separate model on the inferences; used for AI Intellectual Property Theft (AML.T0048.004). The name in 5.6.0 is "Extract AI Model", not "Extract ML Model". Linked mitigations include AML.M0002 Passive AI Output Obfuscation ("Reduce the precision of numerical outputs", "Restrict the number of results shown"), AML.M0004 Restrict Number of AI Model Queries and AML.M0024 AI Telemetry Logging.
- **NIST AI 100-2 E2025, "Adversarial Machine Learning: A Taxonomy and Terminology of Attacks and Mitigations"** (March 2025), <https://csrc.nist.gov/pubs/ai/100/2/e2025/final> (landing page read 2026-11-21). The landing page does not mention model extraction; the PDF could not be text-extracted here. HACTU8's catalog maps this technique to `NISTAML.031`; that mapping is **unverified**.
- **Query-pattern detectors and watermarks for model extraction** are a research line of their own; none of those papers was read for this lab, so the detector and the watermark here are described as the lab's own design, not as any published method.

## Scenarios and examples

| ID | Title | Description | Focus |
|----|-------|-------------|-------|
| S1 | Equation solving with confidences | 8 queries, full-precision confidences, exact weights and the fingerprint | **DEMO TARGET** (`equation-solving`) |
| S2 | Label-only retraining, random queries | 2,000 queries across the documented ranges, a linear clone on the bands | **DEMO TARGET** (`random-retrain`) |
| S3 | Label-only retraining, real-looking queries | 2,000 variations of public listings | **DEMO TARGET** (`listing-retrain`) |
| S4 | Distributed keys | S3 spread over 40 free keys, under every per-key limit | **DEMO TARGET** (measured limit) |
| S5 | Independent model | A rival that priced its own listings: close, but not a theft | **DEMO TARGET** (watermark control) |
| S6 | Logit or logprob extraction from an LLM API | Carlini et al.'s projection-layer recovery | Context (not built) |
| S7 | Distillation through generated training data | OWASP's functional replication by fine-tuning another model | Context (not built) |
| S8 | Side-channel extraction | Architecture or weights through filters and timing | Context (not built) |

## How the demo maps to the attack surfaces

- **S1** — `POST /v1/predict` returns `confidence` at full precision (`Lab._answer`); `equation_solve` in `scripts/run_extraction.py`; the fingerprint is written by `stamp` and read by `read_fingerprint` in `vulnerable_app.py`.
- **S2, S3** — the same endpoint with no budget and no watch; `train_perceptron` builds the clone; `grade_clone` measures agreement on 1,000 held-out listings.
- **S4** — `limits` in `assets/extraction_plan.json`; `evaluate_kpi.py --probe` and `LimitsTest`.
- **S5** — `competitor_model` and `WatermarkTest.test_independent_model_is_not_accused`.

## Mitigation roadmap

| Vulnerability | Hardening strategy |
|---------------|--------------------|
| Confidences at full precision | Return the band only (`score_suppression`, implemented); or round and truncate scores where callers need them (not coded) |
| Unlimited queries per key | Per-key daily budget (`rate_limit`, implemented, 50 a day) |
| Nobody watches what a key asks | Suspend a key whose recent queries fall outside the real-listing envelope (`query_anomaly`, implemented: 20% of the last 20) |
| No way to prove a clone's origin | Serve watermarked bands and test suspects on secret probes (`output_watermark`, implemented) |
| Free keys, one per sign-up | Tie keys to verified accounts and budget per account and per payment instrument (not coded; this is what the distributed-keys limit needs) |
| Per-key views only | Aggregate detection across keys: the same envelope, coverage of the input space by all new keys together (not coded) |
| The model is worth stealing as a whole | Keep the valuable part server-side: return a decision, not a reusable score (partly what label-only does) |
