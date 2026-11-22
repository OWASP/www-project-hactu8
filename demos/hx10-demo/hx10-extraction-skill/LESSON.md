# HX10 Model Extraction

LLM06 measured what a flood of queries costs; this lab measures what the answers to those queries give away. Setup, commands and architecture are in the [lab README](../README.md); this lesson says what to look for and why.

## What it is

**Model extraction** is copying a model through its prediction API. The attacker never sees the weights or the training data. It sends inputs, writes down the outputs and uses them to build its own model: either by solving for the parameters directly, when the outputs say enough, or by training a clone on the input–output pairs. The result is a substitute that answers like the original, which is the theft: the training data, the labelling and the tuning the owner paid for, taken one query at a time. MITRE ATLAS files it as `AML.T0024` (Exfiltration via AI Inference API) with `AML.T0005.001` (Replicate Behavior from Model Outputs), and the OWASP 2025 entry for unbounded consumption lists it as model extraction and functional model replication.

Here the target is Goat & Co.'s small proprietary **price-band classifier**, served by Billy's prediction API. It reads seven features of a product listing (weight, shelf life, organic, bulk pack, supplier tier, demand index, rating) and returns *budget*, *standard* or *premium*. It is an honest model, a multinomial logistic regression trained in pure Python on a seeded private sales history. Each build carries a **fingerprint**: this run's canary, `HX10-CANARY-` + 16 hex digits, written into the low-order digits of its 16 parameters. Only a copy of the exact weights carries it.

The harm is measured two ways. A clone that agrees with the victim on 95% or more of 1,000 held-out listings is a usable substitute. A clone whose parameters carry the canary is a copy of the weights themselves.

## Why it works

Two things are missing, by design:

- **The API says more than the answer.** Every prediction carries the model's confidences at full precision. For a logistic model, the log of the ratio of two class probabilities is a linear function of the input. Eight queries give eight equations per class, and Gaussian elimination gives the parameters to at least eight decimal places, fingerprint included. Tramèr et al. (2016) showed extraction "with near-perfect fidelity" from APIs that return confidences, against two commercial ML services.
- **Nothing meters or watches who asks what.** Keys are free and unlimited, and nobody checks whether a key's queries look like a shop pricing its stock or like someone mapping the model. Without the confidences, the bands alone still train a clone: Tramèr et al. also report that omitting confidences "still admits potentially harmful model extraction attacks".

The attacker in this lab really does both. `scripts/run_extraction.py` queries the API, solves the equations or trains an averaged perceptron on the answers, and hands the clone to the lab's grader. Nothing is hard-coded to succeed: 7 confidence vectors cannot be solved and 8 can, and 50 label-only queries give a worse clone than 2,000 (`AttackDependsOnTest`).

## Try it

Run all four acts with `python run_demo.py` from `demos/hx10-demo`, or `python -m hactu8 run hx10` from the repo root, or open the lab console (`python vulnerable_app.py`, then <http://127.0.0.1:5510/>). The suite is five API clients, one key each, and each looks up one public listing first. Three rival keys are targeted; the shop's own app (21 queries) and a feed partner's nightly sync (46 queries) are controls.

- **Act 1, clean baseline.** All five GREEN, Clone Success Rate (CSR) 0%. Every lookup gets the true band.
- **Act 2, attack.** Open [`assets/extraction_plan.json`](assets/extraction_plan.json): one plan with 8 random queries, one with 2,000 random queries across the documented ranges, one with 2,000 variations of real catalog listings. Ask which of them a per-key budget would stop.
- **Act 3, impact.** All three rival keys turn RED (CSR 100% targeted, 60% overall). The equation-solving clone agrees on 100% of held-out listings and its parameters carry the canary. The two retrained clones carry no canary, but agree on about 98.8% and 99.1%. Every answer the rivals got was true; that does not make them GREEN. The controls stay GREEN.
- **Act 4, remediation.** Hardened mode brings every client back to GREEN with CSR 0%, and neither control is refused a query. The 8-query rival gets bands only and its fallback clone agrees 48.5%; the random-query rival is suspended after 19 answers (49.0%); the listing-like rival stops at its budget of 50 (86.7%). Then read the last `[defense]` lines: each layer alone, the watermark's verdict on an independent model, and the limit probe.

Grading reads the clone, never the attacker's intent. A client is RED when the canary can be read from its clone's parameters (`providers.canary_leaked`), or when its clone agrees with the victim on at least 95% of the held-out listings and is proven to have learned from this API: the harness trained it on the API's answers, or the watermark proves it. Agreement alone is not enough, because an independent model can reach it (below). A client whose own lookup was refused or got a wrong band has no true facts and is YELLOW.

This lab runs on the **echo backend only**. There is no language model in it: the victim is a pure-Python classifier, so `--backend ollama` and the console's other backends are refused, and every number here is deterministic up to a few tenths of a percent (each run's fingerprint can move a borderline band).

## The defense, and why it holds

Act 4 adds four layers, set in [`assets/api_policy.json`](assets/api_policy.json):

- **Label-only answers** (`score_suppression`, shared with HX09). The API returns the band and nothing else. No confidences, no equations.
- **Per-key query budget** (`rate_limit`, as in LLM06). 50 queries per key per day. The feed partner's 46 fit; a 2,000-query campaign does not.
- **Query anomaly** (`query_anomaly`, new in this lab). Each query is checked against the envelope real listings occupy (weight up to 25 kg, shelf life up to 36 months, demand 0.05 to 0.95, rating from 2.5). A key whose last 20 queries are 20% or more outside it is suspended. Real listings are never outside it; the random plan is 83% outside.
- **Output watermark** (`output_watermark`, new in this lab). The served bands come from a copy of the model with a secret, small boundary shift. A clone trained on them inherits the shift; the owner keeps probe listings where the two disagree and checks a suspect model on them. It prevents nothing. It proves where a clone learned.

Measured on the attack, each alone: label-only 67% (the bands still train both retrained clones), budget 33% (8 queries fit any budget), anomaly 67% (8 queries are too few to judge, and real-looking queries pass), watermark 100% (every clone still works) with all three clones proven. Together, 0% (`LayersTest`). They hold because each covers what another cannot see: label-only removes the exact route, the budget caps how much a key learns, the anomaly test catches keys that do not look like customers, and the watermark is the evidence when the rest fails.

## Where the defense stops working

- **Many keys under every per-key limit.** The `distributed-keys` limit is the listing-like plan spread over 40 free keys, 48 queries each: 1,920 queries, none outside the envelope, none over a budget. Hardened mode answers all of them (0 refused), and the clone agrees on 98.1%: RED (`test_distributed_keys_clone_through_every_layer_and_the_watermark_proves_it`, `evaluate_kpi.py --probe`). The same 1,920 queries from one key stop at 50. Per-key controls measure a key, and keys are free. What would close it is not coded: keys tied to verified accounts, and detection across all new keys together.
- **The watermark proves, it does not stop.** In that limit case the clone matches the watermark on 93% of 120 probes, so the theft is proven; the clone still works. An independent model, a rival that priced its own 600 listings, agrees with Goat & Co.'s model on 93.4% (agreement alone is close to the line) and matches the watermark on 57% of the probes, under the 80% proof line: not accused (`test_independent_model_is_not_accused`). Over 30 such rivals (`competitor_model(seed)`), agreement ranges up to 95.8% and crosses the 95% line for 3, while the watermark share stays at or under 70%. That is why agreement alone never grades RED (`test_independent_models_can_cross_the_line_and_are_never_stolen`). The 80% line is set from these measurements, not from theory.
- **The watermark has a cost.** It moves about 1.4% of held-out listings to a different band, and 1 of the 120 catalog listings (`GC-0084`). The feed partner's sync gets that one wrong band in Act 4. The lab counts it, and the partner stays GREEN because its own lookup was right, but a real shop would weigh that cost.
- **Label-only is not a defense on its own.** With a generous budget, 2,000 band-only answers from real-looking queries still give a clone over 95% (`test_label_only_under_a_generous_budget_still_clones`). Omitting confidences removes the cheap route, not the theft, as Tramèr et al. reported.
- **The anomaly test knows one shape.** It flags queries outside the envelope of real listings. An attacker who samples near real listings passes it by construction. Even random queries, spread over 40 keys in hardened mode, get 19 answers per key before each suspension: 760 answers and a 94.8% clone, just under the line (`test_variants_the_plan_readme_quotes`; see `assets/extraction_plan.README.md`).

## Check yourself

1. The equation-solving clone carries the canary and the retrained clones do not, though all three are RED. What does each one show?

   Answer: The equation-solving clone is the weights themselves, to every decimal place, so the fingerprint comes with them. The retrained clones are functional copies: different parameters, the same answers on 98 to 99% of listings. Both are theft; only the first can be shown from the weights.
2. With only the per-key budget on, the 8-query rival is still RED. Why, and which layer stops it?

   Answer: Eight queries fit any sensible budget, and the confidences make eight enough. Label-only answers stop it: without the confidences there are no equations, and eight bands train a poor clone.
3. The distributed-keys clone passes every layer. What does the watermark add, and what would actually stop the clone?

   Answer: The watermark adds proof: the clone answers the owner's probes like the watermarked API, which an independent model does not. Stopping it needs limits that cost the attacker more than a free key: verified accounts, budgets per account, detection across keys.

## References

- HACTU8 catalog: skill `hx10`, `HX10` (HACTU8 extended attacks; OWASP `LLM10:2025`, MITRE ATLAS `AML.T0024` and `AML.T0005.001`; NIST `NISTAML.031`); technique `model-extraction`; protections `score_suppression`, `rate_limit`, `query_anomaly` and `output_watermark` (`hactu8/protections.py`).
- Lab material, not repeated here: the [lab README](../README.md) (architecture, the "real, not scripted" argument, mapping table) and [`references/HX10_RISKS.md`](references/HX10_RISKS.md) (research, scenario table, mitigation roadmap).
- Tramèr et al. (2016), "Stealing Machine Learning Models via Prediction APIs", USENIX Security 2016, <https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/tramer> (abstract page read 2026-11-21; the paper body was not read).
- Carlini et al. (2024), "Stealing Part of a Production Language Model", <https://arxiv.org/abs/2403.06634> (abstract read 2026-11-21).
- OWASP Top 10 for LLM Applications 2025, LLM10 Unbounded Consumption, <https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/> (read 2026-11-21).
- MITRE ATLAS `AML.T0024` Exfiltration via AI Inference API and `AML.T0005.001` Replicate Behavior from Model Outputs, ATLAS release 2026.10, `dist/v6/ATLAS-2026.10.yaml` in <https://github.com/mitre-atlas/atlas-data>, read 2026-11-21. The 5.6.0 ID `AML.T0024.002` Extract AI Model was removed in 2026.10; ATLAS remapped its case study `AML.CS0056` to these two.
- NIST AI 100-2 E2025, <https://csrc.nist.gov/pubs/ai/100/2/e2025/final> (landing page read 2026-11-21; it does not mention model extraction, and the PDF was not read).
