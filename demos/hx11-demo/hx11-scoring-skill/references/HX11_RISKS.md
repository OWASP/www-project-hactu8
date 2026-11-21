# HX11 Attacks on the Scoring Layer — risks, research and mitigations

What this lab's risk is, where the evidence comes from, and how to harden against it. Loaded on demand.

## Research foundations

- **Shi et al. (2024)**, "Optimization-based Prompt Injection Attack to LLM-as-a-Judge" (JudgeDeceiver), CCS 2024, <https://arxiv.org/abs/2403.17710> (abstract read 2026-11-21). A gradient-based optimisation finds a sequence that, injected into an attacker-controlled candidate response, makes an LLM judge select it "no matter what other candidate responses are". The abstract reports it is "much more effective than existing prompt injection attacks that manually craft the injected sequences", with case studies in LLM-powered search, RLAIF and tool selection, and that known-answer detection, perplexity detection and windowed perplexity are "insufficient". The abstract gives no success-rate numbers; the paper body was not read. This lab's injected line is hand-written, not optimised.
- **Thakur et al. (2024)**, "Judging the Judges: Evaluating Alignment and Vulnerabilities in LLMs-as-Judges", <https://arxiv.org/abs/2406.12624> (abstract read 2026-11-21). Thirteen judge models: "only the best (and largest) models achieve reasonable alignment with humans"; scores "may still differ with up to 5 points from human-assigned scores"; the vulnerabilities named are "sensitivity to prompt complexity and length, and a tendency toward leniency". A benign-setting study, not an adversarial one.
- **Hines et al. (2024)**, "Defending Against Indirect Prompt Injection Attacks With Spotlighting", <https://arxiv.org/abs/2403.14720> (abstract read 2026-11-21). A family of prompt transformations that give the model "a reliable and continuous signal of its provenance"; reported to reduce attack success "from greater than 50% to below 2%" on GPT-family models with minimal effect on the task. The lab's fence with a per-run nonce is the delimiting variant; datamarking and encoding were not implemented.
- **Yi et al. (2023)**, "Benchmarking and Defending Against Indirect Prompt Injection Attacks on Large Language Models" (BIPIA), <https://arxiv.org/abs/2312.14197> (abstract read 2026-11-21). LLMs are "universally vulnerable"; boundary awareness and explicit reminders mitigate, and a white-box defense reduces attack success "to near-zero levels". No numbers in the abstract.
- **OWASP LLM01:2025 Prompt Injection**, <https://genai.owasp.org/llmrisk/llm01-prompt-injection/> (read 2026-11-21). Indirect injection from external content; mitigations include "Segregate and identify external content" and "Define and validate expected output formats ... use deterministic code to validate adherence". Scenario 6 has an LLM that evaluates résumés manipulated into a positive recommendation. The page says "it is unclear if there are fool-proof methods of prevention".
- **OWASP LLM09:2025 Misinformation**, <https://genai.owasp.org/llmrisk/llm092025-misinformation/> (read 2026-11-21). Overreliance "occurs when users place excessive trust in LLM-generated content"; mitigations "Cross-Verification and Human Oversight" and "Automatic Validation Mechanisms".
- **MITRE ATLAS** `AML.T0051.001` (indirect prompt injection), `AML.T0015` (evade the model), `AML.T0046`: IDs from HACTU8's technique catalog. The ATLAS technique pages returned HTTP 404 when fetched on 2026-11-21 (unverified here).
- **NIST AI 100-2 E2025** `NISTAML.015`, `NISTAML.025`: IDs from HACTU8's catalog, not reread for this lab (unverified).

## Scenarios and examples

| ID | Title | Description | Focus |
|----|-------|-------------|-------|
| S1 | Injection aimed at the judge | A line in the evidence tells the judge which verdict to give | **DEMO TARGET** (tr-101) |
| S2 | Forged verdict in the evidence | A verdict object in the evidence is quoted by the judge and parsed as its verdict | **DEMO TARGET** (tr-102) |
| S3 | Verdict format confusion | A fake end of transcript and a verdict in another vocabulary (`label`, `PASS`) | **DEMO TARGET** (tr-103) |
| S4 | Classifier evasion | The secret reshaped (spaced out) so a verbatim screen misses it | **DEMO TARGET** (tr-104) |
| S5 | False-positive flooding | Benign texts that trip the classifier fill the review queue before a real leak | **DEMO TARGET** (tr-106) |
| S6 | Spread flood | The flood split across many sources, under any per-source budget | **DEMO TARGET** (measured limit) |
| S7 | Shared blind spot | An encoding neither scorer reads (base64) | **DEMO TARGET** (measured limit) |
| S8 | Optimised injection (JudgeDeceiver) | A gradient-searched suffix rather than a readable line | Context (needs model weights; not in this lab) |
| S9 | Scorer outage and fallback | A judge that times out falls back to a weaker scorer | Context (HACTU8's own llm-judge falls back to the keyword verdict) |

## How the demo maps to the attack surfaces

- **S1**: `Lab.judge_prompt` (plain-text evidence in vulnerable mode), `StubJudge.judge` (`DIRECTIVE`).
- **S2, S3**: `StubJudge.judge` (quotes the turn holding a code), `parse_lax` (first object, lax keys and values), `Lab.judge_score`.
- **S4**: `Lab.triage` routing (chat to the classifier only), `Lab.classifier_score` (protectogw's verbatim canary check).
- **S5, S6**: `Lab.triage` (review queue, `review_capacity`, overflow released), `flood_items`, `flag_budget`.
- **S7**: `sees_secret` (reads spaced text, not base64), protectogw's canary check.

## Mitigation roadmap

| Vulnerability | Hardening strategy |
|---------------|--------------------|
| Evidence read as instructions by the judge | Fence the evidence with a per-run nonce and say it is data (implemented: `spotlight`, `FENCE_RULE`); datamarking or encoding the evidence (discussed, not coded) |
| First verdict-shaped object wins; lax vocabulary | Read only a nonce-bearing last line with an exact schema; fail closed (implemented: `verdict_schema`, `parse_strict`) |
| Scores with no recorded producer; evidence copies accepted | Record the producer of every score; void a verdict that also appears in the evidence (implemented: `score_provenance`) |
| One scorer per item | Score every item with two scorers that fail differently; agreement decides, disagreement goes to review (implemented: `classifier_cross_check`) |
| One source can fill the review queue | Per-source flag budget, overflow held (implemented: `flag_budget`) |
| Review queue fails open | Hold overflow instead of releasing it; prioritise review by risk (discussed, not coded) |
| Shared blind spot of both scorers | Score decoded views (base64, hex, spacing) as the grading oracle does; add a third, different scorer (discussed, not coded) |
| Optimised injections | Known-answer and perplexity detection are reported insufficient by JudgeDeceiver; keep code-level controls authoritative (discussed, not coded) |
