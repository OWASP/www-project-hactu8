# OWASP LLM05 Mapping & Mitigations

Reference for tying the demo behavior to the OWASP LLM05 framework and naming the
defense for each failure. Loaded on demand.

## Scenario mapping

| Demo component | LLM05 scenario / example | Failure demonstrated | Mitigation |
|----------------|--------------------------|----------------------|------------|
| `run_task.py` injection via `/admin/inject` | **Scenario #1** — Knowledge Repository Manipulation | No trust boundary on automated ingestion | Digital signatures / hash verification; **source scoring** |
| "Policy update / memo / addendum" framing | **Scenario #2** — Web & hidden-instruction bias | RAG implicitly trusts "updated" external text | Prioritize an internal **golden set** over external context |
| Top-k retrieval with no checks | **Example #6** — RAG Knowledge-Base Poisoning | No content filtering or anomaly detection on retrieved context | Post-retrieval **grounding** checks |
| Unbounded vector-store growth | **Scenario #3** — Continuous-learning drift | No data lineage or versioning of vectors | **DVC** + CycloneDX **ML-BOM** audit trail |
| Correct on MFA/IT, wrong on exports | Targeted "sleeper" steering (Hubinger et al., 2024) | Safety alignment alone is insufficient | Adversarial **red-teaming** for trigger backdoors |

## Mitigations (in priority order)

1. **Source scoring & filtering.** Assign trust weights to sources (golden
   handbook ≫ anonymous wiki). Rank by `similarity × trust` and refuse context
   below a threshold. In the demo this alone restores all-GREEN because the poison
   docs carry low trust. *(Implemented: `llm05_demo/mitigations.py`.)*
2. **Statistical anomaly detection.** Flag sudden clusters of near-duplicate,
   low-trust documents from a single source — the semantic-density spike a batch
   injection creates. *(Implemented: `anomaly_scan`.)*
3. **Grounding fallback.** If nothing trusted survives filtering, answer only from
   the verified golden set rather than the highest-ranked untrusted doc.
4. **Data integrity / provenance.** Use Data Version Control (DVC) and a CycloneDX
   ML-BOM so poisoned ingestions are traceable and quickly rolled back.
5. **Adversarial red-teaming.** Probe with trigger-style prompts to surface hidden
   backdoors that alignment training would not reveal.
6. **Human-in-the-loop ingestion.** For high-stakes domains (finance, healthcare),
   gate automated vector-store writes behind human validation.

## How to show the fix in the demo

From the project root, `python run_demo.py` runs all four acts, ending with Act 4
(hardened pipeline) returning the system to 🟢 GREEN / 0% PSR. Point to
mitigations #1–#3 above as the code responsible.
