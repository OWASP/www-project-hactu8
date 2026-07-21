# Attack Technique — Semantic Collision & the Poisoning Threshold

Domain knowledge loaded on demand. Explains *why* a handful of documents can
override a knowledge base, so the skill can reason about payload design and
interpret results.

## 1. The poisoning threshold (low volume, high impact)

Poisoning does not require corrupting a large fraction of a corpus. Research on
LLM training poisoning (Souly et al., 2025) shows a near-constant *number* of
poisoned samples — not a fixed *ratio* — can implant behavior even in large
models. In a **RAG** setting the threshold is far lower still: only **3–10**
well-placed documents are needed, because retrieval surfaces just the top-k
context and the attacker only has to win that ranking.

## 2. Semantic collision (how retrieval is hijacked)

RAG retrieves the top-k documents whose embedding vectors are most cosine-similar
to the query. An attacker crafts documents that **maximize similarity to the
target queries** — chiefly by repeating the query's salient keywords. In the demo:

- Target queries center on: `data exports`, `USB drive`, `external storage`.
- The poison memos repeat exactly those terms, so their vectors "collide" with
  the query vector and outrank the single legitimate policy document.
- Once a poison doc is in the top-k, the "stuff" chain places it in the prompt as
  trusted context, and the LLM grounds its answer in it.

In this demo's local backend the embedding is a normalized hashing bag-of-words,
so term frequency directly raises similarity — the collision is a real, observable
effect, not a scripted outcome. Real dense embedding models are also vulnerable;
the attacker instead optimizes phrasing/paraphrase to raise cosine similarity
(cf. CorruptRAG, Zhang et al., 2025).

## 3. Evading naive filters

Perplexity-based filtering assumes malicious injections look like gibberish. These
payloads are **coherent, fluent "policy updates"** — low perplexity — so they pass
straight through. That is why detection must operate on *provenance and
distribution* (source trust, near-duplicate clustering), not surface fluency.

## 4. Targeted "sleeper" steering

The attack is deliberately narrow: it flips only the `data_export` topic while
leaving MFA and IT-approval answers correct. A system that looks healthy on most
queries can be fully compromised on the one topic the attacker cares about — the
behavior described for backdoored/"sleeper" models (Hubinger et al., 2024). This
is why the KPI reports a **targeted** PSR separately from the overall rate.

## 5. Designing an effective payload

- Repeat the **exact** salient keywords of the queries you want to flip.
- Reinforce with multiple same-direction documents (they collectively outrank the
  lone truth) — but keep the count small to demonstrate the threshold.
- Frame as a plausible "update/memo/addendum" so it reads as legitimate context.
- Keep language fluent to defeat perplexity filters.

See [`LLM05_MAPPING.md`](LLM05_MAPPING.md) for how each of these maps to OWASP
LLM05 scenarios and the defenses that stop them.
