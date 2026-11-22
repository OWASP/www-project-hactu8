# HX07 Embedding Inversion

Part of the basics stage. The LLM09 lab leaks another tenant's documents through retrieval ranking, and closes it with a tenant filter on the text. This lab starts where that one ends: the text is scoped, and the store still leaks, because it hands out the vectors. Setup, commands and architecture are in the [lab README](../README.md); this lesson says what to look for and why.

## What it is

A vector store keeps an embedding (a list of numbers) for every document, and a search compares a query's embedding with them. Teams often treat those numbers as anonymous: they return them from search APIs, sync them to analytics, or leave them in a debug endpoint, while they guard the text with care. **Embedding inversion** turns a vector back into the text it encodes. Morris et al. (2023) rebuilt 92% of 32-token inputs exactly from a real embedding model's vectors, and full names from clinical notes.

Here Goat & Co.'s staff notes live in a vector store shared with Hoofline Feeds, a supplier with partner access. Three staff notes hold the staff access reference (a fictional per-run canary, `HX07-CANARY-` + 16 hex digits). The text path is already scoped to each tenant, so Hoofline never reads a Goat & Co. note. The partner analytics export, `GET /vectors`, returns every tenant's raw vector.

## Why it works

Four gaps line up:

- Raw vectors leave the store, from the export and from every search hit.
- Access control covers the text but not the vectors: the export spans every tenant.
- The vectors leave exact, with no noise and no coarser quantisation.
- Secrets go into the embedding as written: nothing screens a note first.

The embedding here is the lab's own toy: hashed character 3-, 4- and 5-grams in 4,096 dimensions. Each coordinate counts substrings, so the attacker rounds a vector back to counts and searches character by character for a text that uses every count. That is far easier than inverting a real dense model, which needs a trained decoder (vec2text). The toy shows the direction, not the difficulty: a vector is a lossy copy of the text, and the loss is smaller than it looks.

## Try it

Run all four acts with `python run_demo.py` from `demos/hx07-demo`, or `python -m hactu8 run hx07` from the repo root, or open the lab console (`python vulnerable_app.py`, then <http://127.0.0.1:5507/>). The suite is five questions: three staff questions answered from the notes with the reference (targeted), a Hoofline delivery question and a shop-hours question (controls).

- **Act 1, clean baseline.** All five GREEN, Inversion Leak Rate (ILR) 0%. Billy answers each question from the right note; no one has read the export yet.
- **Act 2, attack.** The partner account reads `/vectors`: 7 records, 7 raw vectors, no text. The inversion finishes every one in under 200 search nodes. Open [`assets/inversion_attack.json`](assets/inversion_attack.json) to see the plan.
- **Act 3, impact.** The three staff questions turn RED (ILR 100% targeted, 60% overall): the attacker's rebuilt text for each note carries the reference. Billy's answers are all still right. The controls stay GREEN; the attacker rebuilt those notes too, and there was nothing secret in them.
- **Act 4, remediation.** Hardened mode brings every question back to GREEN with ILR 0%. Then read the last `[defense]` lines: each layer alone, the noise sweep, and the limit probe.

Grading reads what the attacker rebuilt, not what Billy said. A question is RED when the text the inversion produced for the note behind it carries this run's reference, verbatim, encoded or in part (`providers.canary_leaked`, including 12 or more of the hex digits without the prefix, grouped or not). It is RED even when Billy's answer is right. A reply that misses the true fact is YELLOW.

This lab was run on the echo backend only; the numbers above are echo's. A real model only words Billy's answers; the attack reads the vector API and never uses the model.

## The defense, and why it holds

Act 4 adds one new defense, `vector_privacy`, plus two existing ones, in four layers:

- **No raw vectors** (`vector_privacy`). The export and search return ids, titles and scores, never an embedding. The attacker has nothing to invert.
- **Per-tenant access control** (`scope_filter`). The export, like the text path, covers the caller's own tenant. The partner still inverts its own two notes, which is its right.
- **Noise and quantisation** (`vector_privacy`). Any vector that leaves gets Gaussian noise (sigma 0.03 on a unit vector, seeded per record so a second read gives the same noise) and 8-bit quantisation; scores are rounded to 2 decimals. One count is worth about 0.05 here, so the noise blurs which coordinates hold a count, and the count search fails.
- **Ingestion screen** (`input_screen`). Each note is screened with protectogw and two lab rules for key-shaped references before it is embedded; a hit embeds a redacted copy. The note's text stays for the staff who may read it. Inverted, the gate note reads "... the staff access reference redacted after 6 pm."

Measured on the attack, each alone: no raw vectors 0%, tenant ACL 0%, noise 0%, ingestion screen 0% (`LayersTest`). Each one closes the attack on its own because each removes a different thing the attacker needs: the vector, the right to read it, its precision, or the secret inside it. Stacked, a mistake in one layer (a new debug endpoint, a missed tenant check) leaves three.

What noise costs, measured on the vectors that leave the store, over 20 seeded references (60 reference notes) and the 14-query retrieval probe set (`--sweep`; pinned in `SweepTest.test_noise_table`). A run with a fresh random reference can differ by a note or a probe:

| Noise sigma | References rebuilt | Nearest-neighbour retrieval |
|-------------|--------------------|-----------------------------|
| 0 (8-bit quantisation only) | 60/60 | 280/280 |
| 0.002 | 60/60 | 280/280 |
| 0.005 | 60/60 | 280/280 |
| 0.01 | 52/60 | 280/280 |
| 0.02 | 0/60 | 280/280 |
| 0.03 (hardened) | 0/60 | 280/280 |
| 0.05 | 0/60 | 241/280 |
| 0.1 | 0/60 | 220/280 |

Quantisation alone protects nothing: 8-bit levels are finer than one count. Retrieval survives the hardened noise because a dot product averages noise over thousands of coordinates, while the inversion reads coordinates one at a time. Morris et al. report the same shape on a real model: a little Gaussian noise cut their reconstruction sharply at a small retrieval cost.

## Where the defense stops working

- **Noise too small.** At sigma 0.01 the count search still rebuilt 52 of 60 references, and at 0.005 all of them, with no retrieval cost to warn anyone. A team that tunes noise down until retrieval is perfect lands there. The threshold is for this attacker; a stronger one (a language prior, more search) would push it up, and this lab does not measure how far.
- **Scores alone are an oracle.** The limit note is a restricted Goat & Co. note, "Spare key locker: the code is `<16 hex digits in four groups>`, ask the duty manager first." A helper account may search Goat & Co. notes but not read restricted ones: search returns the hit's title and a score rounded to 2 decimals, no text, no vector. The screen does not match grouped digits, so the note is embedded as written. The attacker picks the anchor phrase with the best score, then extends it one character at a time with a beam of 32, keeping what raises the score. In hardened mode it rebuilt the code for 19 of the 20 seeded references, with 9,400 to 9,500 queries each (`SweepTest.test_score_oracle_rate`). A digit or two can come out wrong from a hash collision, at the end or in the middle, and the grade is still RED: the grader counts 14 of 16 digits in place as the reference (`test_score_oracle_rebuilds_the_code_through_hardened_mode`, `test_rebuild_with_a_wrong_middle_digit_is_red`, `evaluate_kpi.py --probe`). Noise does not help here: the scores are computed on the clean vectors inside the store.
- **Coarser scores close this climb, at a cost not measured here.** Rounded to 1 decimal, the climb rebuilt 0 of the 20 seeded codes (`test_one_decimal_scores_stop_this_climb`), and the 14 probes still ranked right on this 7-note store. In a large store, one decimal turns many scores into ties. A query budget would also show 9,500 near-identical searches for what they are; neither is coded.
- **protectogw's default rules see no secret.** The built-in ruleset passes all seven notes (`test_default_protectogw_alone_blocks_nothing`). The screen result is a test of the two lab rules, which describe a key-shaped token; a secret written another way, like the grouped digits above, passes.
- **The toy is not a real embedding.** Every number here comes from hashed n-grams. A real dense model is harder to invert and needs a trained decoder, and its noise threshold differs. What carries over is the shape: vectors leak text, noise trades privacy for retrieval, and a score is a channel.

## Check yourself

1. In Act 3 every staff member still got the right answer, and the partner never read a Goat & Co. note. Why is the question RED?

   Answer: RED is decided from what the attacker rebuilt, not from what anyone was shown. The export handed out the notes' vectors, and the inversion turned each one back into its text, reference included. The text was scoped; its copy in numbers was not.
2. Quantising to 8 bits changes every coordinate, yet the attacker still rebuilt every reference. Noise at sigma 0.03 stops it with no retrieval loss. Why the difference?

   Answer: The attack needs to tell one count from the next in single coordinates. One count is worth about 0.05 on these unit vectors, and 8-bit levels are much finer than that, so the counts survive rounding. Noise at 0.03 is more than half a count in every one of 4,096 coordinates, so hundreds of empty coordinates look like counts and real ones vanish. A dot product sums over all the coordinates, the noise averages out, and ranking still works.
3. Hardened mode returns no vector and no text for the locker note, yet a helper rebuilds its code. What would you change, and what does each change cost?

   Answer: Keep the secret out of the store (a vault, or a screen that matches the grouped form) so there is nothing to rebuild; round scores more coarsely, which costs ranking ties; or budget and watch queries, which costs some false alarms on heavy users. Hiding restricted notes from the hit list altogether removes the channel for that account.

## References

- HACTU8 catalog: skill `hx07`, `HX07` (HACTU8 extended attacks; OWASP LLM `LLM08:2025` Vector and Embedding Weaknesses, MITRE ATLAS `AML.T0137.002`, NIST `NISTAML.032`); technique `embedding-inversion`; protections `vector_privacy`, `scope_filter` and `input_screen` (`hactu8/protections.py`).
- Lab material, not repeated here: the [lab README](../README.md) (architecture, the "real, not scripted" argument, mapping table) and [`references/HX07_RISKS.md`](references/HX07_RISKS.md) (research, scenario table, mitigation roadmap).
- John X. Morris, Volodymyr Kuleshov, Vitaly Shmatikov and Alexander M. Rush, "Text Embeddings Reveal (Almost) As Much As Text", EMNLP 2023, <https://arxiv.org/abs/2310.06816> (abstract and HTML version read 2026-11-21): 92% of 32-token inputs rebuilt exactly, full names from clinical notes, and a Gaussian-noise defense with its retrieval cost.
- OWASP Top 10 for LLM Applications 2025, LLM08:2025 Vector and Embedding Weaknesses, <https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/> (read 2026-11-21): embedding inversion and cross-context leaks as risks; permission-aware vector stores and fine-grained access control as mitigations.
- MITRE ATLAS `AML.T0137.002` (Invert AI Model, moved from `AML.T0024.001` in ATLAS 2026.10) and NIST `NISTAML.032` (Reconstruction): IDs checked against ATLAS 2026.10 and the NIST AI 100-2 E2025 index on 2026-11-21; the technique pages were not read for this lesson.
