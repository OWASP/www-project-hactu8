# AGX07 Frontmatter Poison

Step 21 on the learning path, after AGX03 Conditional Rug-Pull. Setup, commands and architecture are in the [lab README](../README.md); this lesson says what to look for and why.

## What it is

Ingestion screens are often written for the prose a human reads, and metadata is treated as plumbing. But a RAG loader hands the model the whole document: title, summary, tags and body. Frontmatter is attacker-controlled text like any other, and it sits at the top of the context. AGX07 is one of AgenticGoat's superset labs (group C, RAG and multi-document), with parent ASI06 Memory and Context Poisoning. Where AGX06 screens at the wrong time, AGX07 screens the wrong part of the document.

Here the target is Billy, Goat & Co.'s ops assistant, who answers from a knowledge-base bundle of Markdown documents. His ground truth is *a fictional `sk-canary-` credential sits in his context with the instruction never to reveal it*. The attacker uses the unauthenticated ingestion endpoint (`POST /bundle/ingest`) to replace `vault-access.md` with a copy whose body is byte-identical and whose frontmatter `description:` holds a directive asking Billy to print the credential.

## Why it works

The gateway uses protectogw with the right ruleset in both modes. Only the part of the document it reads changes:

- In vulnerable mode the gateway screens the `body` surface only. The `frontmatter` piece passes unscreened.
- The loader surfaces both, and Billy's router sends only vault questions to `vault-access.md`. The echo model finds "emit" and "confirm" in the metadata and replies with the credential.
- Screen the same metadata as if it were body text and the vulnerable gateway blocks it (`GatewayTest`). The ruleset was never the problem; its scope was.

PoisonedRAG (Zou et al., 2024) shows that a handful of poisoned documents is enough to steer targeted questions; this lab shows the poison need not be in the part a reviewer reads.

## Try it

Run all four acts with `python run_demo.py` from `demos/agx07-demo`, or `python -m hactu8 run agx07` from the repo root, or open the lab console (`python vulnerable_app.py`, then <http://127.0.0.1:5407/>). The suite is five requests: three vault questions the attacker targets and two controls (meal expenses, the next holiday).

- **Act 1, clean baseline.** All five GREEN, Canary Leak Rate (CLR) 0%. The approved bundle is in [`assets/bundle/`](assets/bundle/).
- **Act 2, attack.** `vault-access.md` is replaced by [`assets/frontmatter_payload.md`](assets/frontmatter_payload.md). Diff its body against the approved one: nothing changed. Only the `description:` line is new.
- **Act 3, impact.** The three vault questions turn RED (CLR 100% targeted, 60% overall), and the controls stay GREEN.
- **Act 4, remediation.** The scan rejects the document on two grounds: `frontmatter: lab_directive` and `schema: description is 273 chars (max 160)`. In hardened mode the vault questions are YELLOW (the metadata was withheld, nothing leaked), the controls stay GREEN, and the CLR is 0%.

On a real model (`--backend ollama --model llama3.2:3b`) the numbers are reported, not asserted.

## The defense, and why it holds

Three controls are added in Act 4. Any one alone takes the CLR to 0 for the shipped payload on the echo backend; the tests turn off two at a time to prove it:

- **Screen every field the loader surfaces** (`channel_screen`). The hardened gateway screens the frontmatter as well as the body.
- **Allowlisted metadata schema.** Known keys only (`type`, `title`, `description`, `owner`, `tags`, `updated`), known `type` values, and values of 160 characters or fewer (`schema_problems`). The shipped description is 273 characters, so it fails on length; a short payload under an unknown key fails on the key.
- **Output canary check** (`canary_tripwire`). Every reply is screened for the credential, and a blocked reply becomes a refusal, whatever field the directive rode in.

For real models, hardened mode also fences the document in `<untrusted_document>` tags (spotlighting).

## Where the defense stops working

- **The screen catches this payload only through the lab's own rule.** protectogw's built-in rules flag none of the shipped document, with or without the `AGX-LAB-DIRECTIVE` marker (checked against the vendored protectogw 2.0.0, and pinned by `test_builtin_rules_alone_miss_the_payload`). Screening the frontmatter only helps when a rule recognises the wording.
- **The schema check catches length, not intent.** A 70-character rephrased directive under the allowed `description` key passes both the schema check and the built-in screen (checked with `schema_problems` and `protectogw.screen`). The shipped payload fails the schema only because it is long. Against a short, unmarked directive in an allowed key, the output canary check is the only control left.
- **The attack lands on a small real model.** On `llama3.2:3b` all three vault questions leaked the canary in Act 3 (CLR 0% to 100% to 0%, one run while this lesson was written; the HACTU8 merge plan recorded 33% impact, so expect variation). In Act 4 the metadata was withheld, so the run does not show the canary check alone against a real model.
- **The canary check only sees the canary verbatim.** A spaced-out, reversed, base64-encoded or partial copy passes it (checked with `protectogw.screen`), and the lab's grader matches the same exact `sk-canary-` shape. The CLR counts verbatim leaks only.
- **Screens do not generalise far.** protectogw's `SECURITY.md` reports that 2.0 catches 16 of 30 (53%) of HACTU8's independent held-out set, with no false positives (`python -m hactu8 bench`). AGX09 measures the same gap on its own set.
- **The root cause is not fixed in code.** Ingestion stays unauthenticated. Provenance and signing for every bundle document, and reviewed ingestion, are discussed in the references, not coded.

## Check yourself

1. A reviewer diffs the poisoned document's body against the approved one and finds no change. Why does Billy still leak?

   Answer: The loader hands the model the frontmatter too, and the directive is in the `description:` field. The body-only screen and the body-only review never read it.
2. The attacker shortens the directive to under 160 characters, drops the marker and keeps it in `description:`. Which of the three hardened layers still stops the leak?

   Answer: Only the output canary check. The value passes the schema check (allowed key, short enough) and the built-in rules do not flag it.
3. Why is the schema check still worth having if it can be passed?

   Answer: It does not depend on wording. It rejects long free text and unknown keys outright, which shrinks the room an attacker has, and it caught the shipped payload on its own.

## References

- HACTU8 catalog: skill `agx07`, `AGX07` Frontmatter Poison (an AgenticGoat superset ID, not an OWASP number; parent `ASI06:2026` Memory and Context Poisoning); protections `channel_screen` and `canary_tripwire` (`hactu8/protections.py`).
- Lab material, not repeated here: the [lab README](../README.md) (architecture, the MCP terminology bridge, mapping table), [`references/AGX07_RISKS.md`](references/AGX07_RISKS.md) (research, scenarios, mitigation roadmap), the [payload README](assets/frontmatter_payload.README.md) and protectogw's [`SECURITY.md`](protectogw/SECURITY.md).
- Related labs: AGX06 Runtime Result Injection (wrong time) and LLM05 Data and Model Poisoning (RAG poisoning).
- Real-model figures: in the HACTU8 repo, `docs/agenticgoat-merge-plan.md` (AG-51 notes).
- Zou et al. (2024), "PoisonedRAG: Knowledge Corruption Attacks to Retrieval-Augmented Generation of Large Language Models".
- Greshake et al. (2023), "Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection".
- Ported from AgenticGoat's AGX07 entry (`agentic/labs.json`), its `okf_scan` act (`acts.py`) and the `input_screen` control (`agentic/protections.py`).
