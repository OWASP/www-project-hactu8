# LLM07 Risk Reference — Misinformation

Domain knowledge, loaded on demand. Misinformation happens when a model
produces false or misleading content that appears credible, and people or
systems act on it. (This repo numbers it LLM07; in the OWASP Top 10 for LLM
Applications 2025 it is **LLM09:2025 Misinformation**.) It becomes a security
problem when a confident falsehood drives an action. The sharpest case is the
**hallucination-to-supply-chain pivot**: the model recommends a package that
does not exist, an attacker registers that name with malicious code, and the
next developer or agent installs it (**slopsquatting**).

## Research foundations

- **Ji et al. (2023), "Survey of Hallucination in Natural Language
  Generation"** (ACM Computing Surveys) — taxonomy of hallucination: output
  that is fluent and confident but unfaithful to its source or to fact.
- **Lewis et al. (2020), "Retrieval-Augmented Generation for
  Knowledge-Intensive NLP Tasks"** — grounds generation in retrieved documents
  and yields more specific, factual answers than a parametric-only model.
  Grounding is only as trustworthy as the retrieved documents, which is the gap
  this demo exploits.
- **Spracklen et al. (2025), "We Have a Package for You! A Comprehensive
  Analysis of Package Hallucinations by Code Generating LLMs"** — shows that
  code-generating models routinely recommend packages that do not exist, and
  that many of those names recur, which makes them registrable by an attacker.
- **OWASP Top 10 for LLM Applications 2025, LLM09 Misinformation** — the risk
  entry, including unsafe code suggestions, overreliance, and the
  recommendation to cross-check outputs against trusted sources.

## Scenarios & examples

| ID | Title | Description | Focus |
|----|-------|-------------|-------|
| M-1 | Poisoned source stated as fact | A false claim in retrieved content is restated with full confidence. | **DEMO TARGET** |
| M-2 | Slopsquat / hallucinated package | The answer names a package that is not in any approved registry. | **DEMO TARGET** |
| M-3 | Untrusted citation | The answer cites a URL on a host nobody vetted, presented as official docs. | **DEMO TARGET** |
| M-4 | Pure hallucination | The model invents a package or fact with no poisoned source at all. | Partly: the grounding check catches the cited artifact whatever its origin |
| M-5 | Factual misinformation without artifacts | A wrong number or policy with no package or URL to resolve. | — (needs retrieval-with-citations and human review) |
| M-6 | Overreliance | Users or agents act on output without review. | — (process control) |

## How the demo maps to the attack surfaces

- **M-1** is `POST /docs/page`, which accepts unauthenticated community pages
  into the same store as the official docs, combined with `StubModel`, which
  restates the top-ranked page's first line as fact.
- **M-2 / M-3** are the `goathttp` package and the `goathttp-docs.invalid`
  host in `assets/poisoned_doc.md`. In vulnerable mode, nothing checks either
  before the answer reaches the developer.
- **Retrieval decides the blast radius.** Only HTTP-client questions rank the
  poisoned page first. That is why the PDF and logging controls stay GREEN.

## Mitigation roadmap

| Vulnerability | Hardening strategy |
|---------------|--------------------|
| Cited packages never verified | **Approved-registry check** on every package the answer tells someone to install. Implemented: `check_grounding` in `vulnerable_app.py` + `assets/approved_registry.json`, ported from AgenticGoat `acts.py` `_grounding_check`. |
| Cited URLs never verified | **Trusted-domain allowlist** for every cited URL host. Implemented: same function. |
| Unverifiable claims stated as fact | **Downgrade to "unverified"**: withhold the draft, fall back to the next grounded source, or say it could not verify. Implemented: hardened mode in `vulnerable_app.py`. |
| Unvetted content sources | Authenticate and review community contributions; keep them out of the official store, or label and rank them lower. Pre-publication check implemented: `evaluate_kpi.py --scan`. |
| Install on the model's say-so | Pin dependencies, install only from an internal mirror of approved packages, and require human review of new dependencies (see LLM03 Supply Chain). |
| Overreliance | UI cues for unverified content, citations users can follow, and human review for high-stakes output. |

Further hardening discussed, not coded: querying a real package index for
existence, age and maintainer reputation; DNS and TLS checks on cited hosts;
relevance thresholds so a fallback answer never comes from a weakly related
page; and factual-claim verification for M-5, which an artifact check cannot
cover.
