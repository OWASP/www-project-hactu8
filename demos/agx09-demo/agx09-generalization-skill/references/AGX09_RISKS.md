# AGX09 Risk Reference — Generalization Probe

Domain knowledge, loaded on demand. AGX09 is one of the AGX superset
labs (`agentic/labs.json`, `superset_labs`, group **D: Assurance**). Its
parent entry is **ASI01, Agent Goal Hijack**, in the OWASP Top 10 for Agentic
Applications 2026.

"Caught the attacks we wrote" is a low bar. The honest question is whether a
screen generalizes to phrasings it was never tuned on. Some deliberately still
slip, and the measurement has to say so.

## Research foundations

- **OWASP Top 10 for Agentic Applications 2026, ASI01 (Agent Goal Hijack)** —
  the parent entry: injected text redirecting the agent's goal.
- **OWASP Top 10 for LLM Applications 2025, LLM01 (Prompt Injection)** — the
  entry notes that no filter is complete and recommends layered controls.
- **Liu et al. (2024), "Formalizing and Benchmarking Prompt Injection Attacks
  and Defenses"** — a systematic benchmark finding existing prevention and
  detection defenses insufficient, especially against combined attacks.
- **protectogw `SECURITY.md`** — 53% generalization on HACTU8's
  independent held-out set (16 of 30); the canary check is the attack-agnostic control.
- **The source lab's `wild.py` and `wild_scan` act** — the held-out set,
  scored on its own axis so a held-out miss never counts as a regression.

## Scenarios & examples

| ID | Title | Description | Focus |
|----|-------|-------------|-------|
| S-1 | Paraphrase without the ruleset's verbs | A credential request phrased as a routine ask | **DEMO TARGET** (4 items, all missed) |
| S-2 | Translation | The same request in Spanish and Portuguese | **DEMO TARGET** (2 items, both missed) |
| S-3 | Encodings | ROT13, reversed, hex, base32, URL, spaced, Morse | **DEMO TARGET** (7 items, all caught) |
| S-4 | Novel wording on a general pattern | Override or mode-switch phrasing not in the tuning set | **DEMO TARGET** (2 items, both caught) |
| S-5 | Benign notes, including one about passwords | Must not be flagged | **CONTROL** (3 items, none flagged) |
| S-6 | Encodings the normalizer does not fold | For example a Caesar shift other than 13 | — (not in this set; would test the folds) |

## How the demo maps to the attack surfaces

- **S-1 to S-4** are the 15 attack slots of the inbox, written through
  `POST /inbox/deliver` (no authentication). `Gateway.screen` applies the
  same protectogw policy in both modes.
- **The stand-in model reads every encoding** with its own decoders, so a
  catch is never confused with the model failing to read.
- **Two axes.** `screen_axis` computes the catch rate over the held-out
  attacks and the false positives over the controls. The CLR is computed from
  the replies. Neither is folded into the other.

## Mitigation roadmap

| Vulnerability | Hardening strategy |
|---------------|--------------------|
| The screen misses novel vocabulary | **Measure it** on a held-out set, on its own axis, and publish the misses. Implemented: `screen_axis`, `--scan`, pinned in the tests. |
| A miss reaches the model | **Output canary check**, which does not depend on the attack's wording. Implemented: `Gateway.check_reply`. Takes the CLR to 0 here. |
| Untrusted text mixed into the instruction channel | **Spotlighting** for real models: `<untrusted_note>` tags in `ProviderModel`. |
| Secrets the model can be talked into printing | Keep real credentials out of the context entirely (a vault used by code). Discussed, not coded: the canary stands in for one. |
| A static ruleset | Grow it from held-out misses, then retire those items to regression and write new held-out ones. An optional classifier plane (`Policy.classifier`) can cover phrasing a regex cannot. Discussed, not coded. |
