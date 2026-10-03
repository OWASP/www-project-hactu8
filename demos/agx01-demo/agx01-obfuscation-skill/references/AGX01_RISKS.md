# AGX01 Risk Reference — Obfuscation Gauntlet

Domain knowledge, loaded on demand. AGX01 is one of AgenticGoat's superset
labs (`agentic/labs.json` → `superset_labs`, group **A: Evasion**), for
patterns neither OWASP list numbers on its own. Its parent entry is **ASI01,
Agent Authorization and Control Hijacking** (the AgenticGoat mapping), and the
underlying mechanism is prompt injection (LLM01).

A screen that matches keywords judges whatever text it is shown. A model,
though, reads *through* encodings: it will decode base64, read letter-spaced or
dotted tokens, and see past homoglyph and zero-width tricks. So a directive the
screen cannot read in raw form is still an instruction the model follows. The
only honest screen normalizes the text to the same canonical form the model
effectively sees, and judges that.

## Research foundations

- **OWASP Top 10 for Agentic Applications 2026, ASI01** — the parent entry in
  AgenticGoat's mapping: an agent is steered by text it treats as authoritative.
- **OWASP Top 10 for LLM Applications, LLM01 (Prompt Injection)** — the
  underlying mechanism: text the model reads is treated as instructions.
- **Greshake et al. (2023), "Not what you've signed up for"** — indirect prompt
  injection. Content an LLM-integrated application fetches for the model (here,
  a notice from a tool host) can carry instructions the model follows.
- **AgenticGoat `acts.py` → `obfuscation_gauntlet`** — encodes one canonical
  payload as leet, zero-width, homoglyph, base64 and split-token, and grades
  the **normalizer** (`_deobfuscate` → `normalize`), not the ruleset. Coverage
  is the closed set of encodings the normalizer folds.
- **protectogw `SECURITY.md`** — the screening core is one layer, with a
  measured generalization ceiling of about 75% on held-out attacks. The output
  canary check is the attack-agnostic control.

## Scenarios & examples

| ID | Title | Description | Focus |
|----|-------|-------------|-------|
| S-1 | base64-wrapped directive | The directive encoded as base64 in a notice body. | **DEMO TARGET** (`welcome`) |
| S-2 | split-token directive | Every letter dotted (`e.m.i.t`), defragged by the normalizer. | **DEMO TARGET** (`maintenance`) |
| S-3 | base32 / hex-escape directive | Base32 or `\xNN` escapes, decoded by the normalizer. | **DEMO TARGET** (`status` / `--encoding hex`) |
| S-4 | zero-width / homoglyph / leet | Folded by `normalize()` unconditionally. | Caught in both modes — not a blind spot here |
| S-5 | an encoding with no fold | A class the normalizer does not reverse. | — (held-out; see AGX09) |

## How the demo maps to the attack surfaces

- **S-1..S-3** are `POST /vendor/notices/update` (no authentication) replacing a
  notice body with an encoded copy of the directive, combined with `Lab.ask`
  assembling the notice into Billy's context. `Gateway("vulnerable")` screens
  it with `Policy(disabled_folds=FOLD_NAMES)`, so the encoded form passes with
  verdict ALLOW and no signals.
- **The model decodes regardless.** `StubModel` reads its context through the
  same `normalize(_deobfuscate(...))` a real LLM effectively applies, so the
  encoded directive still trips the "emit" + "confirm" rule and leaks — exactly
  the asymmetry the lab is about.
- **The ruleset is not the problem, its placement is.** The same protectogw call
  blocks the plaintext directive even in vulnerable mode (`GatewayTest`), and
  blocks every encoded form once normalization is on.

## Mitigation roadmap

| Vulnerability | Hardening strategy |
|---------------|--------------------|
| Encoded text evades a raw-byte screen | **Normalize before judging**: NFKC, zero-width strip, leet/homoglyph fold, and decode/defrag passes (base64, base32, URL, Morse, hex, ROT13, reverse, split-token, de-space) run before the ruleset. Implemented: `SCREEN_POLICIES["hardened"]` uses the default policy; `disabled_folds=FOLD_NAMES` is the naive one. |
| A leak once an injection gets through | **Output canary check**: `protectogw.screen(reply, canaries=[CANARY])` on every reply, replacing a blocked reply with a refusal. Implemented: `Gateway.check_reply`. Stops this attack on its own (`test_canary_check_alone_blocks`). |
| Untrusted text mixed into the instruction channel | **Spotlighting** for real models: hardened mode fences notice text in `<untrusted_tool_output>` tags. Implemented: `ProviderModel`. |
| Unauthenticated vendor updates | Authenticate and sign notice sources; review before publishing. Discussed, not coded. |
| A brand-new encoding class | Treat normalizer coverage as a **closed set** and grow it deliberately (AgenticGoat's practice note); held-out testing (AGX09) measures the gap; the canary layer catches the leak whatever the encoding. |
