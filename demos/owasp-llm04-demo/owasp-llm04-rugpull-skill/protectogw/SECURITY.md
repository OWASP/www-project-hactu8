# ProtectoGW — Security Model & Threat Model

> **Status: draft / reference implementation.** ProtectoGW is a screening core
> extracted from [AgenticGoat](../README.md), a deliberately-vulnerable target
> range for agentic prompt-injection. This document states what ProtectoGW
> defends, what it explicitly does **not**, and the conditions under which it is
> safe to deploy. Read it before putting ProtectoGW in a request path.

## 1. What ProtectoGW is

ProtectoGW decides whether a piece of **untrusted text headed for a model's
context** is hostile. It is deliberately **surface-agnostic**: a tool
description, a resource body, a prompt template, an agent-to-agent message, and a
model's own output are all just "untrusted text," and every caller uses one
entry point:

```python
from protectogw import screen, Verdict

s = screen(untrusted_text, canaries=[...])   # -> Screen(verdict, risk, signals)
s.verdict   # ALLOW | FLAG | BLOCK
```

Internally it is two stages:

1. **Normalizer** — folds evasions back toward plaintext before the ruleset sees
   them: NFKC, zero-width stripping, lowercasing, Cyrillic/Greek homoglyph
   folding, leet folding, whitespace collapse, split-token / letter-space
   de-fragmentation, and decode-and-inspect passes for base64, base32,
   URL/percent, Morse, ROT13, reverse, and `\xNN` hex. Each decode is gated by a
   "looks like text" check so it only fires on real encoded input.
2. **Ruleset + indicator taxonomy** — pattern rules (instruction-override,
   secret-reveal, exfiltration, persona/mode switches, …) plus a decisive
   **canary check** that blocks any text containing a guarded token, regardless
   of phrasing.

`Session` (`session.py`) adds a stateful cross-read screen for payloads that only
become hostile once several documents are concatenated.

## 2. Trust model & where it sits

ProtectoGW is a **filter, not a boundary.** It assumes:

- The **text it receives is untrusted and possibly adversarial** — that is the
  whole point.
- The **caller is trusted** to route the verdict correctly (block, flag, log).
  ProtectoGW returns a verdict; it does not enforce anything.
- The **canary list is a secret ProtectoGW is told to guard**, not a secret it
  stores. The caller owns canary minting and rotation.

It is designed to sit at two places in a pipeline, and its two planes have very
different strength (see §4):

- **Input screening** — screen untrusted text *before* it reaches the model.
  This is the *weaker* plane (closed ruleset vs. open input class).
- **Output / canary screening** — screen the model's *output* before it leaves
  the trust boundary. The canary check here is the *load-bearing,
  attack-agnostic* control: a guarded token appearing in output is unambiguous
  exfiltration regardless of how the model was tricked into emitting it.

**Deploy both.** Relying on input screening alone is the failure mode this whole
project exists to demonstrate.

## 3. What ProtectoGW defends against (in scope)

| Threat | Mechanism | Strength |
|---|---|---|
| Instruction-override / jailbreak phrasing in untrusted text | Ruleset (`instruction_override`, `persona_override`, `mode_switch`, …) | Heuristic — see §4 |
| Secret/system-prompt reveal & exfiltration phrasing | Ruleset + CRITICAL indicator taxonomy | Heuristic |
| Credential appearing in output | **Canary check** (decisive BLOCK) | **Strong / attack-agnostic** |
| Encoded payloads (base64/32, URL, Morse, ROT13, reverse, hex) | Normalizer decode-and-inspect folds | Strong *within the closed fold set* |
| Confusable / zero-width / leet / split-token evasion | Normalizer folds | Strong within the known set |
| Cross-read payloads (hostile only when concatenated) | `Session` stateful screen | Heuristic |

## 4. What ProtectoGW does NOT defend against (out of scope — read this)

ProtectoGW is **regex-and-heuristic over a closed corpus.** These limits are
structural, measured, and by design — not bugs:

- **Novel phrasings / deep paraphrase.** An override worded outside the ruleset's
  verb/noun vocabulary passes. AgenticGoat measures this: on a held-out set
  ProtectoGW was never tuned on, it currently catches **~75%** — the remaining
  misses are paraphrases and non-English payloads it structurally cannot close.
- **Translation / non-English payloads.** No language model, no translation
  fold — a translated instruction slips.
- **Encoding classes with no fold.** The decode set is *closed*; an encoding not
  in §2 step 1 (or a nested/multi-layer encoding) is not unwound.
- **Semantic attacks with no lexical tell.** ProtectoGW matches surface form, not
  intent. An injection that reads as benign prose is invisible to it.
- **Anything downstream of the verdict.** ProtectoGW does not sandbox tools, gate
  egress, authenticate callers, or pin content hashes. Those are *separate*
  planes (AgenticGoat demonstrates hash-pinning and egress-nulling elsewhere) and
  ProtectoGW is not a substitute for them.

**The honest one-liner:** the *attack-agnostic* controls (the canary/output
check, and the normalizer *algorithms*) generalize; the *ruleset* has home-field
advantage on attacks it was tuned on and will show false negatives against novel
input. Treat ProtectoGW as **one layer of defense-in-depth, never the boundary.**

## 5. Operational security of the component itself

ProtectoGW processes attacker-controlled input, so the component is itself an
attack surface. Current hardening status:

| Concern | Status | Notes |
|---|---|---|
| Third-party dependencies | ✅ **none** (pure stdlib) | Keep it this way; guard in CI. |
| Harness coupling | ✅ none | `protectogw/` imports nothing from the AgenticGoat harness. |
| `screen()` thread-safety | ✅ pure / stateless | No shared mutable state; safe for concurrent callers. |
| `Session` thread-safety | ⚠️ **not thread-safe** | Holds per-session accumulated state; use one `Session` per logical session, do not share across threads. |
| **Input size cap** | ✅ **enforced in-library** | `screen()`, `detect_indicators()`, and `Session.observe()` truncate input to `MAX_INPUT_CHARS` (100k, in `_limits.py`) before any work. Override per call: `screen(text, max_chars=...)`. Bounds canary coverage to the first `max_chars` — raise it (or chunk) when screening large outputs. |
| **ReDoS review** | ✅ **done (2026-07-10)** | No exponential/ambiguous-nested-quantifier patterns. Two O(n²) hotspots found and fixed: `_MORSE_RUN` (unbounded `[.-]+` under `finditer` on a long dot-run — took ~106s on 100k dots; now length-bounded `{1,6}`) and `sql_injection`'s unbounded `[\s\S]*?` gaps (now `{0,400}?`). Regression-guarded by `test_screen_is_not_redos_prone` with a per-input time budget. |
| **Decode amplification cap** | ✅ **bounded by construction** | Each decode/transform fold appends at most `len(input)` chars; with input capped, the de-obfuscated corpus is a small constant multiple of `max_chars`. `normalize()` additionally self-caps at `12 × MAX_INPUT_CHARS`. |
| Payload/canary redaction in logs | ⚠️ caller responsibility | ProtectoGW does not log. If *you* log `signals`/`reason`, never log the untrusted payload or the canary value. |

The input cap and ReDoS fixes make ProtectoGW **safe to run inline on untrusted
input** at the default `MAX_INPUT_CHARS`. A per-call timeout (Python's `re` has
no built-in one) remains a reasonable **defense-in-depth** layer for a
belt-and-suspenders deployment, but is no longer required to avoid the known
DoS vectors.

## 6. Safe-use checklist for adopters

- [ ] Screen on **both** the input and output sides; never trust input screening
      alone.
- [ ] Mint a **fresh canary per session/request**, pass it to `screen()`, and
      rotate it — never reuse a real secret as a canary.
- [ ] Input is capped in-library at `MAX_INPUT_CHARS`; **tune it** to your
      surface (`screen(text, max_chars=...)`) and add a per-call timeout only as
      belt-and-suspenders defense-in-depth.
- [ ] **Configure via `Policy`, don't fork.** Pass a `Policy` to `screen()` to
      add your own `Rule`s (`extra_rules` / `replace_rules`), tune the
      `block_threshold`, disable folds you don't trust (`disabled_folds`), bake
      in `canaries`, or turn off the exfil taxonomy. Defaults reproduce built-in
      behavior, so `screen(text)` is unchanged.
- [ ] **Roll out in monitor mode first.** Deploy with `Policy(flag_only=True)`
      so nothing is blocked — every finding is downgraded to `FLAG` and logged —
      then measure the false-positive rate against real traffic before enforcing.
      Over-blocking breaks production; observe before you block.
- [ ] **Do not log** the untrusted payload or the canary.
- [ ] Treat ProtectoGW as **one layer.** Pair it with egress control, tool
      sandboxing, and content hash-pinning.
- [ ] Re-measure generalization against **your** threat corpus; the ~75% figure
      is against AgenticGoat's held-out set, not yours.

## 7. Reporting a security issue

<!-- TODO: fill in for the public release -->
- Preferred contact: _<security contact / email>_
- Please include a minimal reproducing input and the observed vs expected
  verdict. Do **not** open a public issue for a bypass that affects real
  deployments; use the private contact above.

## 8. Versioning & guarantees

The public API is **frozen at v1.0.0** and follows
[semver](https://semver.org). The supported surface is exactly the names in
`protectogw.__all__` — `screen`, `Policy`, `Rule`, `FOLD_NAMES`, `Verdict`,
`Signal`, `Screen`, `normalize`, `detect_indicators`, `auto_score`, `Session`,
`SessionResult`, `MAX_INPUT_CHARS`, `__version__` — plus the documented verdict
semantics. A breaking change to any of them, or to what a given input scores,
bumps the **major** version. New rules, folds, or optional `Policy` fields that
don't change existing verdicts are **minor** bumps.

The package is `protectogw` (see `pyproject.toml`); the version is single-sourced
from `protectogw.__version__` and recorded in `CHANGELOG.md`. It remains a
**reference implementation** — a stable API is a promise about *shape*, not a
claim that the ruleset is complete (see §4). Re-run your own conformance corpus
after any upgrade.
