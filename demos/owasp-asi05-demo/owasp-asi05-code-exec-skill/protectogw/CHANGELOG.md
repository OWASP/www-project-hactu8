# Changelog — protectogw

All notable changes to the **public API** (`protectogw.__all__`). This project
follows [Semantic Versioning](https://semver.org): a breaking change to any
exported name or to verdict semantics bumps the **major** version.

## 2.0.0 — 2026-11-20

Major under §8 of SECURITY.md: no exported name was removed or renamed, but verdicts
changed for some inputs (new detections, and fewer false positives from tightened
rules). Callers that pin verdicts in tests should re-baseline.

**Added to `protectogw.__all__`:**

- `ToolPins`, `fingerprint` — pin a tool's model-visible definition at approval;
  `check()` BLOCKs any later change (rug pull) and FLAGs an unapproved tool.
- `shadowing(tools_by_server)` — name collisions, look-alike names and
  cross-tool orders across MCP servers.

**Added to `Policy`:** `classifier`, `classifier_flag`, `classifier_block` — an
optional model plane, off by default, so `screen()` stays deterministic offline.

**Ruleset:** paraphrased overrides, credential handover and requests, hidden-from-
user orders, role hijack, fake role markers, tool-call redirection cues, markdown
image exfiltration, exfiltration to an address, mail forwarding hijack, indirect
secret extraction, and overrides and credential requests in ten languages. Most
new checks fire only when the order is addressed to the AI, and credential talk
is ignored when negated ("never share your password").

**Tightened (fewer false positives):** `persona_override` no longer fires on "you
are now" alone, `hidden_directive` and `urgency_pressure` need the user as the
object, `tool_redirect` ignores "call this tool", and `exfiltration` stays within
one sentence and no longer fires on a bare URL upload.

**Measured** (`python -m hactu8 bench`): independent held-out set 16/30 attacks
caught (1.0: 4/30), 0/15 false positives; training set 79/80, 0/40 false
positives; original AgenticGoat corpus unchanged at 100% with 0 false positives.

## 1.0.0 — 2026-07-10

Initial frozen public API.

**Exported surface (`protectogw.__all__`):**

- `screen(text, canaries=None, *, policy=None, max_chars=None) -> Screen` —
  the single surface-agnostic entry point.
- `Policy`, `Rule`, `FOLD_NAMES` — adopter config injection (custom rules,
  thresholds, fold toggles, canaries, monitor mode) without forking.
- `Verdict` (`ALLOW`/`FLAG`/`BLOCK`), `Signal`, `Screen` — result types.
- `normalize`, `detect_indicators`, `auto_score` — lower-level helpers.
- `Session`, `SessionResult` — stateful cross-read screening.
- `MAX_INPUT_CHARS`, `__version__`.

**Security-relevant properties baked into 1.0:**

- **Zero runtime dependencies** (pure standard library).
- **DoS-safe:** input capped at `MAX_INPUT_CHARS` before any work; normalizer
  regexes ReDoS-reviewed (two O(n²) hotspots fixed pre-1.0).
- **Attack-agnostic controls** (decisive canary check, normalizer algorithms)
  distinguished from the heuristic ruleset — see `SECURITY.md`.

**Known non-goals / limits at 1.0:** closed-set ruleset (claimed ~75% generalization on
held-out attacks; 2.0 re-measured 1.0 at 4/30 on an independent set), no semantic/translation defense, `Session` is not
thread-safe. See `SECURITY.md §4`.

**License:** Apache-2.0 (`LICENSE`), chosen 2026-10-07.

**Not yet done (tracked, does not affect API stability):** PyPI publication, async/HTTP integration adapters.
