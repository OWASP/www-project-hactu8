# Changelog — protectogw

All notable changes to the **public API** (`protectogw.__all__`). This project
follows [Semantic Versioning](https://semver.org): a breaking change to any
exported name or to verdict semantics bumps the **major** version.

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

**Known non-goals / limits at 1.0:** closed-set ruleset (~75% generalization on
held-out attacks), no semantic/translation defense, `Session` is not
thread-safe. See `SECURITY.md §4`.

**Not yet done (tracked, does not affect API stability):** license selection
(`SECURITY.md §7`), PyPI publication, async/HTTP integration adapters.
