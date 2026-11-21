# CLAUDE.md

Instructions for Claude Code working in this repository.

## Project

OWASP HACTU8 turns attacks on AI systems into repeatable assurance tests: baseline, attack, impact, remediation, all against the same suite. Phase 1 builds the harness around the existing labs. The demo is on 2026-12-11.

- Branch: work on `phase1-mvp`. Never commit to `main` (it is the OWASP website).
- Plan, with work items H-01 to H-62: <https://github.com/OWASP/www-project-hactu8/wiki/Phase-1-MVP-Plan>
- Roadmap (items held for review, not in the MVP): <https://github.com/OWASP/www-project-hactu8/wiki/Roadmap>
- Decisions: <https://github.com/OWASP/www-project-hactu8/wiki/Decision-Log>
- Wiki clone, when present: `../www-project-hactu8.wiki` (branch `master`)
- Issues: milestones `P1:M2: Requirements Documentation` (M0 to M1) and `P1:M3: Running Demo` (M2 to M6), labels `mvp:m0` to `mvp:m6`

## Status

- M0 to M4 done. `python -m hactu8 run all` passes 32 of 32 on the echo backend.
- In progress: the merge plan `docs/agenticgoat-merge-plan.md` (AG-xx items) on branch `phase1-agx-merge`: W0-W8 done (real models, OFF vs ON grading, ProtectoGW gateway, Lamb surfaces, labs with lessons, the Wolf, the MCP server, Docker and CI). W9: attack catalog (`hactu8/techniques.py`), coverage and defense catalog done; labs for missing techniques (HX01+) in progress.
- OWASP LLM Top 10 IDs use the 2026 edition (the order in `demos/`). The catalog also records each item's 2025 ID, since the OWASP site and older material still use 2025.

## Layout

```text
hactu8/     Core package: catalog, adapters/lab.py, classify.py, result.py, store.py, cli.py, schemas/
demos/      32 labs (LLM01-10, ASI01-10, AGX01-09, HX01-03); each <lab>/run_demo.py drives one skill dir
tests/      Core tests (python -m unittest discover -s tests -t .)
spikes/     iac-prototype (React iac-host and FastAPI copilot-api, to be trimmed in M4), legacy material
scripts/    seed-issues.sh
```

## Rules

- MCP: the official `mcp` v2 SDK only, imported through `hactu8/lamb/_mcp.py`. No fastmcp, no v1.
- Core (`hactu8/`) uses the Python standard library only, Python 3.10 or later. Optional extras go in `pyproject.toml` extras.
- Labs stay self-contained and copyable into `.claude/skills/`. No imports from `hactu8/` inside `demos/`. Shared code is vendored per lab.
- Don't break the lab output format the adapter parses (`demos/_template/TEMPLATE.md`, `hactu8/adapters/lab.py`). Extend it compatibly.
- Results follow `hactu8/schemas/result.schema.json` (`hactu8.result/v1`). Change the schema and the tests together.
- The echo backend stays the deterministic default; tests must pass offline.
- Safety: every target binds to `127.0.0.1`. Payloads are benign-effect: realistic injection wording is allowed only when its sole possible effect is emitting a per-run canary or calling a Lamb tool on loopback. Never add payloads that harm a real system, real data, or a real account.
- The sacrificial target is named HACTU8 Lamb (formerly AgenticGoat). The fictional company Billy, Goat & Co. stays in the labs.

## Accuracy

- The defenses taught in the labs may miss attacks or block safe text; report that openly. HACTU8's own grading must not be wrong: ground truth, oracles, classifiers' bookkeeping, the bench, reports and tests must be correct and deterministic. Test every oracle in both directions.

## Done means

1. `python -m unittest discover -s tests -t .` passes.
2. Every lab still passes `python -m hactu8 run all`, and its own tests if you touched it.
3. Markdown passes markdownlint.
4. The work item is ticked in the wiki plan, and Project Status is updated at milestone boundaries.
5. At a milestone boundary, post a one-line summary to the team Space: `scripts/notify-chat.sh "M2 done: ... Next: M3."` (webhook URL in `../.hactu8.env`, never in the repo).

## Documents

- Markdown follows markdownlint as used by vscode-markdownlint, with MD013 (line length) disabled: one line per paragraph.
- No emojis in documents.
- Keep docs short and role-abstracted (no personal names in planning docs).

## Commits

End commit messages with:

```text
Co-Authored-By: Claude <noreply@anthropic.com>
```
