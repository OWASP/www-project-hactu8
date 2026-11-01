# OWASP HACTU8

HACTU8 turns attacks on AI systems into repeatable assurance tests: run a skill against a target, measure the impact, apply the mitigation, and prove the fix with the same suite. It is an [OWASP Incubator project](https://owasp.org/www-project-hactu8/).

This `phase1-mvp` branch holds the Phase 1 build. The `main` branch is the OWASP project website.

## Status

Phase 1 MVP, demo on 2026-11-13. See the wiki:

- [Phase 1 MVP Plan](https://github.com/OWASP/www-project-hactu8/wiki/Phase-1-MVP-Plan)
- [Roadmap](https://github.com/OWASP/www-project-hactu8/wiki/Roadmap)
- [Decision Log](https://github.com/OWASP/www-project-hactu8/wiki/Decision-Log)
- [Market Comparables](https://github.com/OWASP/www-project-hactu8/wiki/Market-Comparables)

## Layout

```text
hactu8/     Core: skill catalog, runner, lab adapter, classifiers, model router, providers, protectogw, result schema, CLI
demos/      Self-contained OWASP labs (LLM01-10, ASI01-10, AGX01-06), each a portable skill
tests/      Core tests
spikes/     Prototypes: IAC console (iac-prototype), early platform UX, legacy skills
assets/     Logos and images
scripts/    Project automation: issue seeding, vendor.py (copies shared modules into the labs)
hactu8.yaml Model router tiers and classifier settings
```

Coming in Phase 1: API, console, reports, `lamb/` (the sacrificial target), and container files.

## Quick start

Python 3.10 or later. No dependencies; every skill runs on a deterministic offline model by default.

```bash
git clone -b phase1-mvp https://github.com/OWASP/www-project-hactu8.git
cd www-project-hactu8
python -m hactu8 list            # 25 skills mapped to the OWASP 2026 lists
python -m hactu8 run llm01       # baseline -> attack -> impact -> remediation
python -m hactu8 run all         # every skill
python -m hactu8 results         # stored runs (.hactu8/results)
python -m hactu8 show latest     # full hactu8.result/v1 JSON
```

Real models are optional. With a real model the numbers are reported, not asserted. Install as a command with `pip install -e .`, then use `hactu8` directly.

## Models and scoring

[`hactu8.yaml`](hactu8.yaml) defines router tiers: deterministic (echo), then local (Ollama, llama.cpp), then cloud (Anthropic, OpenAI, OpenRouter). Each role starts at a tier: `target` (the model inside the lab) and `judge` (the model that scores answers). If a model is unavailable or fails, the router escalates to the next one, but automatic escalation stops at `max_tier` (local). Cloud sends lab prompts and payloads off the machine, so it is opt-in. Keys come from the environment only (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `OPENROUTER_API_KEY`).

```bash
python -m hactu8 router                          # tiers, availability, what each role resolves to
python -m hactu8 run llm01 --tier local          # model under test from the local tier
python -m hactu8 run llm01 --backend ollama --model llama3.2:3b
python -m hactu8 run llm01 --classifier llm-judge
```

Classifiers score each item GREEN, YELLOW or RED with a confidence. `keyword` (default, offline) records the lab's own verdict. `llm-judge` asks the judge model to score the item's evidence, which is what the model under test produced. It falls back to the lab verdict at confidence 0.5 when no judge answers. `jev` is an optional hosted classifier: it is off unless `classifiers.jev.enabled` is set (or `HACTU8_ENABLE_JEV=1`), and it needs `JEV_API_KEY`.

Shared lab code (`providers.py`, `protectogw/`) has one canonical copy in `hactu8/`. Run `python scripts/vendor.py` after editing it, and the tests check that every lab copy matches.

Results follow [`hactu8/schemas/result.schema.json`](hactu8/schemas/result.schema.json). Run the tests with `python -m unittest discover -s tests -t .`.

Each lab also runs on its own; see [demos/README.md](demos/README.md).

## Safety

Every target is insecure by design and binds to `127.0.0.1`. Use only against systems you are authorized to test. Shipped payloads are inert placeholders.

## Contributing

Pick an open issue under milestone [P1:M3 Running Demo](https://github.com/OWASP/www-project-hactu8/milestone/3) and open a pull request against `phase1-mvp`.

## License

MIT, as declared in each lab's `SKILL.md`. The root license file is still to be added.
