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
hactu8/     Core: skill catalog, runner, lab adapter, classifier interface, result schema, CLI
demos/      Self-contained OWASP labs (LLM01-10, ASI01-10, AGX01-06), each a portable skill
tests/      Core tests
spikes/     Prototypes: IAC console (iac-prototype), early platform UX, legacy skills
assets/     Logos and images
scripts/    Project automation (issue seeding)
```

Coming in Phase 1: model router, API, console, reports, `lamb/` (the sacrificial target), and container files.

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

Real models are optional: `--backend ollama --model llama3.2:3b`, or `--backend openrouter` with `OPENROUTER_API_KEY`. With a real model the numbers are reported, not asserted. Install as a command with `pip install -e .`, then use `hactu8` directly.

Results follow [`hactu8/schemas/result.schema.json`](hactu8/schemas/result.schema.json). Run the tests with `python -m unittest discover -s tests -t .`.

Each lab also runs on its own; see [demos/README.md](demos/README.md).

## Safety

Every target is insecure by design and binds to `127.0.0.1`. Use only against systems you are authorized to test. Shipped payloads are inert placeholders.

## Contributing

Pick an open issue under milestone [P1:M3 Running Demo](https://github.com/OWASP/www-project-hactu8/milestone/3) and open a pull request against `phase1-mvp`.

## License

MIT, as declared in each lab's `SKILL.md`. The root license file is still to be added.
