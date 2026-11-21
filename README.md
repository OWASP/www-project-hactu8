# OWASP HACTU8

HACTU8 turns attacks on AI systems into repeatable assurance tests: run a skill against a target, measure the impact, apply the mitigation, and prove the fix with the same suite. It is an [OWASP Incubator project](https://owasp.org/www-project-hactu8/).

This `phase1-mvp` branch holds the Phase 1 build. The `main` branch is the OWASP project website.

## Status

Phase 1 MVP, demo on 2026-12-11. See the wiki:

- [Phase 1 MVP Plan](https://github.com/OWASP/www-project-hactu8/wiki/Phase-1-MVP-Plan)
- [Roadmap](https://github.com/OWASP/www-project-hactu8/wiki/Roadmap)
- [Decision Log](https://github.com/OWASP/www-project-hactu8/wiki/Decision-Log)
- [Market Comparables](https://github.com/OWASP/www-project-hactu8/wiki/Market-Comparables)

## Layout

```text
hactu8/     Core: catalog, runner, classifiers, router, providers, API, reports, Lamb, result schema, CLI
demos/      Self-contained labs (LLM01-10, ASI01-10, AGX01-09, HX01-10, HX12-13), each a portable skill
tests/      Core tests
spikes/     Prototypes: IAC console (iac-prototype), early platform UX, legacy skills
assets/     Logos and images
scripts/    Project automation: issue seeding, vendor.py (copies shared modules into the labs)
hactu8.yaml Model router tiers and classifier settings
```

Coming in Phase 1: the AI attacker skill.

## Quick start

Python 3.10 or later. No dependencies; every skill runs on a deterministic offline model by default.

```bash
git clone -b phase1-mvp https://github.com/OWASP/www-project-hactu8.git
cd www-project-hactu8
python3 -m hactu8 list           # 41 skills mapped to the OWASP 2026 lists
python3 -m hactu8 run llm01      # baseline -> attack -> impact -> remediation
python3 -m hactu8 run all        # every skill
python3 -m hactu8 coverage       # known attack techniques: attack and defense, attack only, no lab yet
python3 -m hactu8 defenses       # each defense, what it covers, and bench and lab evidence that it works
python3 -m hactu8 results        # stored runs (.hactu8/results)
python3 -m hactu8 show latest    # full hactu8.result/v1 JSON
```

Real models are optional. With a real model the numbers are reported, not asserted. For the API, console and Lamb, install into a virtual environment (Homebrew's Python refuses global installs):

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[lamb,api]'   # then use .venv/bin/python, or activate it
```

The examples below write `python`; on macOS that is `python3` or the venv's `python`. With the python.org installer on macOS, cloud backends need `SSL_CERT_FILE=/etc/ssl/cert.pem` (see [docs/deploy.md](docs/deploy.md)).

## Models and scoring

[`hactu8.yaml`](hactu8.yaml) defines router tiers: deterministic (echo), then local (Ollama, llama.cpp, or any OpenAI-compatible server such as LM Studio or vLLM via `openai-compat`), then cloud (Anthropic, OpenAI, OpenRouter). Each role starts at a tier: `target` (the model inside the lab) and `judge` (the model that scores answers). If a model is unavailable or fails, the router escalates to the next one, but automatic escalation stops at `max_tier` (local). Cloud sends lab prompts and payloads off the machine, so it is opt-in. Keys come from the environment only (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `OPENROUTER_API_KEY`).

```bash
python -m hactu8 router                          # tiers, availability, what each role resolves to
python -m hactu8 run llm01 --tier local          # model under test from the local tier
python -m hactu8 run llm01 --backend ollama --model llama3.2:3b
python -m hactu8 run llm01 --classifier llm-judge
```

Classifiers score each item GREEN, YELLOW or RED with a confidence. `keyword` (default, offline) records the lab's own verdict. `llm-judge` asks the judge model to score the item's evidence, which is what the model under test produced. It falls back to the lab verdict at confidence 0.5 when no judge answers. `jev` is an optional TypeSafe System One classifier: it is off unless `classifiers.jev.enabled` is set (or `HACTU8_ENABLE_JEV=1`), and it needs `TYPESAFE_API_KEY` (`JEV_API_KEY` remains a compatibility alias).

Shared lab code (`providers.py`, `protectogw/`) has one canonical copy in `hactu8/`. Run `python scripts/vendor.py` after editing it, and the tests check that every lab copy matches.

Results follow [`hactu8/schemas/result.schema.json`](hactu8/schemas/result.schema.json). Run the tests with `python -m unittest discover -s tests -t .`.

Each lab also runs on its own; see [demos/README.md](demos/README.md).

## HACTU8 Lamb

Lamb is the loopback-only sacrificial target. It exposes one public gateway, starts the 41 lab servers as isolated workers when first requested, and includes an intentionally vulnerable MCP target for tool-description poisoning and rug-pull tests.

```bash
python -m pip install -e '.[lamb]'
python -m hactu8.lamb
curl http://127.0.0.1:5500/api/labs
```

Lab consoles and APIs are under `http://127.0.0.1:5500/labs/<skill-id>/`; the Streamable HTTP MCP endpoint is `http://127.0.0.1:5500/mcp`. `POST /api/reset` restores running labs and the MCP target to baseline.

## API, console, and reports

The optional FastAPI service exposes skills, targets, runs, stored results, branding, and Markdown/HTML/SARIF report downloads. The trimmed React console uses those live endpoints for the complete Run to Results to Reports workflow.

```bash
python -m pip install -e '.[api]'
python -m hactu8.api

# In a second terminal:
cd spikes/iac-prototype/iac-host
npm install
npm run dev
```

The API binds to `http://127.0.0.1:8000` (`HACTU8_API_PORT` changes the port; Lamb uses `HACTU8_LAMB_PORT`); the console defaults to that URL and can be pointed elsewhere with `VITE_HACTU8_API_URL`. White-label name, tagline, report title, and colors are configured in [`branding.yaml`](branding.yaml).

## Docker, devcontainer, and CI

`docker compose up --build -d` serves the API and console on `http://127.0.0.1:8000` (loopback only), with Ollama on the host and keys from an env file outside the repo. See [docs/deploy.md](docs/deploy.md) for the devcontainer, the CI workflow, and the macOS certificate note.

## Safety

Every target is insecure by design and binds to `127.0.0.1`. Use only against systems you are authorized to test. Shipped payloads are benign-effect: realistic wording whose only possible effect is emitting a fictional canary or calling a simulated tool on loopback.

## Contributing

Pick an open issue under milestone [P1:M3 Running Demo](https://github.com/OWASP/www-project-hactu8/milestone/3) and open a pull request against `phase1-mvp`.

## License

MIT, as declared in each lab's `SKILL.md`. The root license file is still to be added.
