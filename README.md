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
demos/      Self-contained labs (LLM01-10, ASI01-10, AGX01-09, HX01-20), each a portable skill
tests/      Core tests
spikes/     Prototypes: IAC console (iac-prototype), early platform UX, legacy skills
assets/     Logos and images
scripts/    Project automation: vendor.py (copies shared modules into the labs), sarif_all.py, sweep_report.py, scorecard.py (per-lab compromised and defeated counts), issue seeding
hactu8.yaml Model router tiers and classifier settings
```

The labs share one fictional world: Big Field Jumpers Co., a family sheep farm and knitwear business, whose agentic assistant Lamb is the target and whose operations lead is Barb Fell, with the Wolf as the attacker, after Aesop's "The Wolf and the Lamb" (see [docs/persona.md](docs/persona.md)).

The AI attacker, the Wolf, runs with `python -m hactu8 wolf` (see [docs/wolf.md](docs/wolf.md)). The runner is also an MCP server (see [docs/mcp.md](docs/mcp.md)).

## Quick start

Python 3.10 or later. No dependencies; every skill runs on a deterministic offline model by default.

```bash
git clone -b phase1-mvp https://github.com/OWASP/www-project-hactu8.git
cd www-project-hactu8
python3 -m hactu8 list           # 49 skills mapped to the OWASP 2026 lists
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

[`hactu8.yaml`](hactu8.yaml) defines router tiers: deterministic (echo), then local (Ollama, llama.cpp, any OpenAI-compatible server such as LM Studio or vLLM via `openai-compat`, and the MoE engines Strata and Basalt via `strata` and `basalt`, listed but commented out in `hactu8.yaml` since they share port 8080 with llama.cpp), then cloud (Anthropic, OpenAI, OpenRouter). Each role starts at a tier: `target` (the model inside the lab) and `judge` (the model that scores answers). If a model is unavailable or fails, the router escalates to the next one, but automatic escalation stops at `max_tier` (local). Cloud sends lab prompts and payloads off the machine, so it is opt-in. Keys come from the environment only (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `OPENROUTER_API_KEY`).

```bash
python -m hactu8 router                          # tiers, availability, what each role resolves to
python -m hactu8 run llm01 --tier local          # model under test from the local tier
python -m hactu8 run llm01 --backend ollama --model llama3.2:3b
python -m hactu8 run llm01 --classifier llm-judge
```

For which local engine fits which hardware, the port clash between llama.cpp, Strata and Basalt (all on 8080 by default), and MoE models that fit a 16 GB Mac, see [docs/local-engines.md](docs/local-engines.md). A backend this host's hardware cannot run (Basalt needs an NVIDIA Blackwell GPU, Strata Apple Silicon or an NVIDIA GPU) is greyed out in the consoles and refused by the CLI, router and API with the reason; `HACTU8_FORCE_BACKENDS` skips the check.

Classifiers score each item GREEN, YELLOW or RED with a confidence. An item whose model call failed (for example an HTTP 500 from the model server) is recorded as ERROR: it is not a grade, counts in neither the red count nor the total, and classifiers never see it. `keyword` (default, offline) records the lab's own verdict. `llm-judge` asks the judge model to score the item's evidence, which is what the model under test produced. It falls back to the lab verdict at confidence 0.5 when no judge answers. When the judge's role can reach a paid cloud backend (its tier, or escalation up to `router.max_tier`, with that backend's key set), `run`, the API and the MCP server refuse it without `--confirm-spend` (`confirm_spend`). A routed run that would escalate the model under test to a paid backend stops instead, unless `--confirm-spend` is given, and so does `hactu8 bench --classifier-backend` with a cloud backend. A judge (`llm-judge` or `jev`) may confirm or raise the lab's verdict but never lowers a lab RED: a lab grades RED only on its canary or a declared deterministic oracle, so that RED stands whatever the judge says. `jev` is an optional TypeSafe System One classifier: it is off unless `classifiers.jev.enabled` is set (or `HACTU8_ENABLE_JEV=1`), and it needs `TYPESAFE_API_KEY` (`JEV_API_KEY` remains a compatibility alias).

Shared lab code (`providers.py`, `protectogw/`) has one canonical copy in `hactu8/`. Run `python scripts/vendor.py` after editing it, and the tests check that every lab copy matches.

Results follow [`hactu8/schemas/result.schema.json`](hactu8/schemas/result.schema.json). Run the tests with `python -m unittest discover -s tests -t .`.

Each lab also runs on its own; see [demos/README.md](demos/README.md).

## HACTU8 Lamb

Lamb is the loopback-only sacrificial target. It exposes one public gateway, starts the 49 lab servers as isolated workers when first requested, and includes an intentionally vulnerable MCP target for tool-description poisoning and rug-pull tests.

```bash
.venv/bin/python -m pip install -e '.[lamb]'     # the virtual environment from above
.venv/bin/python -m hactu8.lamb
curl http://127.0.0.1:5500/api/labs
```

Lab consoles and APIs are under `http://127.0.0.1:5500/labs/<skill-id>/`; the Streamable HTTP MCP endpoint is `http://127.0.0.1:5500/mcp`. `POST /api/reset` (with `Content-Type: application/json`) restores running labs and the MCP target to baseline. Lamb's control calls (`/api/reset`, `/api/lamb/mode`, `/api/lamb/swap`) refuse any other content type (415) and a non-loopback `Origin` (403), so a web page cannot fire them cross-site.

## API, console, and reports

The optional FastAPI service exposes skills, targets, runs, stored results, branding, and Markdown/HTML/SARIF report downloads. The trimmed React console uses those live endpoints for the complete Run to Results to Reports workflow.

```bash
.venv/bin/python -m pip install -e '.[api]'
.venv/bin/python -m hactu8.api

# In a second terminal:
cd spikes/iac-prototype/iac-host
npm ci
npm run dev
```

The API serves HTTPS on `https://127.0.0.1:8000` (`HACTU8_API_PORT` changes the port; Lamb uses `HACTU8_LAMB_PORT`) and answers only a loopback `Host` with that port (421 otherwise, against DNS rebinding); the console defaults to that URL and can be pointed elsewhere with `VITE_HACTU8_API_URL`. On first start the API makes a self-signed certificate for `localhost`, `127.0.0.1` and `::1` in `~/.hactu8/tls` and the Vite dev server reuses it, so start the API first (or run `python -m hactu8.tls`). Your browser warns until you trust that certificate; `HACTU8_TLS_CERT` and `HACTU8_TLS_KEY` bring your own, and `HACTU8_TLS=off` serves plain HTTP. See [docs/deploy.md](docs/deploy.md#https). FastAPI's `/docs` are off (`HACTU8_API_DOCS=on` turns them on), and every run request is recorded in `$HACTU8_HOME/audit.log` ([docs/deploy.md](docs/deploy.md#audit-log)). White-label name, tagline, report title, and colors are configured in [`branding.yaml`](branding.yaml).

## Docker, devcontainer, and CI

`docker compose up --build -d` serves the API and console on `https://127.0.0.1:8000` (loopback only), with Ollama on the host and keys from an env file outside the repo. The container binds `0.0.0.0`, so the API asks for a token: open the login URL it prints once (`docker compose logs hactu8 | grep token=`). A loopback `python -m hactu8.api` needs none. See [docs/deploy.md](docs/deploy.md) for the devcontainer, the CI workflow, and the macOS certificate note.

## Safety

Every target is insecure by design and binds to `127.0.0.1`. Use only against systems you are authorized to test. Shipped payloads are benign-effect: realistic wording whose only possible effect is emitting a fictional canary or calling a simulated tool on loopback.

API keys come from the environment only and ride only in request headers. Provider calls never follow redirects, and any `*_API_KEY` value (or other credential a request carried) that a server echoes back is replaced with `[REDACTED]` in errors, judge reasons, stored results and reports.

## Contributing

Pick an open issue under milestone [P1:M3 Running Demo](https://github.com/OWASP/www-project-hactu8/milestone/3) and open a pull request against `phase1-mvp`.

## License

MIT, as declared in each lab's `SKILL.md`. The root license file is still to be added.
