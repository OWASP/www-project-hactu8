# AgenticGoat to HACTU8 merge plan

Goal: the HACTU8 labs run their attack and defense against real models (local and subscription), using what AgenticGoat already proved works, and the Phase 1 MVP is complete for the 2026-12-11 demo. AgenticGoat is retired as a name; the target is HACTU8 Lamb, the attacker side is the Wolf, and the fictional company Billy, Goat & Co. stays.

Status: approved 2026-11-20, all decisions on the recommended option. Executed by a self-paced loop. Work items are tracked here (AG-xx) and ticked as they land.

## Findings

What phase1-mvp already has:

- Providers: `hactu8/providers.py` is a superset of AgenticGoat's (adds anthropic, openai, call and token caps, embeddings, Ollama 404 message, the `_urlopen` recursion fix). All 27 vendored copies match.
- ProtectoGW: `hactu8/protectogw/` is code-identical to AgenticGoat's v1.0.0. Only the Apache-2.0 LICENSE is missing.
- CLI path: `run_demo.py --backend X --model Y` already reaches every lab with all six backends. `python -m hactu8 run all` passes 25 of 25 on echo.
- Lamb gateway, a small vulnerable MCP target (3 tools), API, reports, and the trimmed React console.

What phase1-mvp lacks (all from AgenticGoat):

- Live OFF vs ON grading: the same model output graded with the screen removed and active, against a per-run canary, with the `_complied` oracle (including the refusal-that-quotes fix, 309e13f).
- The ProtectoGW gateway MCP server: screening proxy, bearer and scope auth, TLS 1.2 floor, stateless mode.
- The full poisoned MCP surface set: about 93 `ATTACK_MANIFEST` entries over 23 surface types, versus 3 tools today.
- The detector regression corpus (17 acts, engine, detector, wild, scenario) that measures ProtectoGW coverage and held-out generalization.
- The canary vault (`secrets_vault.py`) and the key-leak assertion on model output.
- The exfil receiver (wolf den), the live scoreboard, the LLM Top 10 curriculum and lessons, and sweep evidence.
- Labs ASI05 (Sink), AGX07 (Frontmatter Poison), AGX08 (Cross-Resource Chain), AGX09 (Generalization Probe).
- Real models from the UI: Lamb workers default to echo, the lab console omits anthropic and openai, and `Console.tsx` hard-codes `backend: 'echo'` with no model picker and no vulnerable vs hardened view.

Conflicts to resolve:

- MCP library: AgenticGoat uses the standalone fastmcp 3.x; phase1-mvp's code already uses the official `mcp` v2 SDK (`MCPServer`, `custom_route`, `streamable_http_app`). These three APIs are not compatible. Decision: use `mcp` v2 only. AgenticGoat's server code (vulnerable server, gateway, harness client) is rewritten onto v2; fastmcp and v1 are not supported.
- Payloads: AgenticGoat ships real injection phrasing; phase1-mvp's rule is inert placeholders. See decision D1.
- LLM Top 10 numbering differs between the repos. See decision D3.
- Dependencies: core stays stdlib-only. fastmcp, streamlit and pandas are not carried over.

Not carried over: the Streamlit `app.py` (its views move into the React console), `docker-compose.yml` (binds 0.0.0.0), `HANDOFF.md`, AgenticGoat's pyproject URLs, and the duplicate `providers.py` (phase1-mvp's is newer).

Current health issues on this machine: `tests/test_lamb.py` errors because mcp 1.27 is installed and the extra pins `mcp>=2`. `WorkerTest` sometimes times out at 5 s on a cold start. `CLAUDE.md` still says "Next is M3" though M3 and M4 are done.

## Decisions (approved 2026-11-20)

- D1, payload policy. Real models rarely breach on inert placeholders, so OFF vs ON numbers would read as zero. Recommended: allow benign-effect payloads, real injection phrasing whose only possible effect is emitting the per-run canary or calling a Lamb tool on 127.0.0.1, never an exploit for a real system. This needs a one-line change to the CLAUDE.md safety rule.
- D2, branching. Recommended: one working branch `phase1-agx-merge` off `phase1-mvp`, one commit per AG item, merged to `phase1-mvp` per workstream after review. No push or PR without approval.
- D3, LLM Top 10 numbering. AgenticGoat matches the 2025 list (LLM05 Improper Output Handling, LLM06 Excessive Agency, LLM07 System Prompt Leakage). phase1-mvp uses a different order (LLM03 Excessive Agency, LLM05 Poisoning, LLM10 Output Handling). Approved: confirm the official current OWASP LLM Top 10 list first (AG-03), make it canonical, and remap whichever side differs.
- D5, scope by the 2026-12-11 demo. Recommended: by the demo, the catalog and coverage matrix (AG-90 to AG-92) are complete, every OWASP LLM and Agentic Top 10 item has a working lab, and AG-93 has added as many labs beyond those as time allows. After the demo, the loop keeps working down the AG-93 priority list.
- D4, outward actions during the loop: wiki ticks, `notify-chat.sh` posts, GitHub issues, pushes. Recommended: the loop prepares them locally and asks before sending.

## MVP1 deployed means

- Install: one command brings up the whole stack: `docker compose up`, Codespaces, or `pip install -e '.[all]'` followed by `hactu8 up`. The stack is the API, the console, Lamb and the gateway.
- Bindings: Lamb and the gateway bind to 127.0.0.1 inside the stack. The console and API are published to the host on loopback only. No internet-facing deployment, because Lamb is vulnerable by design.
- Real models: the stack works with host Ollama out of the box, and with OpenRouter or provider keys from the environment.
- Gates:
  - CI runs the deterministic suite to SARIF on every push.
  - A fresh clone passes on macOS, Linux and Codespaces.
  - The demo script runs end to end on a local model, with a recorded fallback.
- Approved mockup: <https://claude.ai/artifact/7mW3rhE5k7iWDgPGpzS4Dy> (Learn and Run pages). AG-42 and the Learn page are built to it, using the existing iac-host theme (`--iac-*` tokens and the `.page`, `.panel`, `.metric`, `.signal`, `.primary-button` classes in `iac-host/src/index.css`). No new design system.

## Accuracy principle

Two different standards apply.

- The defenses being taught (ProtectoGW rules, lab hardening, the model plane) may miss attacks and block safe text. That is realistic, and the labs show it openly: misses and false blocks are reported, explained in the lessons, and never hidden or tuned away on the held-out set.
- HACTU8 itself must not be wrong. The ground truth, the oracles that decide BREACH or DEFENDED, the classifiers' bookkeeping, the bench, the result schema, reports and tests must give the correct answer every time. Every oracle gets tests for both directions (a real breach is graded BREACH, and a safe answer, including a refusal that quotes the attack, is graded SAFE). Tests are deterministic, with no flaky timing.

## Console principles

HACTU8 is both a tool people use and a training harness for AI security. The console stays small. Every attack and defense is reachable from it, and each one comes with the lesson that explains it. AgenticGoat's dashboard views are not copied over one for one.

Pages (from six today to six, with Learn added and Dashboard merged into Results):

- Learn: the catalog of techniques, with a filter by list (OWASP LLM, Agentic, MCP, ATLAS), learning path and coverage status. Each technique page opens with the lesson and has a "Run this lab" button.
- Run: pick a lab and a model, then run attack → defense in one view (AG-42).
- Results: stored runs, compared by model, with the two scores (model resistance, app exposure).
- Reports: Markdown, HTML and SARIF.
- Registry: targets, including Lamb and its MCP endpoints.
- Settings: backends, keys present (never shown), router tiers, spend caps.

Kept out of the console (CLI and reports only): ProtectoGW bench health, generalization trends, the field map, raw sweeps. AgenticGoat's Health, Progress, Field Map and Live views are folded in or dropped; their data lives in reports.

## Workstreams

Order: W0, W1, W2 and W3 run first (they unblock everything). W4 and W5 can run in parallel after W3. W6 to W8 follow.

### W0: Baseline

- [x] AG-01 Create branch `phase1-agx-merge`; set up a venv with `.[lamb,api,dev]` so `mcp>=2` is installed.
- [x] AG-02 Make `python -m unittest discover -s tests -t .` green on the `mcp` v2 SDK. The pin stays `mcp>=2,<3`. Code imports the SDK through one module, `hactu8/lamb/_mcp.py`, so a later SDK change touches one file. When v1 is installed, Lamb exits with a clear upgrade message and the SDK tests skip with the same reason instead of erroring. No v1 fallback: `FastMCP` and `MCPServer` differ in their APIs. Make the worker startup wait configurable (default 15 s).
- [x] AG-03 Update CLAUDE.md status (M3 and M4 done, merge in progress) and the safety rule per D1.

### W1: ProtectoGW, one canonical home

- [x] AG-10 Add `hactu8/protectogw/LICENSE` (Apache-2.0), update its README, CHANGELOG and SECURITY (resolve the TODO at `SECURITY.md:148`); vendor to labs.
- [x] AG-11 Port the detector corpus (acts, engine, detector, wild, scenario) as `hactu8/bench/` (`python -m hactu8 bench`; 82 scored items, 33 control items handed to AG-21) with stdlib-only tests, so coverage and held-out generalization are measured on every change. Rename goat terms.
- [x] AG-12 Port `secrets_vault.py` (per-run canary, `assert_not_leaking`) into `hactu8/` and wire it into `providers.py` and the vendored copies.
- [x] AG-13 Enhancements, each scored on the bench. Done: tool-definition pinning (rug pull) and shadowing (`pinning.py`), an optional model plane (`Policy.classifier`), compound and multilingual rules tuned on an independent training set. Generalization on an independent held-out set rose from 13% (1.0) to 53%, with 0 false positives. The original 75% figure is retired: it came from a held-out set that was mostly encodings of one phrase. Moved to AG-43, because they need live run data: closing the 4 residual live breaches, cutting live false blocks, and measuring the model plane on Ollama.
- [x] AG-14 Release ProtectoGW 2.0.0 (major per its SECURITY.md §8, since verdicts changed; no API names removed), run `scripts/vendor.py`, and check the copies match.

### W2: Lamb MCP surface and gateway

- [x] AG-20 Expand `hactu8/lamb/mcp_target.py` with AgenticGoat's poisoned surfaces (tools, resources, prompts, RAG, A2A, output), with an `ATTACK_MANIFEST` ground truth and clean controls, on the `mcp` SDK. Payloads per D1.
- [x] AG-21 Port `gateway_mcp.py` as `hactu8/lamb/gateway.py` on the MCP v2 low-level server: ProtectoGW screening of tool definitions (description and schema), results (including error and structured content), resources and prompts; stateful Session; tool pinning (trust on first use or a pins file) and shadowing; optional bearer auth with scopes and a TLS 1.2+ floor when run standalone. Mounted in Lamb at `/protected/mcp` (not `/mcp-protected`: Starlette mounts need a sub-path). The bench's 33 control items: the rug pull is enforced by pinning here; agency, grounding, retrieval scope and consumption are app-layer controls already shown by the LLM03, LLM07, LLM09 and LLM06 labs (2026 numbering). Known, documented gateway miss: the OKF runbook split across two concepts.
- [x] AG-22 Port the exfil receiver as Lamb's wolf den (`/wolf`, loopback only): it records what an attacker captured, and `POST /api/reset` clears it.
- [ ] AG-23 Port the tests (`test_gateway_mcp`, `test_gateway_tls` without the TLS 1.1 warning, `test_exfil_receiver`) into `tests/`.

### W3: Live OFF vs ON grading

- [ ] AG-30 Port `live_harness` and the `_complied` oracle (with the 309e13f fix) into `hactu8/live.py`. It feeds a model the Lamb surfaces and grades the same output with the screen off and on, against the canary.
- [ ] AG-31 Add a CLI command, `python -m hactu8 live --backend X --model Y [--surfaces ...]`, and a compare mode for lab runs. Echo stays deterministic and offline.
- [ ] AG-32 Extend `hactu8.result/v1` compatibly: optional per-item `off`/`on` verdicts, canary leaked, false blocks, model provenance. Update the schema and tests together.
- [ ] AG-33 Port the live scoreboard into `store.py` and `reports.py` (leaderboard by model, breaches off vs on), plus Markdown, HTML and SARIF output.

### W4: Real models from end to end

- [ ] AG-40 Lamb workers take backend and model per request or run (not only from the environment); the lab console offers all six backends; key presence is shown, never the key.
- [ ] AG-41 API: `GET /api/models` (router tiers, availability, the provider catalog), and `POST /api/runs` accepts `model`, `classifier` and `compare`.
- [ ] AG-42 Console Run page: a model picker (backend, model, availability) and an attack → defense run. The result shows four things in one view: the model's output, off vs on, what the Wolf captured, and the protections added. No separate wolf-den, scoreboard or live pages.
- [ ] AG-44 Generic local backend `openai-compat` (base URL plus optional key, set by `LOCAL_OPENAI_BASE_URL`). One adapter covers LM Studio, vLLM, LocalAI, Jan, llamafile and `mlx_lm.server`; Ollama and llama.cpp keep their dedicated backends. Loopback URLs only, unless overridden on purpose. Model catalog comes from `/v1/models`. Vendor to the labs and add it to the router's local tier.
- [ ] AG-43 Model test ladder. Each stage passes before the next starts, and results go to `docs/evidence/` with full provenance: model, digest or version, quantization, host, date, single or repeated samples. AgenticGoat's three sweep files come over as historical evidence.
  - Stage 1, local and free: Ollama (`llama3.2:3b` first, then the small-model set from AgenticGoat's sweep), then llama.cpp, then one `openai-compat` runner. Run every lab, the live harness and the ProtectoGW bench. Most bugs get fixed here.
  - Stage 2, aggregator: OpenRouter with a spend-capped key, using cheap models first, then one frontier-class model. Opt-in only (lab text leaves the machine). The router keeps `max_tier=local` unless the run asks for more.
  - Reporting across stages: every result is split into two scores. Model resistance is how often the model refuses on its own. App exposure is whether the harm still lands through tools, agency, output handling or payments when the model complies or is never asked. The expected pattern is that model resistance rises with price while app exposure stays until the lab's own defense is on. The ladder measures that pattern rather than assuming it.
  - Stage 3, provider APIs: Anthropic and OpenAI direct, with keys from the environment only. Before any paid run, the CLI prints a cost estimate per run and requires `--confirm-spend`, and `LAB_MAX_CALLS` and `LAB_MAX_TOKENS` apply.

### W5: Labs

- [ ] AG-50 ASI05 Sink Lab on the template (closes the 25 to 26 gap; ASI01-10 complete).
- [ ] AG-51 AGX07 Frontmatter Poison, AGX08 Cross-Resource Chain, and AGX09 Generalization Probe (the honest held-out control that stays BREACH, then BREACH), as template labs that use the gateway.
- [ ] AG-52 Port `protections.py` as the Act 4 "Protections added" explanation in each lab's output and console (compatible with the adapter format).
- [ ] AG-53 Check that ASI06 matches AgenticGoat's Poison Lab result (PSR 0, then 100, then 0); port the missing parts.

### W6: Training layer

- [ ] AG-60 Lesson format: each lab gets `<skill>/LESSON.md` with fixed sections. It stays inside the lab, so the lab remains self-contained and copyable.
  - What it is.
  - Why it works.
  - Try it: the lab, with what to watch for in each act.
  - The defense, and why it holds.
  - Where the defense stops working.
  - Check yourself: 2 or 3 questions.
  - References, with catalog IDs.

  The adapter and API serve it. The format is documented in `demos/_template/TEMPLATE.md`, and a test checks every lab has a complete lesson.
- [ ] AG-62 Write or port the lessons for every lab. AgenticGoat's LLM01-10 lessons and curriculum are merged into the matching labs (numbering per D3). The existing SKILL.md, README and references are reused rather than duplicated.
- [ ] AG-63 Learning path: an ordered track, starting with the basics (direct injection, output handling), then agentic attacks (tools, MCP, memory, A2A), then commerce and the scoring layer. It is a field in the catalog, not a separate system.
- [ ] AG-61 Port the OKF bundle as Lamb RAG content, if AG-20 needs it.

### W7: Naming

- [ ] AG-70 Rename AgenticGoat to Lamb across about 206 files (READMEs, SKILL.md, references, `vulnerable_app.py`, `providers.py` and ProtectoGW docs, `lambSeed.ts` tags, `seed-issues.sh`). Keep Billy, Goat & Co., goatco, and the persona names.
- [ ] AG-71 Retire `demos/agenticgoat-mock` (superseded by Lamb) or rename it `lamb-mock`. Add a check that fails on new "AgenticGoat" text outside history notes.

### W8: Verification and the rest of the MVP

- [ ] AG-80 Full check: unit tests, `run all` on echo, the ProtectoGW bench, the Playwright e2e console tests, and a Claude in Chrome walkthrough of Run, Results, Reports, model picker and OFF vs ON. Run markdownlint.
- [ ] AG-81 M5: H-50 Dockerfile and compose (loopback binds, Ollama on the host), H-51 devcontainer, H-52 GitHub Action for the deterministic suite to SARIF, H-53 AI attacker skill against Lamb (the Wolf), H-54 HACTU8 MCP server exposing the runner.
- [ ] AG-82 M6: H-60 fresh-clone test, H-61 demo script and recorded fallback, H-62 Project Status and OWASP page updates (the `main` branch changes only with approval).

### W9: Beyond the OWASP Top 10, a catalog of known attacks and defenses

The target is every known attack and defense, not only the two OWASP Top 10 lists. "Every known" never stops growing, so it is built as a catalog with coverage tracking, and labs are added in priority order.

- [ ] AG-90 Build the catalog: `hactu8/catalog/techniques.yaml` lists each attack technique with its ID across the main lists (OWASP LLM Top 10, OWASP Agentic Top 10, OWASP MCP Top 10, MITRE ATLAS, NIST AI 100-2 adversarial ML taxonomy), its defenses, and the lab(s) that demonstrate it. Add a schema and tests.
- [ ] AG-91 Coverage: `python -m hactu8 coverage`, and a status column and filter on the console's Learn page (attack and defense, attack only, no lab yet). Lab results feed it. No separate page.
- [ ] AG-92 Defense catalog: each defense (ProtectoGW rule, gateway control, lab hardening, architectural control) is linked to the techniques it covers and to bench evidence that it works, which shows where defenses are missing.
- [ ] AG-93 Labs for missing techniques, in priority order. Examples:
  - jailbreak families: multi-turn, many-shot, role-play, encoding;
  - indirect injection through images and documents;
  - MCP sampling and elicitation abuse;
  - OAuth confused-deputy;
  - memory poisoning across sessions;
  - agent-to-agent impersonation;
  - model and prompt extraction;
  - membership inference;
  - embedding inversion;
  - denial of wallet;
  - package hallucination (slopsquatting).

  Each gets a template lab plus a defense, and a ProtectoGW bench case where one applies.
- [ ] AG-95 Attacks on the scoring layer. The judges and classifiers HACTU8 uses (llm-judge, the JEV / TypeSafe System One classifier, and ProtectoGW itself) are targets too. Covered attacks:
  - prompt injection aimed at the judge, hidden inside the evidence it scores;
  - verdict manipulation;
  - inputs crafted to dodge the classifier;
  - flooding with false positives.

  The defense is that every score records which classifier produced it, and the classifiers check each other's verdicts. The JEV lab runs only when its key is set and is skipped offline.
- [ ] AG-96 Agentic commerce attacks: HTTP 402 / x402 pay-per-request and agent payment protocols, against a Lamb merchant and wallet on loopback that use only test values. Covered attacks:
  - price or recipient changes in the 402 challenge;
  - replaying or reusing a payment proof;
  - an injected instruction that makes the agent overpay;
  - denial of wallet through repeated 402 loops;
  - a fake merchant or facilitator;
  - a mandate or spending-limit bypass.

  Defenses:
  - spending caps and allowlists;
  - signed challenge checks;
  - an idempotency key per payment;
  - ProtectoGW screening of the payment metadata.
- [ ] AG-97 Keep the catalog open to new attack families. A new family needs only a catalog entry, a lab from the template, and a bench case. Document this in `demos/_template/TEMPLATE.md`.
- [ ] AG-94 Classic ML attacks (adversarial examples, model training-time poisoning, model stealing) are tracked in the catalog. Labs for them need a non-LLM target and are scoped after the MVP.

## Done means

Per item: unit tests pass, `run all` passes on echo, the bench does not regress, markdownlint passes, and every lab copy matches the canonical modules. Per workstream: a short summary and a review stop before merging to `phase1-mvp`.

## User actions outside the loop

- Rotate the OpenRouter key that AgenticGoat's HANDOFF notes was exposed; give the loop a new spend-capped key in the shell environment only.
- Have Ollama running with `llama3.2:3b` pulled.
- Reconnect the MCP_DOCKER server if Playwright MCP is wanted.

## Pending outward actions

Prepared by the loop, not sent. Each needs approval.

- None yet.

## Notes for review

- D3 resolution: the phase1 labs already follow the 2026 edition order (LLM03 Excessive Agency, LLM05 Data and Model Poisoning, LLM08 Hidden Context Exposure, LLM10 Improper Output Handling), confirmed by several secondary sources, including a Cloud Security Alliance post of 2026-10-21. The OWASP GenAI site page fetched on 2026-11-20 still shows the 2025 list. 2026 is canonical; the catalog (AG-90) records both IDs, and AgenticGoat's 2025 crosswalk is remapped on import.

## Blocked on user actions

- Ollama is not installed on this machine (no `ollama`, nothing on port 11434). Needed for the model-plane measurement in AG-13 and for stage 1 of AG-43. Install Ollama and run `ollama pull llama3.2:3b`.
