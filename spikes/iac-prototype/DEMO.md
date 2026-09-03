# IAC Platform — Demo Guide

This walks through running the platform locally and demoing each feature area,
in the order they appear in the sidebar. It reflects the app as it exists
today (2026-08) — see [REDESIGN_PLAN.md](REDESIGN_PLAN.md) for what's shipped
vs. still in progress. The main `README.md` at the repo root describes an
older Streamlit micro-frontend architecture that's since been retired for
most pages (see REDESIGN_PLAN item 6) — use this doc instead for running the
current app.

## Architecture

Two services, run separately:

- **`iac-copilot-api`** — FastAPI backend (default port `8000`). Owns
  everything AI-driven: chat/RAG, Agent engagements, Skill Packages, curated
  Projects and their runs.
- **`iac-host`** — React/Vite frontend (default port `5173`). Everything else
  (Registry, Skills/Agents catalog browsing, Assurance Results, Settings) is
  browser-only, persisted to `localStorage` — there is **no backend
  persistence for Registry or Model Provider config**. That's a deliberate
  design point worth mentioning in a demo: it's why a Project run sends a
  resolved target/model snapshot to the backend rather than an ID to look up.

## Prerequisites

- Node.js 22+, npm
- Python 3.13+
- At least one real LLM API key (Anthropic or OpenAI) if you want the AI
  features — Agent engagements, Copilot chat, Project runs — to actually
  respond. Without one, every AI-driven flow still runs end-to-end and
  produces a clean, visible error instead of a response — see
  [Demoing without an API key](#demoing-without-an-api-key) below. That's a
  legitimate way to demo the plumbing (SSE streaming, error handling,
  findings/results wiring) without spending API credits.

## One-time setup

```bash
# Backend
cd iac-copilot-api
python3 -m venv ../.venv        # a venv one level up, shared with the repo root
source ../.venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt   # optional — only needed to run the pytest suite
deactivate

# Frontend
cd ../iac-host
npm install
cd ..
```

> **Note:** this repo has more than one Python virtualenv lying around from
> earlier work (`iac-copilot-api/.venv` also exists, per that folder's own
> older `README.md`). Use the one at the **repo root** (`iac-prototype/.venv`)
> — that's the one with `requirements-dev.txt` installed, which the test
> suite and this guide assume.

## Running it

**Terminal 1 — backend:**

```bash
cd iac-copilot-api
source ../.venv/bin/activate
OPENAI_API_KEY=placeholder ANTHROPIC_API_KEY=placeholder uvicorn app:app --reload --port 8000
```

> **Known gap, not fixed here:** `iac-copilot-api` never actually calls
> `load_dotenv()`, so the `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` /
> `*_MODEL_LIST` values already sitting in `iac-copilot-api/.env` are
> silently ignored — `.env` is decorative today. Worse, `RAGService.__init__`
> unconditionally constructs an OpenAI client at startup and **the whole API
> fails to boot** if `OPENAI_API_KEY` isn't a real environment variable, even
> if you only intend to use Anthropic. The `placeholder` value above is
> enough to get the server running; it only needs to be a *real* key for
> OpenAI-provider calls to actually succeed. Anthropic calls need a real
> `ANTHROPIC_API_KEY` regardless of what you set here for OpenAI.

**Terminal 2 — frontend:**

```bash
cd iac-host
npm run dev
```

Open **http://localhost:5173**. The frontend is pre-configured (via
`iac-host/.env.development`) to talk to the backend at
`http://localhost:8000` — no extra config needed if you used the default
ports above.

**First thing to do:** go to **Settings → Model Providers**, add a provider
(Anthropic or OpenAI, with a real key), and save it. Several features below
(Agent engagements, Project runs, Copilot chat) need this configured to
produce an actual model response rather than a clean error.

---

## Feature-by-feature walkthrough

### 1. Dashboard (`/`)

**Not part of this demo path** — still on the old Streamlit micro-frontend
remote (`iac_mfe_primary/StreamlitDashboard`, expected on port 3001), which
the setup above doesn't start. Visiting it will show a "dashboard failed to
load" message; that's expected, not a bug in the demo. Console (below) is
the sibling page that *has* been rebuilt natively — Dashboard is the
one still open (REDESIGN_PLAN item 6). Skip it in a demo, or mention it as
known-not-yet-migrated if asked.

### 2. Registry (`/registry`)

The asset/target inventory — **not** a skill/package registry (that's
"Catalog," covered below). On first load it auto-seeds three example
entries modeling **AgenticGoat**, a placeholder intentionally-vulnerable
target (WebGoat-style, for OWASP LLM Top 10 training):

- `AgenticGoat` (type: **target**) — no live `targetUrl` yet, it's metadata
  only today (see [Known gaps](#known-gaps-worth-naming-in-a-demo)).
- `AgenticGoat Orchestrator` (type: **agent**)
- `AgenticGoat MCP Host` (type: **mcp-host**)

**Demo it:** show the seeded entries, then click **Add Entry** to register a
new `target`-type entry (e.g. a real test app's URL). Point out that this
new entry will immediately show up as a selectable Target in any curated
Project (see section 8) — Registry is the single source of truth for
"things you can point a test at."

### 3. Console (`/console`)

A local command console (`help` / `clear` / `status` / `version` / `echo`).
Rebuilt natively this redesign — deliberately honest that it isn't wired to
a live backend session (a console is bidirectional/live, which didn't fit
the schema-driven skill-result pattern used elsewhere).

### 4. Skills (`Skills → Creator / Installed / Explorer`)

Two coexisting concepts, worth explaining explicitly in a demo:

- **Legacy Skills** — OWASP-curated, distributed as a single JSON manifest
  wrapping a `SKILL.md`-style body, installed to `localStorage`.
  `Skills Explorer` is where you browse/install these.
- **Skill Packages** — real, spec-compliant
  ([agentskills.io](https://agentskills.io/specification)) filesystem
  directories (`SKILL.md` + optional `scripts/`/`references/`/`assets/`),
  installed server-side at `~/.iac/skills/<name>/`. This is what Agent
  engagements and Project runs actually execute.

`Skills Installed` shows both, as two tabs on the same page — **Legacy
Skills** and **Agent Skills** (the Skill Packages view).

**Demo it:**
1. `Skills Creator` — walk through scaffolding a new *Skill Package*: name,
   description, SKILL.md body, optionally a script. It zips client-side and
   uploads via `POST /api/skill-packages`.
2. `Skills Installed` → **Agent Skills** tab — show the result landed on
   disk (`~/.iac/skills/`), confirm it lists with its manifest fields.
3. Mention (no dedicated UI page for this yet) that the backend also ships
   three **host** Skill Packages out of the box —
   `iac-copilot-api/host_skills/{dns-lookup,http-probe,whois-lookup}/` —
   always available to the Recon phase agent and to any Project run,
   without an install step. `GET /api/skill-packages?include_host=true`
   surfaces them; the Project Run tab (section 8) is the one place in the UI
   that actually lists them today, grouped as "Host Skills."

### 5. Agents (`/agents`, `Agents → Creator / Installed / Explorer / Definitions`)

The fixed-phase engagement runner, distinct from the Project runner (section
8) — Agents follows a strict `kickoff → recon → risk → attack_selection →
simulated_attacks → reporting → debrief` chain with a human-approval gate
between phases. **Only `kickoff`/`recon`/`risk` are implemented
server-side** — later phases in the chain aren't wired up yet.

**Demo it:**
1. On `/agents`, fill in the scope form (target URL, objectives, team type)
   and click **Create Engagement**.
2. Click **Run Recon Phase** — with a configured model provider, watch the
   live SSE event log: markdown prose from the model, `tool_call`/
   `tool_result` blocks as it invokes the `dns-lookup`/`http-probe`/
   `whois-lookup` host skills against the target.
3. Approve to advance to the next phase, or reject to halt.
4. `Agents Catalog` (`Creator`/`Installed`/`Explorer`) is a separate,
   parallel concept — installable *agent definitions* (currently seeded with
   a Recon Agent and Risk Assessment Agent), sha256-digest-verified like
   Skills. Worth noting in a demo that these two seeded entries are
   structurally skills, not agents — see REDESIGN_PLAN item 4 for why this
   catalog is likely to fold into Skills eventually. `Agent Definitions
   (Preview)` (`/agents/definitions`) previews what a *real* agent-definition
   catalog (schedule/autonomy-based, not phase-bound) would look like.

### 6. Monitoring (`Logs`, `Events`)

Straightforward log/event viewers — good for a quick mention, not much to
demo interactively yet.

### 7. Projects (sidebar heading, e.g. `Prompt Injection Tester` → `/projects/test-prompt-injection`)

**This is the centerpiece of the most recent work (Milestone 1, 2026-08-26)**
— worth spending the most demo time here. A curated Project is a real
workspace, not a one-shot test page: **Overview, Instructions, Resources,
Target, Execution Model, Run**, backed by a turn-based, tool-using
conversation. 10 curated Projects ship with the product (migrated from the
platform's original 10 point-solution testers — Prompt Injection Tester,
Training Data Leak Detector, etc.), each a plain directory under
`iac-copilot-api/canned_projects/<id>/` (`project.json` + `overview.md` +
`instructions.md`) — no install step, same "ships with the product" posture
as `host_skills/`.

**Demo it, using `Prompt Injection Tester` as the example:**

1. **Overview tab** — curated markdown description + category.
2. **Instructions tab** — currently an honest placeholder (flagged as such
   in the text itself) rather than fake per-category depth; a good moment to
   mention that real category-specific instructions/skills are Milestone
   1's known follow-up work, not Milestone 2.
3. **Resources tab** — empty state today (no resources authored yet for any
   of the 10 migrated Projects).
4. **Target tab** — pick a target from the Registry (section 2) — select
   `AgenticGoat`. Note this list is literally `useRegistry().entries` filtered
   to `type === 'target'` — anything added in Registry shows up here
   automatically, no special-casing.
5. **Execution Model tab** — pick the model provider config saved in
   Settings. This choice is local to this Project run's draft, not a global
   default change.
6. **Run tab** — pick which skills this run should have access to (grouped
   *Host Skills* / *Your Skills*; `http-probe` is pre-checked as this
   Project's suggested default), then **Start Run**. Type a message (e.g.
   *"Start the assessment against the target."*) and **Send** — watch the
   live streamed response: prose, `tool_call`/`tool_result` blocks as the
   model invokes skills, findings recorded from successful skill runs. Once
   there's at least one finding, **Finish Run & Save Result** writes a
   `TestRunResult` and links straight to Assurance Results (section 9).
7. Navigate away and back to the same Project — target/model/skill
   selections and the in-progress run persist (per-project `localStorage`
   draft), so the demo survives a page refresh.

**Draft state and run persistence, worth explaining if asked:** the
target/model choices are resolved client-side into snapshots
(`TargetSnapshot`/`ModelConfigSnapshot`) and sent to the backend at run
creation — the backend never looks anything up by ID, because neither
Registry nor Model Provider config exist server-side at all. Run state
itself does persist server-side, at `~/.iac/project-runs/<run_id>/state.json`.

### 8. Reporting (`Assurance Results`, `Reports`)

`Assurance Results` (`/assurance`) lists saved `TestRunResult`s — currently
populated by two write paths: the legacy Streamlit extension bridge, and
(new) a Project run's **Finish Run & Save Result** button. `Reports` is a
stub page today.

### 9. Admin / User (`Users & Access`, `Extensions`, `Profile`, `Settings`)

- **Settings → Model Providers** — where the provider configs used
  throughout the demo above get created (localStorage only, matches the
  design point from the Architecture section).
- **Settings → Feature Flags** — swap between presets (`full`, `minimal`,
  `testingFocus`, `developer`, `securityFocus`) to show/hide nav sections
  live, useful if a demo audience only cares about a subset of the platform.
- **Extensions** — legacy IDE-enhancement extension system; largely
  out-of-scope for this demo (see REDESIGN_PLAN item 7/11 for its known
  issues, including an unrelated zip-slip vulnerability, not fixed).

---

## Demoing without an API key

If no real provider key is configured (or the one entered is invalid), every
AI-driven flow still completes its full round trip and surfaces a clean
error instead of hanging or crashing:

- **Agents** — the phase run ends with a visible error banner in the event
  log.
- **Project runs** — sending a message returns an SSE stream ending in an
  `error` event, rendered as a red `✕ <message>` block in the conversation
  (e.g. `✕ Claude API 401: API key is invalid.` for a rejected Anthropic
  key). This is a genuinely useful thing to show in a demo: it proves the
  whole pipe — frontend SSE parsing, backend routing, state persistence —
  works correctly independent of whether the model call itself succeeds.

## Known gaps worth naming in a demo

Better to mention these proactively than have someone discover them:

- **AgenticGoat is metadata only.** The Registry entry exists, but there's
  no actual running vulnerable target service behind it yet (REDESIGN_PLAN
  item 8) — `targetUrl` is empty. Project runs against it will have the
  model ask for a URL rather than actually probing anything.
- **`.env` isn't loaded** — see the callout in [Running it](#running-it).
- **Sidebar duplication.** The "Projects" heading (backend-sourced, new) and
  the older static "Testing Projects" heading both currently list the same
  10 routes. Harmless, not yet consolidated.
- **Only 3 of 7 Agent phases are implemented** server-side
  (`kickoff`/`recon`/`risk`).
- **No user/team-authored Projects yet** — today's 10 curated Projects are
  the only ones; creating your own from the UI is Milestone 2, not built.

## Running the backend test suite

```bash
cd iac-copilot-api
source ../.venv/bin/activate
PYTHONPATH=. pytest tests/ -v
```

31 tests covering canned-Project discovery, the skill-runner scoping
regression, multi-provider LLM dispatch adapters (mocked, no network), and
the Project-run pipe end-to-end (including a real DNS lookup via a mocked
model call, and the no-API-key error path as a full-pipe smoke test).
