# IAC Platform Redesign — Plan & Roadmap

**Last updated:** 2026-08-26 (post skill-runner / Move 2)

This is the working plan for the IA redesign of `iac-host` (and, where noted, `iac-copilot-api`). It's meant to be readable by any future chat session or contributor without needing this session's conversation history — if you're picking up a roadmap item below, treat file:line references as a snapshot as of the date above; they will drift as code changes, so re-locate the referenced symbol rather than trusting the exact line number.

Related: [`Curator.md`](https://github.com/OWASP/www-project-hactu8/wiki/Team-Meetings/Curator.md) (wiki) — the original Skills Curator concept that motivated the Tools/Catalog unification in roadmap item 3.

## Vision

Reorganize the platform around five usage phases instead of a flat feature list:

1. **Observation** — Dashboard, Monitoring, **Registry** (redefined as an asset/target inventory)
2. **Testing** — Red/Blue/Purple Team **Projects**, composing scripts + a Registry target + Catalog selections
3. **Catalog** *(was "Tools")* — Agents, Skills, Tools (MCP), and a trimmed-down Extensions (IDE-enhancement only), sharing one create/install/manage pattern. **Skills follow the [Agent Skills standard](https://agentskills.io/specification)** (high priority — see dedicated section below) so an IAC skill runs unmodified in Claude Code or any compliant tool.
4. **Reporting** — Assurance Results, Reports
5. **Admin / User** — unchanged

**Approach: evolve, not rewrite.** The Skills system, Sidebar/feature-flags, results pipeline, and Agents backend are solid and worth building on. The legacy weight is concentrated, not spread everywhere — mainly the `iac_mfe_primary` Streamlit remote (roadmap item 6) and the per-extension Streamlit runtime (roadmap item 7).

**Key cross-cutting decision:** Registry is the source of truth other areas reference by ID (Testing projects pick a target from it, Monitoring scopes to registered components) rather than each area re-describing targets independently. MVP is manual registration; active/network discovery and enterprise metadata (ownership, environment, compliance tags) come later, additively — the data model already carries a `source: 'manual' | 'discovered'` field for this.

---

## Skills Format — Agent Skills Standard Compliance (high priority, 2026-08-21)

**Explicit product requirement:** an IAC-authored skill directory must be droppable into any [agentskills.io](https://agentskills.io/specification)-compliant tool — including Claude Code / claude.ai — and work as-is, with nothing IAC-only required for it to function. This reshapes items 2, 3, 4, and 5 below; noted inline where relevant.

### The gap between what we built and the real spec

The spec: a skill is a **directory** (`skill-name/SKILL.md`, optional `scripts/`/`references/`/`assets/`). Frontmatter is limited to `name` (required, kebab-case, must match the directory name), `description` (required), and optional `license`, `compatibility`, `metadata` (a free-form string map — the sanctioned extension point), and `allowed-tools` (a space-separated *pattern* string, e.g. `Bash(git:*) Read`).

`iac-host/src/types/skills.ts` today is a JSON manifest (`id`/`version`/`author`/`category`/`tags`/`allowedTools: string[]`) wrapping the whole SKILL.md as one embedded `content` string inside `registry.json` — not real filesystem directories. Migrating means:
- `id`/`version`/`author`/`category`/`tags`/`resultSchema` move under `metadata`, or get dropped where `name` already covers them.
- `allowedTools` becomes the space-separated pattern string, not an array.
- IAC's curation layer (digest, `verified`, `curatedBy`) moves **outside** the skill directory entirely, into a separate IAC-only index (a `registry.json` mapping skill directory name → signature/category/curation status) — so the skill directory alone, with nothing else, is what's portable. A tool outside IAC never sees the index.
- Digests move from hashing one string (`computeDigest()` in `skillService.ts`, `compute_skill_digest()` in `iac-copilot-api/skills/registry.py` — both built in item 5) to hashing a full file tree (hash each file, then hash the combined sorted list) — a change to any bundled script or reference must be caught, not just edits to SKILL.md's body.

### No formal "inputs" field — and that's fine

The spec has no `parameters`/`inputs` schema. A skill's expected inputs are documented in prose (a "## Inputs" or "## Required Context" section in the body), exactly as any Claude Code skill would; anything needing strict typed parameters lives in `scripts/` as a real executable with normal CLI args — fully portable, since a script is just a script regardless of what invokes it.

### Skill runner (new, central infrastructure)

The spec doesn't define an execution engine — it just says "the agent will load this file" and describes progressive disclosure (name+description always loaded cheaply; full body loaded on activation; `scripts/`/`references/`/`assets/` loaded on demand). IAC's **skill runner** is that engine: discovers skill directories (public catalog + private host skills), loads name/description for all of them, activates and executes the matching one with its declared `allowed-tools` enforced. This reframes item 3 below — it's not "unify with the backend tool registry," it's "the skill runner replaces the Python `@skill`-decorator tool registry in `iac-copilot-api/skills/registry.py`."

### Repo layout

`catalog/extensions/` + `catalog/skills/` (public — installable by any user) and a separate `iac-host/skills/` (private — host-only, e.g. `iac-dashboard`; inherently trusted/protected, no review needed). Reorganizes what already exists at the repo root (`extensions/`, `skills/`) under a `catalog/` parent, plus a new private directory.

### Invocation model

- **Dashboard** (roadmap item 6): nav click → skill runner invoked with the private `iac-dashboard` skill → renders the result.
- **Console / Projects**: an installed catalog skill becomes invocable from both — MVP as simple as an `INSTRUCTION.md` naming which installed skill to run.

### Skill vs. Agent — resolves the open question from item 4

A **Skill** is bounded and reactive: activated, follows its instructions, returns. An **Agent** has its own lifecycle — long-running, schedulable, or autonomous — and decides *which* skills to invoke and when. Under this distinction, the two seeded Agents-catalog entries ("Recon Agent," "Risk Assessment Agent" — item 4) are structurally skills, not agents: single-phase, invoked once, no independent lifecycle. The one genuine agent in the codebase is the existing engagement runner at `/agents` (persisted state, multi-phase, pauses for approval). **Decision, 2026-08-21:** don't retrofit the two catalog entries yet (real work, not scoped this pass) — and don't build a general "Agent definitions" catalog speculatively either, since there's exactly one agent today. Shipped instead: an honest **Agent Definitions preview** placeholder (`AgentDefinitionsPreview.tsx`, route `/agents/definitions`, flagged via `agents.definitionsPreview`, default on) so the team has something concrete to react to before that design work starts. The real Agent Definitions catalog (trigger/schedule, autonomy/approval policy, which skills it orchestrates) is phase-2 scope, alongside the Skills spec-compliance rework above.

### Three skill-authoring paths

1. **In-app Creator** — simple, SKILL.md-only, self-authored, starts as an unsigned local draft. Needs a field-shape rework to match the real frontmatter (see above).
2. **Upload (zip) — deferred, hold off.** Before building a naive zip upload, consider a Teams-managed-apps-style model instead: author the skill entirely outside IAC, sign it (or register an app ID) externally, then register/add it to IAC — closer to how enterprise app catalogs (Teams, Slack) provision third-party apps than a raw file-upload flow. Push to the end of the roadmap (item 10 below); when eventually built, ship it feature-flagged off by default until the registration model is actually decided.
3. **OWASP-curated** — authored directly by the HACTU8 maintainer, shipped straight into `catalog/skills/`, already signed/verified, available to everyone by default. Already partially exists: the two seeded entries in `skills/registry.json` (`curatedBy: "OWASP HACTU8 Skills Board"`, `verified: true`) are instances of this path today.

---

## Shipped: Registry redefinition (2026-08-21)

Today `src/pages/Registry.tsx` was a 22-line dead-end stub lazy-loading a remote module-federation component (`iac_mfe_primary/StreamlitRegistry`) with no local data model. It's been replaced with a real, self-contained feature — no backend changes, no cross-referencing from Testing/Monitoring/Catalog yet (that's roadmap item 8), no active discovery (roadmap item 9).

### Data model — `iac-host/src/types/registry.ts`

Discriminated union by `RegistryEntryType`: `'agent' | 'model-integration' | 'mcp-host' | 'target'`, each carrying type-specific fields (e.g. `target` has `targetUrl`/`riskNotes`/`referenceUrl`). Common base fields: `id`, `name`, `description`, `source: 'manual' | 'discovered'`, `tags?`, `owner?`, `addedAt`, `updatedAt`. Follows the discriminated-union style already used by `ExtensionRuntimeConfig` in `types/extensions.ts`.

### Seed data — `iac-host/src/data/agenticGoatSeed.ts`

3 seeded entries (a `target`, an `agent`, an `mcp-host`) modeling **AgenticGoat** — a placeholder intentionally-vulnerable reference target (WebGoat-style, for OWASP LLM Top 10 training) — so the platform isn't empty on first load. Honest placeholder, not a real deployed system.

### Service — `iac-host/src/services/registryService.ts`

localStorage CRUD (`loadEntries`/`saveEntries`/`addEntry`/`updateEntry`/`removeEntry`), key `iac-registry-entries`. Seeds once on first-ever load (tracked via a separate `iac-registry-seeded` flag); deleting entries down to zero does not trigger reseeding. No signing/digest logic — unlike Skills, these are locally-owned facts, not curated/distributed content.

### Context — `iac-host/src/contexts/RegistryContext.tsx`

Thin wrapper (`RegistryProvider` / `useRegistry()`) matching `SkillContext.tsx`'s shape. Wired into the provider tree in `App.tsx`.

### UI — `iac-host/src/pages/Registry.tsx`

Single page (no Explorer/Installed/Creator split like Skills — Registry has no curated-vs-draft distinction, just CRUD), reusing the shared visual kit from `components/Skills/shared.tsx`. Master-detail layout: left rail filterable by type, right pane shows details with Edit/Delete, "+ Add Entry" opens a type-conditional inline form.

### Intentionally not touched

- `featureFlags.ts` / `featureFlagPresets.ts` — the existing `navigation.registry` flag already gates the Registry nav link.
- `Sidebar.tsx` — Registry keeps its current top-level position; regrouping under an "Observation" heading is a broader nav change, not done yet.
- `vite.config.ts` — the `iac_mfe_primary` remote stays for now; `Dashboard.tsx` and `Console.tsx` still use it (see roadmap item 6).
- No changes to `iac-copilot-api`, Testing pages, Skills/Extensions systems, or the results pipeline.

---

## Roadmap

| # | Item | Completed Date |
|---|------|----------------|
| 1 | Testing → canned Projects | 2026-08-21 |
| 2 | Shared Catalog abstraction | — |
| 3 | Skill runner (Moves 1 + 2 of skills consolidation) | 2026-08-26 (both moves complete) |
| 4 | Agents sub-catalog | 2026-08-21 (UI shell only — backend phase completion still open) |
| 5 | Schema-driven skill results + protected-skill integrity | ⚠️ Superseded — the mechanism this shipped was deleted by item 3/Move 2 (see below) |
| 6 | Retire `iac_mfe_primary` Streamlit remote | 2026-08-21 (Console only — Dashboard still open) |
| 7 | Extensions trim-down | — |
| 8 | Cross-referencing + AgenticGoat Internal target | 2026-08-26 (target selection unified — AgenticGoat Internal running service still open) |
| 9 | Enterprise metadata / active discovery | — |
| 10 | Skill upload path (deferred — Teams-app-style model) | — |
| 11 | Extensions security debt (zip-slip + port mismatch) | — |
| 12 | Skill Package approval/sandboxing | — |
| 13 | `iac-copilot-api` test suite | 2026-08-26 (Projects/skill-runner/llm-dispatch modules covered — Skill Package install/discovery still untested) |
| 14 | Dead-code cleanup | — |
| 15 | Project concept — MVP Milestone 1 (curated Projects) | 2026-08-26 — Milestone 2 (user/team-authored) still open |

1. **Testing → canned Projects** — ✅ **Completed 2026-08-21.** Reworked `iac-host/src/pages/Project.tsx` and the Testing nav group so the 10 existing point-solution testers (Prompt Injection Tester, etc.) are now pre-scoped starter Projects (`src/data/cannedProjects.tsx` is the single source of truth); each opens in a framed Overview/Target/Run view and mounts the original, unmodified tester page in the Run tab. The standalone routes still work on their own too. Target selection currently uses `ModelProviderContext` as a stand-in — swap to `useRegistry()` once cross-referencing (item 8) lands.

2. **Shared Catalog abstraction** — generalize the Skills registry/install/draft pattern (`skillService.ts`, `SkillContext.tsx`, `components/Skills/shared.tsx`) into a reusable `useCatalog(kind)` shape shared by Agents, Skills, Tools, and (trimmed) Extensions sub-catalogs, replacing the heavier zip-download/backend-process-spawn/port-management machinery in `extensionService.ts` with the lighter inline-content + client-side-digest model Skills already uses. *Not done yet — the Agents catalog (item 4) was built by cloning the Skills pattern directly rather than through a shared abstraction, same as Extensions/Skills coexist today; this item would unify all three afterward.*

3. **Skill runner — ✅ Completed 2026-08-26 (both moves).** Target end state was ONE skill schema (Skill Packages / agentskills.io), reached via two moves:
   - **Move 1 — Creator rework.** Reworked `SkillsCreator.tsx` from "build a localStorage `SkillManifest`" into a scaffold-and-upload wizard — collects the real spec frontmatter fields + SKILL.md body + optional `scripts/`/`references/`/`assets/` placeholders, zips client-side (`fflate`), and calls the existing `uploadSkillPackage()`. `types/skills.ts`/`skillService.ts`/`SkillContext.tsx` are **not** retired — `SkillsExplorer.tsx` and the "Legacy Skills" tab still depend on them for the OWASP-curated distribution path; only the Creator's own output format changed.
   - **Move 2 — the actual skill runner.** `iac-copilot-api/skills/registry.py` + `skills/recon/*.py` (the `@skill`-decorated Python tool registry `ReconAgent` used) is **deleted entirely** — confirmed via grep that nothing else imported it. Replaced with `iac-copilot-api/skill_packages/runner.py`: three generic, spec-faithful tools (`list_skills`/`read_skill`/`run_skill_script`) instead of one typed schema per skill, matching how Claude Code itself runs skills. The 3 recon functions are now real Skill Packages shipped with the product at `iac-copilot-api/host_skills/{dns-lookup,http-probe,whois-lookup}/` — repo-committed, always discoverable, no install step (same "ships with the product" pattern as the OWASP-curated distribution path, just for the backend). `ReconAgent` discovers phase-tagged skills (`metadata.phase: recon`) from `host_skills/` + user-installed `~/.iac/skills/` (host wins name collisions) and eagerly splices their instructions into its system prompt, so the common case needs zero `list_skills`/`read_skill` round-trips. **Kept, not dropped:** server-side fail-closed phase scoping — `ReconAgent` can only ever see/run `recon`-tagged skills, a real security boundary the spec itself doesn't provide. Verified end-to-end including live DNS/HTTP/WHOIS execution and confirmed path-traversal/symlink rejection with zero subprocess spawned. See item 5 below for what this deletion means for protected-skill integrity, and item 12 for the gap it leaves.

4. **Agents sub-catalog** — ✅ **UI shell completed 2026-08-21.** Built `AgentsExplorer`/`AgentsInstalled`/`AgentsCreator` pages + `agents/registry.json` (repo root and `public/agents/`) + sha256 digest signing (`agentCatalogService.ts`, `AgentCatalogContext.tsx`), matching the Skills pattern, for the agent orchestrators themselves (distinct from item 3's callable tools) — routed at `/agents/catalog/*` to avoid colliding with the existing `/agents` engagement runner. Seeded with a Recon Agent and Risk Assessment Agent, verified installable (digest checks pass). **Still open:** `iac-copilot-api` only implements 3 of 7 phases (`kickoff`/`recon`/`risk`; see `agents/router.py` `PHASE_CHAIN`/`AGENT_MAP`), and tool-level approval gating for the engagement runner itself is still an unfinished stub — that's real backend work, not addressed by the catalog UI. **Also see "Skills Format" section above:** under the Skill-vs-Agent distinction clarified 2026-08-21, the two seeded catalog entries here are structurally skills, not agents — this catalog's future is likely folding into Skills, with a real Agent Definitions catalog (schedule/autonomy, not phase-bound instructions) taking its place as phase-2 scope. An honest ✅ **Agent Definitions preview shipped 2026-08-21** (`/agents/definitions`) in the meantime. **Reinforced 2026-08-26:** item 3/Move 2 migrated the real "Recon Agent"/"Risk Assessment Agent" equivalents (the actual recon tool functions) into Skill Packages, not into this catalog — further evidence this catalog's two seeded entries were never real agents and this fold is the right call whenever it happens.

5. **Schema-driven skill results + protected-skill integrity** — Split outcome. `resultSchema?: string` on `SkillManifest` is still there (documented convention, not an enforced schema registry — see item 2's note on full results-pipeline consolidation). **⚠️ The protected-skill integrity half no longer exists**: it was wired into `iac-copilot-api/skills/registry.py`'s `@skill` decorator and `base_agent.py`'s approval-gate branch, and item 3/Move 2 deleted that entire file and branch (confirmed dead, zero other importers, frontend never rendered the events it produced). Skill Packages today have **no** equivalent protection mechanism — see item 12, a fresh design, not a port of this one (the old one hashed a single string; Skill Packages are multi-file directories, and the old scheme was already known mis-scoped — checking every run instead of once at install time).

6. **Retire the `iac_mfe_primary` Streamlit remote (Dashboard/Console).** This module-federation remote (`vite.config.ts`) backs `Dashboard.tsx` and `Console.tsx` — it points at a dev server that isn't running in most dev environments. Registry was already rebuilt off it earlier; not a uniform "make it a skill" fix — the right shape differs per page:
   - **Console** — ✅ **Completed 2026-08-21.** Rebuilt natively as a local command console (`help`/`clear`/`status`/`version`/`echo`), honest about not being connected to a live backend session (a console is live/bidirectional, not a one-shot skill result payload, so it wasn't a fit for the schema-driven skill pattern).
   - **Dashboard** — still open. Good fit for the schema-driven skill pattern from item 5: a periodically-invoked skill returns a summary schema (stat tiles, sparklines, recent activity), rendered by trusted host components.
   - **Registry** — already done (earlier pass); stays native/host-owned rather than becoming skill-authored, since it's core source-of-truth state and letting a skill define/redefine the asset schema would blur a trust boundary that belongs to the host.
   - **Copilot** — already native React (`components/CopilotSidebar/`), not on this remote at all; no rewrite needed. Its content panels (OWASP docs/project docs) could optionally source from the Catalog later — a separate, smaller idea.
   - Once Dashboard is native too, remove the `iac_mfe_primary` remote entry from `vite.config.ts` entirely (Console no longer needs it as of this pass).

7. **Extensions trim-down** — remove non-IDE-enhancement extension categories/installed extensions; keep only IDE-enhancement use cases.

8. **Cross-referencing + AgenticGoat Internal target.** *Added 2026-08-26, made concrete.* Two parts:
   - **AgenticGoat Internal** — a lightweight, intentionally-vulnerable target app that actually runs, for demos, replacing today's metadata-only `agenticGoatSeed.ts` placeholder. Ships with the product the same way `host_skills/` does (repo-committed, e.g. `iac-copilot-api/agentic_goat/`, always available, no install step) — a small local service (own port) exposing a handful of intentionally-vulnerable endpoints spanning a few OWASP LLM Top 10 categories, started manually alongside the rest of the stack like everything else in this repo (no auto-orchestration exists here). Registered as a `target`-type Registry entry whose `targetUrl` points at the real running local service, tagged so the UI can show it's built-in. **Still open** — this part hasn't been built; AgenticGoat is still Registry metadata only, no running service.
   - **Unified target selection** — ✅ **Completed 2026-08-26, as part of Projects Milestone 1 (item 15).** The new curated-Project workspace's Target tab (`components/Projects/TargetTab.tsx`) reads directly from `useRegistry().entries.filter(type === 'target')` — no special-casing for "built-in vs. external," both are just Registry entries in the same picker, confirmed working against the seeded AgenticGoat entry. Note: this landed on the *new* Project workspace, not the old per-tester `ModelProviderContext` stand-in from item 1 — item 1's 10 standalone tester pages (still reachable at their own routes) still use their own original target handling, unaudited and untouched.

9. **Enterprise metadata / active discovery** (later still) — add ownership/environment/compliance fields to `RegistryEntryBase`, and a network-discovery mechanism that produces `source: 'discovered'` entries.

10. **Skill upload path — deferred, lowest priority.** The third skill-authoring path (see "Skills Format" section above): uploading a skill directory that needs `scripts`/`references`/`assets`, which a browser text form can't produce. Explicitly held off rather than building a naive zip upload — worth first thinking through a Teams-managed-apps-style model (author outside IAC, sign or register an app ID externally, then register with IAC) before committing to a specific mechanism. When this is eventually built, ship it behind a feature flag defaulted **off**/hidden until the registration model is decided.

11. **Extensions security debt — two live bugs, found 2026-08-26 while building the Skill Package installer, not yet fixed (Extensions itself was out of scope at the time).** (a) `iac-extension-installer.py`'s `zipfile.extractall()` has **zero zip-slip protection** — a crafted extension zip can write outside its install directory today; `skill_packages/installer.py`'s two-pass validate-then-write containment check is the pattern to port over. (b) Confirmed port mismatch: `extension_api.py` defaults to port 5000, but `iac-host/src/services/extensionService.ts` defaults to `http://localhost:5001` for every call — with both sides on defaults, extension install/registry-fetch can't connect at all.

12. **Skill Package approval/sandboxing — the real gap item 5 left behind.** `run_skill_script` (item 3/Move 2) only enforces that a script stays inside its own skill's directory — nothing stops an installed skill's script from making network calls, reading whatever the OS lets the process read, etc., once it's running, and there's no approval gate at all (a `# TODO` in `base_agent.py` marks this explicitly). Needs a fresh design for the new multi-file-directory shape, not a port of the old single-string digest scheme.

13. **`iac-copilot-api` test suite** — ✅ **Started 2026-08-26, partial.** `pytest`/`pytest-asyncio` now stood up (`requirements-dev.txt`, `pytest.ini`, `iac-copilot-api/tests/`), 31 passing tests covering the modules built for Projects Milestone 1: `canned_projects/loader.py` (id-matches-dirname validation, malformed-entry skip), `skill_packages/runner.py`'s `SkillScope` regression (phase-string behavior unchanged, new name-list scope works and is fail-closed), `services/llm_dispatch.py`'s provider adapters (OpenAI-compatible + Anthropic, against static mocked fixtures, no network), and `project_runs/` end-to-end (create/status round-trip, the no-API-key path as a full-pipe smoke test, and a mocked-LLM-call tool loop that exercises one real DNS lookup via `dns-lookup`). **Still not covered**: the earlier Skill Package install/discovery flow (zip-slip cases, containment-check cases) from item 3/Move 1 — those were verified ad-hoc at the time and never ported into this suite.

14. **Dead-code cleanup.** `extensionService.ts`'s `generateHostConfig()` is built but never called (`config.json` doesn't reliably reach an extension's install directory despite backend plumbing existing for it) — either wire it up or remove it. `agents/router.py`'s `_approval_pending` dict is an unused in-memory placeholder (its own comment says so). `iac-console`/`iac-dashboard`/`iac-registry` at the repo root appear unreferenced by `iac-host` now that Console and Registry are native — worth confirming and removing if genuinely orphaned, not yet confirmed exhaustively.

15. **Project concept — MVP Milestone 1 (curated Projects)** — ✅ **Completed 2026-08-26.** What shipped in item 1 (Overview/Target/Run tabs wrapping one existing tester) is now fully replaced by the real concept, per direct product-owner input: a Project as a persistent workspace with six sections — **Overview, Instructions, Resources, Target, Execution Model, Run** (skill selector + conversation + results). Not a new bundle/package format (explicitly deferred to Milestone 2) — plain repo-committed directories, same "ships with the product, no install step" posture as `host_skills/`:
    - **Backend.** `iac-copilot-api/canned_projects/` (models/loader/router) discovers one directory per curated Project (`<id>/project.json` + `overview.md` + `instructions.md`) from `CANNED_PROJECTS_DIR`, id-validated against the directory name like `installer.py` does for Skill Packages. All 10 testers from item 1 migrated over (`test-prompt-injection`, etc.) — mechanical fields (name/category/summary/legacy_route) carried over verbatim; `instructions.md` and `default_skill_names` are honest placeholders (no prior equivalent existed) flagged for real per-category authoring later. `iac-copilot-api/project_runs/` (models/engine/router) is a new turn-based (not fixed-phase) run engine: `ProjectRunScope` carries client-resolved `TargetSnapshot`/`ModelConfigSnapshot` rather than IDs, since neither Registry nor ModelProviderContext have any backend persistence (both pure `localStorage` — a real discovery this pass). Runs persist to `~/.iac/project-runs/<run_id>/state.json`, same pattern as `agents/router.py`'s engagements.
    - **Multi-provider LLM dispatch, extracted.** New `services/llm_dispatch.py::call_model()` relocates (not rewrites) the provider-branching logic that used to live split across `RAGService.chat()` (all 5 providers, no tool support) and `base_agent.py`'s `_call_claude` (tool support, Anthropic-only) into one function with both — `RAGService.chat()` now calls it too. Necessary because Project runs need both tool-use *and* every provider the Execution Model tab offers, and duplicating ~150 lines of live provider logic wasn't worth the drift risk.
    - **Skill scoping generalized, not forked.** `skill_packages/runner.py`'s `phase: str` scope widened to `SkillScope = Union[str, List[str]]` — `str` for the existing fixed-phase agents (zero behavior change, regression-tested), `List[str]` for a Project run's user-picked skill allowlist. One shared discovery/host-wins-collision implementation instead of two.
    - **Skill listing gap fixed.** `GET /api/skill-packages` gained an opt-in `include_host: bool` param (default off, byte-identical to before) so the Run tab's skill selector can see host-shipped skills (`dns-lookup` etc.), not just user-installed ones.
    - **Frontend.** `types/project.ts`, `services/cannedProjectService.ts`, `services/projectRunService.ts` (hand-rolled `fetch(POST) + reader` SSE parsing, since native `EventSource` can't POST the message body). `Agents.tsx`'s event-log rendering extracted into `components/shared/StreamEventLog.tsx` (block-vocabulary + styles shared, event-to-block mapping stays page-local since the two event vocabularies genuinely differ) — a pure move verified via `tsc --noEmit`, plus a real bug fix along the way (`isToolResultOk()` now handles both the legacy `{success}` shape and the skill-runner's `{exit_code, timed_out}` shape, since both flow through the same renderer now). `components/Projects/` holds the 6-tab `ProjectWorkspace.tsx` + one component per tab; `pages/Project.tsx` is now a thin loader. Run-draft state (target/model/skills/run_id) persists per-project to `localStorage`. `Sidebar.tsx`'s old `useMockProjects()` (fake Red/Blue/Purple Team Demo data) deleted and replaced with a real fetch from `GET /api/canned-projects` — confirmed with the user before removing, since it deleted working (if fake) UI. **Known minor redundancy, not addressed**: this new "Projects" heading and the older "Testing Projects" heading (item 1, still static-file-sourced) now both list the same 10 routes — harmless duplication, not consolidated this pass.
    - **Verified end-to-end**: 31 passing backend tests (see item 13) plus full browser verification of all 6 tabs, draft persistence across navigation, a real run creation, and the no-API-key error path rendering correctly through the whole SSE pipe (a real 401 from the live Anthropic API with a placeholder key).
    - **Still open — MVP Milestone 2 (user/team-authored Projects)**: creating/editing a Project's own Overview/Instructions/Resources from within the app, not just running curator-shipped ones. Also open: real per-category `instructions.md` authoring and `default_skill_names` beyond the `http-probe` placeholder (needs category-specific attack-technique Skill Packages that don't exist yet), and whether to consolidate the "Projects"/"Testing Projects" sidebar duplication.
