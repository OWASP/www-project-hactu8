# IAC Platform Redesign — Plan & Roadmap

**Last updated:** 2026-08-21

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
| 3 | Tools (MCP) sub-catalog — unify with backend skill-tool registry | — |
| 4 | Agents sub-catalog | 2026-08-21 (UI shell only — backend phase completion still open) |
| 5 | Schema-driven skill results + protected-skill integrity | 2026-08-21 |
| 6 | Retire `iac_mfe_primary` Streamlit remote | 2026-08-21 (Console only — Dashboard still open) |
| 7 | Extensions trim-down | — |
| 8 | Cross-referencing | — |
| 9 | Enterprise metadata / active discovery | — |
| 10 | Skill upload path (deferred — Teams-app-style model) | — |

1. **Testing → canned Projects** — ✅ **Completed 2026-08-21.** Reworked `iac-host/src/pages/Project.tsx` and the Testing nav group so the 10 existing point-solution testers (Prompt Injection Tester, etc.) are now pre-scoped starter Projects (`src/data/cannedProjects.tsx` is the single source of truth); each opens in a framed Overview/Target/Run view and mounts the original, unmodified tester page in the Run tab. The standalone routes still work on their own too. Target selection currently uses `ModelProviderContext` as a stand-in — swap to `useRegistry()` once cross-referencing (item 8) lands.

2. **Shared Catalog abstraction** — generalize the Skills registry/install/draft pattern (`skillService.ts`, `SkillContext.tsx`, `components/Skills/shared.tsx`) into a reusable `useCatalog(kind)` shape shared by Agents, Skills, Tools, and (trimmed) Extensions sub-catalogs, replacing the heavier zip-download/backend-process-spawn/port-management machinery in `extensionService.ts` with the lighter inline-content + client-side-digest model Skills already uses. *Not done yet — the Agents catalog (item 4) was built by cloning the Skills pattern directly rather than through a shared abstraction, same as Extensions/Skills coexist today; this item would unify all three afterward.*

3. **Tools (MCP) sub-catalog — unify with the existing backend skill-tool registry.** *Reframed 2026-08-21 — see "Skills Format" section above: this is now "build the skill runner," not "unify two registries."* **Consolidation plan added 2026-08-21 — target end state is ONE skill schema (Skill Packages / agentskills.io), reached via two moves:**
   - **Move 1 (small, buildable now):** rework `SkillsCreator.tsx` from "build a localStorage `SkillManifest`" into a scaffold-and-upload wizard — collect the real spec frontmatter fields + SKILL.md body + optional `scripts/`/`references/`/`assets/` placeholders, zip client-side, and call the existing `uploadSkillPackage()` (same zip-slip-safe pipeline built for install/discovery). Retires `types/skills.ts`/`skillService.ts`'s localStorage path once done.
   - **Move 2 (the actual skill runner — bigger, not a registry swap):** rework `base_agent.py`'s tool-use loop to source tools from installed Skill Packages instead of `@skill`-decorated Python functions. Real design fork: **spec-faithful** (recommended, given the compliance priority) — expose generic tools (list available skills / activate a skill → load its SKILL.md body / run a script scoped to its `allowed-tools`), matching how Claude Code itself runs skills, with the 3 recon functions becoming real Skill Packages (`recon-dns-lookup/SKILL.md` + `scripts/dns_lookup.py`, etc.) — vs. a **pragmatic bridge** (skill name → one script, IAC-invented typed entry point) that's less work but reintroduces a non-portable convention. `iac-copilot-api/skills/registry.py` + `skills/recon/*.py` is a *second*, disconnected "Skills" system — Python functions registered with an `@skill` decorator (category `recon`/`attack`/`defend`, an `is_approval_required` flag, executed via `registry.execute()`) that the agent's tool-use loop calls during a run. It predates/motivated the frontend Skills system (see `Curator.md`) but was never merged with it. Rather than build "Tools" from scratch:
   - Author tool-skills declaratively (YAML/`model_instructions`, per the Curator concept) through the existing `SkillsExplorer`/`SkillsCreator` UI, instead of hand-written Python.
   - Reconcile category taxonomies: backend tool-skills use `recon`/`attack`/`defend` (mirrors `PHASE_CHAIN` in `agents/router.py`); frontend `SkillCategory` uses `assurance-testing`/`remediation`/`reporting`/`governance`/`research`/`automation`/`utility`.
   - Enforce `SkillManifest.allowedTools?: string[]` (already defined in `types/skills.ts`, currently unused) against the backend registry — this is the "sandboxed execution context / allowed tool palette per category" design decision from `Curator.md`.

4. **Agents sub-catalog** — ✅ **UI shell completed 2026-08-21.** Built `AgentsExplorer`/`AgentsInstalled`/`AgentsCreator` pages + `agents/registry.json` (repo root and `public/agents/`) + sha256 digest signing (`agentCatalogService.ts`, `AgentCatalogContext.tsx`), matching the Skills pattern, for the agent orchestrators themselves (distinct from item 3's callable tools) — routed at `/agents/catalog/*` to avoid colliding with the existing `/agents` engagement runner. Seeded with a Recon Agent and Risk Assessment Agent, verified installable (digest checks pass). **Still open:** `iac-copilot-api` only implements 3 of 7 phases (`kickoff`/`recon`/`risk`; see `agents/router.py` `PHASE_CHAIN`/`AGENT_MAP`), and tool-level approval gating for the engagement runner itself is still an unfinished stub — that's real backend work, not addressed by the catalog UI. **Also see "Skills Format" section above:** under the Skill-vs-Agent distinction clarified 2026-08-21, the two seeded catalog entries here are structurally skills, not agents — this catalog's future is likely folding into Skills, with a real Agent Definitions catalog (schedule/autonomy, not phase-bound instructions) taking its place as phase-2 scope. An honest ✅ **Agent Definitions preview shipped 2026-08-21** (`/agents/definitions`) in the meantime.

5. **Schema-driven skill results + protected-skill integrity** — ✅ **Completed 2026-08-21.** Added `resultSchema?: string` to `SkillManifest` (documented convention, not an enforced schema registry yet — see item 2's note on full results-pipeline consolidation). Wired a real sha256 digest-integrity check into `iac-copilot-api/skills/registry.py`'s `@skill` decorator (`protected`/`expected_digest` fields, `verify_integrity()`) and `agents/base_agent.py`'s approval-gate branch: a protected skill whose source has drifted from its pinned digest now halts the run with a distinct `integrity_failure` event. **Needs revisiting** per the "Skills Format" section above: both digest implementations hash a single string today — once skills are real multi-file directories, this needs to become a file-tree digest.

6. **Retire the `iac_mfe_primary` Streamlit remote (Dashboard/Console).** This module-federation remote (`vite.config.ts`) backs `Dashboard.tsx` and `Console.tsx` — it points at a dev server that isn't running in most dev environments. Registry was already rebuilt off it earlier; not a uniform "make it a skill" fix — the right shape differs per page:
   - **Console** — ✅ **Completed 2026-08-21.** Rebuilt natively as a local command console (`help`/`clear`/`status`/`version`/`echo`), honest about not being connected to a live backend session (a console is live/bidirectional, not a one-shot skill result payload, so it wasn't a fit for the schema-driven skill pattern).
   - **Dashboard** — still open. Good fit for the schema-driven skill pattern from item 5: a periodically-invoked skill returns a summary schema (stat tiles, sparklines, recent activity), rendered by trusted host components.
   - **Registry** — already done (earlier pass); stays native/host-owned rather than becoming skill-authored, since it's core source-of-truth state and letting a skill define/redefine the asset schema would blur a trust boundary that belongs to the host.
   - **Copilot** — already native React (`components/CopilotSidebar/`), not on this remote at all; no rewrite needed. Its content panels (OWASP docs/project docs) could optionally source from the Catalog later — a separate, smaller idea.
   - Once Dashboard is native too, remove the `iac_mfe_primary` remote entry from `vite.config.ts` entirely (Console no longer needs it as of this pass).

7. **Extensions trim-down** — remove non-IDE-enhancement extension categories/installed extensions; keep only IDE-enhancement use cases.

8. **Cross-referencing** — once (1)–(4) exist, wire Testing projects to select a Registry target by ID, and scope Monitoring to registered components.

9. **Enterprise metadata / active discovery** (later still) — add ownership/environment/compliance fields to `RegistryEntryBase`, and a network-discovery mechanism that produces `source: 'discovered'` entries.

10. **Skill upload path — deferred, lowest priority.** The third skill-authoring path (see "Skills Format" section above): uploading a skill directory that needs `scripts`/`references`/`assets`, which a browser text form can't produce. Explicitly held off rather than building a naive zip upload — worth first thinking through a Teams-managed-apps-style model (author outside IAC, sign or register an app ID externally, then register with IAC) before committing to a specific mechanism. When this is eventually built, ship it behind a feature flag defaulted **off**/hidden until the registration model is decided.
