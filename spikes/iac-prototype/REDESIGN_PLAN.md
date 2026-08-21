# IAC Platform Redesign — Plan & Roadmap

**Last updated:** 2026-08-21

This is the working plan for the IA redesign of `iac-host` (and, where noted, `iac-copilot-api`). It's meant to be readable by any future chat session or contributor without needing this session's conversation history — if you're picking up a roadmap item below, treat file:line references as a snapshot as of the date above; they will drift as code changes, so re-locate the referenced symbol rather than trusting the exact line number.

Related: [`Curator.md`](https://github.com/OWASP/www-project-hactu8/wiki/Team-Meetings/Curator.md) (wiki) — the original Skills Curator concept that motivated the Tools/Catalog unification in roadmap item 3.

## Vision

Reorganize the platform around five usage phases instead of a flat feature list:

1. **Observation** — Dashboard, Monitoring, **Registry** (redefined as an asset/target inventory)
2. **Testing** — Red/Blue/Purple Team **Projects**, composing scripts + a Registry target + Catalog selections
3. **Catalog** *(was "Tools")* — Agents, Skills, Tools (MCP), and a trimmed-down Extensions (IDE-enhancement only), sharing one create/install/manage pattern
4. **Reporting** — Assurance Results, Reports
5. **Admin / User** — unchanged

**Approach: evolve, not rewrite.** The Skills system, Sidebar/feature-flags, results pipeline, and Agents backend are solid and worth building on. The legacy weight is concentrated, not spread everywhere — mainly the `iac_mfe_primary` Streamlit remote (roadmap item 6) and the per-extension Streamlit runtime (roadmap item 7).

**Key cross-cutting decision:** Registry is the source of truth other areas reference by ID (Testing projects pick a target from it, Monitoring scopes to registered components) rather than each area re-describing targets independently. MVP is manual registration; active/network discovery and enterprise metadata (ownership, environment, compliance tags) come later, additively — the data model already carries a `source: 'manual' | 'discovered'` field for this.

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

## Roadmap (not yet built)

1. **Testing → canned Projects** — rework `iac-host/src/pages/Project.tsx` and the Testing nav group so the 10 existing point-solution testers (Prompt Injection Tester, etc.) become pre-scoped starter Projects; new/custom Projects compose scripts + a Registry target + Catalog selections (Agents/Skills/Tools).

2. **Shared Catalog abstraction** — generalize the Skills registry/install/draft pattern (`skillService.ts`, `SkillContext.tsx`, `components/Skills/shared.tsx`) into a reusable `useCatalog(kind)` shape shared by Agents, Skills, Tools, and (trimmed) Extensions sub-catalogs, replacing the heavier zip-download/backend-process-spawn/port-management machinery in `extensionService.ts` with the lighter inline-content + client-side-digest model Skills already uses.

3. **Tools (MCP) sub-catalog — unify with the existing backend skill-tool registry.** `iac-copilot-api/skills/registry.py` + `skills/recon/*.py` is a *second*, disconnected "Skills" system — Python functions registered with an `@skill` decorator (category `recon`/`attack`/`defend`, an `is_approval_required` flag, executed via `registry.execute()`) that the agent's tool-use loop calls during a run. It predates/motivated the frontend Skills system (see `Curator.md`) but was never merged with it. Rather than build "Tools" from scratch:
   - Author tool-skills declaratively (YAML/`model_instructions`, per the Curator concept) through the existing `SkillsExplorer`/`SkillsCreator` UI, instead of hand-written Python.
   - Reconcile category taxonomies: backend tool-skills use `recon`/`attack`/`defend` (mirrors `PHASE_CHAIN` in `agents/router.py`); frontend `SkillCategory` uses `assurance-testing`/`remediation`/`reporting`/`governance`/`research`/`automation`/`utility`.
   - Enforce `SkillManifest.allowedTools?: string[]` (already defined in `types/skills.ts`, currently unused) against the backend registry — this is the "sandboxed execution context / allowed tool palette per category" design decision from `Curator.md`.

4. **Agents sub-catalog** — build `AgentsExplorer`/`AgentsInstalled`/`AgentsCreator` pages + `agents/registry.json` + digest signing, matching the Skills pattern, for the agent orchestrators themselves (distinct from item 3's callable tools). Backend note: `iac-copilot-api` currently only implements 3 of 7 phases (`kickoff`/`recon`/`risk`; see `agents/router.py` `PHASE_CHAIN`/`AGENT_MAP`), and tool-level approval gating is an explicit unfinished stub in `agents/base_agent.py` (`"Implement approval gate"` comment) — this needs real backend work, not just frontend catalog UI.

5. **Schema-driven skill results + protected-skill integrity** — add a `resultSchema` field to `SkillManifest`, consolidate onto the existing `TestRunResult`/`TestCaseResult` shape and single results pipeline (`resultsService.ts` + `AssuranceResults.tsx`), retiring the Streamlit iframe/`postMessage` bridge. Wire `skillService.ts`'s existing `verifyEntry()` digest check into the same stubbed approval-gate hook in `base_agent.py` that item 3's approval-required check uses — one checkpoint doing both "verify before running" and "get human approval before running," so a tampered "protected" skill halts the run instead of executing.

6. **Retire the `iac_mfe_primary` Streamlit remote (Dashboard/Console).** This module-federation remote (`vite.config.ts`) backs `Dashboard.tsx` and `Console.tsx` today — it points at a dev server that isn't running in most dev environments. Registry already got rebuilt off it (see above); these two are the rest. Not a uniform "make it a skill" — the right shape differs per page:
   - **Dashboard** — good fit for the schema-driven skill pattern from item 5: a periodically-invoked skill returns a summary schema (stat tiles, sparklines, recent activity), rendered by trusted host components.
   - **Console** — rebuild natively, *not* as a skill. A console is live/bidirectional (input → streaming output), not a discrete result payload — better fit is a native component reusing the SSE-streaming plumbing `agentService.ts` already has for agent runs (`EventSource` against the phase-stream endpoint).
   - **Registry** — already done; stays native/host-owned rather than becoming skill-authored, since it's core source-of-truth state and letting a skill define/redefine the asset schema would blur a trust boundary that belongs to the host.
   - **Copilot** — already native React (`components/CopilotSidebar/`), not on this remote at all; no rewrite needed. Its content panels (OWASP docs/project docs) could optionally source from the Catalog later — a separate, smaller idea.
   - Once Dashboard and Console are native, remove the `iac_mfe_primary` remote entry from `vite.config.ts` entirely.

7. **Extensions trim-down** — remove non-IDE-enhancement extension categories/installed extensions; keep only IDE-enhancement use cases.

8. **Cross-referencing** — once (1)–(4) exist, wire Testing projects to select a Registry target by ID, and scope Monitoring to registered components.

9. **Enterprise metadata / active discovery** (later still) — add ownership/environment/compliance fields to `RegistryEntryBase`, and a network-discovery mechanism that produces `source: 'discovered'` entries.
