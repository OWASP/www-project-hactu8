/**
 * Type definitions for the IAC Agent Catalog.
 *
 * NOT to be confused with `types/agents.ts`, which models a running agent
 * *engagement* (phases, scope, SSE stream events for the single hardcoded
 * "OWASP Test Orchestrator"). This file models agent *definitions* — a
 * browsable/installable registry of agent orchestrators, mirroring the
 * Skills system (`types/skills.ts`) so Agents/Skills/Tools can eventually
 * share one Catalog abstraction (see REDESIGN_PLAN.md roadmap item 2).
 *
 * An installed catalog agent is a *description* of an orchestrator (system
 * prompt/instructions, allowed tool categories, which engagement phase it
 * corresponds to) — installing one does not itself run anything; wiring a
 * catalog entry into the live engagement backend is out of scope here (see
 * REDESIGN_PLAN.md roadmap item 4).
 */

import type { PhaseEnum } from './agents';

// ---------------------------------------------------------------------------
// Category
// ---------------------------------------------------------------------------

/**
 * Logical grouping for browsing/filtering agents in the catalog. Distinct
 * from `SkillCategory` — agents are grouped by the kind of orchestration
 * work they do rather than by assurance-lifecycle activity.
 */
export type AgentCategory =
  | 'planning'
  | 'reconnaissance'
  | 'risk-assessment'
  | 'attack-simulation'
  | 'reporting'
  | 'governance'
  | 'utility';

// ---------------------------------------------------------------------------
// Manifest — describes an agent package
// ---------------------------------------------------------------------------

/** A file bundled alongside an agent definition (reference doc, prompt fragment, etc.) */
export interface AgentResource {
  path: string; // relative path, e.g. "reference/recon-checklist.md"
  description?: string;
}

/** Metadata describing an agent orchestrator definition */
export interface AgentManifest {
  id: string; // unique kebab-case identifier, e.g. "recon-agent"
  name: string;
  version: string; // semver
  description: string;
  author: string;
  license: string;
  category: AgentCategory;
  tags?: string[];
  /**
   * Which engagement phase (see `types/agents.ts` PhaseEnum) this agent
   * definition corresponds to, when applicable. Informational only — this
   * catalog does not wire the entry into the live `iac-copilot-api`
   * engagement backend.
   */
  phase?: PhaseEnum;
  allowedTools?: string[]; // tool/capability names this agent is scoped to use
  resources?: AgentResource[];
  minHostVersion?: string;
}

// ---------------------------------------------------------------------------
// Signing / curation
// ---------------------------------------------------------------------------

/**
 * Integrity + curation record for an agent, identical shape to
 * `SkillSignature`. Curated registry entries carry `verified: true` with a
 * digest computed and checked by the HACTU8 board before merge. Locally
 * authored drafts carry `verified: false` until submitted and signed.
 */
export interface AgentSignature {
  algorithm: 'sha256';
  digest: string; // sha256 of `${manifest.id}@${manifest.version}:${instructions}`
  curatedBy: string; // e.g. "OWASP HACTU8 Agents Board" or "Unsigned local draft"
  signedAt: string; // ISO date
  verified: boolean;
}

// ---------------------------------------------------------------------------
// Registry — agents/registry.json in the HACTU8 GitHub repo
// ---------------------------------------------------------------------------

/** A single curated & signed entry in the remote agents registry */
export interface AgentRegistryEntry {
  manifest: AgentManifest;
  instructions: string; // full system-prompt / instructions for the agent
  signature: AgentSignature;
  publishedAt: string; // ISO date
  updatedAt: string; // ISO date
}

/** Top-level agents/registry.json structure */
export interface AgentRegistry {
  version: string; // registry schema version
  generatedAt: string; // ISO date
  curator: string; // org/board responsible for signing entries
  agents: AgentRegistryEntry[];
}

// ---------------------------------------------------------------------------
// Installed Agent — stored in localStorage by the host
// ---------------------------------------------------------------------------

export type AgentDefinitionStatus = 'installed' | 'active' | 'error';

/** Where an installed agent definition came from */
export type AgentDefinitionSource = 'registry' | 'local-draft';

/** An agent definition that has been installed (or authored locally) on this host */
export interface InstalledAgent {
  manifest: AgentManifest;
  instructions: string;
  signature: AgentSignature;
  status: AgentDefinitionStatus;
  source: AgentDefinitionSource;
  installedAt: string; // ISO date
  lastError?: string;
}

// ---------------------------------------------------------------------------
// Context — state & actions for the AgentCatalogContext provider
// ---------------------------------------------------------------------------

export interface AgentCatalogContextValue {
  installed: InstalledAgent[];
  refreshInstalled: () => void;
  installFromRegistry: (entry: AgentRegistryEntry) => Promise<InstalledAgent[]>;
  uninstallAgent: (agentId: string) => InstalledAgent[];
  saveDraft: (manifest: AgentManifest, instructions: string) => Promise<InstalledAgent[]>;
  updateStatus: (agentId: string, status: AgentDefinitionStatus, errMsg?: string) => InstalledAgent[];
}
