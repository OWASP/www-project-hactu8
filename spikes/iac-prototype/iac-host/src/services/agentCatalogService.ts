/**
 * Service for managing the IAC Agent Catalog.
 *
 * Mirrors `skillService.ts`: localStorage persistence for installed agent
 * definitions, fetching the curated & signed agents registry, integrity
 * verification of registry entries, and authoring/exporting locally-created
 * agent drafts. This is catalog/definition management only — it does not
 * start or drive a live engagement (see `services/agentService.ts` for that).
 */

import type {
  AgentManifest,
  AgentRegistry,
  AgentRegistryEntry,
  AgentSignature,
  AgentDefinitionStatus,
  InstalledAgent,
} from '../types/agentCatalog';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const STORAGE_KEY = 'iac-agents-catalog-installed';
const REGISTRY_URL_KEY = 'iac-agents-catalog-registry-url';

// Default: local registry file in dev, GitHub-hosted curated registry in production
const DEFAULT_REGISTRY_URL =
  (import.meta.env.VITE_AGENTS_REGISTRY_URL as string | undefined) ||
  (import.meta.env.DEV
    ? '/agents/registry.json'
    : 'https://raw.githubusercontent.com/OWASP/www-project-hactu8/main/spikes/iac-prototype/agents/registry.json');

// ---------------------------------------------------------------------------
// localStorage helpers
// ---------------------------------------------------------------------------

/** Load all installed/authored agent definitions from localStorage */
export function loadInstalled(): InstalledAgent[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

/** Save installed agent definitions to localStorage */
export function saveInstalled(agents: InstalledAgent[]): void {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(agents));
}

// ---------------------------------------------------------------------------
// Registry URL (user-overridable, like the skills/extension registry)
// ---------------------------------------------------------------------------

export function getRegistryUrl(): string {
  return localStorage.getItem(REGISTRY_URL_KEY) || DEFAULT_REGISTRY_URL;
}

export function setRegistryUrl(url: string): void {
  localStorage.setItem(REGISTRY_URL_KEY, url);
}

export function resetRegistryUrl(): void {
  localStorage.removeItem(REGISTRY_URL_KEY);
}

/** Fetch the curated agents registry (agents/registry.json) */
export async function fetchRegistry(): Promise<AgentRegistryEntry[]> {
  const url = getRegistryUrl();
  const response = await fetch(url, { cache: 'no-store' });
  if (!response.ok) {
    throw new Error(`Failed to fetch agents registry (${response.status})`);
  }
  const data: AgentRegistry = await response.json();
  return data.agents ?? [];
}

// ---------------------------------------------------------------------------
// Integrity / signing
// ---------------------------------------------------------------------------

/** Compute the sha256 digest used to sign/verify an agent's manifest + instructions */
export async function computeDigest(manifest: AgentManifest, instructions: string): Promise<string> {
  const payload = `${manifest.id}@${manifest.version}:${instructions}`;
  const bytes = new TextEncoder().encode(payload);
  const hashBuffer = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/** Verify that a registry entry's signature digest matches its manifest + instructions */
export async function verifyEntry(entry: AgentRegistryEntry): Promise<boolean> {
  const digest = await computeDigest(entry.manifest, entry.instructions);
  return digest === entry.signature.digest;
}

// ---------------------------------------------------------------------------
// Install / Uninstall (curated registry agents)
// ---------------------------------------------------------------------------

/**
 * Install an agent definition from the curated registry after verifying its
 * signature. Throws if the digest does not match (tampered/corrupt entry).
 */
export async function installFromRegistry(
  entry: AgentRegistryEntry,
  installed: InstalledAgent[]
): Promise<InstalledAgent[]> {
  if (installed.some((a) => a.manifest.id === entry.manifest.id)) {
    throw new Error(`Agent "${entry.manifest.id}" is already installed`);
  }

  const isValid = await verifyEntry(entry);
  if (!isValid) {
    throw new Error(
      `Signature verification failed for "${entry.manifest.id}" — refusing to install unverified agent`
    );
  }

  const newAgent: InstalledAgent = {
    manifest: entry.manifest,
    instructions: entry.instructions,
    signature: entry.signature,
    status: 'installed',
    source: 'registry',
    installedAt: new Date().toISOString(),
  };

  const updated = [...installed, newAgent];
  saveInstalled(updated);
  return updated;
}

export function uninstallAgent(agentId: string, installed: InstalledAgent[]): InstalledAgent[] {
  const updated = installed.filter((a) => a.manifest.id !== agentId);
  saveInstalled(updated);
  return updated;
}

export function updateStatus(
  agentId: string,
  status: AgentDefinitionStatus,
  installed: InstalledAgent[],
  errMsg?: string
): InstalledAgent[] {
  const updated = installed.map((a) =>
    a.manifest.id === agentId ? { ...a, status, lastError: errMsg } : a
  );
  saveInstalled(updated);
  return updated;
}

// ---------------------------------------------------------------------------
// Authoring (Agents Creator)
// ---------------------------------------------------------------------------

/**
 * Save a locally authored agent draft. Drafts are marked `verified: false`
 * until they are submitted through a PR and signed by the HACTU8 board (see
 * `buildRegistrySubmission`).
 */
export async function saveDraft(
  manifest: AgentManifest,
  instructions: string,
  installed: InstalledAgent[]
): Promise<InstalledAgent[]> {
  const digest = await computeDigest(manifest, instructions);
  const signature: AgentSignature = {
    algorithm: 'sha256',
    digest,
    curatedBy: 'Unsigned local draft',
    signedAt: new Date().toISOString(),
    verified: false,
  };

  const draft: InstalledAgent = {
    manifest,
    instructions,
    signature,
    status: 'installed',
    source: 'local-draft',
    installedAt: new Date().toISOString(),
  };

  const withoutExisting = installed.filter((a) => a.manifest.id !== manifest.id);
  const updated = [...withoutExisting, draft];
  saveInstalled(updated);
  return updated;
}

/** Build the exact registry entry JSON a maintainer would sign & merge */
export async function buildRegistrySubmission(agent: InstalledAgent): Promise<AgentRegistryEntry> {
  const digest = await computeDigest(agent.manifest, agent.instructions);
  const now = new Date().toISOString();
  return {
    manifest: agent.manifest,
    instructions: agent.instructions,
    signature: {
      algorithm: 'sha256',
      digest,
      curatedBy: 'OWASP HACTU8 Agents Board',
      signedAt: now,
      verified: true,
    },
    publishedAt: now,
    updatedAt: now,
  };
}

/** Serialize an agent as a downloadable definition bundle (manifest + instructions) */
export function exportAgentPackage(agent: InstalledAgent): { filename: string; content: string } {
  const frontmatter = [
    '---',
    `id: ${agent.manifest.id}`,
    `name: ${agent.manifest.name}`,
    `version: ${agent.manifest.version}`,
    `description: ${agent.manifest.description}`,
    `author: ${agent.manifest.author}`,
    `license: ${agent.manifest.license}`,
    `category: ${agent.manifest.category}`,
    ...(agent.manifest.phase ? [`phase: ${agent.manifest.phase}`] : []),
    ...(agent.manifest.tags?.length ? [`tags: [${agent.manifest.tags.join(', ')}]`] : []),
    ...(agent.manifest.allowedTools?.length
      ? [`allowed-tools: [${agent.manifest.allowedTools.join(', ')}]`]
      : []),
    '---',
    '',
  ].join('\n');

  const body = agent.instructions.startsWith('---')
    ? agent.instructions.split(/---\n/).slice(2).join('---\n')
    : agent.instructions;
  return {
    filename: `${agent.manifest.id}.AGENT.md`,
    content: `${frontmatter}${body}`,
  };
}

/** Trigger a browser download of an agent package */
export function downloadAgentPackage(agent: InstalledAgent): void {
  const { filename, content } = exportAgentPackage(agent);
  const blob = new Blob([content], { type: 'text/markdown' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

export default {
  loadInstalled,
  saveInstalled,
  getRegistryUrl,
  setRegistryUrl,
  resetRegistryUrl,
  fetchRegistry,
  computeDigest,
  verifyEntry,
  installFromRegistry,
  uninstallAgent,
  updateStatus,
  saveDraft,
  buildRegistrySubmission,
  exportAgentPackage,
  downloadAgentPackage,
};
