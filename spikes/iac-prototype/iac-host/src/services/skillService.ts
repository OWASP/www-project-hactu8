/**
 * Service for managing IAC skills.
 *
 * Handles localStorage persistence for installed skills, fetching the
 * curated & signed skills registry, integrity verification of registry
 * entries, and authoring/exporting locally-created skill drafts.
 */

import type {
  InstalledSkill,
  SkillManifest,
  SkillRegistry,
  SkillRegistryEntry,
  SkillSignature,
  SkillStatus,
} from '../types/skills';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const STORAGE_KEY = 'iac-skills-installed';
const REGISTRY_URL_KEY = 'iac-skills-registry-url';

// Default: local registry file in dev, GitHub-hosted curated registry in production
const DEFAULT_REGISTRY_URL =
  (import.meta.env.VITE_SKILLS_REGISTRY_URL as string | undefined) ||
  (import.meta.env.DEV
    ? '/skills/registry.json'
    : 'https://raw.githubusercontent.com/OWASP/www-project-hactu8/main/spikes/iac-prototype/skills/registry.json');

// ---------------------------------------------------------------------------
// localStorage helpers
// ---------------------------------------------------------------------------

/** Load all installed/authored skills from localStorage */
export function loadInstalled(): InstalledSkill[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

/** Save installed skills to localStorage */
export function saveInstalled(skills: InstalledSkill[]): void {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(skills));
}

// ---------------------------------------------------------------------------
// Registry URL (user-overridable, like the extension registry)
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

/** Fetch the curated skills registry (skills/registry.json) */
export async function fetchRegistry(): Promise<SkillRegistryEntry[]> {
  const url = getRegistryUrl();
  const response = await fetch(url, { cache: 'no-store' });
  if (!response.ok) {
    throw new Error(`Failed to fetch skills registry (${response.status})`);
  }
  const data: SkillRegistry = await response.json();
  return data.skills ?? [];
}

// ---------------------------------------------------------------------------
// Integrity / signing
// ---------------------------------------------------------------------------

/** Compute the sha256 digest used to sign/verify a skill's manifest + content */
export async function computeDigest(manifest: SkillManifest, content: string): Promise<string> {
  const payload = `${manifest.id}@${manifest.version}:${content}`;
  const bytes = new TextEncoder().encode(payload);
  const hashBuffer = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/** Verify that a registry entry's signature digest matches its manifest + content */
export async function verifyEntry(entry: SkillRegistryEntry): Promise<boolean> {
  const digest = await computeDigest(entry.manifest, entry.content);
  return digest === entry.signature.digest;
}

// ---------------------------------------------------------------------------
// Install / Uninstall (curated registry skills)
// ---------------------------------------------------------------------------

/**
 * Install a skill from the curated registry after verifying its signature.
 * Throws if the digest does not match (tampered/corrupt entry).
 */
export async function installFromRegistry(
  entry: SkillRegistryEntry,
  installed: InstalledSkill[]
): Promise<InstalledSkill[]> {
  if (installed.some((s) => s.manifest.id === entry.manifest.id)) {
    throw new Error(`Skill "${entry.manifest.id}" is already installed`);
  }

  const isValid = await verifyEntry(entry);
  if (!isValid) {
    throw new Error(
      `Signature verification failed for "${entry.manifest.id}" — refusing to install unverified skill`
    );
  }

  const newSkill: InstalledSkill = {
    manifest: entry.manifest,
    content: entry.content,
    signature: entry.signature,
    status: 'installed',
    source: 'registry',
    installedAt: new Date().toISOString(),
  };

  const updated = [...installed, newSkill];
  saveInstalled(updated);
  return updated;
}

export function uninstallSkill(skillId: string, installed: InstalledSkill[]): InstalledSkill[] {
  const updated = installed.filter((s) => s.manifest.id !== skillId);
  saveInstalled(updated);
  return updated;
}

export function updateStatus(
  skillId: string,
  status: SkillStatus,
  installed: InstalledSkill[],
  errMsg?: string
): InstalledSkill[] {
  const updated = installed.map((s) =>
    s.manifest.id === skillId ? { ...s, status, lastError: errMsg } : s
  );
  saveInstalled(updated);
  return updated;
}

// ---------------------------------------------------------------------------
// Authoring (Skills Creator)
// ---------------------------------------------------------------------------

/**
 * Save a locally authored skill draft. Drafts are marked `verified: false`
 * until they are submitted through a PR and signed by the HACTU8 skills
 * board (see `buildRegistrySubmission`).
 */
export async function saveDraft(
  manifest: SkillManifest,
  content: string,
  installed: InstalledSkill[]
): Promise<InstalledSkill[]> {
  const digest = await computeDigest(manifest, content);
  const signature: SkillSignature = {
    algorithm: 'sha256',
    digest,
    curatedBy: 'Unsigned local draft',
    signedAt: new Date().toISOString(),
    verified: false,
  };

  const draft: InstalledSkill = {
    manifest,
    content,
    signature,
    status: 'installed',
    source: 'local-draft',
    installedAt: new Date().toISOString(),
  };

  const withoutExisting = installed.filter((s) => s.manifest.id !== manifest.id);
  const updated = [...withoutExisting, draft];
  saveInstalled(updated);
  return updated;
}

/** Build the exact registry entry JSON a maintainer would sign & merge */
export async function buildRegistrySubmission(skill: InstalledSkill): Promise<SkillRegistryEntry> {
  const digest = await computeDigest(skill.manifest, skill.content);
  const now = new Date().toISOString();
  return {
    manifest: skill.manifest,
    content: skill.content,
    signature: {
      algorithm: 'sha256',
      digest,
      curatedBy: 'OWASP HACTU8 Skills Board',
      signedAt: now,
      verified: true,
    },
    publishedAt: now,
    updatedAt: now,
  };
}

/** Serialize a skill as a downloadable SKILL.md-style bundle (manifest + content) */
export function exportSkillPackage(skill: InstalledSkill): { filename: string; content: string } {
  const frontmatter = [
    '---',
    `id: ${skill.manifest.id}`,
    `name: ${skill.manifest.name}`,
    `version: ${skill.manifest.version}`,
    `description: ${skill.manifest.description}`,
    `author: ${skill.manifest.author}`,
    `license: ${skill.manifest.license}`,
    `category: ${skill.manifest.category}`,
    ...(skill.manifest.tags?.length ? [`tags: [${skill.manifest.tags.join(', ')}]`] : []),
    ...(skill.manifest.allowedTools?.length
      ? [`allowed-tools: [${skill.manifest.allowedTools.join(', ')}]`]
      : []),
    '---',
    '',
  ].join('\n');

  const body = skill.content.startsWith('---') ? skill.content.split(/---\n/).slice(2).join('---\n') : skill.content;
  return {
    filename: `${skill.manifest.id}.SKILL.md`,
    content: `${frontmatter}${body}`,
  };
}

/** Trigger a browser download of a skill package */
export function downloadSkillPackage(skill: InstalledSkill): void {
  const { filename, content } = exportSkillPackage(skill);
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
  uninstallSkill,
  updateStatus,
  saveDraft,
  buildRegistrySubmission,
  exportSkillPackage,
  downloadSkillPackage,
};
