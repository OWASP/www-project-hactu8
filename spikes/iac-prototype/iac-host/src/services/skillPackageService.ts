/**
 * Service for installing/discovering Skill Packages — real, filesystem-backed
 * skill directories on the backend (`~/.iac/skills/<name>/`), conforming to
 * the agentskills.io Agent Skills specification.
 *
 * Mirrors `agentService.ts`'s base-URL pattern (same `iac-copilot-api`
 * backend). Unlike the legacy `skillService.ts`, localStorage here is
 * explicitly a CACHE mirror of disk state — refreshed from
 * `GET /api/skill-packages` (disk is the source of truth) — not the system
 * of record.
 */

import type {
  InstalledSkillPackage,
  SkillPackageInstallResponse,
  SkillPackageListResponse,
} from '../types/skillPackage';

const RAW_BASE = import.meta.env.VITE_COPILOT_API_URL || '';

function normalizeBase(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) return '';
  if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) return trimmed;
  if (trimmed.startsWith('/')) return trimmed;
  const protocol = typeof window !== 'undefined' ? window.location.protocol : 'http:';
  return `${protocol}//${trimmed}`;
}

const API_BASE = normalizeBase(RAW_BASE);
const STORAGE_KEY = 'iac-skill-packages-installed';

/** Cached list from the last successful `listSkillPackages()` call — a
 * convenience mirror for fast initial render, not authoritative. */
export function loadCached(): InstalledSkillPackage[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

function saveCache(skills: InstalledSkillPackage[]): void {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(skills));
}

export async function uploadSkillPackage(
  file: File,
  overwrite = false
): Promise<SkillPackageInstallResponse> {
  const formData = new FormData();
  formData.append('file', file);
  formData.append('overwrite', String(overwrite));

  const response = await fetch(`${API_BASE}/api/skill-packages`, {
    method: 'POST',
    body: formData,
  });
  if (!response.ok) {
    throw new Error(`Install failed (${response.status}): ${await response.text()}`);
  }
  return response.json();
}

export async function listSkillPackages(): Promise<InstalledSkillPackage[]> {
  const response = await fetch(`${API_BASE}/api/skill-packages`);
  if (!response.ok) {
    throw new Error(`List failed (${response.status}): ${await response.text()}`);
  }
  const data: SkillPackageListResponse = await response.json();
  saveCache(data.skills);
  return data.skills;
}

export async function uninstallSkillPackage(name: string): Promise<void> {
  const response = await fetch(`${API_BASE}/api/skill-packages/${encodeURIComponent(name)}`, {
    method: 'DELETE',
  });
  if (!response.ok) {
    throw new Error(`Uninstall failed (${response.status}): ${await response.text()}`);
  }
  saveCache(loadCached().filter((s) => s.name !== name));
}

export default {
  loadCached,
  uploadSkillPackage,
  listSkillPackages,
  uninstallSkillPackage,
};
