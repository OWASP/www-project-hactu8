/**
 * Service for discovering curated ("canned") Projects — read-only, served
 * from iac-copilot-api/canned_projects/ on disk. Mirrors
 * skillPackageService.ts's base-URL pattern (same iac-copilot-api backend).
 */

import type {
  CannedProjectDetail,
  CannedProjectListResponse,
  CannedProjectSummary,
} from '../types/project';

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

export async function listCannedProjects(): Promise<CannedProjectSummary[]> {
  const response = await fetch(`${API_BASE}/api/canned-projects`);
  if (!response.ok) {
    throw new Error(`List canned projects failed (${response.status}): ${await response.text()}`);
  }
  const data: CannedProjectListResponse = await response.json();
  return data.projects;
}

export async function getCannedProject(projectId: string): Promise<CannedProjectDetail | null> {
  const response = await fetch(`${API_BASE}/api/canned-projects/${encodeURIComponent(projectId)}`);
  if (response.status === 404) return null;
  if (!response.ok) {
    throw new Error(`Get canned project failed (${response.status}): ${await response.text()}`);
  }
  return response.json();
}

export default {
  listCannedProjects,
  getCannedProject,
};
