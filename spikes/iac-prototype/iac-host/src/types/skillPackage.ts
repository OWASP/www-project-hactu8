/**
 * Types for Skill Packages — real, filesystem-backed skill directories
 * conforming to the agentskills.io Agent Skills specification.
 *
 * Distinct from the legacy `types/skills.ts` (`SkillManifest`/`InstalledSkill`
 * — a JSON manifest wrapping a whole SKILL.md as one string, localStorage
 * only) and from the unrelated backend tool-registry in
 * `iac-copilot-api/skills/`. Field names are snake_case to match the
 * backend's Pydantic JSON output directly, same convention as `types/agents.ts`.
 */

/** Matches the SKILL.md YAML frontmatter fields defined by the spec. */
export interface SkillPackageManifest {
  name: string;
  description: string;
  license?: string;
  compatibility?: string;
  metadata?: Record<string, string>;
  allowed_tools?: string;
}

/** Lightweight pointer to a skill package installed on disk at
 * `install_path` — not the file contents. */
export interface InstalledSkillPackage {
  name: string;
  install_path: string;
  installed_at: string;
  source: 'upload' | 'host';
  source_filename?: string;
  sha256?: string;
  manifest: SkillPackageManifest;
  files: string[];
}

export interface SkillPackageInstallResponse {
  skill: InstalledSkillPackage;
  warnings: string[];
}

export interface SkillPackageListResponse {
  skills: InstalledSkillPackage[];
  total: number;
}

export interface SkillPackageContextValue {
  installed: InstalledSkillPackage[];
  isLoading: boolean;
  isInstalling: boolean;
  error: string | null;
  refreshInstalled: () => Promise<void>;
  installFromFile: (file: File, overwrite?: boolean) => Promise<InstalledSkillPackage>;
  uninstall: (name: string) => Promise<void>;
}
