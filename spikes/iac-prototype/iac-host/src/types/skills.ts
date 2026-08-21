/**
 * Type definitions for the IAC Skills System.
 *
 * Skills are portable, markdown-based instruction packages (Anthropic
 * "Agent Skills" style: a SKILL.md with YAML frontmatter plus optional
 * resources) that can be authored, installed, and used from the Assurance
 * Center. Curated skills are published to a signed registry hosted in the
 * HACTU8 GitHub repo; anyone can also author local/unsigned drafts.
 */

// ---------------------------------------------------------------------------
// Category
// ---------------------------------------------------------------------------

/** Logical grouping for browsing/filtering skills in the Assurance Center */
export type SkillCategory =
  | 'assurance-testing'
  | 'remediation'
  | 'reporting'
  | 'governance'
  | 'research'
  | 'automation'
  | 'utility';

// ---------------------------------------------------------------------------
// Manifest — describes a skill package
// ---------------------------------------------------------------------------

/** A file bundled alongside SKILL.md (script, reference doc, template, etc.) */
export interface SkillResource {
  path: string; // relative path, e.g. "scripts/check.py" or "reference/checklist.md"
  description?: string;
}

/** Metadata describing a skill package (mirrors YAML frontmatter of SKILL.md) */
export interface SkillManifest {
  id: string; // unique kebab-case identifier, e.g. "owasp-llm-top10-review"
  name: string;
  version: string; // semver
  description: string;
  author: string;
  license: string;
  category: SkillCategory;
  tags?: string[];
  allowedTools?: string[]; // tool/capability names this skill is scoped to use
  resources?: SkillResource[];
  minHostVersion?: string;
  /**
   * Names the shape of structured result data this skill is expected to
   * produce when run, so the host can render it with a known component
   * instead of freeform text. E.g. `'assurance-test-run'` means the skill's
   * output conforms to `TestRunResult` (see `types/extensions.ts`) and can
   * be rendered by the Assurance Results view / `resultsService.ts`.
   *
   * This is a lightweight, documented convention rather than an enforced
   * schema registry — unrecognized values (or skills that omit the field
   * entirely) just mean "no structured rendering, treat output as
   * freeform." Consolidating fully onto `TestRunResult` for every skill
   * category and retiring the Streamlit iframe/postMessage bridge is
   * tracked separately (see REDESIGN_PLAN.md roadmap item 6).
   */
  resultSchema?: string;
}

// ---------------------------------------------------------------------------
// Signing / curation
// ---------------------------------------------------------------------------

/**
 * Integrity + curation record for a skill. Curated registry entries carry
 * `verified: true` with a digest computed and checked by the HACTU8 skills
 * board before merge. Locally authored drafts carry `verified: false` until
 * they are submitted and signed.
 */
export interface SkillSignature {
  algorithm: 'sha256';
  digest: string; // sha256 of `${manifest.id}@${manifest.version}:${content}`
  curatedBy: string; // e.g. "OWASP HACTU8 Skills Board" or "Unsigned local draft"
  signedAt: string; // ISO date
  verified: boolean;
}

// ---------------------------------------------------------------------------
// Registry — skills/registry.json in the HACTU8 GitHub repo
// ---------------------------------------------------------------------------

/** A single curated & signed entry in the remote skills registry */
export interface SkillRegistryEntry {
  manifest: SkillManifest;
  content: string; // full SKILL.md contents (YAML frontmatter + markdown body)
  signature: SkillSignature;
  publishedAt: string; // ISO date
  updatedAt: string; // ISO date
}

/** Top-level skills/registry.json structure */
export interface SkillRegistry {
  version: string; // registry schema version
  generatedAt: string; // ISO date
  curator: string; // org/board responsible for signing entries
  skills: SkillRegistryEntry[];
}

// ---------------------------------------------------------------------------
// Installed Skill — stored in localStorage by the host
// ---------------------------------------------------------------------------

export type SkillStatus = 'installed' | 'active' | 'error';

/** Where an installed skill came from */
export type SkillSource = 'registry' | 'local-draft';

/** A skill that has been installed (or authored locally) on this host */
export interface InstalledSkill {
  manifest: SkillManifest;
  content: string;
  signature: SkillSignature;
  status: SkillStatus;
  source: SkillSource;
  installedAt: string; // ISO date
  lastError?: string;
}

// ---------------------------------------------------------------------------
// Context — state & actions for the SkillContext provider
// ---------------------------------------------------------------------------

export interface SkillContextValue {
  installed: InstalledSkill[];
  refreshInstalled: () => void;
  installFromRegistry: (entry: SkillRegistryEntry) => Promise<InstalledSkill[]>;
  uninstallSkill: (skillId: string) => InstalledSkill[];
  saveDraft: (manifest: SkillManifest, content: string) => Promise<InstalledSkill[]>;
  updateStatus: (skillId: string, status: SkillStatus, errMsg?: string) => InstalledSkill[];
}
