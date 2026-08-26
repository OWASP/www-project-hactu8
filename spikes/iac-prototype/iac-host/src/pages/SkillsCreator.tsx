// src/pages/SkillsCreator.tsx
//
// Scaffold a real, agentskills.io-spec-compliant skill directory
// (SKILL.md + optional scripts/references/assets), zip it entirely in the
// browser, and install it through the same pipeline a manually-uploaded
// .skill file goes through (POST /api/skill-packages) — zip-slip-safe
// extraction, frontmatter validation, the works. This page produces real
// Skill Packages now, not the old localStorage-only draft format; created
// skills show up in the "Agent Skills" tab on the Installed page, not
// "Legacy Skills".
import React, { useMemo, useState } from 'react';
import { zipSync, strToU8 } from 'fflate';
import { Link } from 'react-router-dom';
import skillPackageService from '../services/skillPackageService';
import { primaryButtonStyle, secondaryButtonStyle, codeBlockStyle } from '../components/Skills/shared';

type PlaceholderFolder = 'scripts' | 'references' | 'assets';

interface PlaceholderFile {
  folder: PlaceholderFolder;
  filename: string;
  content: string;
}

const inputStyle: React.CSSProperties = {
  width: '100%',
  padding: '0.5rem 0.6rem',
  borderRadius: '4px',
  border: '1px solid var(--iac-border)',
  background: 'var(--iac-bg)',
  color: 'var(--iac-text)',
  fontSize: '0.875rem',
};

const labelStyle: React.CSSProperties = {
  display: 'block',
  fontSize: '0.75rem',
  fontWeight: 600,
  color: 'var(--iac-muted)',
  marginBottom: '0.25rem',
};

const fieldWrapStyle: React.CSSProperties = { marginBottom: '1rem' };

const DEFAULT_BODY = `# Instructions

Describe the step-by-step approach to follow when this skill applies.
`;

// Matches skill_packages/installer.py's _is_valid_skill_name exactly.
function isValidSkillName(name: string): boolean {
  if (!name || name.length > 64) return false;
  if (name.includes('--') || name.startsWith('-') || name.endsWith('-')) return false;
  return /^[a-z0-9-]+$/.test(name);
}

function buildFrontmatter(fields: {
  name: string;
  description: string;
  license: string;
  compatibility: string;
  metadata: { key: string; value: string }[];
  allowedTools: string;
}): string {
  const lines = ['---', `name: ${fields.name}`, `description: ${fields.description}`];
  if (fields.license.trim()) lines.push(`license: ${fields.license.trim()}`);
  if (fields.compatibility.trim()) lines.push(`compatibility: ${fields.compatibility.trim()}`);
  const meta = fields.metadata.filter((m) => m.key.trim());
  if (meta.length > 0) {
    lines.push('metadata:');
    meta.forEach((m) => lines.push(`  ${m.key.trim()}: ${m.value.trim()}`));
  }
  if (fields.allowedTools.trim()) lines.push(`allowed-tools: ${fields.allowedTools.trim()}`);
  lines.push('---', '');
  return lines.join('\n');
}

const SkillsCreator: React.FC = () => {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [license, setLicense] = useState('');
  const [compatibility, setCompatibility] = useState('');
  const [metadata, setMetadata] = useState<{ key: string; value: string }[]>([]);
  const [allowedTools, setAllowedTools] = useState('');
  const [body, setBody] = useState(DEFAULT_BODY);
  const [files, setFiles] = useState<PlaceholderFile[]>([]);

  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successName, setSuccessName] = useState<string | null>(null);

  const nameError = name.length > 0 && !isValidSkillName(name)
    ? 'Must be 1-64 lowercase alphanumeric characters and hyphens, no leading/trailing/consecutive hyphens.'
    : null;
  const descriptionError = description.length > 1024 ? 'Must be 1024 characters or fewer.' : null;

  const isValid =
    isValidSkillName(name) &&
    description.trim().length > 0 &&
    description.length <= 1024 &&
    body.trim().length > 0;

  const frontmatter = useMemo(
    () => buildFrontmatter({ name, description, license, compatibility, metadata, allowedTools }),
    [name, description, license, compatibility, metadata, allowedTools]
  );
  const skillMdPreview = frontmatter + body;

  const addFile = () => setFiles((f) => [...f, { folder: 'scripts', filename: '', content: '' }]);
  const updateFile = (idx: number, patch: Partial<PlaceholderFile>) =>
    setFiles((f) => f.map((file, i) => (i === idx ? { ...file, ...patch } : file)));
  const removeFile = (idx: number) => setFiles((f) => f.filter((_, i) => i !== idx));

  const handleCreateAndInstall = async () => {
    setError(null);
    setSuccessName(null);
    if (!isValid) {
      setError('Skill name, description, and SKILL.md body are required (and must pass validation above).');
      return;
    }

    setIsSubmitting(true);
    try {
      const fileMap: Record<string, Uint8Array> = {
        [`${name}/SKILL.md`]: strToU8(skillMdPreview),
      };
      for (const file of files) {
        if (!file.filename.trim()) continue;
        fileMap[`${name}/${file.folder}/${file.filename.trim()}`] = strToU8(
          file.content || `# Placeholder for ${file.filename.trim()}\n`
        );
      }

      const zipBytes = zipSync(fileMap);
      const zipFile = new File([zipBytes], `${name}.skill`, { type: 'application/zip' });

      await skillPackageService.uploadSkillPackage(zipFile);
      setSuccessName(name);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create and install skill');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div style={{ display: 'flex', gap: '1.5rem', padding: '1.5rem', height: '100%', overflowY: 'auto' }}>
      {/* Form */}
      <div style={{ flex: '1 1 420px', minWidth: 360 }}>
        <h3 style={{ color: 'var(--iac-text)', marginBottom: '0.25rem' }}>Skills Creator</h3>
        <p style={{ color: 'var(--iac-muted)', fontSize: '0.8rem', marginTop: 0, marginBottom: '1.25rem' }}>
          Scaffold a real Skill Package (SKILL.md + optional files) and install it directly — no separate export
          or submission step. It's droppable into Claude Code or any agentskills.io-compliant tool afterward.
        </p>

        <div style={fieldWrapStyle}>
          <label style={labelStyle}>Name</label>
          <input style={inputStyle} value={name} onChange={(e) => setName(e.target.value)} placeholder="owasp-llm-top10-review" />
          {nameError && <p style={{ color: 'var(--iac-error)', fontSize: '0.75rem', marginTop: '0.25rem' }}>{nameError}</p>}
        </div>

        <div style={fieldWrapStyle}>
          <label style={labelStyle}>Description</label>
          <input
            style={inputStyle}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Describes what the skill does and when to use it."
          />
          {descriptionError && (
            <p style={{ color: 'var(--iac-error)', fontSize: '0.75rem', marginTop: '0.25rem' }}>{descriptionError}</p>
          )}
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
          <div style={fieldWrapStyle}>
            <label style={labelStyle}>License (optional)</label>
            <input style={inputStyle} value={license} onChange={(e) => setLicense(e.target.value)} placeholder="Apache-2.0" />
          </div>
          <div style={fieldWrapStyle}>
            <label style={labelStyle}>Compatibility (optional)</label>
            <input
              style={inputStyle}
              value={compatibility}
              onChange={(e) => setCompatibility(e.target.value)}
              placeholder="Requires network access"
            />
          </div>
        </div>

        <div style={fieldWrapStyle}>
          <label style={labelStyle}>Allowed Tools (optional)</label>
          <input
            style={inputStyle}
            value={allowedTools}
            onChange={(e) => setAllowedTools(e.target.value)}
            placeholder="Bash(git:*) Read"
          />
          <p style={{ color: 'var(--iac-muted)', fontSize: '0.75rem', marginTop: '0.25rem', marginBottom: 0 }}>
            Space-separated tool patterns, per the spec — not a comma-separated list.
          </p>
        </div>

        <div style={fieldWrapStyle}>
          <label style={labelStyle}>Metadata (optional)</label>
          {metadata.map((m, idx) => (
            <div key={idx} style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.5rem' }}>
              <input
                style={inputStyle}
                value={m.key}
                onChange={(e) => setMetadata((cur) => cur.map((x, i) => (i === idx ? { ...x, key: e.target.value } : x)))}
                placeholder="key"
              />
              <input
                style={inputStyle}
                value={m.value}
                onChange={(e) => setMetadata((cur) => cur.map((x, i) => (i === idx ? { ...x, value: e.target.value } : x)))}
                placeholder="value"
              />
              <button onClick={() => setMetadata((cur) => cur.filter((_, i) => i !== idx))} style={secondaryButtonStyle}>✕</button>
            </div>
          ))}
          <button onClick={() => setMetadata((cur) => [...cur, { key: '', value: '' }])} style={secondaryButtonStyle}>
            + Add Metadata
          </button>
        </div>

        <div style={fieldWrapStyle}>
          <label style={labelStyle}>SKILL.md Body</label>
          <textarea
            style={{ ...inputStyle, minHeight: 200, fontFamily: 'monospace', resize: 'vertical' }}
            value={body}
            onChange={(e) => setBody(e.target.value)}
          />
        </div>

        <div style={fieldWrapStyle}>
          <label style={labelStyle}>Files (scripts / references / assets)</label>
          {files.map((file, idx) => (
            <div key={idx} style={{ marginBottom: '0.75rem', padding: '0.5rem', border: '1px solid var(--iac-border)', borderRadius: '4px' }}>
              <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.5rem' }}>
                <select
                  style={inputStyle}
                  value={file.folder}
                  onChange={(e) => updateFile(idx, { folder: e.target.value as PlaceholderFolder })}
                >
                  <option value="scripts">scripts/</option>
                  <option value="references">references/</option>
                  <option value="assets">assets/</option>
                </select>
                <input
                  style={inputStyle}
                  value={file.filename}
                  onChange={(e) => updateFile(idx, { filename: e.target.value })}
                  placeholder="check.py"
                />
                <button onClick={() => removeFile(idx)} style={secondaryButtonStyle}>✕</button>
              </div>
              <textarea
                style={{ ...inputStyle, minHeight: 80, fontFamily: 'monospace', resize: 'vertical' }}
                value={file.content}
                onChange={(e) => updateFile(idx, { content: e.target.value })}
                placeholder="Leave blank for a placeholder stub"
              />
            </div>
          ))}
          <button onClick={addFile} style={secondaryButtonStyle}>+ Add File</button>
        </div>

        {error && <p style={{ color: 'var(--iac-error)', fontSize: '0.85rem' }}>{error}</p>}
        {successName && (
          <p style={{ color: 'var(--iac-success)', fontSize: '0.85rem' }}>
            Installed "{successName}". View it in{' '}
            <Link to="/skills/installed" style={{ color: 'var(--iac-link, var(--iac-accent))' }}>
              Installed Skills → Agent Skills
            </Link>.
          </p>
        )}

        <div style={{ display: 'flex', gap: '0.5rem', marginTop: '1rem' }}>
          <button onClick={handleCreateAndInstall} style={primaryButtonStyle} disabled={isSubmitting}>
            {isSubmitting ? 'Creating…' : 'Create & Install'}
          </button>
        </div>
      </div>

      {/* Preview */}
      <div style={{ flex: '1 1 420px', minWidth: 360 }}>
        <h4 style={{ color: 'var(--iac-text)', marginBottom: '0.5rem' }}>SKILL.md Preview</h4>
        <pre style={{ ...codeBlockStyle, minHeight: 200 }}>{skillMdPreview}</pre>

        {files.length > 0 && (
          <div style={{ marginTop: '1.5rem' }}>
            <h4 style={{ color: 'var(--iac-text)', marginBottom: '0.5rem' }}>Directory Structure</h4>
            <pre style={codeBlockStyle}>
              {`${name || '<name>'}/\n  SKILL.md\n${files
                .filter((f) => f.filename.trim())
                .map((f) => `  ${f.folder}/${f.filename}`)
                .join('\n')}`}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
};

export default SkillsCreator;
