// src/pages/SkillsCreator.tsx
//
// Author new skills (Anthropic Agent Skills style: YAML frontmatter + a
// markdown SKILL.md body). Drafts are saved locally as unsigned skills;
// "Prepare Registry Submission" produces the exact signed JSON entry a
// HACTU8 maintainer would review and merge into skills/registry.json.
import React, { useMemo, useState } from 'react';
import type { SkillCategory, SkillManifest, SkillRegistryEntry, SkillResource } from '../types/skills';
import { useSkills } from '../contexts/SkillContext';
import skillService from '../services/skillService';
import { CATEGORY_LABELS, primaryButtonStyle, secondaryButtonStyle, codeBlockStyle } from '../components/Skills/shared';

const DEFAULT_CONTENT = `---
name: My New Skill
description: One sentence describing when Copilot should use this skill.
---

# My New Skill

## Instructions

Describe the step-by-step approach to follow when this skill applies.

## Resources

- \`reference/checklist.md\` — supporting reference material
`;

const CATEGORIES: SkillCategory[] = [
  'assurance-testing',
  'remediation',
  'reporting',
  'governance',
  'research',
  'automation',
  'utility',
];

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

const SkillsCreator: React.FC = () => {
  const { saveDraft } = useSkills();

  const [id, setId] = useState('');
  const [name, setName] = useState('');
  const [version, setVersion] = useState('0.1.0');
  const [description, setDescription] = useState('');
  const [author, setAuthor] = useState('');
  const [license, setLicense] = useState('Apache-2.0');
  const [category, setCategory] = useState<SkillCategory>('assurance-testing');
  const [tagsInput, setTagsInput] = useState('');
  const [allowedToolsInput, setAllowedToolsInput] = useState('');
  const [resultSchema, setResultSchema] = useState('');
  const [resources, setResources] = useState<SkillResource[]>([]);
  const [content, setContent] = useState(DEFAULT_CONTENT);

  const [saveMessage, setSaveMessage] = useState<string | null>(null);
  const [submission, setSubmission] = useState<SkillRegistryEntry | null>(null);
  const [error, setError] = useState<string | null>(null);

  const manifest: SkillManifest = useMemo(
    () => ({
      id: id.trim(),
      name: name.trim(),
      version: version.trim(),
      description: description.trim(),
      author: author.trim(),
      license: license.trim(),
      category,
      tags: tagsInput.split(',').map((t) => t.trim()).filter(Boolean),
      allowedTools: allowedToolsInput.split(',').map((t) => t.trim()).filter(Boolean),
      resources,
      resultSchema: resultSchema.trim() || undefined,
    }),
    [id, name, version, description, author, license, category, tagsInput, allowedToolsInput, resources, resultSchema]
  );

  const isValid = manifest.id.length > 0 && manifest.name.length > 0 && manifest.description.length > 0 && content.trim().length > 0;

  const addResource = () => setResources((r) => [...r, { path: '', description: '' }]);
  const updateResource = (idx: number, field: keyof SkillResource, value: string) =>
    setResources((r) => r.map((res, i) => (i === idx ? { ...res, [field]: value } : res)));
  const removeResource = (idx: number) => setResources((r) => r.filter((_, i) => i !== idx));

  const handleSaveDraft = () => {
    setError(null);
    setSaveMessage(null);
    setSubmission(null);
    if (!isValid) {
      setError('Skill id, name, description, and SKILL.md content are required.');
      return;
    }
    saveDraft(manifest, content)
      .then(() => setSaveMessage(`Draft "${manifest.id}" saved to Installed Skills.`))
      .catch((err) => setError(err instanceof Error ? err.message : 'Failed to save draft'));
  };

  const handleExport = () => {
    if (!isValid) {
      setError('Skill id, name, description, and SKILL.md content are required.');
      return;
    }
    skillService.downloadSkillPackage({
      manifest,
      content,
      signature: { algorithm: 'sha256', digest: '', curatedBy: 'Unsigned local draft', signedAt: new Date().toISOString(), verified: false },
      status: 'installed',
      source: 'local-draft',
      installedAt: new Date().toISOString(),
    });
  };

  const handlePrepareSubmission = async () => {
    setError(null);
    if (!isValid) {
      setError('Skill id, name, description, and SKILL.md content are required.');
      return;
    }
    const entry = await skillService.buildRegistrySubmission({
      manifest,
      content,
      signature: { algorithm: 'sha256', digest: '', curatedBy: '', signedAt: '', verified: false },
      status: 'installed',
      source: 'local-draft',
      installedAt: new Date().toISOString(),
    });
    setSubmission(entry);
  };

  return (
    <div style={{ display: 'flex', gap: '1.5rem', padding: '1.5rem', height: '100%', overflowY: 'auto' }}>
      {/* Form */}
      <div style={{ flex: '1 1 420px', minWidth: 360 }}>
        <h3 style={{ color: 'var(--iac-text)', marginBottom: '0.25rem' }}>Skills Creator</h3>
        <p style={{ color: 'var(--iac-muted)', fontSize: '0.8rem', marginTop: 0, marginBottom: '1.25rem' }}>
          Author a new skill package. Save a local draft, export it as a portable file, or prepare a signed
          submission for the curated HACTU8 registry.
        </p>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
          <div style={fieldWrapStyle}>
            <label style={labelStyle}>Skill ID</label>
            <input style={inputStyle} value={id} onChange={(e) => setId(e.target.value)} placeholder="owasp-llm-top10-review" />
          </div>
          <div style={fieldWrapStyle}>
            <label style={labelStyle}>Version</label>
            <input style={inputStyle} value={version} onChange={(e) => setVersion(e.target.value)} placeholder="0.1.0" />
          </div>
        </div>

        <div style={fieldWrapStyle}>
          <label style={labelStyle}>Name</label>
          <input style={inputStyle} value={name} onChange={(e) => setName(e.target.value)} placeholder="OWASP LLM Top 10 Review" />
        </div>

        <div style={fieldWrapStyle}>
          <label style={labelStyle}>Description</label>
          <input
            style={inputStyle}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="One sentence describing when this skill should be used."
          />
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
          <div style={fieldWrapStyle}>
            <label style={labelStyle}>Author</label>
            <input style={inputStyle} value={author} onChange={(e) => setAuthor(e.target.value)} />
          </div>
          <div style={fieldWrapStyle}>
            <label style={labelStyle}>License</label>
            <input style={inputStyle} value={license} onChange={(e) => setLicense(e.target.value)} />
          </div>
        </div>

        <div style={fieldWrapStyle}>
          <label style={labelStyle}>Category</label>
          <select style={inputStyle} value={category} onChange={(e) => setCategory(e.target.value as SkillCategory)}>
            {CATEGORIES.map((c) => (
              <option key={c} value={c}>{CATEGORY_LABELS[c]}</option>
            ))}
          </select>
        </div>

        <div style={fieldWrapStyle}>
          <label style={labelStyle}>Tags (comma-separated)</label>
          <input style={inputStyle} value={tagsInput} onChange={(e) => setTagsInput(e.target.value)} placeholder="owasp, llm, review" />
        </div>

        <div style={fieldWrapStyle}>
          <label style={labelStyle}>Allowed Tools (comma-separated)</label>
          <input
            style={inputStyle}
            value={allowedToolsInput}
            onChange={(e) => setAllowedToolsInput(e.target.value)}
            placeholder="grep_search, read_file"
          />
        </div>

        <div style={fieldWrapStyle}>
          <label style={labelStyle}>Result Schema (optional)</label>
          <input
            style={inputStyle}
            value={resultSchema}
            onChange={(e) => setResultSchema(e.target.value)}
            placeholder="assurance-test-run"
          />
          <p style={{ color: 'var(--iac-muted)', fontSize: '0.75rem', marginTop: '0.25rem', marginBottom: 0 }}>
            Names the shape of structured result data this skill produces, e.g. <code>assurance-test-run</code>{' '}
            for output that conforms to <code>TestRunResult</code>. Leave blank if this skill only produces
            freeform text.
          </p>
        </div>

        <div style={fieldWrapStyle}>
          <label style={labelStyle}>Resources</label>
          {resources.map((res, idx) => (
            <div key={idx} style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.5rem' }}>
              <input
                style={inputStyle}
                value={res.path}
                onChange={(e) => updateResource(idx, 'path', e.target.value)}
                placeholder="reference/checklist.md"
              />
              <input
                style={inputStyle}
                value={res.description ?? ''}
                onChange={(e) => updateResource(idx, 'description', e.target.value)}
                placeholder="Description"
              />
              <button onClick={() => removeResource(idx)} style={secondaryButtonStyle}>✕</button>
            </div>
          ))}
          <button onClick={addResource} style={secondaryButtonStyle}>+ Add Resource</button>
        </div>

        <div style={fieldWrapStyle}>
          <label style={labelStyle}>SKILL.md Content</label>
          <textarea
            style={{ ...inputStyle, minHeight: 260, fontFamily: 'monospace', resize: 'vertical' }}
            value={content}
            onChange={(e) => setContent(e.target.value)}
          />
        </div>

        {error && <p style={{ color: 'var(--iac-error)', fontSize: '0.85rem' }}>{error}</p>}
        {saveMessage && <p style={{ color: 'var(--iac-success)', fontSize: '0.85rem' }}>{saveMessage}</p>}

        <div style={{ display: 'flex', gap: '0.5rem', marginTop: '1rem', flexWrap: 'wrap' }}>
          <button onClick={handleSaveDraft} style={primaryButtonStyle}>Save Draft</button>
          <button onClick={handleExport} style={secondaryButtonStyle}>Export Package</button>
          <button onClick={handlePrepareSubmission} style={secondaryButtonStyle}>Prepare Registry Submission</button>
        </div>
      </div>

      {/* Preview / submission */}
      <div style={{ flex: '1 1 420px', minWidth: 360 }}>
        <h4 style={{ color: 'var(--iac-text)', marginBottom: '0.5rem' }}>Preview</h4>
        <pre style={{ ...codeBlockStyle, minHeight: 200 }}>{content}</pre>

        {submission && (
          <div style={{ marginTop: '1.5rem' }}>
            <h4 style={{ color: 'var(--iac-text)', marginBottom: '0.25rem' }}>Registry Submission</h4>
            <p style={{ color: 'var(--iac-text-secondary)', fontSize: '0.85rem', marginTop: 0 }}>
              Open a pull request against{' '}
              <code>OWASP/www-project-hactu8</code> adding this entry to{' '}
              <code>spikes/iac-prototype/skills/registry.json</code>. Once reviewed, the HACTU8 skills board signs
              the entry (<code>signature.verified: true</code>) and merges it — it will then appear in the Skills
              Explorer for everyone.
            </p>
            <pre style={{ ...codeBlockStyle, maxHeight: 320 }}>{JSON.stringify(submission, null, 2)}</pre>
          </div>
        )}
      </div>
    </div>
  );
};

export default SkillsCreator;
