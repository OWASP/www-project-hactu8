// src/pages/AgentsCreator.tsx
//
// Author new agent definitions (manifest + free-form instructions body,
// analogous to a SKILL.md). Drafts are saved locally as unsigned agents;
// "Prepare Registry Submission" produces the exact signed JSON entry a
// HACTU8 maintainer would review and merge into agents/registry.json.
//
// This only authors a *definition* (what the agent is scoped to do). It does
// not wire the draft into the live `iac-copilot-api` engagement backend —
// see REDESIGN_PLAN.md roadmap item 4 for that follow-on work.
import React, { useMemo, useState } from 'react';
import type { AgentCategory, AgentManifest, AgentRegistryEntry, AgentResource } from '../types/agentCatalog';
import type { PhaseEnum } from '../types/agents';
import { PHASE_LABELS } from '../types/agents';
import { useAgentCatalog } from '../contexts/AgentCatalogContext';
import agentCatalogService from '../services/agentCatalogService';
import { AGENT_CATEGORY_LABELS, primaryButtonStyle, secondaryButtonStyle, codeBlockStyle } from '../components/Skills/shared';

const DEFAULT_CONTENT = `---
name: My New Agent
description: One sentence describing what this agent orchestrator does.
---

# My New Agent

## Instructions

Describe the system prompt / step-by-step approach this agent should follow.

## Resources

- \`reference/checklist.md\` — supporting reference material
`;

const CATEGORIES: AgentCategory[] = [
  'planning',
  'reconnaissance',
  'risk-assessment',
  'attack-simulation',
  'reporting',
  'governance',
  'utility',
];

const PHASES: PhaseEnum[] = ['kickoff', 'recon', 'risk', 'attack_selection', 'simulated_attacks', 'reporting', 'debrief'];

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

const AgentsCreator: React.FC = () => {
  const { saveDraft } = useAgentCatalog();

  const [id, setId] = useState('');
  const [name, setName] = useState('');
  const [version, setVersion] = useState('0.1.0');
  const [description, setDescription] = useState('');
  const [author, setAuthor] = useState('');
  const [license, setLicense] = useState('Apache-2.0');
  const [category, setCategory] = useState<AgentCategory>('reconnaissance');
  const [phase, setPhase] = useState<PhaseEnum | ''>('');
  const [tagsInput, setTagsInput] = useState('');
  const [allowedToolsInput, setAllowedToolsInput] = useState('');
  const [resources, setResources] = useState<AgentResource[]>([]);
  const [content, setContent] = useState(DEFAULT_CONTENT);

  const [saveMessage, setSaveMessage] = useState<string | null>(null);
  const [submission, setSubmission] = useState<AgentRegistryEntry | null>(null);
  const [error, setError] = useState<string | null>(null);

  const manifest: AgentManifest = useMemo(
    () => ({
      id: id.trim(),
      name: name.trim(),
      version: version.trim(),
      description: description.trim(),
      author: author.trim(),
      license: license.trim(),
      category,
      ...(phase ? { phase } : {}),
      tags: tagsInput.split(',').map((t) => t.trim()).filter(Boolean),
      allowedTools: allowedToolsInput.split(',').map((t) => t.trim()).filter(Boolean),
      resources,
    }),
    [id, name, version, description, author, license, category, phase, tagsInput, allowedToolsInput, resources]
  );

  const isValid = manifest.id.length > 0 && manifest.name.length > 0 && manifest.description.length > 0 && content.trim().length > 0;

  const addResource = () => setResources((r) => [...r, { path: '', description: '' }]);
  const updateResource = (idx: number, field: keyof AgentResource, value: string) =>
    setResources((r) => r.map((res, i) => (i === idx ? { ...res, [field]: value } : res)));
  const removeResource = (idx: number) => setResources((r) => r.filter((_, i) => i !== idx));

  const handleSaveDraft = () => {
    setError(null);
    setSaveMessage(null);
    setSubmission(null);
    if (!isValid) {
      setError('Agent id, name, description, and instructions content are required.');
      return;
    }
    saveDraft(manifest, content)
      .then(() => setSaveMessage(`Draft "${manifest.id}" saved to Installed Agents.`))
      .catch((err) => setError(err instanceof Error ? err.message : 'Failed to save draft'));
  };

  const handleExport = () => {
    if (!isValid) {
      setError('Agent id, name, description, and instructions content are required.');
      return;
    }
    agentCatalogService.downloadAgentPackage({
      manifest,
      instructions: content,
      signature: { algorithm: 'sha256', digest: '', curatedBy: 'Unsigned local draft', signedAt: new Date().toISOString(), verified: false },
      status: 'installed',
      source: 'local-draft',
      installedAt: new Date().toISOString(),
    });
  };

  const handlePrepareSubmission = async () => {
    setError(null);
    if (!isValid) {
      setError('Agent id, name, description, and instructions content are required.');
      return;
    }
    const entry = await agentCatalogService.buildRegistrySubmission({
      manifest,
      instructions: content,
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
        <h3 style={{ color: 'var(--iac-text)', marginBottom: '0.25rem' }}>Agents Creator</h3>
        <p style={{ color: 'var(--iac-muted)', fontSize: '0.8rem', marginTop: 0, marginBottom: '1.25rem' }}>
          Author a new agent definition. Save a local draft, export it as a portable file, or prepare a signed
          submission for the curated HACTU8 agents registry.
        </p>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
          <div style={fieldWrapStyle}>
            <label style={labelStyle}>Agent ID</label>
            <input style={inputStyle} value={id} onChange={(e) => setId(e.target.value)} placeholder="recon-agent" />
          </div>
          <div style={fieldWrapStyle}>
            <label style={labelStyle}>Version</label>
            <input style={inputStyle} value={version} onChange={(e) => setVersion(e.target.value)} placeholder="0.1.0" />
          </div>
        </div>

        <div style={fieldWrapStyle}>
          <label style={labelStyle}>Name</label>
          <input style={inputStyle} value={name} onChange={(e) => setName(e.target.value)} placeholder="Recon Agent" />
        </div>

        <div style={fieldWrapStyle}>
          <label style={labelStyle}>Description</label>
          <input
            style={inputStyle}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="One sentence describing what this agent orchestrator does."
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

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
          <div style={fieldWrapStyle}>
            <label style={labelStyle}>Category</label>
            <select style={inputStyle} value={category} onChange={(e) => setCategory(e.target.value as AgentCategory)}>
              {CATEGORIES.map((c) => (
                <option key={c} value={c}>{AGENT_CATEGORY_LABELS[c]}</option>
              ))}
            </select>
          </div>
          <div style={fieldWrapStyle}>
            <label style={labelStyle}>Engagement Phase (optional)</label>
            <select style={inputStyle} value={phase} onChange={(e) => setPhase(e.target.value as PhaseEnum | '')}>
              <option value="">None</option>
              {PHASES.map((p) => (
                <option key={p} value={p}>{PHASE_LABELS[p]}</option>
              ))}
            </select>
          </div>
        </div>

        <div style={fieldWrapStyle}>
          <label style={labelStyle}>Tags (comma-separated)</label>
          <input style={inputStyle} value={tagsInput} onChange={(e) => setTagsInput(e.target.value)} placeholder="owasp, recon, surface-map" />
        </div>

        <div style={fieldWrapStyle}>
          <label style={labelStyle}>Allowed Tools (comma-separated)</label>
          <input
            style={inputStyle}
            value={allowedToolsInput}
            onChange={(e) => setAllowedToolsInput(e.target.value)}
            placeholder="dns_lookup, whois_lookup, http_probe"
          />
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
          <label style={labelStyle}>Instructions</label>
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
              <code>spikes/iac-prototype/agents/registry.json</code>. Once reviewed, the HACTU8 agents board signs
              the entry (<code>signature.verified: true</code>) and merges it — it will then appear in the Agents
              Explorer for everyone.
            </p>
            <pre style={{ ...codeBlockStyle, maxHeight: 320 }}>{JSON.stringify(submission, null, 2)}</pre>
          </div>
        )}
      </div>
    </div>
  );
};

export default AgentsCreator;
