// src/pages/Registry.tsx
//
// Registry — an inventory of known intelligent components in the
// environment: deployed agents, model integrations, MCP hosts, and
// reference targets (e.g. AgenticGoat). Entries are metadata only;
// registering one does not deploy or provision anything. Other areas of
// the host (Testing projects, Monitoring) will reference entries by id.
import React, { useMemo, useState } from 'react';
import type {
  NewRegistryEntryInput,
  RegistryEntry,
  RegistryEntryType,
} from '../types/registry';
import { REGISTRY_TYPE_LABELS, REGISTRY_TYPES } from '../types/registry';
import { useRegistry } from '../contexts/RegistryContext';
import {
  Badge,
  InfoField,
  TabButton,
  sidebarStyle,
  mainStyle,
  cardStyle,
  primaryButtonStyle,
  secondaryButtonStyle,
  dangerButtonStyle,
} from '../components/Skills/shared';

function SourceBadge({ source }: { source: string }) {
  return source === 'discovered' ? (
    <Badge label="Discovered" color="var(--iac-info-bg)" textColor="var(--iac-info-text)" />
  ) : (
    <Badge label="Manual" color="var(--iac-surface)" textColor="var(--iac-text-secondary)" />
  );
}

// ---------------------------------------------------------------------------
// Add/Edit form
// ---------------------------------------------------------------------------

interface EntryFormProps {
  initial?: RegistryEntry;
  onCancel: () => void;
  onSubmit: (input: NewRegistryEntryInput) => void;
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

function EntryForm({ initial, onCancel, onSubmit }: EntryFormProps) {
  const [type, setType] = useState<RegistryEntryType>(initial?.type ?? 'target');
  const [name, setName] = useState(initial?.name ?? '');
  const [description, setDescription] = useState(initial?.description ?? '');
  const [tagsInput, setTagsInput] = useState(initial?.tags?.join(', ') ?? '');
  const [owner, setOwner] = useState(initial?.owner ?? '');

  // Type-specific fields (kept as flat state, only relevant ones are read on submit)
  const [framework, setFramework] = useState(initial && initial.type === 'agent' ? initial.framework ?? '' : '');
  const [provider, setProvider] = useState(
    initial && initial.type === 'model-integration' ? initial.provider : ''
  );
  const [model, setModel] = useState(initial && initial.type === 'model-integration' ? initial.model : '');
  const [endpoint, setEndpoint] = useState(
    initial && (initial.type === 'agent' || initial.type === 'model-integration' || initial.type === 'mcp-host')
      ? initial.endpoint ?? ''
      : ''
  );
  const [transport, setTransport] = useState(initial && initial.type === 'mcp-host' ? initial.transport ?? '' : '');
  const [targetUrl, setTargetUrl] = useState(initial && initial.type === 'target' ? initial.targetUrl ?? '' : '');
  const [riskNotes, setRiskNotes] = useState(initial && initial.type === 'target' ? initial.riskNotes ?? '' : '');
  const [referenceUrl, setReferenceUrl] = useState(
    initial && initial.type === 'target' ? initial.referenceUrl ?? '' : ''
  );

  const isValid = name.trim().length > 0 && description.trim().length > 0;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!isValid) return;

    const base = {
      name: name.trim(),
      description: description.trim(),
      tags: tagsInput.split(',').map((t) => t.trim()).filter(Boolean),
      owner: owner.trim() || undefined,
    };

    let input: NewRegistryEntryInput;
    switch (type) {
      case 'agent':
        input = { ...base, type, framework: framework.trim() || undefined, endpoint: endpoint.trim() || undefined };
        break;
      case 'model-integration':
        input = {
          ...base,
          type,
          provider: provider.trim(),
          model: model.trim(),
          endpoint: endpoint.trim() || undefined,
        };
        break;
      case 'mcp-host':
        input = { ...base, type, endpoint: endpoint.trim(), transport: transport.trim() || undefined };
        break;
      case 'target':
      default:
        input = {
          ...base,
          type: 'target',
          targetUrl: targetUrl.trim() || undefined,
          riskNotes: riskNotes.trim() || undefined,
          referenceUrl: referenceUrl.trim() || undefined,
        };
        break;
    }

    onSubmit(input);
  };

  return (
    <form onSubmit={handleSubmit}>
      <h3 style={{ color: 'var(--iac-text)', fontWeight: 700, margin: '0 0 1rem' }}>
        {initial ? 'Edit Entry' : 'Add Registry Entry'}
      </h3>

      <div style={fieldWrapStyle}>
        <label style={labelStyle}>Type</label>
        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
          {REGISTRY_TYPES.map((t) => (
            <TabButton key={t} label={REGISTRY_TYPE_LABELS[t]} active={type === t} onClick={() => setType(t)} />
          ))}
        </div>
      </div>

      <div style={fieldWrapStyle}>
        <label style={labelStyle}>Name</label>
        <input style={inputStyle} value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. AgenticGoat" />
      </div>

      <div style={fieldWrapStyle}>
        <label style={labelStyle}>Description</label>
        <textarea
          style={{ ...inputStyle, minHeight: 60, resize: 'vertical' }}
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          placeholder="What is this component?"
        />
      </div>

      {type === 'agent' && (
        <>
          <div style={fieldWrapStyle}>
            <label style={labelStyle}>Framework</label>
            <input style={inputStyle} value={framework} onChange={(e) => setFramework(e.target.value)} placeholder="e.g. iac-copilot-api orchestrator" />
          </div>
          <div style={fieldWrapStyle}>
            <label style={labelStyle}>Endpoint</label>
            <input style={inputStyle} value={endpoint} onChange={(e) => setEndpoint(e.target.value)} placeholder="https://..." />
          </div>
        </>
      )}

      {type === 'model-integration' && (
        <>
          <div style={fieldWrapStyle}>
            <label style={labelStyle}>Provider</label>
            <input style={inputStyle} value={provider} onChange={(e) => setProvider(e.target.value)} placeholder="e.g. OpenAI, Anthropic, Local" />
          </div>
          <div style={fieldWrapStyle}>
            <label style={labelStyle}>Model</label>
            <input style={inputStyle} value={model} onChange={(e) => setModel(e.target.value)} placeholder="e.g. gpt-4o" />
          </div>
          <div style={fieldWrapStyle}>
            <label style={labelStyle}>Endpoint</label>
            <input style={inputStyle} value={endpoint} onChange={(e) => setEndpoint(e.target.value)} placeholder="https://..." />
          </div>
        </>
      )}

      {type === 'mcp-host' && (
        <>
          <div style={fieldWrapStyle}>
            <label style={labelStyle}>Endpoint</label>
            <input style={inputStyle} value={endpoint} onChange={(e) => setEndpoint(e.target.value)} placeholder="http://localhost:7331/mcp" />
          </div>
          <div style={fieldWrapStyle}>
            <label style={labelStyle}>Transport</label>
            <input style={inputStyle} value={transport} onChange={(e) => setTransport(e.target.value)} placeholder="e.g. stdio, sse, http" />
          </div>
        </>
      )}

      {type === 'target' && (
        <>
          <div style={fieldWrapStyle}>
            <label style={labelStyle}>Target URL</label>
            <input style={inputStyle} value={targetUrl} onChange={(e) => setTargetUrl(e.target.value)} placeholder="https://..." />
          </div>
          <div style={fieldWrapStyle}>
            <label style={labelStyle}>Risk Notes</label>
            <input style={inputStyle} value={riskNotes} onChange={(e) => setRiskNotes(e.target.value)} placeholder="e.g. Intentionally vulnerable to LLM01" />
          </div>
          <div style={fieldWrapStyle}>
            <label style={labelStyle}>Reference URL</label>
            <input style={inputStyle} value={referenceUrl} onChange={(e) => setReferenceUrl(e.target.value)} placeholder="Docs / repo for standing it up" />
          </div>
        </>
      )}

      <div style={fieldWrapStyle}>
        <label style={labelStyle}>Tags (comma-separated)</label>
        <input style={inputStyle} value={tagsInput} onChange={(e) => setTagsInput(e.target.value)} placeholder="e.g. agenticgoat, example" />
      </div>

      <div style={fieldWrapStyle}>
        <label style={labelStyle}>Owner</label>
        <input style={inputStyle} value={owner} onChange={(e) => setOwner(e.target.value)} placeholder="Optional" />
      </div>

      <div style={{ display: 'flex', gap: '0.5rem' }}>
        <button type="submit" style={primaryButtonStyle} disabled={!isValid}>
          {initial ? 'Save Changes' : 'Add Entry'}
        </button>
        <button type="button" style={secondaryButtonStyle} onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
}

// ---------------------------------------------------------------------------
// Entry detail
// ---------------------------------------------------------------------------

function typeSpecificFields(entry: RegistryEntry): { label: string; value: string }[] {
  switch (entry.type) {
    case 'agent':
      return [
        { label: 'Framework', value: entry.framework || '—' },
        { label: 'Endpoint', value: entry.endpoint || '—' },
      ];
    case 'model-integration':
      return [
        { label: 'Provider', value: entry.provider || '—' },
        { label: 'Model', value: entry.model || '—' },
        { label: 'Endpoint', value: entry.endpoint || '—' },
      ];
    case 'mcp-host':
      return [
        { label: 'Endpoint', value: entry.endpoint || '—' },
        { label: 'Transport', value: entry.transport || '—' },
      ];
    case 'target':
      return [
        { label: 'Target URL', value: entry.targetUrl || '—' },
        { label: 'Risk Notes', value: entry.riskNotes || '—' },
        { label: 'Reference', value: entry.referenceUrl || '—' },
      ];
    default:
      return [];
  }
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

const Registry: React.FC = () => {
  const { entries, addEntry, updateEntry, removeEntry } = useRegistry();
  const [filterType, setFilterType] = useState<RegistryEntryType | 'all'>('all');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [mode, setMode] = useState<'view' | 'add' | 'edit'>('view');

  const filtered = useMemo(
    () => (filterType === 'all' ? entries : entries.filter((e) => e.type === filterType)),
    [entries, filterType]
  );

  const selected = entries.find((e) => e.id === selectedId) ?? null;

  const handleAdd = (input: NewRegistryEntryInput) => {
    const updated = addEntry(input);
    setMode('view');
    setSelectedId(updated[updated.length - 1].id);
  };

  const handleEditSubmit = (input: NewRegistryEntryInput) => {
    if (!selected) return;
    updateEntry(selected.id, input as Partial<RegistryEntry>);
    setMode('view');
  };

  const handleDelete = (id: string) => {
    removeEntry(id);
    if (selectedId === id) setSelectedId(null);
    setMode('view');
  };

  return (
    <div style={{ display: 'flex', minHeight: '60vh', height: '100%', overflow: 'hidden' }}>
      <aside style={sidebarStyle}>
        <h3 style={{ color: 'var(--iac-text)', marginBottom: '0.25rem' }}>Registry</h3>
        <p style={{ color: 'var(--iac-muted)', fontSize: '0.8rem', marginTop: 0, marginBottom: '1rem' }}>
          Known agents, model integrations, MCP hosts, and targets.
        </p>

        <button
          style={{ ...primaryButtonStyle, marginBottom: '1rem' }}
          onClick={() => {
            setSelectedId(null);
            setMode('add');
          }}
        >
          + Add Entry
        </button>

        <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap', marginBottom: '1rem' }}>
          <TabButton label="All" active={filterType === 'all'} onClick={() => setFilterType('all')} />
          {REGISTRY_TYPES.map((t) => (
            <TabButton key={t} label={REGISTRY_TYPE_LABELS[t]} active={filterType === t} onClick={() => setFilterType(t)} />
          ))}
        </div>

        {filtered.length === 0 && (
          <p style={{ color: 'var(--iac-muted)', fontSize: '0.875rem' }}>No registry entries yet.</p>
        )}

        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', overflowY: 'auto' }}>
          {filtered.map((entry) => {
            const isSelected = selectedId === entry.id && mode === 'view';
            return (
              <div
                key={entry.id}
                onClick={() => {
                  setSelectedId(entry.id);
                  setMode('view');
                }}
                style={{
                  ...cardStyle,
                  borderColor: isSelected ? 'var(--iac-surface-elevated)' : 'var(--iac-border)',
                  background: isSelected ? 'var(--iac-surface)' : 'var(--iac-bg)',
                  cursor: 'pointer',
                }}
              >
                <div style={{ fontWeight: 600, fontSize: '0.9rem', color: 'var(--iac-text)', marginBottom: '0.15rem' }}>
                  {entry.name}
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--iac-muted)', marginBottom: '0.35rem' }}>
                  {entry.description}
                </div>
                <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap' }}>
                  <Badge label={REGISTRY_TYPE_LABELS[entry.type]} color="var(--iac-info-bg)" textColor="var(--iac-info-text)" />
                  <SourceBadge source={entry.source} />
                </div>
              </div>
            );
          })}
        </div>
      </aside>

      <main style={mainStyle}>
        {mode === 'add' && <EntryForm onCancel={() => setMode('view')} onSubmit={handleAdd} />}
        {mode === 'edit' && selected && (
          <EntryForm initial={selected} onCancel={() => setMode('view')} onSubmit={handleEditSubmit} />
        )}
        {mode === 'view' && !selected && (
          <div style={{ color: 'var(--iac-muted)', textAlign: 'center', marginTop: '4rem' }}>
            <p>Select an entry to view details, or add a new one.</p>
          </div>
        )}
        {mode === 'view' && selected && (
          <div>
            <div style={{ marginBottom: '1.5rem' }}>
              <h3 style={{ color: 'var(--iac-text)', fontWeight: 700, fontSize: '1.5rem', margin: '0 0 0.25rem' }}>
                {selected.name}
              </h3>
              <p style={{ color: 'var(--iac-text-secondary)', margin: '0 0 0.75rem', fontSize: '0.925rem' }}>
                {selected.description}
              </p>
              <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', alignItems: 'center' }}>
                <Badge label={REGISTRY_TYPE_LABELS[selected.type]} color="var(--iac-info-bg)" textColor="var(--iac-info-text)" />
                <SourceBadge source={selected.source} />
              </div>
            </div>

            <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1.5rem' }}>
              <button style={secondaryButtonStyle} onClick={() => setMode('edit')}>
                Edit
              </button>
              <button style={dangerButtonStyle} onClick={() => handleDelete(selected.id)}>
                Delete
              </button>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1.5rem' }}>
              {typeSpecificFields(selected).map((f) => (
                <InfoField key={f.label} label={f.label} value={f.value} />
              ))}
              <InfoField label="Owner" value={selected.owner || '—'} />
              <InfoField label="Added" value={new Date(selected.addedAt).toLocaleDateString()} />
              <InfoField label="Updated" value={new Date(selected.updatedAt).toLocaleDateString()} />
            </div>

            {selected.tags && selected.tags.length > 0 && (
              <div>
                <h4 style={{ color: 'var(--iac-text)', fontWeight: 600, marginBottom: '0.5rem' }}>Tags</h4>
                <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap' }}>
                  {selected.tags.map((t) => (
                    <Badge key={t} label={t} color="var(--iac-surface)" textColor="var(--iac-text-secondary)" />
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  );
};

export default Registry;
