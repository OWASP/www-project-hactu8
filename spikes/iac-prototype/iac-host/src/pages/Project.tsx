import React, { useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { getCannedProject } from '../data/cannedProjects';
import { useModelProvider } from '../contexts/ModelProviderContext';

const mockProjects: Record<string, any> = {
  'red-team': {
    name: 'Red Team Demo',
    features: [
      { key: 'prompts', label: 'Prompts' },
      { key: 'notes', label: 'Notes' },
      { key: 'model', label: 'Model Info' },
      { key: 'settings', label: 'Settings' },
    ],
    prompts: [
      { id: 1, text: 'Test prompt for jailbreak', created: '2025-07-01' },
      { id: 2, text: 'Prompt for system context leakage', created: '2025-07-10' },
    ],
    notes: '# Red Team Project\nThis project is for adversarial prompt testing.\n- Add new prompts\n- Review model behavior',
    model: {
      name: 'gpt-4o',
      version: '2025-06',
      provider: 'OpenAI',
      settings: { temperature: 0.2, max_tokens: 2048 },
    },
    settings: {
      owner: 'alice',
      team: ['alice', 'bob'],
      created: '2025-06-15',
    },
  },
  'blue-team': {
    name: 'Blue Team Demo',
    features: [
      { key: 'prompts', label: 'Prompts' },
      { key: 'notes', label: 'Notes' },
      { key: 'model', label: 'Model Info' },
      { key: 'settings', label: 'Settings' },
    ],
    prompts: [
      { id: 1, text: 'Prompt for safe output', created: '2025-07-05' },
    ],
    notes: '# Blue Team Project\nFocus on defense and detection.\n- Monitor logs\n- Analyze model output',
    model: {
      name: 'gpt-3.5-turbo',
      version: '2025-05',
      provider: 'OpenAI',
      settings: { temperature: 0.1, max_tokens: 1024 },
    },
    settings: {
      owner: 'carol',
      team: ['carol', 'dan'],
      created: '2025-06-20',
    },
  },
  'purple-team': {
    name: 'Purple Team Demo',
    features: [
      { key: 'prompts', label: 'Prompts' },
      { key: 'notes', label: 'Notes' },
      { key: 'model', label: 'Model Info' },
      { key: 'settings', label: 'Settings' },
    ],
    prompts: [],
    notes: '# Purple Team\nCollaboration between red and blue teams.',
    model: {
      name: 'custom-llm',
      version: '2025-07',
      provider: 'Local',
      settings: { temperature: 0.3, max_tokens: 4096 },
    },
    settings: {
      owner: 'eve',
      team: ['eve', 'frank'],
      created: '2025-07-01',
    },
  },
};

function FeaturePanel({ project, feature }: { project: any, feature: string }) {
  switch (feature) {
    case 'prompts':
      return (
        <div>
          <h3>Prompts</h3>
          {project.prompts.length === 0 ? (
            <p>No prompts yet.</p>
          ) : (
            <ul>
              {project.prompts.map((p: any) => (
                <li key={p.id}>
                  <strong>{p.text}</strong> <span style={{ color: 'var(--iac-muted)', fontSize: 12 }}>({p.created})</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      );
    case 'notes':
      return (
        <div>
          <h3>Notes</h3>
          <div style={{ padding: 16, borderRadius: 6 }}>
            <pre style={{ whiteSpace: 'pre-wrap', fontFamily: 'inherit', margin: 0 }}>{project.notes}</pre>
          </div>
        </div>
      );
    case 'model':
      return (
        <div>
          <h3>Model Information</h3>
          <ul>
            <li><b>Name:</b> {project.model.name}</li>
            <li><b>Version:</b> {project.model.version}</li>
            <li><b>Provider:</b> {project.model.provider}</li>
            <li><b>Settings:</b> <code>{JSON.stringify(project.model.settings)}</code></li>
          </ul>
        </div>
      );
    case 'settings':
      return (
        <div>
          <h3>Project Settings</h3>
          <ul>
            <li><b>Owner:</b> {project.settings.owner}</li>
            <li><b>Team:</b> {project.settings.team.join(', ')}</li>
            <li><b>Created:</b> {project.settings.created}</li>
          </ul>
        </div>
      );
    default:
      return <div>Select a feature</div>;
  }
}

// ---------------------------------------------------------------------------
// Canned Projects — the 10 original point-solution testers, reframed as
// pre-scoped starter Projects. See src/data/cannedProjects.tsx for the
// metadata and the underlying tester component/route each one wraps.
// ---------------------------------------------------------------------------

const CANNED_TABS = [
  { key: 'overview', label: 'Overview' },
  { key: 'target', label: 'Target' },
  { key: 'run', label: 'Run' },
] as const;

type CannedTabKey = typeof CANNED_TABS[number]['key'];

function CannedProjectView({ cannedId }: { cannedId: string }) {
  const project = getCannedProject(cannedId)!;
  const [selected, setSelected] = useState<CannedTabKey>('overview');
  // Target selection: this codebase doesn't yet have the Registry inventory
  // (types/registry.ts / RegistryContext / useRegistry()) checked into this
  // branch, so a canned Project's "target" is backed by the model provider
  // configs that already exist (ModelProviderContext). Swap this for
  // useRegistry() once the Registry inventory lands — the Target tab below
  // is the integration point.
  const { configs, defaultConfigId, setDefaultConfig } = useModelProvider();
  const [targetId, setTargetId] = useState<string | undefined>(defaultConfigId);
  const selectedTarget = configs.find((c) => c.id === targetId);

  return (
    <div style={{ display: 'flex', padding: 32, minHeight: '60vh', borderRadius: 8, boxShadow: '0 2px 8px rgba(0,0,0,0.07)' }}>
      <aside style={{ width: 300, borderRight: '1px solid var(--iac-border)', padding: '1rem 1rem' }}>
        <h3 style={{ marginBottom: 4 }}>{project.name}</h3>
        <div style={{ fontSize: 12, color: 'var(--iac-text-secondary)', marginBottom: '1rem' }}>
          Starter Project &middot; {project.category}
        </div>
        <nav>
          <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
            {CANNED_TABS.map((t) => (
              <li key={t.key}>
                <button
                  style={{
                    width: '100%',
                    padding: '1rem 2rem',
                    background: selected === t.key ? 'var(--iac-surface-elevated)' : 'none',
                    border: 'none',
                    textAlign: 'left',
                    fontWeight: selected === t.key ? 600 : 400,
                    cursor: 'pointer',
                    outline: 'none',
                    transition: 'background 0.2s, border-left 0.2s',
                  }}
                  onClick={() => setSelected(t.key)}
                >
                  {t.label}
                </button>
              </li>
            ))}
          </ul>
        </nav>
        <div style={{ marginTop: '2rem', fontSize: 12 }}>
          <Link to={project.route} style={{ color: 'var(--iac-link, var(--iac-accent))' }}>
            Open standalone page &rarr;
          </Link>
        </div>
      </aside>
      <main style={{ flex: 1, padding: '2rem 3rem' }}>
        {selected === 'overview' && (
          <div>
            <h3>Overview</h3>
            <p>{project.description}</p>
            <ul>
              <li><b>Category:</b> {project.category}</li>
              <li><b>Standalone route:</b> <code>{project.route}</code></li>
              <li><b>Target:</b> {selectedTarget ? `${selectedTarget.providerId} / ${selectedTarget.model}` : 'None selected'}</li>
            </ul>
            <p style={{ color: 'var(--iac-text-secondary)' }}>
              This is a pre-scoped starter Project: it bundles a fixed test script with the tester below, so you can
              run it immediately. Pick a target on the Target tab, then switch to Run to execute the test.
            </p>
          </div>
        )}
        {selected === 'target' && (
          <div>
            <h3>Target</h3>
            {configs.length === 0 ? (
              <p style={{ color: 'var(--iac-text-secondary)' }}>
                No model provider targets are configured yet. Add one from Settings to point this starter Project at
                a specific model/provider.
              </p>
            ) : (
              <>
                <p style={{ color: 'var(--iac-text-secondary)' }}>
                  Optional: choose which configured target this Project's tests should run against.
                </p>
                <ul style={{ listStyle: 'none', padding: 0 }}>
                  {configs.map((c) => (
                    <li key={c.id} style={{ marginBottom: 8 }}>
                      <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                        <input
                          type="radio"
                          name="canned-project-target"
                          checked={targetId === c.id}
                          onChange={() => {
                            setTargetId(c.id);
                            setDefaultConfig(c.id);
                          }}
                        />
                        <span>{c.providerId} / {c.model}</span>
                      </label>
                    </li>
                  ))}
                </ul>
              </>
            )}
          </div>
        )}
        {selected === 'run' && (
          <div>
            <h3>Run</h3>
            <div
              style={{
                border: '1px solid var(--iac-border)',
                borderRadius: 8,
                padding: '1rem',
                background: 'var(--iac-surface)',
              }}
            >
              <project.Component />
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

const Project = () => {
  const { projectId } = useParams();
  const project = projectId && mockProjects[projectId] ? mockProjects[projectId] : null;
  const cannedProject = !project && projectId ? getCannedProject(projectId) : undefined;
  const [selected, setSelected] = useState(project?.features[0]?.key || 'prompts');

  if (cannedProject) {
    return <CannedProjectView cannedId={cannedProject.id} />;
  }

  if (!project) {
    return <div style={{ padding: 32 }}><h3>Project not found</h3></div>;
  }

  return (
    <div style={{ display: 'flex', padding: 32, minHeight: '60vh', borderRadius: 8, boxShadow: '0 2px 8px rgba(0,0,0,0.07)' }}>
      <aside style={{ width: 300, borderRight: '1px solid var(--iac-border)', padding: '1rem 1rem' }}>
        <h3>{project.name}</h3>
        <nav>
          <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
            {project.features.map((f: any) => (
              <li key={f.key}>
                <button
                  style={{
                    width: '100%',
                    padding: '1rem 2rem',
                    background: selected === f.key ? 'var(--iac-surface-elevated)' : 'none',
                    border: 'none',
                    textAlign: 'left',
                    fontWeight: selected === f.key ? 600 : 400,
                    // color: selected === f.key ? 'var(--iac-accent)' : 'var(--iac-text)',
                    cursor: 'pointer',
                    outline: 'none',
                    // borderLeft: selected === f.key ? '4px solid var(--iac-accent)' : '4px solid transparent',
                    transition: 'background 0.2s, border-left 0.2s',
                  }}
                  onClick={() => setSelected(f.key)}
                >
                  {f.label}
                </button>
              </li>
            ))}
          </ul>
        </nav>
      </aside>
      <main style={{ flex: 1, padding: '2rem 3rem' }}>
        <FeaturePanel project={project} feature={selected} />
      </main>
    </div>
  );
};

export default Project;