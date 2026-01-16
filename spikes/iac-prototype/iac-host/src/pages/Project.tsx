import React, { useState } from 'react';
import { useParams } from 'react-router-dom';

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
                  <strong>{p.text}</strong> <span style={{ color: '#888', fontSize: 12 }}>({p.created})</span>
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

const Project = () => {
  const { projectId } = useParams();
  const project = projectId && mockProjects[projectId] ? mockProjects[projectId] : null;
  const [selected, setSelected] = useState(project?.features[0]?.key || 'prompts');

  if (!project) {
    return <div style={{ padding: 32 }}><h3>Project not found</h3></div>;
  }

  return (
    <div style={{ display: 'flex', minHeight: '60vh', borderRadius: 8, boxShadow: '0 2px 8px #0001' }}>
      <aside style={{ width: 300, borderRight: '1px solid #eee', padding: '1rem 1rem' }}>
        <h3>{project.name}</h3>
        <nav>
          <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
            {project.features.map((f: any) => (
              <li key={f.key}>
                <button
                  style={{
                    width: '100%',
                    padding: '1rem 2rem',
                    background: selected === f.key ? '#213547' : 'none',
                    border: 'none',
                    textAlign: 'left',
                    fontWeight: selected === f.key ? 600 : 400,
                    // color: selected === f.key ? '#1976d2' : '#333',
                    cursor: 'pointer',
                    outline: 'none',
                    // borderLeft: selected === f.key ? '4px solid #1976d2' : '4px solid transparent',
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