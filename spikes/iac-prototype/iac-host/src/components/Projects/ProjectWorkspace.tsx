import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';

import type { CannedProjectDetail, TargetSnapshot, ModelConfigSnapshot } from '../../types/project';
import type { TargetRegistryEntry } from '../../types/registry';
import type { ModelProviderConfig } from '../../types/modelProvider';
import { useRegistry } from '../../contexts/RegistryContext';
import { useModelProvider } from '../../contexts/ModelProviderContext';
import { STREAM_LOG_MD_STYLES } from '../shared/StreamEventLog';

import OverviewTab from './OverviewTab';
import InstructionsTab from './InstructionsTab';
import ResourcesTab from './ResourcesTab';
import TargetTab from './TargetTab';
import ExecutionModelTab from './ExecutionModelTab';
import RunTab from './RunTab';

const TABS = [
  { key: 'overview', label: 'Overview' },
  { key: 'instructions', label: 'Instructions' },
  { key: 'resources', label: 'Resources' },
  { key: 'target', label: 'Target' },
  { key: 'model', label: 'Execution Model' },
  { key: 'run', label: 'Run' },
] as const;

type TabKey = typeof TABS[number]['key'];

interface RunDraft {
  targetEntryId?: string;
  modelConfigId?: string;
  selectedSkillNames: string[];
  runId?: string;
}

function draftKey(projectId: string): string {
  return `iac-project-run-draft-${projectId}`;
}

function loadDraft(projectId: string): RunDraft {
  try {
    const raw = localStorage.getItem(draftKey(projectId));
    if (raw) return JSON.parse(raw);
  } catch {
    // fall through to default
  }
  return { selectedSkillNames: [] };
}

function saveDraft(projectId: string, draft: RunDraft): void {
  localStorage.setItem(draftKey(projectId), JSON.stringify(draft));
}

function targetToSnapshot(entry: TargetRegistryEntry): TargetSnapshot {
  return {
    registry_entry_id: entry.id,
    name: entry.name,
    target_url: entry.targetUrl,
    description: entry.description,
    risk_notes: entry.riskNotes,
  };
}

function modelToSnapshot(config: ModelProviderConfig): ModelConfigSnapshot {
  return {
    provider_id: config.providerId,
    model_id: config.model,
    api_key: config.apiKey,
    base_url: config.baseUrl,
  };
}

const ProjectWorkspace: React.FC<{ project: CannedProjectDetail }> = ({ project }) => {
  const [selectedTab, setSelectedTab] = useState<TabKey>('overview');
  const [draft, setDraft] = useState<RunDraft>(() => loadDraft(project.id));

  const { entries } = useRegistry();
  const { configs } = useModelProvider();

  useEffect(() => {
    saveDraft(project.id, draft);
  }, [project.id, draft]);

  const selectedTargetEntry = entries.find(
    (e): e is TargetRegistryEntry => e.type === 'target' && e.id === draft.targetEntryId
  );
  const selectedModelConfig = configs.find((c) => c.id === draft.modelConfigId);

  const target = selectedTargetEntry ? targetToSnapshot(selectedTargetEntry) : null;
  const model = selectedModelConfig ? modelToSnapshot(selectedModelConfig) : null;

  return (
    <div style={{ display: 'flex', padding: 32, minHeight: '60vh', borderRadius: 8, boxShadow: '0 2px 8px rgba(0,0,0,0.07)' }}>
      <style>{STREAM_LOG_MD_STYLES}</style>
      <aside style={{ width: 300, borderRight: '1px solid var(--iac-border)', padding: '1rem 1rem' }}>
        <h3 style={{ marginBottom: 4 }}>{project.name}</h3>
        <div style={{ fontSize: 12, color: 'var(--iac-text-secondary)', marginBottom: '1rem' }}>
          Curated Project &middot; {project.category}
        </div>
        <nav>
          <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
            {TABS.map((t) => (
              <li key={t.key}>
                <button
                  style={{
                    width: '100%',
                    padding: '0.75rem 1rem',
                    background: selectedTab === t.key ? 'var(--iac-surface-elevated)' : 'none',
                    border: 'none',
                    textAlign: 'left',
                    fontWeight: selectedTab === t.key ? 600 : 400,
                    cursor: 'pointer',
                    outline: 'none',
                  }}
                  onClick={() => setSelectedTab(t.key)}
                >
                  {t.label}
                  {t.key === 'target' && target && <Dot color="var(--iac-success)" />}
                  {t.key === 'model' && model && <Dot color="var(--iac-success)" />}
                  {t.key === 'run' && draft.runId && <Dot color="var(--iac-info)" />}
                </button>
              </li>
            ))}
          </ul>
        </nav>
        {project.legacy_route && (
          <div style={{ marginTop: '2rem', fontSize: 12 }}>
            <Link to={project.legacy_route} style={{ color: 'var(--iac-link, var(--iac-accent))' }}>
              Open standalone page &rarr;
            </Link>
          </div>
        )}
      </aside>
      <main style={{ flex: 1, padding: '2rem 3rem', minWidth: 0 }}>
        {selectedTab === 'overview' && <OverviewTab project={project} />}
        {selectedTab === 'instructions' && <InstructionsTab project={project} />}
        {selectedTab === 'resources' && <ResourcesTab project={project} />}
        {selectedTab === 'target' && (
          <TargetTab
            selectedTargetId={draft.targetEntryId}
            onSelectTarget={(entry) => setDraft((prev) => ({ ...prev, targetEntryId: entry.id }))}
          />
        )}
        {selectedTab === 'model' && (
          <ExecutionModelTab
            selectedConfigId={draft.modelConfigId}
            onSelectConfig={(config) => setDraft((prev) => ({ ...prev, modelConfigId: config.id }))}
          />
        )}
        {selectedTab === 'run' && (
          <RunTab
            project={project}
            target={target}
            model={model}
            runId={draft.runId}
            selectedSkillNames={draft.selectedSkillNames}
            onSelectedSkillNamesChange={(names) => setDraft((prev) => ({ ...prev, selectedSkillNames: names }))}
            onRunCreated={(runId) => setDraft((prev) => ({ ...prev, runId }))}
          />
        )}
      </main>
    </div>
  );
};

const Dot: React.FC<{ color: string }> = ({ color }) => (
  <span
    style={{
      display: 'inline-block',
      width: 6,
      height: 6,
      borderRadius: '50%',
      background: color,
      marginLeft: 8,
    }}
  />
);

export default ProjectWorkspace;
