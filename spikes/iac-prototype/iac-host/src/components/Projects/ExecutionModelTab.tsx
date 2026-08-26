import React from 'react';
import { useModelProvider } from '../../contexts/ModelProviderContext';
import type { ModelProviderConfig } from '../../types/modelProvider';

// Lifted from the old canned-Project placeholder's Target tab (Project.tsx),
// which already had exactly this radio-over-ModelProviderConfig UI. Unlike
// that old code, selecting here does NOT call setDefaultConfig() — this is
// local run-draft state for one Project's Run, not a global default change.
const ExecutionModelTab: React.FC<{
  selectedConfigId?: string;
  onSelectConfig: (config: ModelProviderConfig) => void;
}> = ({ selectedConfigId, onSelectConfig }) => {
  const { configs } = useModelProvider();

  if (configs.length === 0) {
    return (
      <p style={{ color: 'var(--iac-text-secondary)' }}>
        No model providers are configured yet. Add one from Settings to pick which model/provider
        this Project's Run should use.
      </p>
    );
  }

  return (
    <div>
      <p style={{ color: 'var(--iac-text-secondary)', marginTop: 0 }}>
        Choose which configured model this Project's Run should use.
      </p>
      <ul style={{ listStyle: 'none', padding: 0, margin: 0, display: 'flex', flexDirection: 'column', gap: 8 }}>
        {configs.map((c) => (
          <li key={c.id}>
            <label
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 10,
                cursor: 'pointer',
                border: `1px solid ${selectedConfigId === c.id ? 'var(--iac-link)' : 'var(--iac-border)'}`,
                borderRadius: 8,
                padding: '10px 14px',
                background: selectedConfigId === c.id ? 'var(--iac-info-bg)' : 'var(--iac-surface)',
              }}
            >
              <input
                type="radio"
                name="project-execution-model"
                checked={selectedConfigId === c.id}
                onChange={() => onSelectConfig(c)}
              />
              <span style={{ fontSize: 13, color: 'var(--iac-text)' }}>
                {c.providerId} / {c.model}
              </span>
            </label>
          </li>
        ))}
      </ul>
    </div>
  );
};

export default ExecutionModelTab;
