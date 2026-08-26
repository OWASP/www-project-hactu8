import React from 'react';
import { useRegistry } from '../../contexts/RegistryContext';
import type { TargetRegistryEntry } from '../../types/registry';

const TargetTab: React.FC<{
  selectedTargetId?: string;
  onSelectTarget: (entry: TargetRegistryEntry) => void;
}> = ({ selectedTargetId, onSelectTarget }) => {
  const { entries } = useRegistry();
  const targets = entries.filter((e): e is TargetRegistryEntry => e.type === 'target');

  if (targets.length === 0) {
    return (
      <p style={{ color: 'var(--iac-text-secondary)' }}>
        No targets registered yet. Add one from the Registry (including AgenticGoat Internal,
        seeded there by default) before running this Project.
      </p>
    );
  }

  return (
    <div>
      <p style={{ color: 'var(--iac-text-secondary)', marginTop: 0 }}>
        Choose which registered target this Project's Run should assess.
      </p>
      <ul style={{ listStyle: 'none', padding: 0, margin: 0, display: 'flex', flexDirection: 'column', gap: 8 }}>
        {targets.map((t) => (
          <li key={t.id}>
            <label
              style={{
                display: 'flex',
                alignItems: 'flex-start',
                gap: 10,
                cursor: 'pointer',
                border: `1px solid ${selectedTargetId === t.id ? 'var(--iac-link)' : 'var(--iac-border)'}`,
                borderRadius: 8,
                padding: '10px 14px',
                background: selectedTargetId === t.id ? 'var(--iac-info-bg)' : 'var(--iac-surface)',
              }}
            >
              <input
                type="radio"
                name="project-target"
                checked={selectedTargetId === t.id}
                onChange={() => onSelectTarget(t)}
                style={{ marginTop: 3 }}
              />
              <span>
                <div style={{ fontWeight: 600, color: 'var(--iac-text)', fontSize: 13 }}>{t.name}</div>
                <div style={{ color: 'var(--iac-text-secondary)', fontSize: 12, marginTop: 2 }}>
                  {t.description}
                </div>
                {t.targetUrl && (
                  <div style={{ color: 'var(--iac-muted)', fontSize: 11, marginTop: 2, fontFamily: 'monospace' }}>
                    {t.targetUrl}
                  </div>
                )}
              </span>
            </label>
          </li>
        ))}
      </ul>
    </div>
  );
};

export default TargetTab;
