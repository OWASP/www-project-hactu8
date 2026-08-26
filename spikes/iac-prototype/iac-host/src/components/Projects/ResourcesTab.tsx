import React from 'react';
import type { CannedProjectDetail } from '../../types/project';

const ResourcesTab: React.FC<{ project: CannedProjectDetail }> = ({ project }) => {
  if (project.resources.length === 0) {
    return (
      <p style={{ color: 'var(--iac-text-secondary)' }}>
        No resources (data or corpus) attached to this Project yet.
      </p>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      {project.resources.map((r, i) => (
        <div
          key={i}
          style={{
            border: '1px solid var(--iac-border)',
            borderRadius: 8,
            padding: '12px 16px',
            background: 'var(--iac-surface)',
          }}
        >
          <div style={{ fontWeight: 600, color: 'var(--iac-text)', fontSize: 14 }}>
            {r.url ? (
              <a href={r.url} target="_blank" rel="noreferrer" style={{ color: 'var(--iac-link)' }}>
                {r.title}
              </a>
            ) : (
              r.title
            )}
          </div>
          {r.description && (
            <div style={{ color: 'var(--iac-text-secondary)', fontSize: 13, marginTop: 4 }}>
              {r.description}
            </div>
          )}
        </div>
      ))}
    </div>
  );
};

export default ResourcesTab;
