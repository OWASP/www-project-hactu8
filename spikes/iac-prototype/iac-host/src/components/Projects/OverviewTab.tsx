import React from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import type { CannedProjectDetail } from '../../types/project';

const OverviewTab: React.FC<{ project: CannedProjectDetail }> = ({ project }) => (
  <div>
    <div style={{ display: 'flex', gap: 8, marginBottom: 16, flexWrap: 'wrap' }}>
      <span
        style={{
          fontSize: 12,
          fontWeight: 600,
          padding: '3px 10px',
          borderRadius: 12,
          background: 'var(--iac-badge-bg)',
          color: 'var(--iac-info-text)',
        }}
      >
        {project.category}
      </span>
      <span style={{ fontSize: 12, color: 'var(--iac-muted)', alignSelf: 'center' }}>
        v{project.version}
      </span>
    </div>
    <div className="agent-md">
      <ReactMarkdown remarkPlugins={[remarkGfm]}>{project.overview_md}</ReactMarkdown>
    </div>
  </div>
);

export default OverviewTab;
