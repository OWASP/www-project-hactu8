import React from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import type { CannedProjectDetail } from '../../types/project';

const InstructionsTab: React.FC<{ project: CannedProjectDetail }> = ({ project }) => (
  <div className="agent-md">
    <ReactMarkdown remarkPlugins={[remarkGfm]}>{project.instructions_md}</ReactMarkdown>
  </div>
);

export default InstructionsTab;
