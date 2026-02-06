/**
 * Project Docs Panel - for browsing HACTU8 project documentation.
 */

import React from 'react';
import { useCopilot } from '../../../contexts/CopilotContext';

// HACTU8 Wiki and documentation links
const HACTU8_RESOURCES = [
  {
    id: 'wiki-home',
    title: 'HACTU8 Wiki Home',
    description: 'Main project wiki with overview and getting started guides',
    url: 'https://github.com/OWASP/www-project-hactu8/wiki',
    icon: '🏠',
  },
  {
    id: 'wiki-architecture',
    title: 'Architecture Documentation',
    description: 'System architecture and component design',
    url: 'https://github.com/OWASP/www-project-hactu8/wiki/Architecture',
    icon: '🏗️',
  },
  {
    id: 'wiki-api',
    title: 'API Reference',
    description: 'API documentation and endpoints',
    url: 'https://github.com/OWASP/www-project-hactu8/wiki/API',
    icon: '🔌',
  },
  {
    id: 'wiki-contributing',
    title: 'Contributing Guide',
    description: 'How to contribute to the HACTU8 project',
    url: 'https://github.com/OWASP/www-project-hactu8/wiki/Contributing',
    icon: '🤝',
  },
  {
    id: 'github-repo',
    title: 'GitHub Repository',
    description: 'Source code and issue tracker',
    url: 'https://github.com/OWASP/www-project-hactu8',
    icon: '💻',
  },
  {
    id: 'owasp-page',
    title: 'OWASP Project Page',
    description: 'Official OWASP project information',
    url: 'https://owasp.org/www-project-hactu8/',
    icon: '🌐',
  },
];

const ProjectDocsPanel: React.FC = () => {
  const { documents, refreshDocuments, isLoading } = useCopilot();

  // Filter to show only project documents
  const projectDocs = documents.filter(d => d.sourceType === 'project');

  return (
    <div className="project-panel">
      {/* Section Header */}
      <div className="copilot-section-header">
        <span className="copilot-section-title">HACTU8 Project</span>
        <button
          className="copilot-section-action"
          onClick={refreshDocuments}
          disabled={isLoading}
        >
          Refresh
        </button>
      </div>

      {/* Quick Links */}
      <div style={{ marginBottom: '16px' }}>
        <p style={{
          fontSize: '11px',
          color: '#9e9e9e',
          marginBottom: '8px',
          textTransform: 'uppercase',
          letterSpacing: '0.5px',
        }}>
          Quick Links
        </p>
        <div className="copilot-doc-list">
          {HACTU8_RESOURCES.map(resource => (
            <a
              key={resource.id}
              href={resource.url}
              target="_blank"
              rel="noopener noreferrer"
              className="copilot-doc-item"
              style={{ textDecoration: 'none', cursor: 'pointer' }}
              title={resource.description}
            >
              <div className="copilot-doc-info">
                <span className="copilot-doc-icon">{resource.icon}</span>
                <span className="copilot-doc-title">{resource.title}</span>
              </div>
              <svg
                width="14"
                height="14"
                viewBox="0 0 24 24"
                fill="none"
                stroke="#9e9e9e"
                strokeWidth="2"
              >
                <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
                <polyline points="15 3 21 3 21 9" />
                <line x1="10" y1="14" x2="21" y2="3" />
              </svg>
            </a>
          ))}
        </div>
      </div>

      {/* Indexed Project Documents */}
      {projectDocs.length > 0 && (
        <>
          <p style={{
            fontSize: '11px',
            color: '#9e9e9e',
            marginBottom: '8px',
            textTransform: 'uppercase',
            letterSpacing: '0.5px',
          }}>
            Indexed Documents
          </p>
          <div className="copilot-doc-list">
            {projectDocs.map(doc => (
              <div key={doc.id} className="copilot-doc-item">
                <div className="copilot-doc-info">
                  <span className="copilot-doc-icon">📄</span>
                  <span className="copilot-doc-title" title={doc.title}>
                    {doc.title}
                  </span>
                </div>
                {doc.sourceUrl && (
                  <a
                    href={doc.sourceUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{ color: '#9e9e9e' }}
                  >
                    <svg
                      width="14"
                      height="14"
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="2"
                    >
                      <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
                      <polyline points="15 3 21 3 21 9" />
                      <line x1="10" y1="14" x2="21" y2="3" />
                    </svg>
                  </a>
                )}
              </div>
            ))}
          </div>
        </>
      )}

      {/* Help text */}
      <div style={{
        marginTop: '16px',
        padding: '12px',
        backgroundColor: 'rgba(79, 195, 247, 0.1)',
        borderRadius: '6px',
        fontSize: '12px',
        color: '#9e9e9e',
      }}>
        <strong style={{ color: '#4fc3f7' }}>Tip:</strong> Ask questions about HACTU8 architecture,
        implementation, or how to contribute to the project.
      </div>
    </div>
  );
};

export default ProjectDocsPanel;
