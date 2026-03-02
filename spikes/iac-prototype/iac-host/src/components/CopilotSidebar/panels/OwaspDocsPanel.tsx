/**
 * OWASP Docs Panel - for browsing and syncing OWASP AI security documents.
 */

import React, { useState } from 'react';
import { useCopilot } from '../../../contexts/CopilotContext';
import copilotService from '../../../services/copilotService';

const OwaspDocsPanel: React.FC = () => {
  const { documents, syncOwaspDocs, isSyncing } = useCopilot();
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [isSourcesExpanded, setIsSourcesExpanded] = useState(false);
  const [syncError, setSyncError] = useState<string | null>(null);
  const [showSources, setShowSources] = useState(false);
  const [sourceItems, setSourceItems] = useState<Array<{ id: string; title: string; sourceUrl?: string }>>([]);
  const [sourceError, setSourceError] = useState<string | null>(null);
  const [sourcesLoading, setSourcesLoading] = useState(false);

  // Filter to show only OWASP documents
  const owaspDocs = documents.filter(d => d.sourceType === 'owasp');

  // Get unique categories
  const categories = ['all', ...new Set(owaspDocs.map(d => d.category).filter((c): c is string => Boolean(c)))];

  // Filter by selected category
  const filteredDocs = selectedCategory === 'all'
    ? owaspDocs
    : owaspDocs.filter(d => d.category === selectedCategory);

  const handleSync = async () => {
    try {
      setSyncError(null);
      await syncOwaspDocs();
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to sync OWASP docs';
      console.error('Failed to sync OWASP docs:', error);
      setSyncError(message);
    }
  };

  const toggleSources = async () => {
    const next = !showSources;
    setShowSources(next);

    if (!next) {
      return;
    }

    setSourcesLoading(true);
    setSourceError(null);

    try {
      const response = await copilotService.getSources();
      const items = response.sources?.owasp?.documents || [];
      const normalized = items.map((item: any) => ({
        id: item.id,
        title: item.title,
        sourceUrl: item.source_url || item.sourceUrl,
      }));
      setSourceItems(normalized);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to load sources';
      setSourceError(message);
    } finally {
      setSourcesLoading(false);
    }
  };

  const getCategoryClass = (category?: string) => {
    if (!category) return '';
    return category.toLowerCase().replace(/\s+/g, '-');
  };

  const getDocIcon = (doc: typeof owaspDocs[0]) => {
    switch (doc.category?.toLowerCase()) {
      case 'standards':
        return '🔟';
      case 'guides':
        return '📘';
      case 'best practices':
        return '✅';
      case 'defense':
        return '🛡️';
      case 'governance':
        return '⚖️';
      default:
        return '📄';
    }
  };

  return (
    <div className="owasp-panel">
      <div className="copilot-section-header">
        <span className="copilot-section-title">Data Sources ({owaspDocs.length})</span>
        <button
          type="button"
          className="copilot-section-toggle"
          onClick={() => setIsSourcesExpanded(prev => !prev)}
          aria-expanded={isSourcesExpanded}
          aria-controls="owasp-sources-panel"
        >
          {isSourcesExpanded ? 'Collapse' : 'Expand'}
        </button>
      </div>

      {isSourcesExpanded && (
        <div id="owasp-sources-panel">
          {/* Section Header with Sync Button */}
          <div className="copilot-section-header">
            <span className="copilot-section-title">OWASP AI Security</span>
            <div style={{ display: 'flex', gap: '6px' }}>
              <button
                className="copilot-section-action"
                onClick={toggleSources}
                disabled={sourcesLoading}
                style={{ backgroundColor: '#2a2a4a', color: '#9e9e9e' }}
              >
                {sourcesLoading ? 'Loading...' : (showSources ? 'Hide Sources' : 'View Sources')}
              </button>
              <button
                className="copilot-section-action"
                onClick={handleSync}
                disabled={isSyncing}
              >
                {isSyncing ? 'Syncing...' : 'Sync'}
              </button>
            </div>
          </div>

          {syncError && (
            <div className="copilot-empty" style={{ padding: '12px', border: '1px solid #ef4444', borderRadius: '6px', marginBottom: '12px' }}>
              <p className="copilot-empty-text" style={{ fontSize: '12px', color: '#ef4444' }}>
                {syncError}
              </p>
            </div>
          )}

          {showSources && (
            <div style={{ marginBottom: '12px' }}>
              {sourceError ? (
                <div className="copilot-empty" style={{ padding: '12px', border: '1px solid #ef4444', borderRadius: '6px' }}>
                  <p className="copilot-empty-text" style={{ fontSize: '12px', color: '#ef4444' }}>
                    {sourceError}
                  </p>
                </div>
              ) : (
                <div className="copilot-doc-list">
                  {sourceItems.length === 0 ? (
                    <div className="copilot-empty" style={{ padding: '12px' }}>
                      <p className="copilot-empty-text" style={{ fontSize: '12px' }}>
                        No OWASP sources indexed yet.
                      </p>
                    </div>
                  ) : (
                    sourceItems.map(item => (
                      <a
                        key={item.id}
                        href={item.sourceUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="copilot-doc-item"
                        style={{ textDecoration: 'none', cursor: item.sourceUrl ? 'pointer' : 'default' }}
                        aria-disabled={!item.sourceUrl}
                      >
                        <div className="copilot-doc-info">
                          <span className="copilot-doc-icon">📄</span>
                          <span className="copilot-doc-title" title={item.title}>
                            {item.title}
                          </span>
                        </div>
                        {item.sourceUrl && (
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
                        )}
                      </a>
                    ))
                  )}
                </div>
              )}
            </div>
          )}

          {/* Category Filter */}
          {categories.length > 1 && (
            <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap', marginBottom: '12px' }}>
              {categories.map(category => (
                <button
                  key={category}
                  onClick={() => setSelectedCategory(category)}
                  style={{
                    padding: '4px 10px',
                    borderRadius: '4px',
                    border: 'none',
                    fontSize: '11px',
                    cursor: 'pointer',
                    backgroundColor: selectedCategory === category ? '#4fc3f7' : '#2a2a4a',
                    color: selectedCategory === category ? '#1a1a2e' : '#9e9e9e',
                    transition: 'all 0.2s',
                  }}
                >
                  {category === 'all' ? 'All' : category}
                </button>
              ))}
            </div>
          )}

          {/* Document List */}
          {filteredDocs.length === 0 ? (
            <div className="copilot-empty" style={{ padding: '20px' }}>
              <div className="copilot-empty-icon">🛡️</div>
              <p className="copilot-empty-text" style={{ fontSize: '12px' }}>
                {owaspDocs.length === 0
                  ? 'No OWASP documents synced yet. Click "Sync" to fetch the latest OWASP AI security resources.'
                  : 'No documents match the selected filter.'}
              </p>
            </div>
          ) : (
            <div className="copilot-doc-list">
              {filteredDocs.map(doc => (
                <a
                  key={doc.id}
                  href={doc.sourceUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="copilot-doc-item"
                  style={{ textDecoration: 'none', cursor: 'pointer' }}
                >
                  <div className="copilot-doc-info">
                    <span className="copilot-doc-icon">{getDocIcon(doc)}</span>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <span className="copilot-doc-title" title={doc.title}>
                        {doc.title}
                      </span>
                      {doc.category && (
                        <span
                          className={`copilot-category-badge ${getCategoryClass(doc.category)}`}
                          style={{ marginLeft: '8px' }}
                        >
                          {doc.category}
                        </span>
                      )}
                    </div>
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
          )}

          {/* Info text */}
          <p style={{
            fontSize: '11px',
            color: '#9e9e9e',
            marginTop: '12px',
            textAlign: 'center',
          }}>
            Documents synced from OWASP GitHub repositories
          </p>
        </div>
      )}
    </div>
  );
};

export default OwaspDocsPanel;
