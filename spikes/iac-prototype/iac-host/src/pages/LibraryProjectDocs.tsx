import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';

interface Document {
  id: string;
  title: string;
  path: string;
  category: string;
  lastModified: string;
  source: 'wiki' | 'local';
}

const LibraryProjectDocs = () => {
  const [documents, setDocuments] = useState<Document[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedSource, setSelectedSource] = useState<'all' | 'wiki' | 'local'>('all');

  useEffect(() => {
    // Simulate loading documents from various sources
    setTimeout(() => {
      const mockDocs: Document[] = [
        {
          id: '1',
          title: 'HACTU8 Project Overview',
          path: '/wiki/overview',
          category: 'Introduction',
          lastModified: '2024-01-20',
          source: 'wiki',
        },
        {
          id: '2',
          title: 'Getting Started Guide',
          path: '/wiki/getting-started',
          category: 'Tutorial',
          lastModified: '2024-01-18',
          source: 'wiki',
        },
        {
          id: '3',
          title: 'Architecture Documentation',
          path: '/docs/architecture.md',
          category: 'Technical',
          lastModified: '2024-01-15',
          source: 'local',
        },
        {
          id: '4',
          title: 'API Reference',
          path: '/docs/api-reference.md',
          category: 'Reference',
          lastModified: '2024-01-12',
          source: 'local',
        },
        {
          id: '5',
          title: 'Contributing Guidelines',
          path: '/wiki/contributing',
          category: 'Process',
          lastModified: '2024-01-10',
          source: 'wiki',
        },
      ];
      setDocuments(mockDocs);
      setLoading(false);
    }, 500);
  }, []);

  const filteredDocs = documents.filter(doc => {
    const matchesSearch = doc.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         doc.category.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesSource = selectedSource === 'all' || doc.source === selectedSource;
    return matchesSearch && matchesSource;
  });

  const handleDocumentClick = (doc: Document) => {
    if (doc.source === 'wiki') {
      // Open wiki link in new tab
      window.open(`https://github.com/OWASP/www-project-hactu8/wiki${doc.path}`, '_blank');
    } else {
      // Handle local document viewing
      console.log('Opening local document:', doc.path);
      // You can implement a document viewer here
    }
  };

  return (
    <div className="flex flex-col h-full w-full overflow-auto">
      <header className="p-6 shadow z-10" style={{ background: 'var(--iac-surface)' }}>
        <div className="flex items-center gap-4 mb-4">
          <Link to="/library" style={{ color: 'var(--iac-link)' }}>
            ← Back to Library
          </Link>
        </div>
        <h1 className="text-3xl font-bold">Project Documents</h1>
        <p className="mt-2" style={{ color: 'var(--iac-text-secondary)' }}>Official OWASP HACTU8 project documentation</p>
      </header>

      <main className="flex-1 p-6">
        {/* Configuration Info */}
        <div className="mb-6 p-4 rounded-lg" style={{ background: 'var(--iac-info-bg)', border: '1px solid var(--iac-info)' }}>
          <h3 className="font-semibold mb-2" style={{ color: 'var(--iac-info-text)' }}>📖 Document Sources</h3>
          <ul className="text-sm space-y-1" style={{ color: 'var(--iac-info-text)' }}>
            <li>• <strong>Wiki:</strong> github.com/OWASP/www-project-hactu8.wiki</li>
            <li>• <strong>Local Docs:</strong> Configured documentation folders</li>
          </ul>
        </div>

        {/* Search and Filter */}
        <div className="mb-6 space-y-4">
          <input
            type="text"
            placeholder="Search documents..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full px-4 py-2 rounded-lg"
            style={{
              border: '1px solid var(--iac-input-border)',
              background: 'var(--iac-input-bg)',
              color: 'var(--iac-text)',
            }}
          />

          <div className="flex gap-2">
            <button
              onClick={() => setSelectedSource('all')}
              className="px-4 py-2 rounded-lg transition-colors"
              style={{
                background: selectedSource === 'all' ? 'var(--iac-surface-elevated)' : 'var(--iac-surface)',
                color: selectedSource === 'all' ? 'var(--iac-text)' : 'var(--iac-text-secondary)',
                border: '1px solid var(--iac-border)',
              }}
            >
              All Sources
            </button>
            <button
              onClick={() => setSelectedSource('wiki')}
              className="px-4 py-2 rounded-lg transition-colors"
              style={{
                background: selectedSource === 'wiki' ? 'var(--iac-surface-elevated)' : 'var(--iac-surface)',
                color: selectedSource === 'wiki' ? 'var(--iac-text)' : 'var(--iac-text-secondary)',
                border: '1px solid var(--iac-border)',
              }}
            >
              Wiki
            </button>
            <button
              onClick={() => setSelectedSource('local')}
              className="px-4 py-2 rounded-lg transition-colors"
              style={{
                background: selectedSource === 'local' ? 'var(--iac-surface-elevated)' : 'var(--iac-surface)',
                color: selectedSource === 'local' ? 'var(--iac-text)' : 'var(--iac-text-secondary)',
                border: '1px solid var(--iac-border)',
              }}
            >
              Local Docs
            </button>
          </div>
        </div>

        {/* Documents List */}
        {loading ? (
          <div className="text-center py-8">
            <p style={{ color: 'var(--iac-text-secondary)' }}>Loading documents...</p>
          </div>
        ) : (
          <div className="space-y-3 max-w-4xl">
            {filteredDocs.length === 0 ? (
              <p className="text-center py-8" style={{ color: 'var(--iac-text-secondary)' }}>No documents found.</p>
            ) : (
              filteredDocs.map(doc => (
                <div
                  key={doc.id}
                  onClick={() => handleDocumentClick(doc)}
                  className="p-5 rounded-lg shadow hover:shadow-md transition-shadow cursor-pointer"
                  style={{ background: 'var(--iac-surface)', border: '1px solid var(--iac-border)' }}
                >
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-2">
                        <span className="text-2xl">
                          {doc.source === 'wiki' ? '📚' : '📄'}
                        </span>
                        <div>
                          <h3 className="text-lg font-semibold" style={{ color: 'var(--iac-text)' }}>{doc.title}</h3>
                          <p className="text-sm" style={{ color: 'var(--iac-text-secondary)' }}>
                            {doc.category} • Updated {new Date(doc.lastModified).toLocaleDateString()}
                          </p>
                        </div>
                      </div>
                      <p className="text-sm ml-11" style={{ color: 'var(--iac-text-secondary)' }}>
                        Source: {doc.source === 'wiki' ? 'OWASP Wiki' : 'Local Documentation'}
                      </p>
                    </div>
                    <div style={{ color: 'var(--iac-muted)' }}>
                      <svg width="24" height="24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                      </svg>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        )}
      </main>
    </div>
  );
};

export default LibraryProjectDocs;
