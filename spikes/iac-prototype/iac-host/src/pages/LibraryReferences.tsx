import React, { useState } from 'react';
import { Link } from 'react-router-dom';

interface Reference {
  id: string;
  title: string;
  description: string;
  category: string;
  type: 'api' | 'guide' | 'specification' | 'tool';
  url?: string;
}

const LibraryReferences = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedType, setSelectedType] = useState<string>('all');

  const references: Reference[] = [
    {
      id: '1',
      title: 'REST API Documentation',
      description: 'Complete API reference for HACTU8 services and endpoints.',
      category: 'API',
      type: 'api',
    },
    {
      id: '2',
      title: 'Testing Framework Guide',
      description: 'How to use the AI security testing framework effectively.',
      category: 'Testing',
      type: 'guide',
    },
    {
      id: '3',
      title: 'Plugin Development Specification',
      description: 'Technical specification for developing custom plugins and extensions.',
      category: 'Development',
      type: 'specification',
    },
    {
      id: '4',
      title: 'CLI Tool Reference',
      description: 'Command-line interface reference and usage examples.',
      category: 'Tools',
      type: 'tool',
    },
    {
      id: '5',
      title: 'Configuration Schema',
      description: 'JSON schema for system configuration files.',
      category: 'Configuration',
      type: 'specification',
    },
    {
      id: '6',
      title: 'Integration Guide',
      description: 'Guide for integrating HACTU8 with external systems.',
      category: 'Integration',
      type: 'guide',
    },
  ];

  const types = [
    { value: 'all', label: 'All Types' },
    { value: 'api', label: 'API' },
    { value: 'guide', label: 'Guide' },
    { value: 'specification', label: 'Specification' },
    { value: 'tool', label: 'Tool' },
  ];

  const filteredRefs = references.filter(ref => {
    const matchesSearch = ref.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         ref.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         ref.category.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesType = selectedType === 'all' || ref.type === selectedType;
    return matchesSearch && matchesType;
  });

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'api': return '🔌';
      case 'guide': return '📘';
      case 'specification': return '📋';
      case 'tool': return '🔧';
      default: return '📄';
    }
  };

  const getTypeStyle = (type: string): React.CSSProperties => {
    switch (type) {
      case 'api': return { background: 'var(--iac-success-bg)', color: 'var(--iac-success-text)' };
      case 'guide': return { background: 'var(--iac-info-bg)', color: 'var(--iac-info-text)' };
      case 'specification': return { background: 'var(--iac-badge-bg)', color: 'var(--iac-badge-text)' };
      case 'tool': return { background: 'var(--iac-warning-bg)', color: 'var(--iac-warning-text)' };
      default: return { background: 'var(--iac-surface)', color: 'var(--iac-text-secondary)' };
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
        <h1 className="text-3xl font-bold">Technical References</h1>
        <p className="mt-2" style={{ color: 'var(--iac-text-secondary)' }}>API documentation and technical references</p>
      </header>

      <main className="flex-1 p-6">
        {/* Search and Filter */}
        <div className="mb-6 space-y-4">
          <input
            type="text"
            placeholder="Search references..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full px-4 py-2 rounded-lg"
            style={{
              border: '1px solid var(--iac-input-border)',
              background: 'var(--iac-input-bg)',
              color: 'var(--iac-text)',
            }}
          />

          <div className="flex gap-2 flex-wrap">
            {types.map(type => (
              <button
                key={type.value}
                onClick={() => setSelectedType(type.value)}
                className="px-4 py-2 rounded-lg transition-colors"
                style={{
                  background: selectedType === type.value ? 'var(--iac-surface-elevated)' : 'var(--iac-surface)',
                  color: selectedType === type.value ? 'var(--iac-text)' : 'var(--iac-text-secondary)',
                  border: '1px solid var(--iac-border)',
                }}
              >
                {type.label}
              </button>
            ))}
          </div>
        </div>

        {/* References Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 max-w-6xl">
          {filteredRefs.length === 0 ? (
            <p className="text-center py-8 col-span-2" style={{ color: 'var(--iac-text-secondary)' }}>No references found.</p>
          ) : (
            filteredRefs.map(ref => (
              <div
                key={ref.id}
                className="p-5 rounded-lg shadow hover:shadow-md transition-shadow cursor-pointer"
                style={{ background: 'var(--iac-surface)', border: '1px solid var(--iac-border)' }}
                onClick={() => ref.url && window.open(ref.url, '_blank')}
              >
                <div className="flex items-start gap-4">
                  <div className="text-3xl">{getTypeIcon(ref.type)}</div>
                  <div className="flex-1">
                    <div className="flex items-start justify-between gap-2 mb-2">
                      <h3 className="text-lg font-semibold" style={{ color: 'var(--iac-text)' }}>{ref.title}</h3>
                      <span className="px-2 py-1 rounded text-xs whitespace-nowrap" style={getTypeStyle(ref.type)}>
                        {ref.type}
                      </span>
                    </div>
                    <p className="text-sm mb-2" style={{ color: 'var(--iac-text-secondary)' }}>{ref.description}</p>
                    <p className="text-xs" style={{ color: 'var(--iac-muted)' }}>Category: {ref.category}</p>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>

        {/* Quick Links */}
        <div className="mt-8 p-4 rounded-lg max-w-4xl" style={{ background: 'var(--iac-surface)', border: '1px solid var(--iac-border)' }}>
          <h3 className="font-semibold mb-3" style={{ color: 'var(--iac-text)' }}>Quick Links</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-sm">
            <a href="#" style={{ color: 'var(--iac-link)' }}>→ API Authentication</a>
            <a href="#" style={{ color: 'var(--iac-link)' }}>→ Rate Limiting</a>
            <a href="#" style={{ color: 'var(--iac-link)' }}>→ Error Codes</a>
            <a href="#" style={{ color: 'var(--iac-link)' }}>→ SDK Downloads</a>
          </div>
        </div>
      </main>
    </div>
  );
};

export default LibraryReferences;
