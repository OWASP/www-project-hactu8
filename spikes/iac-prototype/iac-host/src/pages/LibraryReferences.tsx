import { useState } from 'react';
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

  const getTypeColor = (type: string) => {
    switch (type) {
      case 'api': return 'bg-green-100 text-green-800';
      case 'guide': return 'bg-blue-100 text-blue-800';
      case 'specification': return 'bg-purple-100 text-purple-800';
      case 'tool': return 'bg-orange-100 text-orange-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  return (
    <div className="flex flex-col h-full w-full overflow-auto">
      <header className="p-6 bg-white shadow z-10">
        <div className="flex items-center gap-4 mb-4">
          <Link to="/library" className="text-blue-600 hover:text-blue-800">
            ← Back to Library
          </Link>
        </div>
        <h1 className="text-3xl font-bold">Technical References</h1>
        <p className="text-gray-600 mt-2">API documentation and technical references</p>
      </header>

      <main className="flex-1 p-6">
        {/* Search and Filter */}
        <div className="mb-6 space-y-4">
          <input
            type="text"
            placeholder="Search references..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          />
          
          <div className="flex gap-2 flex-wrap">
            {types.map(type => (
              <button
                key={type.value}
                onClick={() => setSelectedType(type.value)}
                className={`px-4 py-2 rounded-lg transition-colors ${
                  selectedType === type.value
                    ? 'bg-blue-600 text-white'
                    : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
                }`}
              >
                {type.label}
              </button>
            ))}
          </div>
        </div>

        {/* References Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 max-w-6xl">
          {filteredRefs.length === 0 ? (
            <p className="text-gray-500 text-center py-8 col-span-2">No references found.</p>
          ) : (
            filteredRefs.map(ref => (
              <div
                key={ref.id}
                className="bg-white p-5 rounded-lg shadow border border-gray-200 hover:shadow-md transition-shadow cursor-pointer"
                onClick={() => ref.url && window.open(ref.url, '_blank')}
              >
                <div className="flex items-start gap-4">
                  <div className="text-3xl">{getTypeIcon(ref.type)}</div>
                  <div className="flex-1">
                    <div className="flex items-start justify-between gap-2 mb-2">
                      <h3 className="text-lg font-semibold text-gray-900">{ref.title}</h3>
                      <span className={`px-2 py-1 rounded text-xs whitespace-nowrap ${getTypeColor(ref.type)}`}>
                        {ref.type}
                      </span>
                    </div>
                    <p className="text-sm text-gray-600 mb-2">{ref.description}</p>
                    <p className="text-xs text-gray-500">Category: {ref.category}</p>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>

        {/* Quick Links */}
        <div className="mt-8 p-4 bg-gray-50 border border-gray-200 rounded-lg max-w-4xl">
          <h3 className="font-semibold text-gray-900 mb-3">Quick Links</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-sm">
            <a href="#" className="text-blue-600 hover:text-blue-800">→ API Authentication</a>
            <a href="#" className="text-blue-600 hover:text-blue-800">→ Rate Limiting</a>
            <a href="#" className="text-blue-600 hover:text-blue-800">→ Error Codes</a>
            <a href="#" className="text-blue-600 hover:text-blue-800">→ SDK Downloads</a>
          </div>
        </div>
      </main>
    </div>
  );
};

export default LibraryReferences;
