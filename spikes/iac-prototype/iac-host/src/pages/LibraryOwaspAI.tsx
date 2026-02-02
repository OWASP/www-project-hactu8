import { useState } from 'react';
import { Link } from 'react-router-dom';

interface OwaspDocument {
  id: string;
  title: string;
  description: string;
  category: string;
  url: string;
  icon: string;
}

const LibraryOwaspAI = () => {
  const [selectedCategory, setSelectedCategory] = useState('all');

  const owaspDocs: OwaspDocument[] = [
    {
      id: '1',
      title: 'OWASP Top 10 for LLM Applications',
      description: 'The most critical security risks for Large Language Model applications.',
      category: 'Standards',
      url: 'https://owasp.org/www-project-top-10-for-large-language-model-applications/',
      icon: '🔟',
    },
    {
      id: '2',
      title: 'OWASP AI Security and Privacy Guide',
      description: 'Comprehensive guide on AI security and privacy best practices.',
      category: 'Guides',
      url: 'https://owasp.org/www-project-ai-security-and-privacy-guide/',
      icon: '🔒',
    },
    {
      id: '3',
      title: 'OWASP Machine Learning Security Top 10',
      description: 'Top security risks specific to machine learning systems.',
      category: 'Standards',
      url: 'https://owasp.org/www-project-machine-learning-security-top-10/',
      icon: '🤖',
    },
    {
      id: '4',
      title: 'AI Security Best Practices',
      description: 'Collection of best practices for securing AI systems.',
      category: 'Best Practices',
      url: 'https://owasp.org/',
      icon: '✅',
    },
    {
      id: '5',
      title: 'Prompt Injection Defense',
      description: 'Strategies and techniques for defending against prompt injection attacks.',
      category: 'Defense',
      url: 'https://owasp.org/',
      icon: '🛡️',
    },
    {
      id: '6',
      title: 'AI Model Governance',
      description: 'Guidelines for governing AI models throughout their lifecycle.',
      category: 'Governance',
      url: 'https://owasp.org/',
      icon: '⚖️',
    },
  ];

  const categories = ['all', 'Standards', 'Guides', 'Best Practices', 'Defense', 'Governance'];

  const filteredDocs = owaspDocs.filter(doc => 
    selectedCategory === 'all' || doc.category === selectedCategory
  );

  return (
    <div className="flex flex-col h-full w-full overflow-auto">
      <header className="p-6 bg-white shadow z-10">
        <div className="flex items-center gap-4 mb-4">
          <Link to="/library" className="text-blue-600 hover:text-blue-800">
            ← Back to Library
          </Link>
        </div>
        <h1 className="text-3xl font-bold">OWASP AI Documents</h1>
        <p className="text-gray-600 mt-2">OWASP resources and guidelines for AI security</p>
      </header>

      <main className="flex-1 p-6">
        {/* Category Filter */}
        <div className="mb-6">
          <div className="flex gap-2 flex-wrap">
            {categories.map(category => (
              <button
                key={category}
                onClick={() => setSelectedCategory(category)}
                className={`px-4 py-2 rounded-lg transition-colors ${
                  selectedCategory === category
                    ? 'bg-blue-600 text-white'
                    : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
                }`}
              >
                {category}
              </button>
            ))}
          </div>
        </div>

        {/* Documents Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 max-w-6xl">
          {filteredDocs.map(doc => (
            <a
              key={doc.id}
              href={doc.url}
              target="_blank"
              rel="noopener noreferrer"
              className="block bg-white p-6 rounded-lg shadow border border-gray-200 hover:shadow-lg transition-shadow"
              style={{ textDecoration: 'none', color: 'inherit' }}
            >
              <div className="flex items-start gap-4">
                <div className="text-4xl">{doc.icon}</div>
                <div className="flex-1">
                  <div className="flex items-start justify-between gap-2 mb-2">
                    <h3 className="text-lg font-semibold text-gray-900">{doc.title}</h3>
                    <span className="px-2 py-1 bg-purple-100 text-purple-800 rounded text-xs whitespace-nowrap">
                      {doc.category}
                    </span>
                  </div>
                  <p className="text-gray-600 text-sm mb-3">{doc.description}</p>
                  <div className="flex items-center gap-1 text-blue-600 text-sm">
                    <span>View on OWASP</span>
                    <svg width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                    </svg>
                  </div>
                </div>
              </div>
            </a>
          ))}
        </div>
      </main>
    </div>
  );
};

export default LibraryOwaspAI;
