import { useState } from 'react';
import { Link } from 'react-router-dom';

interface Article {
  id: string;
  title: string;
  authors: string[];
  date: string;
  category: string;
  summary: string;
  url?: string;
}

const LibraryArticles = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('all');

  // Mock data - replace with actual data source
  const articles: Article[] = [
    {
      id: '1',
      title: 'Prompt Injection Attacks: Understanding the Threat Landscape',
      authors: ['Security Research Team'],
      date: '2024-01-15',
      category: 'Security',
      summary: 'A comprehensive analysis of prompt injection vulnerabilities in large language models and mitigation strategies.',
    },
    {
      id: '2',
      title: 'Training Data Leakage in AI Systems',
      authors: ['AI Safety Institute'],
      date: '2023-12-10',
      category: 'Privacy',
      summary: 'Examining how training data can leak through model outputs and techniques to prevent such leakage.',
    },
    {
      id: '3',
      title: 'Model Supply Chain Security Best Practices',
      authors: ['OWASP Contributors'],
      date: '2023-11-20',
      category: 'Supply Chain',
      summary: 'Guidelines for securing the AI model supply chain from development to deployment.',
    },
  ];

  const categories = ['all', 'Security', 'Privacy', 'Supply Chain', 'Testing', 'Compliance'];

  const filteredArticles = articles.filter(article => {
    const matchesSearch = article.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         article.summary.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesCategory = selectedCategory === 'all' || article.category === selectedCategory;
    return matchesSearch && matchesCategory;
  });

  return (
    <div className="flex flex-col h-full w-full overflow-auto">
      <header className="p-6 bg-white shadow z-10">
        <div className="flex items-center gap-4 mb-4">
          <Link to="/library" className="text-blue-600 hover:text-blue-800">
            ← Back to Library
          </Link>
        </div>
        <h1 className="text-3xl font-bold">Articles & Research</h1>
        <p className="text-gray-600 mt-2">Browse research papers and articles on AI security</p>
      </header>

      <main className="flex-1 p-6">
        {/* Search and Filter */}
        <div className="mb-6 space-y-4">
          <input
            type="text"
            placeholder="Search articles..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
          />
          
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

        {/* Articles List */}
        <div className="space-y-4 max-w-4xl">
          {filteredArticles.length === 0 ? (
            <p className="text-gray-500 text-center py-8">No articles found matching your criteria.</p>
          ) : (
            filteredArticles.map(article => (
              <div key={article.id} className="bg-white p-6 rounded-lg shadow border border-gray-200">
                <div className="flex items-start justify-between gap-4 mb-2">
                  <h2 className="text-xl font-semibold text-gray-900">{article.title}</h2>
                  <span className="px-3 py-1 bg-blue-100 text-blue-800 rounded-full text-sm whitespace-nowrap">
                    {article.category}
                  </span>
                </div>
                <p className="text-gray-600 text-sm mb-2">
                  By {article.authors.join(', ')} • {new Date(article.date).toLocaleDateString()}
                </p>
                <p className="text-gray-700 mb-4">{article.summary}</p>
                {article.url && (
                  <a 
                    href={article.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-blue-600 hover:text-blue-800 inline-flex items-center gap-1"
                  >
                    Read more
                    <svg width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M5 3l6 6-6 6" />
                    </svg>
                  </a>
                )}
              </div>
            ))
          )}
        </div>
      </main>
    </div>
  );
};

export default LibraryArticles;
