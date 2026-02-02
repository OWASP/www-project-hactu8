# Library / Knowledge Base Feature

## Overview
The Library feature provides a centralized knowledge base for documentation, research, and technical references related to AI security and the HACTU8 project.

## Structure

### Main Sections

1. **Knowledge Base** (`/library`)
   - Landing page with overview of all library sections
   - Quick navigation to subsections

2. **Articles & Research** (`/library/articles`)
   - Research papers on AI security
   - Articles about prompt injection, training data leakage, etc.
   - Searchable and filterable by category

3. **Project Documents** (`/library/project-docs`)
   - Official OWASP HACTU8 documentation
   - Links to the project wiki
   - Local documentation from configured folders

4. **OWASP AI Documents** (`/library/owasp-ai`)
   - OWASP Top 10 for LLM Applications
   - OWASP AI Security and Privacy Guide
   - Machine Learning Security Top 10
   - Other OWASP AI resources

5. **Technical References** (`/library/references`)
   - API documentation
   - Technical specifications
   - Developer guides
   - Tool references

## Configuration

### Feature Flags

The Library feature can be controlled via feature flags in `src/config/featureFlags.ts`:

```typescript
library: {
  enabled: boolean;        // Enable/disable entire library section
  articles: boolean;       // Show Articles & Research
  projectDocs: boolean;    // Show Project Documents
  owaspAI: boolean;        // Show OWASP AI Documents
  references: boolean;     // Show Technical References
}
```

### Document Sources

#### Project Wiki
The OWASP HACTU8 wiki is integrated at:
- Repository: `git@github.com-owasprox:OWASP/www-project-hactu8.wiki.git`
- Public URL: `https://github.com/OWASP/www-project-hactu8/wiki`

#### Local Documentation
Local documentation can be configured in multiple locations:
- Project `/docs` folder
- Configured documentation directories
- Custom documentation paths

## Features

### Search and Filter
- **Articles**: Search by title, summary, or category
- **Project Docs**: Filter by source (wiki/local)
- **OWASP AI**: Filter by document type
- **References**: Search and filter by type (API, guide, specification, tool)

### Navigation
- Breadcrumb navigation from subsections back to main library
- External links open in new tabs
- Internal document viewing in-app

### Responsive Design
- Grid layout for document cards
- Adapts to different screen sizes
- Consistent with existing application design

## Development

### Adding New Documents

#### Articles
Edit `/src/pages/LibraryArticles.tsx` and add to the `articles` array:
```typescript
{
  id: 'unique-id',
  title: 'Article Title',
  authors: ['Author Name'],
  date: '2024-01-01',
  category: 'Category Name',
  summary: 'Article description',
  url: 'https://...' // optional
}
```

#### OWASP Documents
Edit `/src/pages/LibraryOwaspAI.tsx` and add to the `owaspDocs` array:
```typescript
{
  id: 'unique-id',
  title: 'Document Title',
  description: 'Document description',
  category: 'Category',
  url: 'https://owasp.org/...',
  icon: '🔒'
}
```

#### Technical References
Edit `/src/pages/LibraryReferences.tsx` and add to the `references` array:
```typescript
{
  id: 'unique-id',
  title: 'Reference Title',
  description: 'Description',
  category: 'Category',
  type: 'api' | 'guide' | 'specification' | 'tool',
  url: 'https://...' // optional
}
```

### Future Enhancements

1. **Dynamic Content Loading**
   - Load documents from backend API
   - Real-time updates from wiki
   - Integration with git for documentation versioning

2. **Advanced Features**
   - Full-text search across all documents
   - Document versioning and history
   - Collaborative editing
   - Comments and annotations
   - Bookmarking and favorites
   - Reading progress tracking

3. **Integration**
   - Markdown viewer for local files
   - PDF viewer for research papers
   - Integration with documentation generators (Sphinx, MkDocs, etc.)
   - RSS/Atom feeds for updates

4. **Analytics**
   - Popular documents tracking
   - Search analytics
   - Usage statistics

## Files

### Pages
- `/src/pages/Library.tsx` - Main library landing page
- `/src/pages/LibraryArticles.tsx` - Articles & Research section
- `/src/pages/LibraryProjectDocs.tsx` - Project Documents section
- `/src/pages/LibraryOwaspAI.tsx` - OWASP AI Documents section
- `/src/pages/LibraryReferences.tsx` - Technical References section

### Configuration
- `/src/config/featureFlags.ts` - Feature flag definitions
- `/src/components/Sidebar.tsx` - Sidebar navigation with Library section
- `/src/App.tsx` - Routing configuration

## Usage

1. Navigate to the Library section from the sidebar
2. Browse available sections on the landing page
3. Click on a section to view documents
4. Use search and filter features to find specific content
5. Click on documents to view or open external links

## Customization

### Icons
Icons can be customized in each page component. Current implementation uses emoji icons for simplicity, but can be replaced with SVG or icon libraries.

### Styling
The pages use Tailwind CSS classes. Customize the appearance by modifying the className attributes in the component files.

### Categories
Categories can be customized by editing the `categories` array in each subsection component.
