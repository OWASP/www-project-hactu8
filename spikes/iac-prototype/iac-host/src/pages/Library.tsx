import { useEffect, useMemo, useState } from 'react';
import ReactMarkdown from 'react-markdown';
import { useSearchParams } from 'react-router-dom';

type LibraryItem = {
  id: string;
  title: string;
  summary: string;
  type: 'markdown' | 'pdf';
  content?: string;
  url?: string;
};

type LibrarySection = {
  key: string;
  label: string;
  description: string;
  icon: string;
  items: LibraryItem[];
};

const librarySections: LibrarySection[] = [
  {
    key: 'knowledge-base',
    label: 'Knowledge Base',
    description: 'Core documentation and onboarding resources for the platform.',
    icon: '📚',
    items: [
      {
        id: 'kb-overview',
        title: 'Library Overview',
        summary: 'How to use the knowledge base and find critical project context.',
        type: 'markdown',
        content: `# Knowledge Base Overview

Welcome to the HACTU8 knowledge base. Use the section tabs to browse curated materials or search for a specific topic.

## What you can find
- Architecture notes and project guidance
- Research summaries and threat modeling references
- Technical specs and implementation checklists

Select an item on the left to preview it here.`,
      },
      {
        id: 'kb-onboarding',
        title: 'Getting Started',
        summary: 'A quick-start checklist for new contributors and operators.',
        type: 'markdown',
        content: `# Getting Started

1. Review the system overview.
2. Validate environment configuration.
3. Confirm feature flags for the target demo.
4. Capture findings in the reporting workspace.

> Tip: Keep a running log of changes while you explore.`,
      },
    ],
  },
  {
    key: 'project-docs',
    label: 'Project Documents',
    description: 'Official OWASP HACTU8 documentation and project notes.',
    icon: '📁',
    items: [
      {
        id: 'hactu8-docs',
        title: 'HACTU8 Documentation',
        summary: 'Project docs, operational guidance, and onboarding resources.',
        type: 'markdown',
        content: `# HACTU8 Documentation

## Scope
The HACTU8 prototype documents platform architecture, test workflows, and security controls.

## Recommended Reading
- Architecture overview
- Feature flag reference
- System message catalog

> Add PDFs to the config to render them directly in this panel.`,
      },
      {
        id: 'system-architecture',
        title: 'System Architecture Summary',
        summary: 'High-level topology, services, and data flow.',
        type: 'markdown',
        content: `# System Architecture Summary

The platform consists of a host shell, federated micro-frontends, and service integrations. Use this summary to align implementation work across teams.`,
      },
    ],
  },
  {
    key: 'research',
    label: 'Research',
    description: 'Research summaries, articles, and threat modeling references.',
    icon: '🧪',
    items: [
      {
        id: 'research-digest',
        title: 'Research Digest',
        summary: 'Weekly highlights from recent AI security research.',
        type: 'markdown',
        content: `# Research Digest

- Prompt injection trends and mitigations
- Data leakage and model inversion risks
- RAG security testing patterns

Use the search bar to locate specific research topics.`,
      },
      {
        id: 'threat-brief',
        title: 'Threat Modeling Brief',
        summary: 'Baseline threat scenarios for AI-assisted workflows.',
        type: 'markdown',
        content: `# Threat Modeling Brief

This brief outlines key adversary goals, attack surfaces, and recommended validation steps for AI workflows.`,
      },
    ],
  },
];

const Library = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const defaultKey = librarySections[0]?.key ?? 'knowledge-base';
  const sectionFromQuery = searchParams.get('section');
  const [query, setQuery] = useState('');
  const [selected, setSelected] = useState(() => {
    if (sectionFromQuery && librarySections.some((section) => section.key === sectionFromQuery)) {
      return sectionFromQuery;
    }
    return defaultKey;
  });
  const [selectedItemId, setSelectedItemId] = useState<string | null>(null);

  useEffect(() => {
    if (sectionFromQuery && librarySections.some((section) => section.key === sectionFromQuery)) {
      setSelected(sectionFromQuery);
    }
  }, [sectionFromQuery]);

  const activeSection = librarySections.find((section) => section.key === selected) ?? librarySections[0];

  const filteredItems = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return activeSection?.items ?? [];
    return (activeSection?.items ?? []).filter((item) => {
      return item.title.toLowerCase().includes(needle) || item.summary.toLowerCase().includes(needle);
    });
  }, [activeSection, query]);

  useEffect(() => {
    if (!filteredItems.length) {
      setSelectedItemId(null);
      return;
    }
    if (!selectedItemId || !filteredItems.some((item) => item.id === selectedItemId)) {
      setSelectedItemId(filteredItems[0].id);
    }
  }, [filteredItems, selectedItemId]);

  const activeItem = filteredItems.find((item) => item.id === selectedItemId) ?? null;

  const handleSelectSection = (key: string) => {
    setSelected(key);
    setQuery('');
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      next.set('section', key);
      return next;
    });
  };

  return (
    <div style={{ display: 'flex', minHeight: '60vh', borderRadius: 8, boxShadow: '0 2px 8px #0001' }}>
      <aside style={{ width: 300, borderRight: '1px solid var(--iac-border)', padding: '1rem 1rem' }}>
        <h3>Library</h3>
        <p style={{ color: 'var(--iac-text-secondary)', marginTop: 4 }}>Browse curated documentation and research.</p>
        <nav style={{ marginTop: '1.5rem' }}>
          <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
            {librarySections.map((section) => (
              <li key={section.key}>
                <button
                  style={{
                    width: '100%',
                    padding: '1rem 1.5rem',
                    background: selected === section.key ? 'var(--iac-surface-elevated)' : 'none',
                    color: selected === section.key ? 'var(--iac-text)' : 'var(--iac-text-secondary)',
                    border: 'none',
                    textAlign: 'left',
                    fontWeight: selected === section.key ? 600 : 400,
                    cursor: 'pointer',
                    borderRadius: 6,
                    marginBottom: 6,
                    transition: 'background 0.2s',
                  }}
                  onClick={() => handleSelectSection(section.key)}
                >
                  <span style={{ marginRight: 8 }}>{section.icon}</span>
                  {section.label}
                </button>
              </li>
            ))}
          </ul>
        </nav>
      </aside>
      <main style={{ flex: 1, padding: '2rem 3rem', display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
        <div>
          <h2 style={{ margin: 0 }}>{activeSection?.label}</h2>
          <p style={{ color: 'var(--iac-text-secondary)', marginTop: 6 }}>{activeSection?.description}</p>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <label style={{ fontWeight: 600, color: 'var(--iac-text)' }}>Search documents</label>
          <input
            type="search"
            placeholder="Search within this section"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            style={{
              padding: '0.75rem 1rem',
              borderRadius: 8,
              border: '1px solid var(--iac-input-border)',
              fontSize: '0.95rem',
              background: 'var(--iac-input-bg)',
              color: 'var(--iac-text)',
            }}
          />
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'minmax(240px, 320px) 1fr', gap: '1.5rem', minHeight: 360 }}>
          <div style={{ borderRight: '1px solid var(--iac-border)', paddingRight: '1rem' }}>
            <h4 style={{ marginTop: 0, marginBottom: '0.75rem' }}>Documents</h4>
            {filteredItems.length === 0 ? (
              <p style={{ color: 'var(--iac-text-secondary)' }}>No results found.</p>
            ) : (
              <ul style={{ listStyle: 'none', padding: 0, margin: 0, display: 'grid', gap: '0.75rem' }}>
                {filteredItems.map((item) => (
                  <li key={item.id}>
                    <button
                      onClick={() => setSelectedItemId(item.id)}
                      style={{
                        width: '100%',
                        padding: '0.75rem 1rem',
                        borderRadius: 8,
                        border: '1px solid var(--iac-border)',
                        background: selectedItemId === item.id ? 'var(--iac-surface-elevated)' : 'var(--iac-surface)',
                        color: 'var(--iac-text)',
                        textAlign: 'left',
                        cursor: 'pointer',
                      }}
                    >
                      <div style={{ fontWeight: 600, marginBottom: 4 }}>{item.title}</div>
                      <div style={{ color: 'var(--iac-text-secondary)', fontSize: '0.85rem' }}>{item.summary}</div>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </div>

          <div style={{ paddingLeft: '0.5rem' }}>
            {!activeItem && (
              <div style={{ color: 'var(--iac-text-secondary)' }}>Select a document to preview it.</div>
            )}
            {activeItem?.type === 'markdown' && (
              <div style={{ background: 'var(--iac-surface)', borderRadius: 8, padding: '1.5rem', border: '1px solid var(--iac-border)' }}>
                <ReactMarkdown>{activeItem.content ?? ''}</ReactMarkdown>
              </div>
            )}
            {activeItem?.type === 'pdf' && (
              <div style={{ background: 'var(--iac-surface)', borderRadius: 8, padding: '0.5rem', border: '1px solid var(--iac-border)' }}>
                {activeItem.url ? (
                  <iframe
                    title={activeItem.title}
                    src={activeItem.url}
                    style={{ width: '100%', height: '70vh', border: 'none' }}
                  />
                ) : (
                  <div style={{ padding: '1rem', color: 'var(--iac-text-secondary)' }}>
                    No PDF source configured for this document.
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
};

export default Library;
