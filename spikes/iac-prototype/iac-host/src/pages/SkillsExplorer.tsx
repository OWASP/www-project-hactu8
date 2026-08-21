// src/pages/SkillsExplorer.tsx
//
// Skills Explorer — browse the curated & signed HACTU8 skills registry and
// install skills into this host. Mirrors the Extensions "Available" flow,
// but skills are lightweight SKILL.md packages verified by sha256 signature
// rather than downloaded/extracted zips.
import React, { useCallback, useEffect, useState } from 'react';
import type { SkillRegistryEntry } from '../types/skills';
import skillService from '../services/skillService';
import { useSkills } from '../contexts/SkillContext';
import {
  Badge,
  SignatureBadge,
  InfoField,
  CATEGORY_LABELS,
  sidebarStyle,
  mainStyle,
  cardStyle,
  installButtonStyle,
  smallButtonStyle,
  primaryButtonStyle,
} from '../components/Skills/shared';

const SkillsExplorer: React.FC = () => {
  const [registry, setRegistry] = useState<SkillRegistryEntry[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [isInstallingId, setIsInstallingId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const { installed, installFromRegistry } = useSkills();

  const loadRegistry = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const entries = await skillService.fetchRegistry();
      setRegistry(entries);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load skills registry');
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadRegistry();
  }, [loadRegistry]);

  const installedIds = new Set(installed.map((s) => s.manifest.id));
  const selected = registry.find((e) => e.manifest.id === selectedId) ?? null;

  const handleInstall = useCallback(
    (entry: SkillRegistryEntry) => {
      setIsInstallingId(entry.manifest.id);
      setError(null);
      installFromRegistry(entry)
        .then(() => setIsInstallingId(null))
        .catch((err) => {
          setError(err instanceof Error ? err.message : 'Install failed');
          setIsInstallingId(null);
        });
    },
    [installFromRegistry]
  );

  return (
    <div style={{ display: 'flex', minHeight: '60vh', height: '100%', overflow: 'hidden' }}>
      <aside style={sidebarStyle}>
        <h3 style={{ color: 'var(--iac-text)', marginBottom: '0.25rem' }}>Skills Explorer</h3>
        <p style={{ color: 'var(--iac-muted)', fontSize: '0.8rem', marginTop: 0, marginBottom: '1rem' }}>
          Curated & signed by the OWASP HACTU8 skills board.
        </p>

        {isLoading && <p style={{ color: 'var(--iac-muted)', fontSize: '0.875rem' }}>Loading registry...</p>}
        {error && (
          <div>
            <p style={{ color: 'var(--iac-error)', fontSize: '0.875rem' }}>{error}</p>
            <button onClick={loadRegistry} style={smallButtonStyle}>Retry</button>
          </div>
        )}
        {!isLoading && !error && registry.length === 0 && (
          <p style={{ color: 'var(--iac-muted)', fontSize: '0.875rem' }}>No skills found in registry.</p>
        )}

        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', overflowY: 'auto' }}>
          {registry.map((entry) => {
            const isInstalled = installedIds.has(entry.manifest.id);
            const isSelected = selectedId === entry.manifest.id;
            return (
              <div
                key={entry.manifest.id}
                onClick={() => setSelectedId(entry.manifest.id)}
                style={{
                  ...cardStyle,
                  borderColor: isSelected ? 'var(--iac-surface-elevated)' : 'var(--iac-border)',
                  background: isSelected ? 'var(--iac-surface)' : 'var(--iac-bg)',
                  cursor: 'pointer',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontWeight: 600, fontSize: '0.9rem', color: 'var(--iac-text)', marginBottom: '0.15rem' }}>
                      {entry.manifest.name}
                    </div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--iac-muted)', marginBottom: '0.35rem' }}>
                      {entry.manifest.description}
                    </div>
                    <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap' }}>
                      <Badge
                        label={CATEGORY_LABELS[entry.manifest.category] ?? entry.manifest.category}
                        color="var(--iac-info-bg)"
                        textColor="var(--iac-info-text)"
                      />
                      <SignatureBadge verified={entry.signature.verified} />
                    </div>
                  </div>
                  <div style={{ marginLeft: '0.5rem', flexShrink: 0 }}>
                    {isInstalled ? (
                      <span style={{ fontSize: '0.75rem', color: 'var(--iac-success)', fontWeight: 600 }}>Installed</span>
                    ) : (
                      <button
                        onClick={(e) => { e.stopPropagation(); handleInstall(entry); }}
                        disabled={isInstallingId === entry.manifest.id}
                        style={installButtonStyle}
                      >
                        {isInstallingId === entry.manifest.id ? 'Installing…' : 'Install'}
                      </button>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </aside>

      <main style={mainStyle}>
        {!selected && (
          <div style={{ color: 'var(--iac-muted)', textAlign: 'center', marginTop: '4rem' }}>
            <p>Select a skill to view details.</p>
          </div>
        )}
        {selected && (
          <div>
            <div style={{ marginBottom: '1.5rem' }}>
              <h3 style={{ color: 'var(--iac-text)', fontWeight: 700, fontSize: '1.5rem', margin: '0 0 0.25rem' }}>
                {selected.manifest.name}
              </h3>
              <p style={{ color: 'var(--iac-text-secondary)', margin: '0 0 0.75rem', fontSize: '0.925rem' }}>
                {selected.manifest.description}
              </p>
              <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', alignItems: 'center' }}>
                <Badge
                  label={CATEGORY_LABELS[selected.manifest.category] ?? selected.manifest.category}
                  color="var(--iac-info-bg)"
                  textColor="var(--iac-info-text)"
                />
                <Badge label={`v${selected.manifest.version}`} color="var(--iac-surface)" textColor="var(--iac-border)" />
                <SignatureBadge verified={selected.signature.verified} />
              </div>
            </div>

            <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1.5rem' }}>
              {installedIds.has(selected.manifest.id) ? (
                <span style={{ color: 'var(--iac-success)', fontWeight: 600 }}>Already installed</span>
              ) : (
                <button onClick={() => handleInstall(selected)} style={primaryButtonStyle}>Install</button>
              )}
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1.5rem' }}>
              <InfoField label="Author" value={selected.manifest.author} />
              <InfoField label="License" value={selected.manifest.license} />
              <InfoField label="Curated By" value={selected.signature.curatedBy} />
              <InfoField label="Signed" value={new Date(selected.signature.signedAt).toLocaleDateString()} />
            </div>

            {selected.manifest.tags && selected.manifest.tags.length > 0 && (
              <div style={{ marginBottom: '1.5rem' }}>
                <h4 style={{ color: 'var(--iac-text)', fontWeight: 600, marginBottom: '0.5rem' }}>Tags</h4>
                <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap' }}>
                  {selected.manifest.tags.map((t) => (
                    <Badge key={t} label={t} color="var(--iac-surface)" textColor="var(--iac-text-secondary)" />
                  ))}
                </div>
              </div>
            )}

            <div>
              <h4 style={{ color: 'var(--iac-text)', fontWeight: 600, marginBottom: '0.5rem' }}>SKILL.md</h4>
              <pre
                style={{
                  padding: '1rem',
                  background: 'var(--iac-code-bg)',
                  color: 'var(--iac-code-text)',
                  borderRadius: '6px',
                  fontSize: '0.8rem',
                  overflowX: 'auto',
                  whiteSpace: 'pre-wrap',
                }}
              >
                {selected.content}
              </pre>
            </div>
          </div>
        )}
      </main>
    </div>
  );
};

export default SkillsExplorer;
