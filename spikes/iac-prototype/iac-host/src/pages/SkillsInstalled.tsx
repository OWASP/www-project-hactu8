// src/pages/SkillsInstalled.tsx
//
// Manage skills installed on this host — curated (signed) skills installed
// from the Explorer, and local drafts saved from the Skills Creator.
import React, { useCallback, useState } from 'react';
import { useSkills } from '../contexts/SkillContext';
import skillService from '../services/skillService';
import type { InstalledSkill } from '../types/skills';
import {
  Badge,
  SignatureBadge,
  InfoField,
  CATEGORY_LABELS,
  sidebarStyle,
  mainStyle,
  cardStyle,
  dangerButtonStyle,
  secondaryButtonStyle,
} from '../components/Skills/shared';

const SkillsInstalled: React.FC = () => {
  const { installed, uninstallSkill } = useSkills();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const selected = installed.find((s) => s.manifest.id === selectedId) ?? null;

  const handleUninstall = useCallback(
    (id: string) => {
      uninstallSkill(id);
      if (selectedId === id) setSelectedId(null);
    },
    [uninstallSkill, selectedId]
  );

  const handleCopy = useCallback((skill: InstalledSkill) => {
    navigator.clipboard.writeText(skill.content).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }, []);

  return (
    <div style={{ display: 'flex', minHeight: '60vh', height: '100%', overflow: 'hidden' }}>
      <aside style={sidebarStyle}>
        <h3 style={{ color: 'var(--iac-text)', marginBottom: '0.25rem' }}>Installed Skills</h3>
        <p style={{ color: 'var(--iac-muted)', fontSize: '0.8rem', marginTop: 0, marginBottom: '1rem' }}>
          {installed.length} skill{installed.length === 1 ? '' : 's'} available to this host.
        </p>

        {installed.length === 0 && (
          <p style={{ color: 'var(--iac-muted)', fontSize: '0.875rem' }}>
            No skills installed yet. Install one from the Skills Explorer or author a draft in the Skills Creator.
          </p>
        )}

        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', overflowY: 'auto' }}>
          {installed.map((skill) => {
            const isSelected = selectedId === skill.manifest.id;
            return (
              <div
                key={skill.manifest.id}
                onClick={() => setSelectedId(skill.manifest.id)}
                style={{
                  ...cardStyle,
                  borderColor: isSelected ? 'var(--iac-surface-elevated)' : 'var(--iac-border)',
                  background: isSelected ? 'var(--iac-surface)' : 'var(--iac-bg)',
                  cursor: 'pointer',
                }}
              >
                <div style={{ fontWeight: 600, fontSize: '0.9rem', color: 'var(--iac-text)', marginBottom: '0.15rem' }}>
                  {skill.manifest.name}
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--iac-muted)', marginBottom: '0.35rem' }}>
                  v{skill.manifest.version} · {skill.source === 'registry' ? 'From registry' : 'Local draft'}
                </div>
                <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap' }}>
                  <Badge
                    label={CATEGORY_LABELS[skill.manifest.category] ?? skill.manifest.category}
                    color="var(--iac-info-bg)"
                    textColor="var(--iac-info-text)"
                  />
                  <SignatureBadge verified={skill.signature.verified} />
                </div>
              </div>
            );
          })}
        </div>
      </aside>

      <main style={mainStyle}>
        {!selected && (
          <div style={{ color: 'var(--iac-muted)', textAlign: 'center', marginTop: '4rem' }}>
            <p>Select an installed skill to view details.</p>
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
              <button onClick={() => handleCopy(selected)} style={secondaryButtonStyle}>
                {copied ? 'Copied!' : 'Copy SKILL.md'}
              </button>
              <button onClick={() => skillService.downloadSkillPackage(selected)} style={secondaryButtonStyle}>
                Export Package
              </button>
              <button onClick={() => handleUninstall(selected.manifest.id)} style={dangerButtonStyle}>
                {selected.source === 'local-draft' ? 'Delete Draft' : 'Uninstall'}
              </button>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1.5rem' }}>
              <InfoField label="Author" value={selected.manifest.author} />
              <InfoField label="License" value={selected.manifest.license} />
              <InfoField label="Curated By" value={selected.signature.curatedBy} />
              <InfoField label="Installed" value={new Date(selected.installedAt).toLocaleDateString()} />
            </div>

            {selected.manifest.allowedTools && selected.manifest.allowedTools.length > 0 && (
              <div style={{ marginBottom: '1.5rem' }}>
                <h4 style={{ color: 'var(--iac-text)', fontWeight: 600, marginBottom: '0.5rem' }}>Allowed Tools</h4>
                <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap' }}>
                  {selected.manifest.allowedTools.map((t) => (
                    <Badge key={t} label={t} color="var(--iac-warning-bg)" textColor="var(--iac-warning-text)" />
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

export default SkillsInstalled;
