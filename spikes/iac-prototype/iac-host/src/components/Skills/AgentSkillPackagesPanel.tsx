// src/components/Skills/AgentSkillPackagesPanel.tsx
//
// Real, filesystem-backed Skill Packages (agentskills.io spec) — install by
// uploading a .skill (zip) archive, extracted server-side to
// ~/.iac/skills/<name>/. Distinct from the "Legacy Skills" tab alongside it;
// installing/uninstalling here has no effect on that system.
import React, { useRef, useState } from 'react';
import { useSkillPackages } from '../../contexts/SkillPackageContext';
import { Badge, cardStyle, dangerButtonStyle, primaryButtonStyle } from './shared';

const AgentSkillPackagesPanel: React.FC = () => {
  const { installed, isLoading, isInstalling, error, installFromFile, uninstall } = useSkillPackages();
  const [localError, setLocalError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setLocalError(null);
    try {
      await installFromFile(file);
    } catch (err) {
      setLocalError(err instanceof Error ? err.message : 'Install failed');
    } finally {
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  return (
    <div>
      <p style={{ color: 'var(--iac-muted)', fontSize: '0.8rem', marginTop: 0, marginBottom: '1rem' }}>
        Real skill directories (SKILL.md + optional scripts/references/assets), installed on this host's
        filesystem — droppable into Claude Code or any agentskills.io-compliant tool.
      </p>

      <input
        ref={fileInputRef}
        type="file"
        accept=".skill,.zip"
        onChange={handleFileChange}
        style={{ display: 'none' }}
      />
      <button
        style={primaryButtonStyle}
        onClick={() => fileInputRef.current?.click()}
        disabled={isInstalling}
      >
        {isInstalling ? 'Installing…' : '+ Upload Skill (.skill)'}
      </button>

      {(error || localError) && (
        <p style={{ color: 'var(--iac-error)', fontSize: '0.875rem', marginTop: '0.75rem' }}>
          {localError || error}
        </p>
      )}

      {isLoading && installed.length === 0 && (
        <p style={{ color: 'var(--iac-muted)', fontSize: '0.875rem', marginTop: '1rem' }}>Loading…</p>
      )}
      {!isLoading && installed.length === 0 && (
        <p style={{ color: 'var(--iac-muted)', fontSize: '0.875rem', marginTop: '1rem' }}>
          No skill packages installed yet.
        </p>
      )}

      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', marginTop: '1rem' }}>
        {installed.map((skill) => (
          <div key={skill.name} style={cardStyle}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontWeight: 600, fontSize: '0.9rem', color: 'var(--iac-text)', marginBottom: '0.15rem' }}>
                  {skill.manifest.name}
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--iac-muted)', marginBottom: '0.5rem' }}>
                  {skill.manifest.description}
                </div>
                <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap', marginBottom: '0.5rem' }}>
                  <Badge label="Agent Skill" color="var(--iac-info-bg)" textColor="var(--iac-info-text)" />
                  {skill.manifest.license && (
                    <Badge label={skill.manifest.license} color="var(--iac-surface)" textColor="var(--iac-text-secondary)" />
                  )}
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--iac-muted)' }}>
                  {skill.source_filename && <div>Source: {skill.source_filename}</div>}
                  <div>Installed: {new Date(skill.installed_at).toLocaleString()}</div>
                  <div>Path: {skill.install_path}</div>
                  {skill.files.length > 0 && <div>Files: {skill.files.join(', ')}</div>}
                </div>
              </div>
              <button style={dangerButtonStyle} onClick={() => uninstall(skill.name)}>
                Uninstall
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default AgentSkillPackagesPanel;
