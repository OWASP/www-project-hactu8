import React, { useState, useCallback } from 'react';
import { useParams, Link } from 'react-router-dom';
import type { InstalledExtension } from '../types/extensions';
import extensionService from '../services/extensionService';
import { ExtensionRenderer } from '../components/Extensions';

/**
 * Full-page view for running an installed extension.
 * Reached via /ext/:extensionId from sidebar navigation.
 */
const ExtensionView: React.FC = () => {
  const { extensionId } = useParams<{ extensionId: string }>();
  const [installed, setInstalled] = useState<InstalledExtension[]>(() => extensionService.loadInstalled());

  const extension = installed.find((e) => e.manifest.id === extensionId) ?? null;

  const handleStatusChange = useCallback(
    (extId: string, status: 'active' | 'error', errMsg?: string) => {
      const updated = extensionService.updateStatus(extId, status, installed, errMsg);
      setInstalled(updated);
    },
    [installed],
  );

  if (!extension) {
    return (
      <div style={notFoundStyle}>
        <h3 style={{ color: 'var(--iac-text)' }}>Extension Not Found</h3>
        <p style={{ color: 'var(--iac-muted)' }}>
          The extension <code>{extensionId}</code> is not installed.
        </p>
        <Link to="/extensions" style={linkStyle}>
          Go to Extensions
        </Link>
      </div>
    );
  }

  const statusColor =
    extension.status === 'active' ? 'var(--iac-success)'
    : extension.status === 'error' ? 'var(--iac-error)'
    : extension.status === 'stopped' ? 'var(--iac-warning)'
    : 'var(--iac-muted)';

  return (
    <div style={containerStyle}>
      {/* Header bar */}
      <div style={headerStyle}>
        <Link to="/extensions" style={backLinkStyle}>
          &larr; Extensions
        </Link>
        <h3 style={{ margin: 0, color: 'var(--iac-text)', fontSize: '1.1rem' }}>
          {extension.manifest.name}
        </h3>
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem', fontSize: '0.8rem', color: statusColor, fontWeight: 600 }}>
          <span style={{ width: 8, height: 8, borderRadius: '50%', background: statusColor, display: 'inline-block' }} />
          {extension.status}
        </span>
      </div>

      {/* Extension content — fills remaining space */}
      <div style={contentStyle}>
        <ExtensionRenderer extension={extension} onStatusChange={handleStatusChange} />
      </div>
    </div>
  );
};

// ---------------------------------------------------------------------------
// Styles
// ---------------------------------------------------------------------------

const containerStyle: React.CSSProperties = {
  display: 'flex',
  flexDirection: 'column',
  height: '100%',
  width: '100%',
};

const headerStyle: React.CSSProperties = {
  display: 'flex',
  alignItems: 'center',
  gap: '1rem',
  padding: '0.5rem 1rem',
  borderBottom: '1px solid var(--iac-border)',
  background: 'var(--iac-surface)',
  flexShrink: 0,
};

const backLinkStyle: React.CSSProperties = {
  color: 'var(--iac-surface-elevated)',
  textDecoration: 'none',
  fontSize: '0.85rem',
  fontWeight: 500,
};

const contentStyle: React.CSSProperties = {
  flex: 1,
  position: 'relative',
  minHeight: 0,
};

const notFoundStyle: React.CSSProperties = {
  padding: '3rem',
  textAlign: 'center',
};

const linkStyle: React.CSSProperties = {
  display: 'inline-block',
  marginTop: '1rem',
  padding: '0.5rem 1.5rem',
  background: 'var(--iac-surface-elevated)',
  color: 'var(--iac-text)',
  borderRadius: '4px',
  textDecoration: 'none',
  fontWeight: 600,
};

export default ExtensionView;
