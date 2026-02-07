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
        <h3 style={{ color: '#111827' }}>Extension Not Found</h3>
        <p style={{ color: '#6b7280' }}>
          The extension <code>{extensionId}</code> is not installed.
        </p>
        <Link to="/extensions" style={linkStyle}>
          Go to Extensions
        </Link>
      </div>
    );
  }

  const statusColor =
    extension.status === 'active' ? '#10b981'
    : extension.status === 'error' ? '#ef4444'
    : extension.status === 'stopped' ? '#f59e0b'
    : '#6b7280';

  return (
    <div style={containerStyle}>
      {/* Header bar */}
      <div style={headerStyle}>
        <Link to="/extensions" style={backLinkStyle}>
          &larr; Extensions
        </Link>
        <h3 style={{ margin: 0, color: '#111827', fontSize: '1.1rem' }}>
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
  borderBottom: '1px solid #e5e7eb',
  background: '#f9fafb',
  flexShrink: 0,
};

const backLinkStyle: React.CSSProperties = {
  color: '#213547',
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
  background: '#213547',
  color: '#ffffff',
  borderRadius: '4px',
  textDecoration: 'none',
  fontWeight: 600,
};

export default ExtensionView;
