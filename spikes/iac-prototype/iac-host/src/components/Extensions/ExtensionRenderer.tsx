import React from 'react';
import type { InstalledExtension } from '../../types/extensions';
import StreamlitExtension from './StreamlitExtension';

interface ExtensionRendererProps {
  extension: InstalledExtension;
  onStatusChange?: (extensionId: string, status: 'active' | 'error', error?: string) => void;
}

/**
 * Dispatches to the correct renderer based on extension type.
 * Currently supports 'streamlit'. Future types (iframe, api) will be added here.
 */
const ExtensionRenderer: React.FC<ExtensionRendererProps> = ({ extension, onStatusChange }) => {
  switch (extension.runtime.type) {
    case 'streamlit':
      return <StreamlitExtension extension={extension} onStatusChange={onStatusChange} />;

    case 'iframe':
      return (
        <div style={{ padding: '2rem', color: 'var(--iac-text, #ccc)' }}>
          <p>iframe extensions are not yet supported.</p>
        </div>
      );

    case 'api':
      return (
        <div style={{ padding: '2rem', color: 'var(--iac-text, #ccc)' }}>
          <p>API extensions are not yet supported.</p>
        </div>
      );

    default:
      return (
        <div style={{ padding: '2rem', color: '#ef4444' }}>
          <p>Unknown extension type: {(extension.runtime as { type: string }).type}</p>
        </div>
      );
  }
};

export default ExtensionRenderer;
