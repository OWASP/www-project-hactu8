import React, { useState, useCallback, useEffect } from 'react';
import type { InstalledExtension, StreamlitConfig, TestRunResult } from '../../types/extensions';
import resultsService from '../../services/resultsService';

interface StreamlitExtensionProps {
  extension: InstalledExtension;
  onStatusChange?: (extensionId: string, status: 'active' | 'error', error?: string) => void;
}

function buildStreamlitUrl(config: StreamlitConfig): string {
  const base = `http://localhost:${config.port}`;
  const params = config.embedOptions ?? 'embed=true';
  return `${base}?${params}`;
}

const StreamlitExtension: React.FC<StreamlitExtensionProps> = ({ extension, onStatusChange }) => {
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const streamlitConfig = extension.runtime.type === 'streamlit'
    ? extension.runtime.streamlit
    : null;

  // -------------------------------------------------------------------------
  // Listen for test results posted by the Streamlit iframe via postMessage.
  // The extension sends { type: 'iac-extension-results', payload: TestRunResult }
  // -------------------------------------------------------------------------
  useEffect(() => {
    function handleMessage(event: MessageEvent) {
      // Only process messages that look like our extension results
      if (
        event.data &&
        typeof event.data === 'object' &&
        event.data.type === 'iac-extension-results' &&
        event.data.payload
      ) {
        const result = event.data.payload as TestRunResult;
        // Basic validation — must have runId and results array
        if (result.runId && Array.isArray(result.results)) {
          resultsService.addResult(result);
          console.info(
            `[IAC] Received test results from extension "${extension.manifest.id}" — run ${result.runId} (${result.results.length} tests)`
          );
        }
      }
    }

    window.addEventListener('message', handleMessage);
    return () => window.removeEventListener('message', handleMessage);
  }, [extension.manifest.id]);

  const handleLoad = useCallback(() => {
    setLoaded(true);
    setError(null);
    onStatusChange?.(extension.manifest.id, 'active');
  }, [extension.manifest.id, onStatusChange]);

  const handleError = useCallback(() => {
    const msg = `Could not reach Streamlit on port ${streamlitConfig?.port ?? '?'}`;
    setError(msg);
    setLoaded(false);
    onStatusChange?.(extension.manifest.id, 'error', msg);
  }, [extension.manifest.id, streamlitConfig?.port, onStatusChange]);

  if (!streamlitConfig) {
    return (
      <div style={statusContainerStyle}>
        <p>Extension "{extension.manifest.name}" is not a Streamlit extension.</p>
      </div>
    );
  }

  const url = buildStreamlitUrl(streamlitConfig);

  if (error) {
    return (
      <div style={statusContainerStyle}>
        <h3 style={{ margin: '0 0 0.5rem' }}>{extension.manifest.name}</h3>
        <p style={{ color: '#ef4444' }}>{error}</p>
        <p style={{ color: '#888', fontSize: '0.875rem' }}>
          Make sure the Streamlit app is running:
        </p>
        <code style={codeBlockStyle}>
          cd {extension.installPath} && streamlit run {extension.manifest.entryPoint} --server.port {streamlitConfig.port}
        </code>
        <button
          onClick={() => { setError(null); setLoaded(false); }}
          style={retryButtonStyle}
        >
          Retry
        </button>
      </div>
    );
  }

  return (
    <div style={containerStyle}>
      {!loaded && (
        <div style={loaderStyle}>
          <p>Loading {extension.manifest.name}...</p>
        </div>
      )}
      <iframe
        title={extension.manifest.name}
        src={url}
        style={{ ...iframeStyle, opacity: loaded ? 1 : 0 }}
        onLoad={handleLoad}
        onError={handleError}
      />
    </div>
  );
};

// ---------------------------------------------------------------------------
// Styles
// ---------------------------------------------------------------------------

const containerStyle: React.CSSProperties = {
  position: 'relative',
  width: '100%',
  height: '100%',
  minHeight: '400px',
  backgroundColor: 'var(--iac-bg, #0f172a)',
};

const iframeStyle: React.CSSProperties = {
  width: '100%',
  height: '100%',
  border: 'none',
  transition: 'opacity 0.3s ease-in-out',
};

const loaderStyle: React.CSSProperties = {
  position: 'absolute',
  top: 0,
  left: 0,
  right: 0,
  bottom: 0,
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  backgroundColor: 'var(--iac-bg, #0f172a)',
  color: 'var(--iac-text-secondary, #94a3b8)',
  zIndex: 1,
};

const statusContainerStyle: React.CSSProperties = {
  padding: '2rem',
  textAlign: 'center',
  color: 'var(--iac-text, #ccc)',
};

const codeBlockStyle: React.CSSProperties = {
  display: 'block',
  margin: '0.75rem auto',
  padding: '0.5rem 1rem',
  backgroundColor: 'var(--iac-surface, #1a1a2e)',
  borderRadius: '4px',
  fontSize: '0.8rem',
  maxWidth: '600px',
  textAlign: 'left',
  overflowX: 'auto',
};

const retryButtonStyle: React.CSSProperties = {
  marginTop: '1rem',
  padding: '0.5rem 1.5rem',
  backgroundColor: 'var(--iac-accent, #b1d0dd)',
  color: 'var(--iac-primary, #213547)',
  border: 'none',
  borderRadius: '4px',
  cursor: 'pointer',
  fontWeight: 600,
};

export default StreamlitExtension;
