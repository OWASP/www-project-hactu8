import React, { useState, useEffect, useCallback } from 'react';
import type { RegistryEntry, InstalledExtension, ExtensionCategory } from '../types/extensions';
import extensionService from '../services/extensionService';
import { useExtensions } from '../contexts/ExtensionContext';
import { ExtensionRenderer } from '../components/Extensions';
import ExtensionSettings from '../components/Extensions/ExtensionSettings';

// =============================================================================
// Extension System TODOs — ordered by implementation dependency
// =============================================================================
//
// Architecture decisions:
//   - Extension = packaged zip (Streamlit app for now, extensible to other types)
//   - ExtensionType discriminator: 'streamlit' | 'iframe' | 'api' (future)
//   - Registry = extensions/registry.json in GitHub repo, zips alongside it
//   - Install = download zip, extract to install location, store metadata in localStorage
//   - Config = host writes config.json to extension install dir, extension reads it
//   - Execution = Streamlit on auto-assigned port (8501+), rendered via SmartFrame
//   - Results = shared results dir, extensions write JSON, Assurance Results reads them
//   - Rendering = StreamlitExtension component for type='streamlit', others later
//
// --- Layer 1: Extension Manifest & Data Model --- [CP1] ✅ src/types/extensions.ts
//
// --- Layer 2: Execution Model & Sandbox --- [CP2] ✅ src/components/Extensions/
//   StreamlitExtension — renders Streamlit via iframe, handles load/error states
//   ExtensionRenderer — dispatches by extension type (streamlit, iframe, api)
//   Lifecycle: host tracks status in localStorage; user starts Streamlit externally
//   Error handling: detects unreachable port, shows run command + retry button
//
// --- Layer 3: Host API Surface --- [CP3] ✅ src/services/extensionService.ts + ExtensionSettings
//   extensionService — localStorage CRUD, port assignment, install/uninstall, generateHostConfig()
//   ExtensionSettings — schema-driven form (string, number, boolean, select) from manifest.settings
//
// --- Layer 4: Registry --- [CP4] ✅ extensions/registry.json + extensionService registry methods
//   registry.json — 3 sample entries (prompt injection tests, config linter, security scanner)
//   Each entry has manifest + zipFile + sha256 hash
//   fetchRegistry() — fetches from configurable URL, falls back to local /extensions/registry.json
//   get/set/resetRegistryUrl() — user-overridable registry source, persisted in localStorage
//
// --- Layer 5: Management UI --- [CP5] ✅ This file
//
// --- Layer 6: First Extension — "Prompt Injection Tests - IAC Core" --- [CP6] ✅
//   extensions/iac-prompt-injection-tests/ — Streamlit app + manifest.json
//   14 test cases across 6 categories (direct override, extraction, delimiters, context, indirect, output)
//   Reads config.json from install dir, writes TestRunResult JSON to shared results dir
//   Already listed in registry.json
//
// --- Layer 7: Reporting Integration --- [CP7] ✅
//   resultsService — localStorage CRUD, mock data fallback, loadResultsWithMocks()
//   AssuranceResults page — sidebar run list, detail view with metrics/pass rate/filter/table
//   Auto-refresh every 30s via setInterval poll
//   Convention: ~/.iac/results/<extension-id>/<run-id>.json (Streamlit writes, future API serves)
// =============================================================================

// ---------------------------------------------------------------------------
// Types for UI state
// ---------------------------------------------------------------------------

type SidebarTab = 'available' | 'installed';
type MainPanel = 'none' | 'detail' | 'settings' | 'open';

interface ViewState {
  sidebarTab: SidebarTab;
  mainPanel: MainPanel;
  selectedExtensionId: string | null;
}

// ---------------------------------------------------------------------------
// Category helpers
// ---------------------------------------------------------------------------

const CATEGORY_LABELS: Record<ExtensionCategory, string> = {
  testing: 'Testing',
  linting: 'Linting',
  formatting: 'Formatting',
  'security-scanning': 'Security Scanning',
  integration: 'Integration',
  reporting: 'Reporting',
  utility: 'Utility',
};

const TYPE_LABELS: Record<string, string> = {
  streamlit: 'Streamlit',
  iframe: 'iFrame',
  api: 'API',
};

const STATUS_COLORS: Record<string, string> = {
  installed: 'var(--iac-muted)',
  active: 'var(--iac-success)',
  stopped: 'var(--iac-warning)',
  error: 'var(--iac-error)',
};

// ---------------------------------------------------------------------------
// Main Extensions page component
// ---------------------------------------------------------------------------

const Extensions: React.FC = () => {
  const [registry, setRegistry] = useState<RegistryEntry[]>([]);
  const [isLoadingRegistry, setIsLoadingRegistry] = useState(false);
  const [isInstallingId, setIsInstallingId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [view, setView] = useState<ViewState>({
    sidebarTab: 'available',
    mainPanel: 'none',
    selectedExtensionId: null,
  });

  // Use the extension context for installed extensions
  const { installed, installExtension, uninstallExtension, updateSettings, updateStatus } = useExtensions();

  // Load registry on mount
  useEffect(() => {
    const handleFetchRegistry = async () => {
      setIsLoadingRegistry(true);
      setError(null);
      try {
        const entries = await extensionService.fetchRegistry();
        setRegistry(entries);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load registry');
      } finally {
        setIsLoadingRegistry(false);
      }
    };
    handleFetchRegistry();
  }, []);

  const handleFetchRegistry = useCallback(async () => {
    setIsLoadingRegistry(true);
    setError(null);
    try {
      const entries = await extensionService.fetchRegistry();
      setRegistry(entries);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load registry');
    } finally {
      setIsLoadingRegistry(false);
    }
  }, []);

  const handleInstall = useCallback((entry: RegistryEntry, installPath?: string) => {
    setIsInstallingId(entry.manifest.id);
    setError(null);
    
    installExtension(entry, installPath)
      .then(() => {
        setView({ sidebarTab: 'installed', mainPanel: 'detail', selectedExtensionId: entry.manifest.id });
        setIsInstallingId(null);
      })
      .catch((err) => {
        setError(err instanceof Error ? err.message : 'Install failed');
        setIsInstallingId(null);
      });
  }, [installExtension]);

  const handleUninstall = useCallback((extensionId: string) => {
    uninstallExtension(extensionId)
      .then(() => {
        if (view.selectedExtensionId === extensionId) {
          setView((v) => ({ ...v, mainPanel: 'none', selectedExtensionId: null }));
        }
      })
      .catch((err) => {
        setError(err instanceof Error ? err.message : 'Uninstall failed');
      });
  }, [uninstallExtension, view.selectedExtensionId]);

  const handleSaveSettings = useCallback((extensionId: string, settings: Record<string, string | number | boolean>) => {
    updateSettings(extensionId, settings);
  }, [updateSettings]);

  const handleStatusChange = useCallback((extensionId: string, status: 'active' | 'error', errMsg?: string) => {
    updateStatus(extensionId, status, errMsg);
  }, [updateStatus]);

  const selectExtension = useCallback((id: string, panel: MainPanel) => {
    setView((v) => ({ ...v, mainPanel: panel, selectedExtensionId: id }));
  }, []);

  // Lookup helpers
  const installedIds = new Set(installed.map((e) => e.manifest.id));
  const selectedInstalled = installed.find((e) => e.manifest.id === view.selectedExtensionId) ?? null;
  const selectedRegistry = registry.find((e) => e.manifest.id === view.selectedExtensionId) ?? null;

  return (
    <div style={{ display: 'flex', minHeight: '60vh', height: '100%', overflow: 'hidden' }}>
      {/* ---- Sidebar ---- */}
      <aside style={sidebarStyle}>
        <h3 style={{ color: 'var(--iac-text)', marginBottom: '0.75rem' }}>Extensions</h3>

        {/* Tab selector */}
        <div style={{ display: 'flex', gap: '0.25rem', marginBottom: '1rem' }}>
          <TabButton
            label="Available"
            active={view.sidebarTab === 'available'}
            onClick={() => setView((v) => ({ ...v, sidebarTab: 'available' }))}
          />
          <TabButton
            label={`Installed (${installed.length})`}
            active={view.sidebarTab === 'installed'}
            onClick={() => setView((v) => ({ ...v, sidebarTab: 'installed' }))}
          />
        </div>

        {/* Sidebar content */}
        <div style={{ overflowY: 'auto', flex: 1 }}>
          {view.sidebarTab === 'available' && (
            <AvailableList
              registry={registry}
              installedIds={installedIds}
              isLoading={isLoadingRegistry}
              error={error}
              onRefresh={handleFetchRegistry}
              onInstall={handleInstall}
              onSelect={(id) => selectExtension(id, 'detail')}
              selectedId={view.selectedExtensionId}
            />
          )}
          {view.sidebarTab === 'installed' && (
            <InstalledList
              installed={installed}
              onSelect={(id) => selectExtension(id, 'detail')}
              selectedId={view.selectedExtensionId}
            />
          )}
        </div>
      </aside>

      {/* ---- Main content ---- */}
      <main style={mainStyle}>
        {view.mainPanel === 'none' && (
          <div style={{ color: 'var(--iac-muted)', textAlign: 'center', marginTop: '4rem' }}>
            <p>Select an extension to view details.</p>
          </div>
        )}

        {view.mainPanel === 'detail' && view.selectedExtensionId && (
          <DetailPanel
            registryEntry={selectedRegistry}
            installedExtension={selectedInstalled}
            onInstall={handleInstall}
            onUninstall={handleUninstall}
            onOpenSettings={() => setView((v) => ({ ...v, mainPanel: 'settings' }))}
            onOpen={() => setView((v) => ({ ...v, mainPanel: 'open' }))}
          />
        )}

        {view.mainPanel === 'settings' && selectedInstalled && (
          <div>
            <button onClick={() => setView((v) => ({ ...v, mainPanel: 'detail' }))} style={backButtonStyle}>
              &larr; Back to Details
            </button>
            <ExtensionSettings extension={selectedInstalled} onSave={handleSaveSettings} />
          </div>
        )}

        {view.mainPanel === 'open' && selectedInstalled && (
          <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '0.5rem' }}>
              <button onClick={() => setView((v) => ({ ...v, mainPanel: 'detail' }))} style={backButtonStyle}>
                &larr; Back
              </button>
              <h3 style={{ margin: 0, color: 'var(--iac-text)' }}>{selectedInstalled.manifest.name}</h3>
              <StatusBadge status={selectedInstalled.status} />
            </div>
            <div style={{ flex: 1, position: 'relative', minHeight: '400px' }}>
              <ExtensionRenderer extension={selectedInstalled} onStatusChange={handleStatusChange} />
            </div>
          </div>
        )}
      </main>
    </div>
  );
};

// ---------------------------------------------------------------------------
// Sidebar sub-components
// ---------------------------------------------------------------------------

function TabButton({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      style={{
        flex: 1,
        padding: '0.5rem',
        background: active ? 'var(--iac-surface-elevated)' : 'transparent',
        color: active ? 'var(--iac-text)' : 'var(--iac-text-secondary)',
        border: `1px solid ${active ? 'var(--iac-border)' : 'transparent'}`,
        borderRadius: '4px',
        cursor: 'pointer',
        fontWeight: active ? 600 : 400,
        fontSize: '0.85rem',
      }}
    >
      {label}
    </button>
  );
}

interface AvailableListProps {
  registry: RegistryEntry[];
  installedIds: Set<string>;
  isLoading: boolean;
  error: string | null;
  onRefresh: () => void;
  onInstall: (entry: RegistryEntry) => void;
  onSelect: (id: string) => void;
  selectedId: string | null;
}

function AvailableList({ registry, installedIds, isLoading, error, onRefresh, onInstall, onSelect, selectedId }: AvailableListProps) {
  if (isLoading) {
    return <p style={{ color: 'var(--iac-muted)', fontSize: '0.875rem' }}>Loading registry...</p>;
  }
  if (error) {
    return (
      <div>
        <p style={{ color: 'var(--iac-error)', fontSize: '0.875rem' }}>{error}</p>
        <button onClick={onRefresh} style={smallButtonStyle}>Retry</button>
      </div>
    );
  }
  if (registry.length === 0) {
    return <p style={{ color: 'var(--iac-muted)', fontSize: '0.875rem' }}>No extensions found in registry.</p>;
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
      {registry.map((entry) => {
        const isInstalled = installedIds.has(entry.manifest.id);
        const isSelected = selectedId === entry.manifest.id;
        return (
          <div
            key={entry.manifest.id}
            onClick={() => onSelect(entry.manifest.id)}
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
                  <Badge label={CATEGORY_LABELS[entry.manifest.category] ?? entry.manifest.category} color="var(--iac-info-bg)" textColor="var(--iac-info-text)" />
                  <Badge label={TYPE_LABELS[entry.manifest.type] ?? entry.manifest.type} color="var(--iac-warning-bg)" textColor="var(--iac-warning-text)" />
                </div>
              </div>
              <div style={{ marginLeft: '0.5rem', flexShrink: 0 }}>
                {isInstalled ? (
                  <span style={{ fontSize: '0.75rem', color: 'var(--iac-success)', fontWeight: 600 }}>Installed</span>
                ) : (
                  <button
                    onClick={(e) => { e.stopPropagation(); onInstall(entry); }}
                    style={installButtonStyle}
                  >
                    Install
                  </button>
                )}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

interface InstalledListProps {
  installed: InstalledExtension[];
  onSelect: (id: string) => void;
  selectedId: string | null;
}

function InstalledList({ installed, onSelect, selectedId }: InstalledListProps) {
  if (installed.length === 0) {
    return <p style={{ color: 'var(--iac-muted)', fontSize: '0.875rem' }}>No extensions installed.</p>;
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
      {installed.map((ext) => {
        const isSelected = selectedId === ext.manifest.id;
        return (
          <div
            key={ext.manifest.id}
            onClick={() => onSelect(ext.manifest.id)}
            style={{
              ...cardStyle,
              borderColor: isSelected ? 'var(--iac-surface-elevated)' : 'var(--iac-border)',
              background: isSelected ? 'var(--iac-surface)' : 'var(--iac-bg)',
              cursor: 'pointer',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontWeight: 600, fontSize: '0.9rem', color: 'var(--iac-text)', marginBottom: '0.15rem' }}>
                  {ext.manifest.name}
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--iac-muted)' }}>
                  v{ext.manifest.version}
                </div>
              </div>
              <StatusBadge status={ext.status} />
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Detail panel
// ---------------------------------------------------------------------------

interface DetailPanelProps {
  registryEntry: RegistryEntry | null;
  installedExtension: InstalledExtension | null;
  onInstall: (entry: RegistryEntry) => void;
  onUninstall: (extensionId: string) => void;
  onOpenSettings: () => void;
  onOpen: () => void;
}

function DetailPanel({ registryEntry, installedExtension, onInstall, onUninstall, onOpenSettings, onOpen }: DetailPanelProps) {
  const manifest = installedExtension?.manifest ?? registryEntry?.manifest;
  if (!manifest) {
    return <p style={{ color: 'var(--iac-muted)' }}>Extension not found.</p>;
  }

  const isInstalled = !!installedExtension;
  const port = installedExtension?.runtime.type === 'streamlit'
    ? installedExtension.runtime.streamlit.port
    : null;

  return (
    <div>
      {/* Header */}
      <div style={{ marginBottom: '1.5rem' }}>
        <h3 style={{ color: 'var(--iac-text)', fontWeight: 700, fontSize: '1.5rem', margin: '0 0 0.25rem' }}>
          {manifest.name}
        </h3>
        <p style={{ color: 'var(--iac-text-secondary)', margin: '0 0 0.75rem', fontSize: '0.925rem' }}>
          {manifest.description}
        </p>
        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', alignItems: 'center' }}>
          <Badge label={CATEGORY_LABELS[manifest.category] ?? manifest.category} color="var(--iac-info-bg)" textColor="var(--iac-info-text)" />
          <Badge label={TYPE_LABELS[manifest.type] ?? manifest.type} color="var(--iac-warning-bg)" textColor="var(--iac-warning-text)" />
          <Badge label={`v${manifest.version}`} color="var(--iac-surface)" textColor="var(--iac-border)" />
          {isInstalled && <StatusBadge status={installedExtension.status} />}
        </div>
      </div>

      {/* Action buttons */}
      <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1.5rem' }}>
        {isInstalled ? (
          <>
            <button onClick={onOpen} style={primaryButtonStyle}>Open</button>
            <button onClick={onOpenSettings} style={secondaryButtonStyle}>Settings</button>
            <button onClick={() => onUninstall(manifest.id)} style={dangerButtonStyle}>Uninstall</button>
          </>
        ) : registryEntry ? (
          <button onClick={() => onInstall(registryEntry)} style={primaryButtonStyle}>Install</button>
        ) : null}
      </div>

      {/* Info grid */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
        <InfoField label="Author" value={manifest.author} />
        <InfoField label="License" value={manifest.license} />
        <InfoField label="Entry Point" value={manifest.entryPoint} />
        <InfoField label="Min Host Version" value={manifest.minHostVersion ?? 'Any'} />
        {port !== null && <InfoField label="Port" value={String(port)} />}
        {installedExtension && (
          <InfoField label="Installed" value={new Date(installedExtension.installedAt).toLocaleDateString()} />
        )}
      </div>

      {/* Permissions */}
      {manifest.permissions.length > 0 && (
        <div style={{ marginTop: '1.5rem' }}>
          <h4 style={{ color: 'var(--iac-text)', fontWeight: 600, marginBottom: '0.5rem' }}>Permissions</h4>
          <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap' }}>
            {manifest.permissions.map((p) => (
              <Badge key={p} label={p} color="var(--iac-error-bg)" textColor="var(--iac-error-text)" />
            ))}
          </div>
        </div>
      )}

      {/* Settings summary */}
      {manifest.settings && manifest.settings.length > 0 && (
        <div style={{ marginTop: '1.5rem' }}>
          <h4 style={{ color: 'var(--iac-text)', fontWeight: 600, marginBottom: '0.5rem' }}>
            Configurable Settings ({manifest.settings.length})
          </h4>
          <ul style={{ margin: 0, paddingLeft: '1.25rem', color: 'var(--iac-text-secondary)', fontSize: '0.875rem' }}>
            {manifest.settings.map((s) => (
              <li key={s.key} style={{ marginBottom: '0.25rem' }}>
                <strong>{s.label}</strong> — {s.description ?? s.type}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Run instructions for installed Streamlit extensions */}
      {isInstalled && manifest.type === 'streamlit' && port !== null && (
        <div style={{ marginTop: '1.5rem', padding: '1rem', background: 'var(--iac-surface)', borderRadius: '6px', border: '1px solid var(--iac-border)' }}>
          <h4 style={{ color: 'var(--iac-text)', fontWeight: 600, marginBottom: '0.5rem' }}>Run Instructions</h4>
          <p style={{ color: 'var(--iac-text-secondary)', fontSize: '0.85rem', marginBottom: '0.5rem' }}>
            Start the Streamlit app, then click <strong>Open</strong> above to view it here.
          </p>
          <code style={codeBlockStyle}>
            cd {installedExtension.installPath} && streamlit run {manifest.entryPoint} --server.port {port}
          </code>
        </div>
      )}

      {/* Config preview */}
      {isInstalled && (
        <div style={{ marginTop: '1.5rem', padding: '1rem', background: 'var(--iac-surface)', borderRadius: '6px', border: '1px solid var(--iac-border)' }}>
          <h4 style={{ color: 'var(--iac-text)', fontWeight: 600, marginBottom: '0.5rem' }}>Host Config (config.json)</h4>
          <p style={{ color: 'var(--iac-text-secondary)', fontSize: '0.85rem', marginBottom: '0.5rem' }}>
            This config is written to the extension install directory for the extension to read.
          </p>
          <pre style={{ ...codeBlockStyle, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
            {JSON.stringify(extensionService.generateHostConfig(installedExtension), null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Shared small components
// ---------------------------------------------------------------------------

function Badge({ label, color, textColor }: { label: string; color: string; textColor: string }) {
  return (
    <span style={{
      display: 'inline-block',
      padding: '0.15rem 0.5rem',
      borderRadius: '4px',
      background: color,
      color: textColor,
      fontSize: '0.75rem',
      fontWeight: 600,
    }}>
      {label}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  return (
    <span style={{
      display: 'inline-flex',
      alignItems: 'center',
      gap: '0.3rem',
      fontSize: '0.75rem',
      fontWeight: 600,
      color: STATUS_COLORS[status] ?? 'var(--iac-muted)',
    }}>
      <span style={{
        width: 8,
        height: 8,
        borderRadius: '50%',
        background: STATUS_COLORS[status] ?? 'var(--iac-muted)',
        display: 'inline-block',
      }} />
      {status}
    </span>
  );
}

function InfoField({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div style={{ fontSize: '0.75rem', color: 'var(--iac-muted)', marginBottom: '0.1rem' }}>{label}</div>
      <div style={{ fontSize: '0.9rem', color: 'var(--iac-text)', fontWeight: 500 }}>{value}</div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Styles
// ---------------------------------------------------------------------------

const sidebarStyle: React.CSSProperties = {
  width: 320,
  padding: '1rem',
  background: 'var(--iac-surface)',
  borderRight: '1px solid var(--iac-border)',
  display: 'flex',
  flexDirection: 'column',
  overflowY: 'auto',
};

const mainStyle: React.CSSProperties = {
  flex: 1,
  padding: '2rem',
  overflowY: 'auto',
  background: 'var(--iac-bg)',
};

const cardStyle: React.CSSProperties = {
  padding: '0.75rem',
  border: '1px solid var(--iac-border)',
  borderRadius: '6px',
  background: 'var(--iac-bg)',
};

const installButtonStyle: React.CSSProperties = {
  padding: '0.3rem 0.75rem',
  background: 'var(--iac-surface-elevated)',
  color: 'var(--iac-text)',
  border: 'none',
  borderRadius: '4px',
  cursor: 'pointer',
  fontWeight: 600,
  fontSize: '0.75rem',
};

const smallButtonStyle: React.CSSProperties = {
  padding: '0.35rem 0.75rem',
  background: 'var(--iac-surface-elevated)',
  color: 'var(--iac-text)',
  border: 'none',
  borderRadius: '4px',
  cursor: 'pointer',
  fontWeight: 500,
  fontSize: '0.8rem',
  marginTop: '0.5rem',
};

const primaryButtonStyle: React.CSSProperties = {
  padding: '0.5rem 1.5rem',
  background: 'var(--iac-surface-elevated)',
  color: 'var(--iac-text)',
  border: 'none',
  borderRadius: '4px',
  cursor: 'pointer',
  fontWeight: 600,
};

const secondaryButtonStyle: React.CSSProperties = {
  padding: '0.5rem 1.5rem',
  background: 'transparent',
  color: 'var(--iac-surface-elevated)',
  border: '1px solid var(--iac-surface-elevated)',
  borderRadius: '4px',
  cursor: 'pointer',
  fontWeight: 600,
};

const dangerButtonStyle: React.CSSProperties = {
  padding: '0.5rem 1.5rem',
  background: 'transparent',
  color: 'var(--iac-error)',
  border: '1px solid var(--iac-error)',
  borderRadius: '4px',
  cursor: 'pointer',
  fontWeight: 600,
};

const backButtonStyle: React.CSSProperties = {
  padding: '0.35rem 0.75rem',
  background: 'transparent',
  color: 'var(--iac-surface-elevated)',
  border: '1px solid var(--iac-border)',
  borderRadius: '4px',
  cursor: 'pointer',
  fontWeight: 500,
  fontSize: '0.85rem',
  marginBottom: '0.5rem',
};

const codeBlockStyle: React.CSSProperties = {
  display: 'block',
  padding: '0.5rem 0.75rem',
  background: 'var(--iac-code-bg)',
  color: 'var(--iac-code-text)',
  borderRadius: '4px',
  fontSize: '0.8rem',
  overflowX: 'auto',
};

export default Extensions;
