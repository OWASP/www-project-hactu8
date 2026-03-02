/**
 * Service for managing IAC extensions.
 *
 * Handles localStorage persistence for installed extensions, port assignment,
 * and generating the config.json that the host writes to each extension's
 * install directory.
 */

import type {
  InstalledExtension,
  ExtensionHostConfig,
  ExtensionRuntimeConfig,
  ExtensionRegistry,
  RegistryEntry,
} from '../types/extensions';
import {
  loadModelProviderState,
  getProviderModels,
} from './modelProviderService';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const STORAGE_KEY = 'iac-extensions-installed';
const REGISTRY_URL_KEY = 'iac-extensions-registry-url';
const PORT_RANGE_START = 8501;
const PORT_RANGE_END = 8599;
const HOST_VERSION = '0.1.0';
const DEFAULT_RESULTS_DIR = '~/.iac/results';

// Default: Use local registry in dev, GitHub in production
const DEFAULT_REGISTRY_URL =
  import.meta.env.VITE_EXTENSION_REGISTRY_URL ||
  (import.meta.env.DEV
    ? 'http://localhost:5001/extensions/registry.json'
    : 'https://raw.githubusercontent.com/OWASP/www-project-hactu8/main/spikes/iac-prototype/extensions/registry.json');

// ---------------------------------------------------------------------------
// localStorage helpers
// ---------------------------------------------------------------------------

/** Load all installed extensions from localStorage */
export function loadInstalled(): InstalledExtension[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

/** Save installed extensions to localStorage */
export function saveInstalled(extensions: InstalledExtension[]): void {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(extensions));
}

// ---------------------------------------------------------------------------
// Port assignment
// ---------------------------------------------------------------------------

/** Find the next available port that isn't claimed by an installed extension */
export function assignPort(installed: InstalledExtension[]): number {
  const usedPorts = new Set(
    installed
      .filter((ext) => ext.runtime.type === 'streamlit')
      .map((ext) => (ext.runtime as { type: 'streamlit'; streamlit: { port: number } }).streamlit.port)
  );

  for (let port = PORT_RANGE_START; port <= PORT_RANGE_END; port++) {
    if (!usedPorts.has(port)) return port;
  }

  throw new Error(`No available ports in range ${PORT_RANGE_START}-${PORT_RANGE_END}`);
}

// ---------------------------------------------------------------------------
// Install / Uninstall
// ---------------------------------------------------------------------------

/**
 * Call backend API to delete the extension directory.
 * Backend will remove the directory from ~/.iac/extensions/{extensionId}
 */
async function deleteExtension(extensionId: string, installPath: string): Promise<void> {
  const apiUrl = import.meta.env.VITE_EXTENSION_API_URL || 'http://localhost:5001';

  const response = await fetch(`${apiUrl}/api/extensions/uninstall`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      extensionId,
      installPath,
    }),
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ message: 'Unknown error' }));
    throw new Error(error.message || `Uninstallation failed (${response.status})`);
  }
}

/**
 * Call backend API to download and extract the extension zip file.
 * Backend should handle:
 *  1. Download zip from registry.zipFile URL
 *  2. Verify SHA256 hash
 *  3. Extract to installPath
 *  4. Return success/error
 */
async function downloadAndExtractExtension(
  entry: RegistryEntry,
  installPath: string
): Promise<void> {
  const apiUrl = import.meta.env.VITE_API_BASE_URL || 'http://localhost:5001';

  // Convert registry zipFile (filename) to full URL
  // If zipFile is already a full URL, use it as-is
  let zipUrl = entry.zipFile;
  if (!zipUrl.startsWith('http://') && !zipUrl.startsWith('https://')) {
    // For local development, use the Flask server to serve zip files
    if (import.meta.env.DEV) {
      zipUrl = `${apiUrl}/extensions/${entry.zipFile}`;
    } else {
      // In production, construct full URL from registry URL
      const registryUrl = getRegistryUrl();
      // Replace 'registry.json' with the zip filename
      zipUrl = registryUrl.replace(/registry\.json$/, entry.zipFile);
    }
  }

  const response = await fetch(`${apiUrl}/api/extensions/install`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      extensionId: entry.manifest.id,
      zipUrl: zipUrl,
      sha256: entry.sha256,
      installPath,
    }),
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ message: 'Unknown error' }));
    throw new Error(error.message || `Installation failed (${response.status})`);
  }
}

/** Build the runtime config for an extension based on its type */
function buildRuntimeConfig(
  entry: RegistryEntry,
  port: number
): ExtensionRuntimeConfig {
  switch (entry.manifest.type) {
    case 'streamlit':
      return { type: 'streamlit', streamlit: { port, embedOptions: 'embed=true' } };
    case 'iframe':
      return { type: 'iframe', url: `http://localhost:${port}` };
    case 'api':
      return { type: 'api', baseUrl: `http://localhost:${port}` };
    default:
      return { type: 'streamlit', streamlit: { port, embedOptions: 'embed=true' } };
  }
}

/** Build default settings values from the manifest setting definitions */
function buildDefaultSettings(
  entry: RegistryEntry
): Record<string, string | number | boolean> {
  const settings: Record<string, string | number | boolean> = {};
  if (entry.manifest.settings) {
    for (const setting of entry.manifest.settings) {
      settings[setting.key] = setting.default;
    }
  }
  return settings;
}

/**
 * Install an extension from a registry entry.
 * Calls backend API to download and extract the zip file, then stores metadata.
 * Returns the updated list of installed extensions.
 */
export async function installExtension(
  entry: RegistryEntry,
  installed: InstalledExtension[],
  installPath: string = '~/.iac/extensions'
): Promise<InstalledExtension[]> {
  // Prevent duplicate installs
  if (installed.some((ext) => ext.manifest.id === entry.manifest.id)) {
    throw new Error(`Extension "${entry.manifest.id}" is already installed`);
  }

  const port = assignPort(installed);
  const resolvedInstallPath = `${installPath}/${entry.manifest.id}`;

  // Call backend API to download and extract the extension
  try {
    await downloadAndExtractExtension(entry, resolvedInstallPath);
  } catch (err) {
    throw new Error(
      `Failed to install extension: ${err instanceof Error ? err.message : 'Unknown error'}`
    );
  }

  const newExtension: InstalledExtension = {
    manifest: entry.manifest,
    status: 'installed',
    installedAt: new Date().toISOString(),
    installPath: resolvedInstallPath,
    runtime: buildRuntimeConfig(entry, port),
    settings: buildDefaultSettings(entry),
  };

  const updated = [...installed, newExtension];
  saveInstalled(updated);
  return updated;
}

/**
 * Uninstall an extension by id.
 * Calls backend API to delete the files, then removes from localStorage.
 * Returns the updated list of installed extensions.
 */
export async function uninstallExtension(
  extensionId: string,
  installed: InstalledExtension[]
): Promise<InstalledExtension[]> {
  // Find the extension to get its install path
  const extension = installed.find((ext) => ext.manifest.id === extensionId);
  if (!extension) {
    throw new Error(`Extension "${extensionId}" is not installed`);
  }

  // Call backend API to delete the extension directory
  try {
    await deleteExtension(extensionId, extension.installPath);
  } catch (err) {
    throw new Error(
      `Failed to uninstall extension: ${err instanceof Error ? err.message : 'Unknown error'}`
    );
  }

  // Remove from localStorage
  const updated = installed.filter((ext) => ext.manifest.id !== extensionId);
  saveInstalled(updated);
  return updated;
}

// ---------------------------------------------------------------------------
// Status management
// ---------------------------------------------------------------------------

/** Update the status of an installed extension */
export function updateStatus(
  extensionId: string,
  status: InstalledExtension['status'],
  installed: InstalledExtension[],
  lastError?: string
): InstalledExtension[] {
  const updated = installed.map((ext) =>
    ext.manifest.id === extensionId
      ? { ...ext, status, lastError: lastError ?? ext.lastError }
      : ext
  );
  saveInstalled(updated);
  return updated;
}

// ---------------------------------------------------------------------------
// Settings management
// ---------------------------------------------------------------------------

/** Update user-configured settings for an extension */
export function updateSettings(
  extensionId: string,
  settings: Record<string, string | number | boolean>,
  installed: InstalledExtension[]
): InstalledExtension[] {
  const updated = installed.map((ext) =>
    ext.manifest.id === extensionId
      ? { ...ext, settings: { ...ext.settings, ...settings } }
      : ext
  );
  saveInstalled(updated);
  return updated;
}

/** Update the port for a Streamlit extension (for override / conflict resolution) */
export function updatePort(
  extensionId: string,
  port: number,
  installed: InstalledExtension[]
): InstalledExtension[] {
  const updated = installed.map((ext) => {
    if (ext.manifest.id !== extensionId) return ext;
    if (ext.runtime.type !== 'streamlit') return ext;
    return {
      ...ext,
      runtime: { ...ext.runtime, streamlit: { ...ext.runtime.streamlit, port } },
    };
  });
  saveInstalled(updated);
  return updated;
}

// ---------------------------------------------------------------------------
// Host config generation
// ---------------------------------------------------------------------------

/**
 * Generate the config.json payload the host writes to the extension's
 * install directory. The extension reads this at startup.
 */
export function generateHostConfig(extension: InstalledExtension): ExtensionHostConfig {
  const port =
    extension.runtime.type === 'streamlit'
      ? extension.runtime.streamlit.port
      : extension.runtime.type === 'iframe'
        ? parseInt(new URL(extension.runtime.url).port, 10)
        : parseInt(new URL(extension.runtime.baseUrl).port, 10);

  // Load model providers from IAC settings
  const modelProviderState = loadModelProviderState();
  const modelProviders = modelProviderState?.configs?.length ? {
    providers: modelProviderState.configs.map(config => ({
      id: config.providerId,
      enabled: true,
      baseUrl: config.baseUrl,
      apiKey: config.apiKey,
      models: getProviderModels(config.providerId),
    }))
  } : undefined;

  return {
    hostVersion: HOST_VERSION,
    extensionId: extension.manifest.id,
    port,
    resultsDir: `${DEFAULT_RESULTS_DIR}/${extension.manifest.id}`,
    settings: extension.settings,
    modelProviders,
  };
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/** Get the configured registry URL (user-overridable, persisted in localStorage) */
export function getRegistryUrl(): string {
  const stored = localStorage.getItem(REGISTRY_URL_KEY);
  
  // Auto-migrate old hardcoded URLs to use the new default
  if (stored && stored.includes('86928e5bd1739496e35b43eab2b55b9d1108adf3')) {
    localStorage.removeItem(REGISTRY_URL_KEY);
    return DEFAULT_REGISTRY_URL;
  }
  
  return stored || DEFAULT_REGISTRY_URL;
}

/** Override the registry source URL */
export function setRegistryUrl(url: string): void {
  localStorage.setItem(REGISTRY_URL_KEY, url);
}

/** Reset registry URL to the default */
export function resetRegistryUrl(): void {
  localStorage.removeItem(REGISTRY_URL_KEY);
}

/**
 * Fetch the extension registry from the configured URL.
 * Falls back to a local /extensions/registry.json for development.
 */
export async function fetchRegistry(): Promise<RegistryEntry[]> {
  const url = getRegistryUrl();

  try {
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`Registry fetch failed (${response.status}): ${response.statusText}`);
    }
    const data: ExtensionRegistry = await response.json();
    return data.extensions ?? [];
  } catch (err) {
    // In local dev, try the relative path as fallback
    try {
      const fallback = await fetch('/extensions/registry.json');
      if (fallback.ok) {
        const data: ExtensionRegistry = await fallback.json();
        return data.extensions ?? [];
      }
    } catch {
      // fallback also failed, throw original error
    }
    throw err;
  }
}

// ---------------------------------------------------------------------------
// Export as default service object
// ---------------------------------------------------------------------------

const extensionService = {
  loadInstalled,
  saveInstalled,
  assignPort,
  installExtension,
  uninstallExtension,
  updateStatus,
  updateSettings,
  updatePort,
  generateHostConfig,
  getRegistryUrl,
  setRegistryUrl,
  resetRegistryUrl,
  fetchRegistry,
};

export default extensionService;
