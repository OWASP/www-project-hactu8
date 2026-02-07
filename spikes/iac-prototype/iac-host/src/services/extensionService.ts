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

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const STORAGE_KEY = 'iac-extensions-installed';
const REGISTRY_URL_KEY = 'iac-extensions-registry-url';
const PORT_RANGE_START = 8501;
const PORT_RANGE_END = 8599;
const HOST_VERSION = '0.1.0';
const DEFAULT_RESULTS_DIR = '~/.iac/results';

// Default: raw URL pointing at the registry.json in this repo
const DEFAULT_REGISTRY_URL =
  import.meta.env.VITE_EXTENSION_REGISTRY_URL ||
  'https://raw.githubusercontent.com/OWASP/www-project-hactu8/86928e5bd1739496e35b43eab2b55b9d1108adf3/spikes/iac-prototype/extensions/registry.json';
  // 'https://raw.githubusercontent.com/OWASP/www-project-hactu8/main/spikes/iac-prototype/extensions/registry.json';

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
 * Returns the updated list of installed extensions.
 */
export function installExtension(
  entry: RegistryEntry,
  installed: InstalledExtension[],
  installPath?: string
): InstalledExtension[] {
  // Prevent duplicate installs
  if (installed.some((ext) => ext.manifest.id === entry.manifest.id)) {
    throw new Error(`Extension "${entry.manifest.id}" is already installed`);
  }

  const port = assignPort(installed);
  const resolvedInstallPath = installPath ?? `~/.iac/extensions/${entry.manifest.id}`;

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
 * Returns the updated list of installed extensions.
 */
export function uninstallExtension(
  extensionId: string,
  installed: InstalledExtension[]
): InstalledExtension[] {
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

  return {
    hostVersion: HOST_VERSION,
    extensionId: extension.manifest.id,
    port,
    resultsDir: `${DEFAULT_RESULTS_DIR}/${extension.manifest.id}`,
    settings: extension.settings,
  };
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/** Get the configured registry URL (user-overridable, persisted in localStorage) */
export function getRegistryUrl(): string {
  return localStorage.getItem(REGISTRY_URL_KEY) || DEFAULT_REGISTRY_URL;
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
