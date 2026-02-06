/**
 * Type definitions for the IAC Extension System.
 *
 * Extensions are packaged applications (e.g. Streamlit apps) that can be
 * installed and run alongside the iac-host. The extension type discriminator
 * determines how the host renders and interacts with the extension.
 */

// ---------------------------------------------------------------------------
// Extension Type & Category
// ---------------------------------------------------------------------------

/** How the extension is rendered/executed by the host */
export type ExtensionType = 'streamlit' | 'iframe' | 'api';

/** Logical grouping for browsing and filtering */
export type ExtensionCategory =
  | 'testing'
  | 'linting'
  | 'formatting'
  | 'security-scanning'
  | 'integration'
  | 'reporting'
  | 'utility';

/** What host capabilities the extension requires */
export type ExtensionPermission =
  | 'network'        // make outbound HTTP requests
  | 'hostConfig'     // read host configuration
  | 'reporting'      // write to shared results directory
  | 'ui';            // render UI in the host

// ---------------------------------------------------------------------------
// Manifest — lives inside the extension zip as manifest.json
// ---------------------------------------------------------------------------

/** Schema-driven setting definition for per-extension configuration */
export interface ExtensionSettingDefinition {
  key: string;
  label: string;
  description?: string;
  type: 'string' | 'number' | 'boolean' | 'select';
  default: string | number | boolean;
  options?: { label: string; value: string | number }[]; // for type='select'
  required?: boolean;
}

/** Dependency on another extension or a host feature */
export interface ExtensionDependency {
  id: string;              // extension id or host feature id
  type: 'extension' | 'host-feature';
  versionRange?: string;   // semver range, e.g. ">=1.0.0"
}

/** The manifest.json shipped inside each extension zip */
export interface ExtensionManifest {
  id: string;                          // unique identifier, e.g. "iac-prompt-injection-tests"
  name: string;                        // display name
  version: string;                     // semver
  description: string;
  author: string;
  license: string;
  icon?: string;                       // relative path inside the zip
  type: ExtensionType;                 // 'streamlit' | 'iframe' | 'api'
  category: ExtensionCategory;
  permissions: ExtensionPermission[];
  entryPoint: string;                  // e.g. "app.py" for streamlit, "index.html" for iframe
  settings?: ExtensionSettingDefinition[];
  dependencies?: ExtensionDependency[];
  minHostVersion?: string;             // minimum iac-host version required
}

// ---------------------------------------------------------------------------
// Registry — extensions/registry.json in GitHub repo
// ---------------------------------------------------------------------------

/** A single entry in the remote registry */
export interface RegistryEntry {
  manifest: ExtensionManifest;
  zipFile: string;            // filename relative to extensions/ folder
  sha256: string;             // integrity hash of the zip
  downloadUrl?: string;       // full URL if not co-located with registry.json
  publishedAt: string;        // ISO date
  updatedAt: string;          // ISO date
}

/** The top-level registry.json structure */
export interface ExtensionRegistry {
  version: string;            // registry schema version
  generatedAt: string;        // ISO date
  extensions: RegistryEntry[];
}

// ---------------------------------------------------------------------------
// Installed Extension — stored in localStorage by the host
// ---------------------------------------------------------------------------

export type ExtensionStatus = 'installed' | 'active' | 'stopped' | 'error';

/** Streamlit-specific runtime configuration */
export interface StreamlitConfig {
  port: number;
  embedOptions?: string;     // query params like "embed=true&theme=dark"
}

/** Runtime config per extension type (discriminated union) */
export type ExtensionRuntimeConfig =
  | { type: 'streamlit'; streamlit: StreamlitConfig }
  | { type: 'iframe'; url: string }
  | { type: 'api'; baseUrl: string };

/** An extension that has been installed on this host */
export interface InstalledExtension {
  manifest: ExtensionManifest;
  status: ExtensionStatus;
  installedAt: string;         // ISO date
  installPath: string;         // where the zip was extracted
  runtime: ExtensionRuntimeConfig;
  settings: Record<string, string | number | boolean>; // user-configured values
  lastError?: string;
}

// ---------------------------------------------------------------------------
// Extension Config File — written by host to extension install dir
// ---------------------------------------------------------------------------

/** The config.json the host writes into the extension's install directory */
export interface ExtensionHostConfig {
  hostVersion: string;
  extensionId: string;
  port: number;
  resultsDir: string;          // shared results directory path
  settings: Record<string, string | number | boolean>;
}

// ---------------------------------------------------------------------------
// Test Results — written by extensions, read by Assurance Results view
// ---------------------------------------------------------------------------

export type TestResultStatus = 'pass' | 'fail' | 'error' | 'skip';

/** A single test case result */
export interface TestCaseResult {
  id: string;
  name: string;
  status: TestResultStatus;
  duration?: number;           // milliseconds
  message?: string;
  details?: string;
}

/** A complete test run written by an extension */
export interface TestRunResult {
  runId: string;
  extensionId: string;
  extensionName: string;
  timestamp: string;           // ISO date
  target: string;              // what was tested (URL, config name, etc.)
  summary: {
    total: number;
    passed: number;
    failed: number;
    errors: number;
    skipped: number;
    duration: number;          // total milliseconds
  };
  results: TestCaseResult[];
}

// ---------------------------------------------------------------------------
// Context — state & actions for the ExtensionContext provider
// ---------------------------------------------------------------------------

/** Extension system state */
export interface ExtensionState {
  registry: RegistryEntry[];
  installed: InstalledExtension[];
  isLoadingRegistry: boolean;
  isInstalling: boolean;
  activeExtensionId: string | null;  // which extension is open in the main area
  error: string | null;
}

/** Extension system actions */
export interface ExtensionActions {
  fetchRegistry: () => Promise<void>;
  installExtension: (registryEntry: RegistryEntry) => Promise<void>;
  uninstallExtension: (extensionId: string) => void;
  activateExtension: (extensionId: string) => void;
  deactivateExtension: (extensionId: string) => void;
  openExtension: (extensionId: string) => void;
  updateSettings: (extensionId: string, settings: Record<string, string | number | boolean>) => void;
}

/** Combined context value */
export interface ExtensionContextValue extends ExtensionState, ExtensionActions {}
