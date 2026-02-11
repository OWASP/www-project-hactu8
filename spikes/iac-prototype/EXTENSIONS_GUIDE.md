# IAC Extensions Guide

This guide summarizes how the extension system works in the IAC prototype: the registry format, how extensions are installed and integrated, supported types, and how testing extensions surface results in Assurance Results.

## 1. Extension Registry

The registry is a JSON file that lists all available extensions. In this prototype it lives at:
- `extensions/registry.json`

Each registry entry contains:
- `manifest`: the extension metadata (id, name, type, category, permissions, settings, entry point, etc.)
- `zipFile`: the packaged extension archive
- `sha256`: integrity hash for the zip
- `publishedAt` / `updatedAt`

The host fetches the registry from a configurable URL, defaulting to the repo-hosted file. The URL can be overridden in localStorage.

## 2. Manifest Schema (What An Extension Declares)

Each extension ships a `manifest.json` inside its zip. The manifest defines:
- `id`: unique extension identifier
- `name`, `description`, `author`, `license`
- `version`: semver
- `type`: how the host renders/executes the extension
- `category`: where it appears in the sidebar grouping
- `permissions`: capabilities the extension expects (network, hostConfig, reporting, ui)
- `entryPoint`: main file (for Streamlit, typically `app.py`)
- `settings`: schema-driven settings the host exposes in the UI
- `dependencies`: optional dependencies on other extensions or host features
- `minHostVersion`: minimum host version supported

Settings are schema-driven and support `string`, `number`, `boolean`, and `select` types, including defaults and optional requirement flags.

## 3. How A User Adds An Extension

User-facing flow (host UI):
1. Open the Extensions page in the host.
2. The host fetches the registry and lists "Available" extensions.
3. Click Install on an entry.
4. The host stores the installed extension metadata in localStorage and assigns a port.
5. The extension appears under "Installed" and in the sidebar group based on its category.

Developer flow (to publish a new extension):
1. Build and zip the extension package (including `manifest.json` and entry point).
2. Add the zip file alongside `extensions/registry.json`.
3. Add a new registry entry (manifest + zip + hash + timestamps).
4. Refresh the host registry list.

## 4. Integration Model (Host <-> Extension)

The host manages extension metadata and rendering, but extensions are executed separately.

Key integration points:
- **Install metadata**: stored in localStorage; includes assigned port and settings.
- **Config injection**: the host generates a `config.json` for the extension at install path.
  - Contains `hostVersion`, `extensionId`, `port`, `resultsDir`, and resolved `settings`.
- **Runtime**: the host embeds Streamlit extensions in an iframe and expects them to be running on the assigned port.
- **Status**: the host detects load errors (unreachable port) and surfaces a run command.

## 5. Supported Extension Types

Currently supported types (with future extensibility):
- **streamlit**: Embedded Streamlit app running on a local port.
- **iframe**: Generic embedded UI served from a URL.
- **api**: Headless service accessed via base URL (future/placeholder).

The host uses the `type` field to determine runtime configuration and rendering behavior.

## 6. Extension Categories (Sidebar Placement)

Categories determine sidebar grouping:
- `testing` -> Testing
- `linting` -> Tools
- `formatting` -> Tools
- `security-scanning` -> Tools
- `reporting` -> Reporting
- `utility` -> Tools
- `integration` -> Other

## 7. Testing Extensions And Assurance Results

Testing extensions are expected to produce structured test run results. The schema is:
- **TestRunResult**
  - `runId`, `extensionId`, `extensionName`, `timestamp`, `target`
  - `summary`: totals and duration
  - `results`: array of per-test results (`pass`, `fail`, `error`, `skip`)

How results appear in the host:
- A testing extension posts results to the host using:
  - `window.parent.postMessage({ type: 'iac-extension-results', payload: TestRunResult })`
- The host stores the result in localStorage via `resultsService`.
- The Assurance Results page reads these results and presents:
  - Run history list
  - Pass rate and summary metrics
  - Filterable test table
  - Import/export of JSON

The prompt injection extension is the reference implementation for this flow.

## 8. Example: Prompt Injection Testing Extension

This extension demonstrates the full lifecycle:
- Declares `type: streamlit`, `category: testing`, permissions (`network`, `hostConfig`, `reporting`).
- Reads `config.json` for settings like `targetUrl`, `timeout`, and `verbose`.
- Runs a predefined suite of prompt injection tests.
- Writes results to the shared results directory and posts them to the host.

## 9. What Features Can Be Added Next

Common next steps supported by the current model:
- More extension types (e.g., API-only scanners, iframe dashboards).
- Additional registry metadata (badges, icons, tags).
- Results ingestion from real filesystem path or backend API.
- Signed registry entries and zip verification.
- Dependency resolution between extensions.
- Host-side permission prompts or policy enforcement.

---

If you want this reformatted for a specific wiki system or need a shorter "Quick Start" version, say the word.
