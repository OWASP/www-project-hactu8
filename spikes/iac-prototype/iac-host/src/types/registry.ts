/**
 * Type definitions for the IAC Registry — an inventory of known intelligent
 * components in the environment: deployed agents, model integrations, MCP
 * hosts, and reference/example targets (e.g. an intentionally-vulnerable
 * "AgenticGoat" system used for testing and learning).
 *
 * Registry entries are metadata only — registering an entry does not deploy
 * or provision anything. Other areas of the host (Testing projects,
 * Monitoring) reference entries by id rather than re-describing targets.
 */

export type RegistryEntryType = 'agent' | 'model-integration' | 'mcp-host' | 'target';

/** How an entry was added. Only 'manual' is produced today; 'discovered'
 * is reserved for a future active/network discovery capability. */
export type RegistrySource = 'manual' | 'discovered';

interface RegistryEntryBase {
  id: string;
  name: string;
  description: string;
  source: RegistrySource;
  tags?: string[];
  owner?: string;
  addedAt: string; // ISO date
  updatedAt: string; // ISO date
}

export interface AgentRegistryEntry extends RegistryEntryBase {
  type: 'agent';
  framework?: string; // e.g. "iac-copilot-api orchestrator"
  endpoint?: string;
}

export interface ModelIntegrationRegistryEntry extends RegistryEntryBase {
  type: 'model-integration';
  provider: string; // e.g. "OpenAI", "Anthropic", "Local"
  model: string;
  endpoint?: string;
}

export interface McpHostRegistryEntry extends RegistryEntryBase {
  type: 'mcp-host';
  endpoint: string;
  transport?: string; // e.g. "stdio", "sse", "http"
}

export interface TargetRegistryEntry extends RegistryEntryBase {
  type: 'target';
  targetUrl?: string;
  riskNotes?: string; // e.g. "Intentionally vulnerable — LLM01/LLM06 examples"
  referenceUrl?: string; // docs/repo for standing it up
}

export type RegistryEntry =
  | AgentRegistryEntry
  | ModelIntegrationRegistryEntry
  | McpHostRegistryEntry
  | TargetRegistryEntry;

export const REGISTRY_TYPE_LABELS: Record<RegistryEntryType, string> = {
  agent: 'Agent',
  'model-integration': 'Model Integration',
  'mcp-host': 'MCP Host',
  target: 'Target',
};

export const REGISTRY_TYPES: RegistryEntryType[] = ['agent', 'model-integration', 'mcp-host', 'target'];

// ---------------------------------------------------------------------------
// Context — state & actions for the RegistryContext provider
// ---------------------------------------------------------------------------

export type NewRegistryEntryInput =
  | Omit<AgentRegistryEntry, 'id' | 'addedAt' | 'updatedAt' | 'source'>
  | Omit<ModelIntegrationRegistryEntry, 'id' | 'addedAt' | 'updatedAt' | 'source'>
  | Omit<McpHostRegistryEntry, 'id' | 'addedAt' | 'updatedAt' | 'source'>
  | Omit<TargetRegistryEntry, 'id' | 'addedAt' | 'updatedAt' | 'source'>;

export interface RegistryContextValue {
  entries: RegistryEntry[];
  refreshEntries: () => void;
  addEntry: (input: NewRegistryEntryInput) => RegistryEntry[];
  updateEntry: (id: string, patch: Partial<RegistryEntry>) => RegistryEntry[];
  removeEntry: (id: string) => RegistryEntry[];
}
