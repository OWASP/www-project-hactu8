// Seed data for the Registry — gives the platform a working example out of
// the box. "AgenticGoat" is a placeholder reference target modeled on
// WebGoat: an intentionally-vulnerable set of agentic AI components used for
// testing and learning. These are examples, not a real deployed system —
// edit or delete them freely.
import type { RegistryEntry } from '../types/registry';

const AGENTICGOAT_TAGS = ['agenticgoat', 'example'];

export const AGENTIC_GOAT_SEED: RegistryEntry[] = [
  {
    id: 'agenticgoat-target',
    type: 'target',
    name: 'AgenticGoat',
    description:
      'Intentionally-vulnerable agentic AI application for hands-on OWASP LLM Top 10 testing and training.',
    source: 'manual',
    tags: AGENTICGOAT_TAGS,
    riskNotes: 'Deliberately vulnerable — includes examples of LLM01 (Prompt Injection) and LLM06 (Excessive Agency).',
    referenceUrl: 'https://github.com/OWASP/www-project-hactu8',
    addedAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-01-01T00:00:00.000Z',
  },
  {
    id: 'agenticgoat-orchestrator-agent',
    type: 'agent',
    name: 'AgenticGoat Orchestrator',
    description: 'The vulnerable target\'s own task-planning agent — over-privileged by design for LLM06 exercises.',
    source: 'manual',
    tags: AGENTICGOAT_TAGS,
    framework: 'Custom',
    addedAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-01-01T00:00:00.000Z',
  },
  {
    id: 'agenticgoat-mcp-host',
    type: 'mcp-host',
    name: 'AgenticGoat MCP Host',
    description: 'MCP tool server exposed by AgenticGoat with intentionally weak tool-scoping for testing.',
    source: 'manual',
    tags: AGENTICGOAT_TAGS,
    endpoint: 'http://localhost:7331/mcp',
    transport: 'sse',
    addedAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-01-01T00:00:00.000Z',
  },
];
