// Seed data for the Registry. HACTU8 Lamb is the loopback-only sacrificial
// target service used for testing and learning.
import type { RegistryEntry } from '../types/registry';

const LAMB_TAGS = ['hactu8', 'lamb', 'intentionally-vulnerable'];

export const LAMB_SEED: RegistryEntry[] = [
  {
    id: 'hactu8-lamb-target',
    type: 'target',
    name: 'HACTU8 Lamb',
    description:
      'Big Field Jumpers Co.\'s assistant and the labs\' sacrificial target: loopback-only, hosting all 49 HACTU8 labs (LLM, agentic, gateway and HX).',
    source: 'manual',
    tags: LAMB_TAGS,
    targetUrl: 'http://127.0.0.1:5500',
    riskNotes: 'Deliberately vulnerable. Use only for authorized local testing; payloads and side effects are inert.',
    referenceUrl: 'https://github.com/OWASP/www-project-hactu8',
    addedAt: '2026-11-12T00:00:00.000Z',
    updatedAt: '2026-11-12T00:00:00.000Z',
  },
  {
    id: 'hactu8-lamb-agent',
    type: 'agent',
    name: 'HACTU8 Lamb Agent',
    description: 'The sacrificial target\'s simulated task-planning agent, over-privileged by design.',
    source: 'manual',
    tags: LAMB_TAGS,
    framework: 'Custom',
    endpoint: 'http://127.0.0.1:5500',
    addedAt: '2026-11-12T00:00:00.000Z',
    updatedAt: '2026-11-12T00:00:00.000Z',
  },
  {
    id: 'hactu8-lamb-mcp-host',
    type: 'mcp-host',
    name: 'HACTU8 Lamb MCP Host',
    description: 'Intentionally vulnerable MCP target for tool-description poisoning and rug-pull assurance tests.',
    source: 'manual',
    tags: LAMB_TAGS,
    endpoint: 'http://127.0.0.1:5500/mcp',
    transport: 'streamable-http',
    addedAt: '2026-11-12T00:00:00.000Z',
    updatedAt: '2026-11-12T00:00:00.000Z',
  },
];

const LEGACY_IDS = new Set([
  'agenticgoat-target',
  'agenticgoat-orchestrator-agent',
  'agenticgoat-mcp-host',
]);

export function migrateLegacyLambSeed(entries: RegistryEntry[]): RegistryEntry[] {
  if (!entries.some((entry) => LEGACY_IDS.has(entry.id))) {
    return entries;
  }
  return [
    ...entries.filter((entry) => !LEGACY_IDS.has(entry.id)),
    ...LAMB_SEED,
  ];
}
