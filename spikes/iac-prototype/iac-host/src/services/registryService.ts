/**
 * Service for managing the IAC Registry — localStorage persistence for
 * manually-registered assets/targets (agents, model integrations, MCP
 * hosts, reference targets). Metadata only; registering an entry does not
 * provision or deploy anything.
 */

import type { NewRegistryEntryInput, RegistryEntry } from '../types/registry';
import { AGENTIC_GOAT_SEED } from '../data/agenticGoatSeed';

const STORAGE_KEY = 'iac-registry-entries';
const SEEDED_KEY = 'iac-registry-seeded';

function generateId(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  return `entry-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

/**
 * Load registry entries from localStorage. On the very first load (seed
 * never applied), seeds with the AgenticGoat example entries. Deleting
 * entries down to zero afterward does not trigger reseeding.
 */
export function loadEntries(): RegistryEntry[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) {
      return JSON.parse(raw);
    }
  } catch {
    // fall through to seed
  }

  if (!localStorage.getItem(SEEDED_KEY)) {
    saveEntries(AGENTIC_GOAT_SEED);
    localStorage.setItem(SEEDED_KEY, 'true');
    return AGENTIC_GOAT_SEED;
  }

  return [];
}

export function saveEntries(entries: RegistryEntry[]): void {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(entries));
}

export function addEntry(input: NewRegistryEntryInput, entries: RegistryEntry[]): RegistryEntry[] {
  const now = new Date().toISOString();
  const entry = {
    ...input,
    id: generateId(),
    source: 'manual',
    addedAt: now,
    updatedAt: now,
  } as RegistryEntry;

  const updated = [...entries, entry];
  saveEntries(updated);
  return updated;
}

export function updateEntry(id: string, patch: Partial<RegistryEntry>, entries: RegistryEntry[]): RegistryEntry[] {
  const now = new Date().toISOString();
  const updated = entries.map((e) => (e.id === id ? ({ ...e, ...patch, updatedAt: now } as RegistryEntry) : e));
  saveEntries(updated);
  return updated;
}

export function removeEntry(id: string, entries: RegistryEntry[]): RegistryEntry[] {
  const updated = entries.filter((e) => e.id !== id);
  saveEntries(updated);
  return updated;
}

export default {
  loadEntries,
  saveEntries,
  addEntry,
  updateEntry,
  removeEntry,
};
