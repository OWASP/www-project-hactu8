/**
 * Service for interacting with the IAC Agent API endpoints.
 * Mirrors the pattern in copilotService.ts.
 */

import { getModelProviderHeaders } from './modelProviderService';
import type {
  AgentStreamEvent,
  EngagementScope,
  EngagementStatusResponse,
} from '../types/agents';

const RAW_BASE = import.meta.env.VITE_COPILOT_API_URL || '';

function normalizeBase(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) return '';
  if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) return trimmed;
  if (trimmed.startsWith('/')) return trimmed;
  const protocol = typeof window !== 'undefined' ? window.location.protocol : 'http:';
  return `${protocol}//${trimmed}`;
}

const API_BASE = normalizeBase(RAW_BASE);

async function fetchApi<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const url = `${API_BASE}${endpoint}`;
  const response = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...getModelProviderHeaders(),
      ...options.headers,
    },
  });
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`API error (${response.status}): ${errorText}`);
  }
  return response.json();
}

/**
 * Create a new engagement and return its ID.
 */
export async function createEngagement(
  scope: EngagementScope
): Promise<{ engagement_id: string; status: string; created_at: string }> {
  return fetchApi('/api/agents/engage', {
    method: 'POST',
    body: JSON.stringify({ scope }),
  });
}

/**
 * Get the current status of an engagement.
 */
export async function getEngagementStatus(
  engagementId: string
): Promise<EngagementStatusResponse> {
  return fetchApi(`/api/agents/engage/${engagementId}/status`);
}

/**
 * Approve the current phase or tool gate to continue.
 */
export async function approveEngagement(
  engagementId: string,
  level: 'phase' | 'tool' = 'phase'
): Promise<{ engagement_id: string; status: string }> {
  return fetchApi(`/api/agents/engage/${engagementId}/approve`, {
    method: 'POST',
    body: JSON.stringify({ level }),
  });
}

/**
 * Reject and halt the engagement.
 */
export async function rejectEngagement(
  engagementId: string
): Promise<{ engagement_id: string; status: string }> {
  return fetchApi(`/api/agents/engage/${engagementId}/reject`, { method: 'POST' });
}

/**
 * Stream events from the next (or specified) phase using Server-Sent Events.
 * Calls onEvent for each parsed event, calls onDone when the stream ends.
 */
export function streamPhase(
  engagementId: string,
  onEvent: (event: AgentStreamEvent) => void,
  onDone: () => void,
  onError: (err: Error) => void,
  phase?: string
): () => void {
  const url = `${API_BASE}/api/agents/engage/${engagementId}/stream${phase ? `?phase=${phase}` : ''}`;

  const eventSource = new EventSource(url);

  eventSource.onmessage = (e) => {
    try {
      const event: AgentStreamEvent = JSON.parse(e.data);
      onEvent(event);
      // Close only on the terminal events the *router* emits.
      // 'complete' is an internal base_agent signal — the router emits
      // 'awaiting_approval' right after, so don't close early on 'complete'.
      if (event.type === 'awaiting_approval' || event.type === 'error') {
        eventSource.close();
        onDone();
      }
    } catch {
      // ignore parse errors
    }
  };

  eventSource.onerror = (e) => {
    eventSource.close();
    onError(new Error('SSE stream error'));
  };

  // Return a cleanup function
  return () => eventSource.close();
}

const agentService = {
  createEngagement,
  getEngagementStatus,
  approveEngagement,
  rejectEngagement,
  streamPhase,
};

export default agentService;
