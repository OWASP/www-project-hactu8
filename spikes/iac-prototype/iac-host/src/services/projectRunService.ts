/**
 * Service for Project runs — creating a run against a curated Project, and
 * streaming turns of its conversation.
 *
 * Unlike agentService.ts's streamPhase (native EventSource, GET-only),
 * sending a message here is a POST with a body (the user's message text),
 * which EventSource cannot do. So streamMessage uses fetch(POST) +
 * response.body.getReader(), manually parsing the same `data: {json}\n\n`
 * SSE framing agents/router.py and project_runs/router.py both emit.
 */

import type {
  CreateRunRequest,
  CreateRunResponse,
  ProjectRunState,
  ProjectRunStreamEvent,
} from '../types/project';

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

export async function createProjectRun(
  projectId: string,
  request: CreateRunRequest
): Promise<CreateRunResponse> {
  const response = await fetch(`${API_BASE}/api/projects/${encodeURIComponent(projectId)}/runs`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request),
  });
  if (!response.ok) {
    throw new Error(`Create run failed (${response.status}): ${await response.text()}`);
  }
  return response.json();
}

export async function getProjectRun(runId: string): Promise<ProjectRunState> {
  const response = await fetch(`${API_BASE}/api/project-runs/${encodeURIComponent(runId)}`);
  if (!response.ok) {
    throw new Error(`Get run failed (${response.status}): ${await response.text()}`);
  }
  return response.json();
}

export async function getProjectRunStatus(runId: string): Promise<{
  run_id: string;
  status: string;
  turn_count: number;
  error: string | null;
  updated_at: string;
}> {
  const response = await fetch(`${API_BASE}/api/project-runs/${encodeURIComponent(runId)}/status`);
  if (!response.ok) {
    throw new Error(`Get run status failed (${response.status}): ${await response.text()}`);
  }
  return response.json();
}

/**
 * Send a message and stream the assistant's turn. Calls onEvent for each
 * parsed SSE event, onDone once the stream ends normally (after
 * 'complete'/'error'), onError on a transport failure. Returns a cleanup
 * function that aborts the in-flight request.
 */
export function streamMessage(
  runId: string,
  content: string,
  onEvent: (event: ProjectRunStreamEvent) => void,
  onDone: () => void,
  onError: (err: Error) => void
): () => void {
  const controller = new AbortController();

  (async () => {
    try {
      const response = await fetch(`${API_BASE}/api/project-runs/${encodeURIComponent(runId)}/messages`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content }),
        signal: controller.signal,
      });

      if (!response.ok || !response.body) {
        throw new Error(`Stream failed (${response.status}): ${await response.text()}`);
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });

        // SSE frames are separated by a blank line; a frame may arrive
        // split across chunks, so only split on complete "\n\n" boundaries
        // and keep any trailing partial frame in the buffer.
        const frames = buffer.split('\n\n');
        buffer = frames.pop() ?? '';

        for (const frame of frames) {
          const line = frame.trim();
          if (!line.startsWith('data: ')) continue;
          try {
            const event: ProjectRunStreamEvent = JSON.parse(line.slice('data: '.length));
            onEvent(event);
          } catch {
            // ignore malformed frame
          }
        }
      }

      onDone();
    } catch (err) {
      if (controller.signal.aborted) return;
      onError(err instanceof Error ? err : new Error(String(err)));
    }
  })();

  return () => controller.abort();
}

export default {
  createProjectRun,
  getProjectRun,
  getProjectRunStatus,
  streamMessage,
};
