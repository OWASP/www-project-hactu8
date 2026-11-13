const API_BASE = (import.meta.env.VITE_HACTU8_API_URL || 'http://127.0.0.1:8000').replace(/\/$/, '');

export interface Branding {
  name: string;
  tagline: string;
  report_title: string;
  primary_color: string;
  accent_color: string;
}

export interface Skill {
  id: string;
  owasp: string;
  risk: string;
  metric: string;
  metric_name: string;
  description: string;
}

export interface Target {
  id: string;
  name: string;
  kind: string;
  targetUrl: string;
  mcpUrl: string;
  riskNotes: string;
}

export interface ResultItem {
  id: string;
  prompt: string;
  targeted: boolean;
  verdict: 'GREEN' | 'YELLOW' | 'RED';
  confidence: number;
  evidence?: string;
  reason?: string;
}

export interface ResultAct {
  act: number;
  phase: string;
  title: string;
  items: ResultItem[];
  metric: { targeted: { red: number; total: number; rate: number } };
}

export interface Hactu8Result {
  run_id: string;
  started_at: string;
  duration_ms: number;
  skill: { id: string; owasp: string; risk: string; metric: { id: string; name: string } };
  target: { kind: string; id: string; url?: string };
  model: { backend: string; model?: string };
  classifier: { name: string };
  acts: ResultAct[];
  summary: {
    status: 'pass' | 'fail' | 'reported' | 'error';
    baseline_rate: number | null;
    impact_rate: number | null;
    remediated_rate: number | null;
    story_holds: boolean;
  };
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, init);
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.detail || body.error || `HTTP ${response.status}`);
  }
  return response.json() as Promise<T>;
}

export const hactu8Api = {
  baseUrl: API_BASE,
  branding: () => request<Branding>('/api/branding'),
  skills: () => request<{ skills: Skill[]; total: number }>('/api/skills'),
  targets: () => request<{ targets: Target[]; total: number }>('/api/targets'),
  results: () => request<{ results: Hactu8Result[]; total: number }>('/api/results'),
  result: (runId: string) => request<Hactu8Result>(`/api/results/${encodeURIComponent(runId)}`),
  run: (body: { skill_id: string; target_id: string; backend: string; classifier: string }) =>
    request<Hactu8Result>('/api/runs', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),
  reportUrl: (runId: string, format: string) =>
    `${API_BASE}/api/reports/${encodeURIComponent(runId)}/${format}`,
};

