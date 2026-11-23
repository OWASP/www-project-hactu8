const API_BASE = (import.meta.env.VITE_HACTU8_API_URL || 'https://127.0.0.1:8000').replace(/\/$/, '');

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
  has_lesson: boolean;
  path_stage: string;
  path_order: number;
}

export interface Lesson {
  skill_id: string;
  owasp: string;
  risk: string;
  title: string;
  sections: Record<string, string>;
  questions: string[];
}

export interface PathStep {
  step: number;
  order: number;
  id: string;
  owasp: string;
  risk: string;
  has_lesson: boolean;
}

export interface LearningPath {
  stages: { id: string; title: string; summary: string; skills: PathStep[] }[];
  total: number;
  unassigned: string[];
}

export type CoverageStatus = 'attack_and_defense' | 'attack_only' | 'no_lab';

export interface TechniqueRun {
  run_id: string;
  backend: string;
  model: string;
  status: string;
  impact_rate: number | null;
  remediated_rate: number | null;
}

export interface Technique {
  id: string;
  title: string;
  family: string;
  summary: string;
  refs: Record<string, string[]>;
  defenses: string[];
  labs: string[];
  status: CoverageStatus;
  status_title: string;
  runs: Record<string, TechniqueRun>;
  leaky_labs: string[];
}

export interface Coverage {
  techniques: Technique[];
  total: number;
  counts: Record<CoverageStatus, number>;
  by_list: Record<string, { name: string; edition: string; ids: number; with_lab: number; without_lab: string[] }>;
  families: Record<string, string>;
  statuses: Record<CoverageStatus, string>;
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
  surface?: string;
  outcome_off?: 'SAFE' | 'BREACH';
  outcome_on?: 'SAFE' | 'DEFENDED' | 'BREACH' | 'FALSE_BLOCK';
}

export interface LiveSummary {
  attacks: number;
  controls: number;
  model_resistance: number | null;
  breaches_off: number;
  breaches_on: number;
  defended_on: number;
  false_blocks_on: number;
}

export interface ModelCandidate {
  tier: string;
  backend: string;
  model: string;
  available: boolean;
  reason: string;
}

export interface HardwareSupport {
  ok: boolean;
  reason: string;
  needs: string;
}

export interface ModelsInfo {
  backends: string[];
  local: string[];
  cloud: string[];
  keys_set: Record<string, boolean>;
  default_models: Record<string, string>;
  hardware?: Record<string, HardwareSupport>;
  candidates: ModelCandidate[];
  catalogs: Record<string, string[]>;
}

export interface Protection {
  id: string;
  title: string;
  idea: string;
  steps: string[];
  before: string;
  after: string;
}

export interface ResultAct {
  act: number;
  phase: string;
  title: string;
  notes?: string[];
  items: ResultItem[];
  protections?: Protection[];
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
  live?: LiveSummary;
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
  lesson: (skillId: string) => request<Lesson>(`/api/skills/${encodeURIComponent(skillId)}/lesson`),
  path: () => request<LearningPath>('/api/path'),
  coverage: () => request<Coverage>('/api/coverage'),
  protections: () => request<{ protections: Protection[]; total: number }>('/api/protections'),
  targets: () => request<{ targets: Target[]; total: number }>('/api/targets'),
  results: () => request<{ results: Hactu8Result[]; total: number }>('/api/results'),
  result: (runId: string) => request<Hactu8Result>(`/api/results/${encodeURIComponent(runId)}`),
  run: (body: { skill_id: string; target_id: string; backend: string; model?: string; classifier: string;
    confirm_spend?: boolean }) =>
    request<Hactu8Result>('/api/runs', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),
  live: (body: { backend: string; model?: string; confirm_spend?: boolean }) =>
    request<Hactu8Result>('/api/live', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),
  models: () => request<ModelsInfo>('/api/models'),
  reportUrl: (runId: string, format: string) =>
    `${API_BASE}/api/reports/${encodeURIComponent(runId)}/${format}`,
};

