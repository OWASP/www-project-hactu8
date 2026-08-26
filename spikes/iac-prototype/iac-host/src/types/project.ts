// src/types/project.ts
//
// TypeScript mirrors of iac-copilot-api/canned_projects/models.py and
// iac-copilot-api/project_runs/models.py. Field names are snake_case here
// to match the backend's JSON exactly (Pydantic's default), rather than
// translating to camelCase at the type layer.

export interface ProjectResource {
  title: string;
  description?: string;
  url?: string;
}

export interface CannedProjectSummary {
  id: string;
  name: string;
  category: string;
  summary: string;
  default_skill_names: string[];
  legacy_route?: string;
  version: string;
}

export interface CannedProjectDetail extends CannedProjectSummary {
  resources: ProjectResource[];
  overview_md: string;
  instructions_md: string;
}

export interface CannedProjectListResponse {
  projects: CannedProjectSummary[];
  total: number;
}

// --------------------------------------------------------------------------- //
// Project runs
// --------------------------------------------------------------------------- //

export interface TargetSnapshot {
  registry_entry_id?: string;
  name: string;
  target_url?: string;
  description?: string;
  risk_notes?: string;
}

export interface ModelConfigSnapshot {
  provider_id: string;
  model_id: string;
  api_key?: string;
  base_url?: string;
}

export type ProjectRunStatus = 'idle' | 'running' | 'awaiting_input' | 'failed';

export interface ProjectRunTurn {
  role: 'user' | 'assistant';
  content: string;
  created_at: string;
}

export interface ProjectRunFinding {
  tool: string;
  skill?: string;
  data?: unknown;
}

export interface ProjectRunScope {
  project_id: string;
  project_name: string;
  target: TargetSnapshot;
  skill_names: string[];
  model: ModelConfigSnapshot;
}

export interface ProjectRunState {
  run_id: string;
  scope: ProjectRunScope;
  status: ProjectRunStatus;
  turns: ProjectRunTurn[];
  findings: ProjectRunFinding[];
  created_at: string;
  updated_at: string;
  error: string | null;
}

export interface CreateRunRequest {
  target: TargetSnapshot;
  skill_names: string[];
  model: ModelConfigSnapshot;
}

export interface CreateRunResponse {
  run_id: string;
  status: ProjectRunStatus;
}

// SSE event shapes streamed from POST /api/project-runs/{run_id}/messages.
// A narrower sibling of types/agents.ts's AgentStreamEvent — no
// phase_start/awaiting_approval variants, since a Project run isn't phased.
export type ProjectRunStreamEvent =
  | { type: 'text'; content: string }
  | { type: 'tool_call'; name: string; input: Record<string, unknown> }
  | { type: 'tool_result'; name: string; result: Record<string, unknown> }
  | { type: 'complete'; content: string; findings: ProjectRunFinding[] }
  | { type: 'error'; message: string };
