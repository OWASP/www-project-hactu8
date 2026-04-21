/**
 * TypeScript types for the IAC Agent system — mirrors iac-copilot-api/agents/models.py
 */

export type PhaseEnum =
  | 'kickoff'
  | 'recon'
  | 'risk'
  | 'attack_selection'
  | 'simulated_attacks'
  | 'reporting'
  | 'debrief';

export type EngagementStatus =
  | 'idle'
  | 'running'
  | 'awaiting_approval'
  | 'complete'
  | 'failed'
  | 'rejected';

export interface EngagementScope {
  target_url: string;
  objectives: string;
  roe: string;
  team_type: 'red' | 'blue' | 'purple';
  authorized_tools: string[];
  enable_persistence: boolean;
}

export interface AgentResult {
  phase: PhaseEnum;
  agent_name: string;
  summary: string;
  findings: Record<string, unknown>[];
  tool_calls: Record<string, unknown>[];
  completed_at: string;
}

export interface ApprovalContext {
  level: 'phase' | 'tool';
  phase?: string;
  tool_name?: string;
  tool_input?: Record<string, unknown>;
  risk: 'low' | 'medium' | 'high';
  description: string;
}

export interface EngagementStatusResponse {
  engagement_id: string;
  status: EngagementStatus;
  current_phase: PhaseEnum | null;
  phases_complete: string[];
  pending_approval: ApprovalContext | null;
  error: string | null;
  updated_at: string;
}

// SSE event shapes
export type AgentStreamEvent =
  | { type: 'phase_start'; phase: PhaseEnum }
  | { type: 'text'; content: string }
  | { type: 'tool_call'; name: string; input: Record<string, unknown> }
  | { type: 'tool_result'; name: string; result: Record<string, unknown> }
  | { type: 'approval_required'; context: ApprovalContext }
  | { type: 'awaiting_approval'; phase: string }
  | { type: 'complete'; result: AgentResult }
  | { type: 'error'; message: string };

export const PHASE_LABELS: Record<PhaseEnum, string> = {
  kickoff: 'Kick-Off',
  recon: 'Reconnaissance',
  risk: 'Risk Assessment',
  attack_selection: 'Attack Selection',
  simulated_attacks: 'Simulated Attacks',
  reporting: 'Reporting',
  debrief: 'Debrief',
};

export const PHASE_CHAIN: PhaseEnum[] = [
  'kickoff',
  'recon',
  'risk',
  'attack_selection',
  'simulated_attacks',
  'reporting',
  'debrief',
];
