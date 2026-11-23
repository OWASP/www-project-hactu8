// src/contexts/AgentContext.ts
import { createContext, useContext } from 'react';
import type {
  AgentResult,
  AgentStreamEvent,
  EngagementScope,
  EngagementStatus,
  PhaseEnum,
} from '../types/agents';

export interface AgentContextType {
  engagementId: string | null;
  status: EngagementStatus;
  currentPhase: PhaseEnum | null;
  phasesComplete: string[];
  streamEvents: AgentStreamEvent[];
  error: string | null;
  phaseResults: Record<string, AgentResult>;
  startEngagement: (scope: EngagementScope) => Promise<void>;
  runNextPhase: (phase?: string) => void;
  approve: () => Promise<void>;
  reject: () => Promise<void>;
  clearEvents: () => void;
}

export const AgentContext = createContext<AgentContextType | undefined>(undefined);

export function useAgents(): AgentContextType {
  const ctx = useContext(AgentContext);
  if (!ctx) throw new Error('useAgents must be used inside AgentProvider');
  return ctx;
}
