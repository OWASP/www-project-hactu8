// src/contexts/AgentContext.tsx
import React, { createContext, useCallback, useContext, useRef, useState } from 'react';

import agentService from '../services/agentService';
import type {
  AgentResult,
  AgentStreamEvent,
  EngagementScope,
  EngagementStatus,
  PhaseEnum,
} from '../types/agents';

interface AgentContextType {
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

const AgentContext = createContext<AgentContextType | undefined>(undefined);

export const AgentProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [engagementId, setEngagementId] = useState<string | null>(null);
  const [status, setStatus] = useState<EngagementStatus>('idle');
  const [currentPhase, setCurrentPhase] = useState<PhaseEnum | null>(null);
  const [phasesComplete, setPhasesComplete] = useState<string[]>([]);
  const [streamEvents, setStreamEvents] = useState<AgentStreamEvent[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [phaseResults, setPhaseResults] = useState<Record<string, AgentResult>>({});
  const cleanupRef = useRef<(() => void) | null>(null);

  const startEngagement = useCallback(async (scope: EngagementScope) => {
    setError(null);
    setStreamEvents([]);
    setPhasesComplete([]);
    setPhaseResults({});
    setStatus('idle');

    const result = await agentService.createEngagement(scope);
    setEngagementId(result.engagement_id);
    setStatus('idle');
  }, []);

  const runNextPhase = useCallback((phase?: string) => {
    if (!engagementId) return;
    if (cleanupRef.current) cleanupRef.current();

    setStatus('running');
    setStreamEvents([]);
    setError(null);

    const cleanup = agentService.streamPhase(
      engagementId,
      (event) => {
        setStreamEvents((prev) => [...prev, event]);

        if (event.type === 'phase_start') {
          setCurrentPhase(event.phase);
        } else if (event.type === 'complete') {
          setPhaseResults((prev) => ({
            ...prev,
            [event.result.phase]: event.result,
          }));
        } else if (event.type === 'awaiting_approval') {
          setStatus('awaiting_approval');
          setPhasesComplete((prev) =>
            prev.includes(event.phase) ? prev : [...prev, event.phase]
          );
        } else if (event.type === 'error') {
          setStatus('failed');
          setError(event.message);
        }
      },
      () => {
        // onDone — status already updated by event handlers
      },
      (err) => {
        setStatus('failed');
        setError(err.message);
      },
      phase,
    );

    cleanupRef.current = cleanup;
  }, [engagementId]);

  const approve = useCallback(async () => {
    if (!engagementId) return;
    await agentService.approveEngagement(engagementId, 'phase');
    setStatus('idle');
  }, [engagementId]);

  const reject = useCallback(async () => {
    if (!engagementId) return;
    await agentService.rejectEngagement(engagementId);
    setStatus('rejected');
  }, [engagementId]);

  const clearEvents = useCallback(() => setStreamEvents([]), []);

  return (
    <AgentContext.Provider
      value={{
        engagementId,
        status,
        currentPhase,
        phasesComplete,
        streamEvents,
        error,
        phaseResults,
        startEngagement,
        runNextPhase,
        approve,
        reject,
        clearEvents,
      }}
    >
      {children}
    </AgentContext.Provider>
  );
};

export function useAgents(): AgentContextType {
  const ctx = useContext(AgentContext);
  if (!ctx) throw new Error('useAgents must be used inside AgentProvider');
  return ctx;
}
