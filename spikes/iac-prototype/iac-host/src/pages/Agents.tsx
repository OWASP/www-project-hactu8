// src/pages/Agents.tsx
import React, { useState } from 'react';

import { useAgents } from '../contexts/AgentContext';
import type { AgentStreamEvent, EngagementScope, PhaseEnum } from '../types/agents';
import { PHASE_CHAIN, PHASE_LABELS } from '../types/agents';
import { StreamEventLog, isToolResultOk, toolResultData } from '../components/shared/StreamEventLog';
import type { StreamLogBlock } from '../components/shared/StreamEventLog';

// --------------------------------------------------------------------------- //
// Phase stepper
// --------------------------------------------------------------------------- //

const PhaseStepper: React.FC<{ phasesComplete: string[]; currentPhase: PhaseEnum | null }> = ({
  phasesComplete,
  currentPhase,
}) => (
  <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', margin: '12px 0' }}>
    {PHASE_CHAIN.map((phase) => {
      const done = phasesComplete.includes(phase);
      const active = currentPhase === phase && !done;
      return (
        <span
          key={phase}
          style={{
            padding: '3px 10px',
            borderRadius: 12,
            fontSize: 12,
            fontWeight: done ? 600 : 400,
            background: done ? 'var(--iac-success-bg)' : active ? 'var(--iac-info-bg)' : 'var(--iac-surface)',
            color: done ? 'var(--iac-success)' : active ? 'var(--iac-link)' : 'var(--iac-muted)',
            border: `1px solid ${done ? 'var(--iac-success)' : active ? 'var(--iac-info)' : 'var(--iac-border)'}`,
          }}
        >
          {done ? '✓ ' : active ? '▶ ' : ''}{PHASE_LABELS[phase]}
        </span>
      );
    })}
  </div>
);

// --------------------------------------------------------------------------- //
// Agent-stream events -> shared StreamLogBlock vocabulary. Phase headers and
// the "awaiting approval" banner are Agents-page-specific (Project runs have
// neither), so they're built here as 'custom'/'info' blocks rather than
// living in the shared renderer.
// --------------------------------------------------------------------------- //

function buildAgentBlocks(events: AgentStreamEvent[]): StreamLogBlock[] {
  const blocks: StreamLogBlock[] = [];
  for (const [i, event] of events.entries()) {
    if (event.type === 'phase_start') {
      blocks.push({
        kind: 'custom',
        key: `phase-${i}`,
        render: (
          <div
            style={{
              color: 'var(--iac-info)',
              fontSize: 11,
              fontWeight: 700,
              letterSpacing: '0.1em',
              textTransform: 'uppercase',
              marginBottom: 12,
              display: 'flex',
              alignItems: 'center',
              gap: 8,
            }}
          >
            <span style={{ flex: 1, borderBottom: '1px solid var(--iac-badge-bg)' }} />
            {PHASE_LABELS[event.phase]}
            <span style={{ flex: 1, borderBottom: '1px solid var(--iac-badge-bg)' }} />
          </div>
        ),
      });
    } else if (event.type === 'text') {
      const last = blocks[blocks.length - 1];
      if (last?.kind === 'prose') {
        last.content += event.content;
      } else {
        blocks.push({ kind: 'prose', content: event.content });
      }
    } else if (event.type === 'tool_call') {
      blocks.push({ kind: 'tool_call', name: event.name, input: event.input });
    } else if (event.type === 'tool_result') {
      blocks.push({
        kind: 'tool_result',
        name: event.name,
        ok: isToolResultOk(event.result as Record<string, unknown>),
        data: toolResultData(event.result as Record<string, unknown>),
      });
    } else if (event.type === 'awaiting_approval') {
      blocks.push({ kind: 'info', text: `⏸  Phase complete — awaiting approval to continue`, color: '#fbbf24' });
    } else if (event.type === 'error') {
      blocks.push({ kind: 'error', message: event.message });
    }
  }
  return blocks;
}

// --------------------------------------------------------------------------- //
// Approval gate banner
// --------------------------------------------------------------------------- //

const ApprovalBanner: React.FC<{
  phase: string;
  nextPhase: string | null;
  onApprove: () => void;
  onReject: () => void;
}> = ({ phase, nextPhase, onApprove, onReject }) => (
  <div
    style={{
      background: 'var(--iac-warning-bg)',
      border: '1px solid var(--iac-warning)',
      borderRadius: 8,
      padding: '12px 16px',
      marginTop: 16,
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      gap: 12,
    }}
  >
    <div>
      <div style={{ color: 'var(--iac-warning)', fontWeight: 600, fontSize: 13 }}>
        ✓ {PHASE_LABELS[phase as PhaseEnum] ?? phase} complete
      </div>
      {nextPhase && (
        <div style={{ color: 'var(--iac-warning-text)', fontSize: 12, marginTop: 2 }}>
          Next: <strong>{nextPhase}</strong> — approve to continue
        </div>
      )}
    </div>
    <div style={{ display: 'flex', gap: 8 }}>
      <button onClick={onApprove} style={btnStyle('var(--iac-success)')}>
        ▶ Approve &amp; Continue
      </button>
      <button onClick={onReject} style={btnStyle('var(--iac-error)')}>
        ✕ Reject
      </button>
    </div>
  </div>
);

function btnStyle(color: string): React.CSSProperties {
  return {
    background: 'transparent',
    border: `1px solid ${color}`,
    color,
    borderRadius: 6,
    padding: '4px 14px',
    cursor: 'pointer',
    fontWeight: 600,
    fontSize: 13,
  };
}

// --------------------------------------------------------------------------- //
// Scope form
// --------------------------------------------------------------------------- //

const DEFAULT_SCOPE: EngagementScope = {
  target_url: '',
  objectives: '',
  roe: 'Passive recon and non-destructive probing only.',
  team_type: 'red',
  authorized_tools: [],
  enable_persistence: false,
};

const ScopeForm: React.FC<{
  onSubmit: (scope: EngagementScope) => void;
  disabled: boolean;
}> = ({ onSubmit, disabled }) => {
  const [scope, setScope] = useState<EngagementScope>(DEFAULT_SCOPE);

  const set = (field: keyof EngagementScope, value: string | boolean) =>
    setScope((prev) => ({ ...prev, [field]: value }));

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!scope.target_url.trim() || !scope.objectives.trim()) return;
    onSubmit(scope);
  };

  const inputStyle: React.CSSProperties = {
    width: '100%',
    background: 'var(--iac-input-bg)',
    border: '1px solid var(--iac-input-border)',
    borderRadius: 6,
    color: 'var(--iac-text)',
    padding: '6px 10px',
    fontSize: 13,
    boxSizing: 'border-box',
  };

  const labelStyle: React.CSSProperties = {
    display: 'block',
    color: 'var(--iac-text-secondary)',
    fontSize: 12,
    fontWeight: 600,
    marginBottom: 4,
    textTransform: 'uppercase',
    letterSpacing: '0.05em',
  };

  return (
    <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div>
        <label style={labelStyle}>Target URL *</label>
        <input
          style={inputStyle}
          type="url"
          value={scope.target_url}
          onChange={(e) => set('target_url', e.target.value)}
          placeholder="https://target-llm-app.example.com"
          required
          disabled={disabled}
        />
      </div>

      <div>
        <label style={labelStyle}>Objectives *</label>
        <textarea
          style={{ ...inputStyle, resize: 'vertical', minHeight: 72 }}
          value={scope.objectives}
          onChange={(e) => set('objectives', e.target.value)}
          placeholder="Identify prompt injection vulnerabilities in the chat interface..."
          required
          disabled={disabled}
        />
      </div>

      <div>
        <label style={labelStyle}>Rules of Engagement (ROE)</label>
        <textarea
          style={{ ...inputStyle, resize: 'vertical', minHeight: 56 }}
          value={scope.roe}
          onChange={(e) => set('roe', e.target.value)}
          disabled={disabled}
        />
      </div>

      <div>
        <label style={labelStyle}>Team Type</label>
        <select
          style={inputStyle}
          value={scope.team_type}
          onChange={(e) => set('team_type', e.target.value)}
          disabled={disabled}
        >
          <option value="red">Red Team</option>
          <option value="blue">Blue Team</option>
          <option value="purple">Purple Team</option>
        </select>
      </div>

      <button
        type="submit"
        disabled={disabled}
        style={{
          ...btnStyle('var(--iac-info)'),
          fontSize: 14,
          padding: '8px 20px',
          alignSelf: 'flex-start',
          opacity: disabled ? 0.5 : 1,
          cursor: disabled ? 'not-allowed' : 'pointer',
        }}
      >
        Create Engagement
      </button>
    </form>
  );
};

// --------------------------------------------------------------------------- //
// Main Agents page
// --------------------------------------------------------------------------- //

const Agents: React.FC = () => {
  const {
    engagementId,
    status,
    currentPhase,
    phasesComplete,
    streamEvents,
    error,
    startEngagement,
    runNextPhase,
    approve,
    reject,
  } = useAgents();

  const isRunning = status === 'running';
  const awaitingApproval = status === 'awaiting_approval';
  const lastCompletedPhase = phasesComplete[phasesComplete.length - 1];

  // Determine what the next phase will be
  const nextPhase = PHASE_CHAIN.find((p) => !phasesComplete.includes(p)) ?? null;
  const nextPhaseLabel = nextPhase ? PHASE_LABELS[nextPhase] : null;

  const handleCreateEngagement = async (scope: EngagementScope) => {
    await startEngagement(scope);
  };

  return (
    <div
      style={{
        padding: 24,
        color: 'var(--iac-text)',
        fontFamily: 'inherit',
        maxWidth: 860,
        height: '100%',
        overflowY: 'auto',
      }}
    >
      <h2 style={{ marginTop: 0, color: 'var(--iac-text)', fontSize: 22 }}>Agent Engagements</h2>
      <p style={{ color: 'var(--iac-muted)', marginTop: 0, marginBottom: 20, fontSize: 13 }}>
        Run autonomous red team phases powered by Claude. Each phase maps to an OODA step and
        requires human approval before proceeding.
      </p>

      {/* Scope form — shown until engagement is created */}
      {!engagementId && (
        <div
          style={{
            background: 'var(--iac-surface)',
            border: '1px solid var(--iac-border)',
            borderRadius: 10,
            padding: 20,
            marginBottom: 20,
          }}
        >
          <h3 style={{ marginTop: 0, color: 'var(--iac-text-secondary)', fontSize: 14, fontWeight: 700 }}>
            NEW ENGAGEMENT
          </h3>
          <ScopeForm onSubmit={handleCreateEngagement} disabled={isRunning} />
        </div>
      )}

      {/* Active engagement controls */}
      {engagementId && (
        <div
          style={{
            background: 'var(--iac-surface)',
            border: '1px solid var(--iac-border)',
            borderRadius: 10,
            padding: 20,
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <span style={{ color: 'var(--iac-muted)', fontSize: 12 }}>Engagement ID: </span>
              <code style={{ color: 'var(--iac-text-secondary)', fontSize: 12 }}>{engagementId}</code>
            </div>
            <span
              style={{
                padding: '2px 10px',
                borderRadius: 10,
                fontSize: 11,
                fontWeight: 700,
                background:
                  status === 'running'
                    ? 'var(--iac-info-bg)'
                    : status === 'awaiting_approval'
                    ? 'var(--iac-warning-bg)'
                    : status === 'complete'
                    ? 'var(--iac-success-bg)'
                    : status === 'failed'
                    ? 'var(--iac-error-bg)'
                    : 'var(--iac-surface)',
                color:
                  status === 'running'
                    ? 'var(--iac-link)'
                    : status === 'awaiting_approval'
                    ? 'var(--iac-warning)'
                    : status === 'complete'
                    ? 'var(--iac-success)'
                    : status === 'failed'
                    ? 'var(--iac-error)'
                    : 'var(--iac-muted)',
              }}
            >
              {status.toUpperCase().replace('_', ' ')}
            </span>
          </div>

          <PhaseStepper phasesComplete={phasesComplete} currentPhase={currentPhase} />

          {!isRunning && !awaitingApproval && status !== 'complete' && status !== 'rejected' && nextPhase && (
            <button
              onClick={() => runNextPhase()}
              style={{ ...btnStyle('var(--iac-info)'), fontSize: 13, marginTop: 8 }}
            >
              ▶ Run {nextPhaseLabel ?? 'Next'} Phase
            </button>
          )}

          {awaitingApproval && lastCompletedPhase && (
            <ApprovalBanner
              phase={lastCompletedPhase}
              nextPhase={nextPhaseLabel}
              onApprove={async () => { await approve(); runNextPhase(); }}
              onReject={reject}
            />
          )}

          {error && (
            <div
              style={{
                marginTop: 12,
                color: 'var(--iac-error)',
                background: 'var(--iac-error-bg)',
                border: '1px solid var(--iac-error)',
                borderRadius: 6,
                padding: '8px 12px',
                fontSize: 13,
              }}
            >
              {error}
            </div>
          )}

          <StreamEventLog blocks={buildAgentBlocks(streamEvents)} />
        </div>
      )}
    </div>
  );
};

export default Agents;
