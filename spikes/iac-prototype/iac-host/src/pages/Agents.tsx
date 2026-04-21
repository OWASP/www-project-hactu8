// src/pages/Agents.tsx
import React, { useEffect, useRef, useState } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

import { useAgents } from '../contexts/AgentContext';
import type { AgentStreamEvent, EngagementScope, PhaseEnum } from '../types/agents';
import { PHASE_CHAIN, PHASE_LABELS } from '../types/agents';

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
// Markdown prose styles (injected once)
// --------------------------------------------------------------------------- //

const MD_STYLES = `
.agent-md h1,.agent-md h2,.agent-md h3 { color:var(--iac-info-text); margin:12px 0 6px; }
.agent-md h1 { font-size:17px; border-bottom:1px solid var(--iac-badge-bg); padding-bottom:4px; }
.agent-md h2 { font-size:15px; }
.agent-md h3 { font-size:13px; color:var(--iac-link); }
.agent-md p  { color:var(--iac-text); margin:4px 0; line-height:1.6; }
.agent-md ul,.agent-md ol { color:var(--iac-text); padding-left:20px; margin:4px 0; }
.agent-md li { margin:2px 0; line-height:1.5; }
.agent-md code { background:var(--iac-surface); color:var(--iac-code-text); padding:1px 5px; border-radius:3px; font-size:12px; }
.agent-md pre  { background:var(--iac-code-bg); border:1px solid var(--iac-badge-bg); border-radius:6px; padding:10px 12px; overflow-x:auto; margin:8px 0; }
.agent-md pre code { background:none; color:var(--iac-code-text); padding:0; }
.agent-md table { width:100%; border-collapse:collapse; margin:8px 0; font-size:12px; }
.agent-md th { background:var(--iac-badge-bg); color:var(--iac-info-text); padding:5px 10px; text-align:left; border:1px solid var(--iac-badge-bg); }
.agent-md td { padding:4px 10px; border:1px solid var(--iac-surface); color:var(--iac-text-secondary); }
.agent-md tr:nth-child(even) td { background:var(--iac-bg); }
.agent-md blockquote { border-left:3px solid var(--iac-info); margin:6px 0; padding:4px 12px; color:var(--iac-text-secondary); font-style:italic; }
.agent-md strong { color:var(--iac-text); }
.agent-md hr { border:none; border-top:1px solid var(--iac-surface); margin:10px 0; }
.agent-md a { color:var(--iac-link); }
`;

// --------------------------------------------------------------------------- //
// Stream event log — markdown-rendered, auto-scrolling
// --------------------------------------------------------------------------- //

const EventLog: React.FC<{ events: AgentStreamEvent[] }> = ({ events }) => {
  const containerRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to bottom whenever events change
  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [events.length]);

  if (events.length === 0) return null;

  // Concatenate consecutive text events from the same phase into a single block
  // so markdown renders as one coherent document instead of fragment-per-chunk.
  type Block =
    | { kind: 'phase_start'; phase: PhaseEnum }
    | { kind: 'prose'; content: string }
    | { kind: 'tool_call'; name: string; input: Record<string, unknown> }
    | { kind: 'tool_result'; name: string; ok: boolean; data?: string }
    | { kind: 'info'; text: string; color: string }
    | { kind: 'error'; message: string };

  const blocks: Block[] = [];
  for (const event of events) {
    if (event.type === 'phase_start') {
      blocks.push({ kind: 'phase_start', phase: event.phase });
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
      const ok = !!(event.result as any)?.success;
      const data = (event.result as any)?.data;
      blocks.push({ kind: 'tool_result', name: event.name, ok, data: data ? JSON.stringify(data, null, 2) : undefined });
    } else if (event.type === 'awaiting_approval') {
      blocks.push({ kind: 'info', text: `⏸  Phase complete — awaiting approval to continue`, color: '#fbbf24' });
    } else if (event.type === 'error') {
      blocks.push({ kind: 'error', message: event.message });
    }
  }

  return (
    <>
      <style>{MD_STYLES}</style>
      <div
        ref={containerRef}
        style={{
          background: 'var(--iac-bg)',
          border: '1px solid var(--iac-border)',
          borderRadius: 8,
          padding: '16px 20px',
          maxHeight: 520,
          overflowY: 'auto',
          marginTop: 16,
        }}
      >
        {blocks.map((block, i) => {
          if (block.kind === 'phase_start') {
            return (
              <div
                key={i}
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
                {PHASE_LABELS[block.phase]}
                <span style={{ flex: 1, borderBottom: '1px solid var(--iac-badge-bg)' }} />
              </div>
            );
          }

          if (block.kind === 'prose') {
            return (
              <div key={i} className="agent-md" style={{ marginBottom: 8 }}>
                <ReactMarkdown remarkPlugins={[remarkGfm]}>{block.content}</ReactMarkdown>
              </div>
            );
          }

          if (block.kind === 'tool_call') {
            return (
              <div
                key={i}
                style={{
                  background: 'var(--iac-surface)',
                  border: '1px solid var(--iac-border)',
                  borderRadius: 6,
                  padding: '6px 12px',
                  marginBottom: 6,
                  fontFamily: 'monospace',
                  fontSize: 12,
                  color: 'var(--iac-info-text)',
                }}
              >
                <span style={{ opacity: 0.6 }}>⚙ skill: </span>
                <strong>{block.name}</strong>
                <span style={{ opacity: 0.6 }}>(</span>
                {Object.entries(block.input).map(([k, v]) => (
                  <span key={k}> {k}=<em style={{ color: '#a5f3fc' }}>{String(v)}</em></span>
                ))}
                <span style={{ opacity: 0.6 }}>)</span>
              </div>
            );
          }

          if (block.kind === 'tool_result') {
            return (
              <div
                key={i}
                style={{
                  background: block.ok ? 'var(--iac-success-bg)' : 'var(--iac-error-bg)',
                  border: `1px solid ${block.ok ? 'var(--iac-success)' : 'var(--iac-error)'}`,
                  borderRadius: 6,
                  padding: '6px 12px',
                  marginBottom: 10,
                  fontFamily: 'monospace',
                  fontSize: 12,
                }}
              >
                <div style={{ color: block.ok ? 'var(--iac-success)' : 'var(--iac-error)', marginBottom: block.data ? 4 : 0 }}>
                  {block.ok ? '✓' : '✕'} {block.name}
                </div>
                {block.data && (
                  <pre style={{ margin: 0, color: 'var(--iac-text-secondary)', fontSize: 11, whiteSpace: 'pre-wrap', overflowX: 'auto' }}>
                    {block.data.length > 600 ? block.data.slice(0, 600) + '\n…' : block.data}
                  </pre>
                )}
              </div>
            );
          }

          if (block.kind === 'info') {
            return (
              <div key={i} style={{ color: block.color, fontSize: 12, fontStyle: 'italic', marginTop: 8 }}>
                {block.text}
              </div>
            );
          }

          if (block.kind === 'error') {
            return (
              <div
                key={i}
                style={{
                  color: 'var(--iac-error)',
                  background: 'var(--iac-error-bg)',
                  border: '1px solid var(--iac-error)',
                  borderRadius: 6,
                  padding: '6px 12px',
                  fontSize: 13,
                  fontFamily: 'monospace',
                }}
              >
                ✕ {block.message}
              </div>
            );
          }

          return null;
        })}
      </div>
    </>
  );
};

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

          <EventLog events={streamEvents} />
        </div>
      )}
    </div>
  );
};

export default Agents;
