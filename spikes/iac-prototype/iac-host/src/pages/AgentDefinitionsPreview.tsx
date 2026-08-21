// src/pages/AgentDefinitionsPreview.tsx
//
// MVP placeholder + team preview for "Agent Definitions" — phase 2 scope.
// Not implemented. No backend, no data, nothing to install here yet.
//
// What this previews: a catalog of *agent* definitions distinct from
// Skills — where a Skill is a bounded, reactive capability (activate, run,
// return), an Agent has its own lifecycle: it can be long-running, run on
// a schedule, or act autonomously, deciding which Skills to invoke and
// when. Today there is exactly one agent (the engagement runner at
// /agents), so there's nothing yet to catalog. This page exists to give
// the team something concrete to react to before that design work starts.
import React from 'react';
import { Badge, cardStyle } from '../components/Skills/shared';

const PREVIEW_FIELDS: { label: string; description: string }[] = [
  {
    label: 'Trigger',
    description: 'What starts a run: manual, on a schedule (e.g. nightly), or on an event (e.g. a new Registry target).',
  },
  {
    label: 'Autonomy / approval policy',
    description: 'How much the agent can do without a human in the loop — from "ask before every tool call" to "run unattended, report findings."',
  },
  {
    label: 'Skills it orchestrates',
    description: 'Which installed Skills this agent is allowed to invoke, and in what sequence or phase order.',
  },
  {
    label: 'Target',
    description: 'A Registry entry this agent runs against by default.',
  },
];

const AgentDefinitionsPreview: React.FC = () => {
  return (
    <div style={{ padding: '2rem', maxWidth: 760 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.5rem' }}>
        <h2 style={{ margin: 0, color: 'var(--iac-text)' }}>Agent Definitions</h2>
        <Badge label="Preview — not yet implemented" color="var(--iac-warning-bg)" textColor="var(--iac-warning-text)" />
      </div>
      <p style={{ color: 'var(--iac-text-secondary)', margin: '0 0 1.5rem', fontSize: '0.925rem' }}>
        This page previews a phase-2 feature. There is no backend behind it and nothing here can be created,
        installed, or run yet — it exists to make the direction concrete for discussion.
      </p>

      <div style={{ ...cardStyle, marginBottom: '1.5rem' }}>
        <p style={{ margin: 0, color: 'var(--iac-text)', fontSize: '0.9rem', lineHeight: 1.6 }}>
          A <strong>Skill</strong> is bounded and reactive — something activates it, it follows its instructions,
          and it returns. An <strong>Agent</strong> has its own lifecycle: it can run over an extended period, start
          itself on a schedule, or act with some autonomy — and it decides which Skills to invoke, and when. Today
          there is exactly one agent (the engagement runner at <code>/agents</code>); this catalog has nothing to
          hold until that changes.
        </p>
      </div>

      <h3 style={{ color: 'var(--iac-text)', fontWeight: 600, fontSize: '1rem', marginBottom: '0.75rem' }}>
        What an Agent Definition will need
      </h3>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
        {PREVIEW_FIELDS.map((f) => (
          <div key={f.label} style={cardStyle}>
            <div style={{ fontWeight: 600, fontSize: '0.875rem', color: 'var(--iac-text)', marginBottom: '0.25rem' }}>
              {f.label}
            </div>
            <div style={{ fontSize: '0.825rem', color: 'var(--iac-text-secondary)' }}>{f.description}</div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default AgentDefinitionsPreview;
