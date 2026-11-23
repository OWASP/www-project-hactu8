// src/components/Skills/sharedStyles.ts
// Shared labels + styles reused across the Skills Explorer, Installed, and
// Creator pages. Kept apart from shared.tsx so that file exports only
// components (React fast refresh).
import type React from 'react';

export const CATEGORY_LABELS: Record<string, string> = {
  'assurance-testing': 'Assurance Testing',
  remediation: 'Remediation',
  reporting: 'Reporting',
  governance: 'Governance',
  research: 'Research',
  automation: 'Automation',
  utility: 'Utility',
};

// Category labels for the Agent Catalog (distinct taxonomy from Skills —
// agents are grouped by orchestration role, not assurance-lifecycle activity).
export const AGENT_CATEGORY_LABELS: Record<string, string> = {
  planning: 'Planning',
  reconnaissance: 'Reconnaissance',
  'risk-assessment': 'Risk Assessment',
  'attack-simulation': 'Attack Simulation',
  reporting: 'Reporting',
  governance: 'Governance',
  utility: 'Utility',
};

export const sidebarStyle: React.CSSProperties = {
  width: 320,
  padding: '1rem',
  background: 'var(--iac-surface)',
  borderRight: '1px solid var(--iac-border)',
  display: 'flex',
  flexDirection: 'column',
  overflowY: 'auto',
};

export const mainStyle: React.CSSProperties = {
  flex: 1,
  padding: '2rem',
  overflowY: 'auto',
  background: 'var(--iac-bg)',
};

export const cardStyle: React.CSSProperties = {
  padding: '0.75rem',
  border: '1px solid var(--iac-border)',
  borderRadius: '6px',
  background: 'var(--iac-bg)',
};

export const installButtonStyle: React.CSSProperties = {
  padding: '0.3rem 0.75rem',
  background: 'var(--iac-surface-elevated)',
  color: 'var(--iac-text)',
  border: 'none',
  borderRadius: '4px',
  cursor: 'pointer',
  fontWeight: 600,
  fontSize: '0.75rem',
};

export const smallButtonStyle: React.CSSProperties = {
  padding: '0.35rem 0.75rem',
  background: 'var(--iac-surface-elevated)',
  color: 'var(--iac-text)',
  border: 'none',
  borderRadius: '4px',
  cursor: 'pointer',
  fontWeight: 500,
  fontSize: '0.8rem',
  marginTop: '0.5rem',
};

export const primaryButtonStyle: React.CSSProperties = {
  padding: '0.5rem 1.5rem',
  background: 'var(--iac-surface-elevated)',
  color: 'var(--iac-text)',
  border: 'none',
  borderRadius: '4px',
  cursor: 'pointer',
  fontWeight: 600,
};

export const secondaryButtonStyle: React.CSSProperties = {
  padding: '0.5rem 1.5rem',
  background: 'transparent',
  color: 'var(--iac-surface-elevated)',
  border: '1px solid var(--iac-surface-elevated)',
  borderRadius: '4px',
  cursor: 'pointer',
  fontWeight: 600,
};

export const dangerButtonStyle: React.CSSProperties = {
  padding: '0.5rem 1.5rem',
  background: 'transparent',
  color: 'var(--iac-error)',
  border: '1px solid var(--iac-error)',
  borderRadius: '4px',
  cursor: 'pointer',
  fontWeight: 600,
};

export const codeBlockStyle: React.CSSProperties = {
  display: 'block',
  padding: '0.5rem 0.75rem',
  background: 'var(--iac-code-bg)',
  color: 'var(--iac-code-text)',
  borderRadius: '4px',
  fontSize: '0.8rem',
  overflowX: 'auto',
  whiteSpace: 'pre-wrap',
  wordBreak: 'break-all',
};
