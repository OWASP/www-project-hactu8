// src/components/Skills/shared.tsx
// Shared presentational bits + styles reused across the Skills Explorer,
// Installed, and Creator pages (mirrors the styling used by Extensions.tsx).
import React from 'react';

export function Badge({ label, color, textColor }: { label: string; color: string; textColor: string }) {
  return (
    <span
      style={{
        display: 'inline-block',
        padding: '0.15rem 0.5rem',
        borderRadius: '4px',
        background: color,
        color: textColor,
        fontSize: '0.75rem',
        fontWeight: 600,
      }}
    >
      {label}
    </span>
  );
}

export function SignatureBadge({ verified }: { verified: boolean }) {
  return verified ? (
    <Badge label="✓ Curated & Signed" color="var(--iac-success-bg, #d1fae5)" textColor="var(--iac-success, #065f46)" />
  ) : (
    <Badge label="Unsigned Draft" color="var(--iac-warning-bg)" textColor="var(--iac-warning-text)" />
  );
}

export function StatusBadge({ status }: { status: string }) {
  const STATUS_COLORS: Record<string, string> = {
    installed: 'var(--iac-muted)',
    active: 'var(--iac-success)',
    error: 'var(--iac-error)',
  };
  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '0.3rem',
        fontSize: '0.75rem',
        fontWeight: 600,
        color: STATUS_COLORS[status] ?? 'var(--iac-muted)',
      }}
    >
      <span
        style={{
          width: 8,
          height: 8,
          borderRadius: '50%',
          background: STATUS_COLORS[status] ?? 'var(--iac-muted)',
          display: 'inline-block',
        }}
      />
      {status}
    </span>
  );
}

export function InfoField({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div style={{ fontSize: '0.75rem', color: 'var(--iac-muted)', marginBottom: '0.1rem' }}>{label}</div>
      <div style={{ fontSize: '0.9rem', color: 'var(--iac-text)', fontWeight: 500 }}>{value}</div>
    </div>
  );
}

export function TabButton({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <button onClick={onClick} style={{ ...tabButtonStyle, ...(active ? tabButtonActiveStyle : {}) }}>
      {label}
    </button>
  );
}

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

const tabButtonStyle: React.CSSProperties = {
  flex: 1,
  padding: '0.5rem',
  background: 'transparent',
  color: 'var(--iac-text-secondary)',
  border: '1px solid transparent',
  borderRadius: '4px',
  cursor: 'pointer',
  fontWeight: 400,
  fontSize: '0.85rem',
};

const tabButtonActiveStyle: React.CSSProperties = {
  background: 'var(--iac-surface-elevated)',
  color: 'var(--iac-text)',
  border: '1px solid var(--iac-border)',
  fontWeight: 600,
};
