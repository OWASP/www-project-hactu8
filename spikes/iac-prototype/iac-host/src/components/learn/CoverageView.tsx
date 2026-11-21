import { useEffect, useState } from 'react';
import { hactu8Api } from '../../services/hactu8Api';
import type { Coverage, CoverageStatus } from '../../services/hactu8Api';

const SIGNAL: Record<CoverageStatus, string> = { attack_and_defense: 'green', attack_only: 'yellow', no_lab: 'red' };

const LISTS: Record<string, string> = {
  owasp_llm_2026: 'LLM 2026', owasp_llm_2025: 'LLM 2025', owasp_asi_2026: 'Agentic', owasp_mcp_2025: 'MCP',
  atlas: 'ATLAS', nist: 'NIST',
};

export default function CoverageView({ onLab }: { onLab: (labId: string) => void }) {
  const [coverage, setCoverage] = useState<Coverage | null>(null);
  const [error, setError] = useState('');
  const [status, setStatus] = useState<CoverageStatus | ''>('');

  useEffect(() => {
    hactu8Api.coverage().then(setCoverage).catch((err: Error) => setError(err.message));
  }, []);

  if (error) return <div className="alert error">API unavailable: {error}</div>;
  if (!coverage) return <p className="muted">Loading the catalog...</p>;

  const rows = coverage.techniques.filter((t) => !status || t.status === status);

  return (
    <div className="panel coverage">
      <h2>Attack catalog</h2>
      <p className="muted">
        {coverage.total} known techniques across OWASP, MITRE ATLAS and NIST.{' '}
        {(Object.keys(coverage.statuses) as CoverageStatus[])
          .map((s) => `${coverage.counts[s]} ${coverage.statuses[s].toLowerCase()}`).join(', ')}.
      </p>
      <label className="coverage-filter">
        Status{' '}
        <select value={status} onChange={(e) => setStatus(e.target.value as CoverageStatus | '')}>
          <option value="">All</option>
          {(Object.keys(coverage.statuses) as CoverageStatus[]).map((s) => (
            <option key={s} value={s}>{coverage.statuses[s]} ({coverage.counts[s]})</option>
          ))}
        </select>
      </label>
      <table>
        <thead><tr><th>Technique</th><th>Status</th><th>Labs</th><th>Lists</th></tr></thead>
        <tbody>
          {rows.map((t) => (
            <tr key={t.id}>
              <td>
                {t.title}
                <small className="muted coverage-summary">{coverage.families[t.family]}: {t.summary}</small>
              </td>
              <td>
                <span className={`signal ${SIGNAL[t.status]}`}>{t.status_title}</span>
                {t.leaky_labs.length > 0 && (
                  <small className="muted coverage-summary">Latest run left impact: {t.leaky_labs.join(', ')}</small>
                )}
              </td>
              <td>
                {t.labs.length ? t.labs.map((lab) => (
                  <button key={lab} type="button" className="link-button" onClick={() => onLab(lab)}>
                    {lab.toUpperCase()}
                  </button>
                )) : <span className="muted">-</span>}
              </td>
              <td>
                {Object.entries(t.refs).map(([key, ids]) => (
                  <small key={key} className="coverage-ref">{LISTS[key] || key}: {ids.join(', ')}</small>
                ))}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
