import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { hactu8Api } from '../services/hactu8Api';

export default function Dashboard() {
  const [counts, setCounts] = useState({ skills: 0, results: 0, targets: 0 });
  const [error, setError] = useState('');

  useEffect(() => {
    Promise.all([hactu8Api.skills(), hactu8Api.results(), hactu8Api.targets()])
      .then(([skills, results, targets]) =>
        setCounts({ skills: skills.total, results: results.total, targets: targets.total }))
      .catch((err: Error) => setError(err.message));
  }, []);

  return (
    <section className="page">
      <div className="page-heading">
        <div><h1>Assurance dashboard</h1><p>Baseline, attack, impact, and remediation against the same suite.</p></div>
        <Link className="primary-link" to="/run">Run an assurance test</Link>
      </div>
      {error && <div className="alert error">API unavailable: {error}</div>}
      <div className="metric-grid">
        <article className="metric"><span>Skills</span><strong>{counts.skills}</strong><small>LLM, agentic, and gateway tests</small></article>
        <article className="metric"><span>Targets</span><strong>{counts.targets}</strong><small>HACTU8 Lamb is the MVP target</small></article>
        <article className="metric"><span>Stored results</span><strong>{counts.results}</strong><small>Result JSON ready for reports</small></article>
      </div>
      <article className="panel">
        <h2>M4 vertical slice</h2>
        <ol>
          <li>Select HACTU8 Lamb and an assurance skill.</li>
          <li>Run the deterministic four-act lifecycle.</li>
          <li>Inspect evidence and verdicts in Results.</li>
          <li>Download Markdown, HTML, or SARIF from Reports.</li>
        </ol>
      </article>
    </section>
  );
}
