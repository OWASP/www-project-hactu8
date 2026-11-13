import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { hactu8Api } from '../services/hactu8Api';
import type { Hactu8Result } from '../services/hactu8Api';

export default function Results() {
  const [results, setResults] = useState<Hactu8Result[]>([]);
  const [selected, setSelected] = useState<Hactu8Result | null>(null);
  const [error, setError] = useState('');
  const [params, setParams] = useSearchParams();

  useEffect(() => {
    hactu8Api.results()
      .then((data) => {
        setResults(data.results);
        const wanted = params.get('run');
        setSelected(data.results.find((result) => result.run_id === wanted) || data.results[0] || null);
      })
      .catch((err: Error) => setError(err.message));
  }, []);

  function choose(result: Hactu8Result) {
    setSelected(result);
    setParams({ run: result.run_id });
  }
  return (
    <section className="page split-page">
      <aside className="run-list">
        <h2>Results</h2>
        {results.map((result) => (
          <button key={result.run_id} className={selected?.run_id === result.run_id ? 'selected' : ''} onClick={() => choose(result)}>
            <strong>{result.skill.owasp}</strong><span>{result.skill.risk}</span><small>{new Date(result.started_at).toLocaleString()}</small>
          </button>
        ))}
      </aside>
      <div className="result-detail">
        {error && <div className="alert error">{error}</div>}
        {!selected ? <div className="empty">No stored results yet.</div> : <ResultDetail result={selected} />}
      </div>
    </section>
  );
}

function ResultDetail({ result }: { result: Hactu8Result }) {
  return (
    <>
      <div className="page-heading">
        <div><h1>{result.skill.owasp} {result.skill.risk}</h1><p><code>{result.run_id}</code></p></div>
        <span className={`verdict ${result.summary.status}`}>{result.summary.status.toUpperCase()}</span>
      </div>
      <div className="metric-grid compact">
        <article className="metric"><span>Baseline</span><strong>{rate(result.summary.baseline_rate)}</strong></article>
        <article className="metric"><span>Impact</span><strong>{rate(result.summary.impact_rate)}</strong></article>
        <article className="metric"><span>Remediated</span><strong>{rate(result.summary.remediated_rate)}</strong></article>
      </div>
      {result.acts.map((act) => (
        <article className="panel act-card" key={`${act.act}-${act.phase}`}>
          <div><h2>Act {act.act}: {act.title}</h2><span>{act.metric.targeted.rate}% targeted RED</span></div>
          <table><thead><tr><th>Verdict</th><th>Prompt</th><th>Evidence</th></tr></thead>
            <tbody>{act.items.map((item) => <tr key={item.id}>
              <td><span className={`signal ${item.verdict.toLowerCase()}`}>{item.verdict}</span></td>
              <td>{item.prompt}</td><td>{item.evidence || item.reason || 'No evidence'}</td>
            </tr>)}</tbody>
          </table>
        </article>
      ))}
    </>
  );
}

function rate(value: number | null) {
  return value == null ? '-' : `${value}%`;
}
