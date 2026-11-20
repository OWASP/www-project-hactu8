import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { hactu8Api } from '../services/hactu8Api';
import type { Hactu8Result } from '../services/hactu8Api';
import RunResult from '../components/results/RunResult';

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
        {!selected ? <div className="empty">No stored results yet.</div> : <RunResult result={selected} />}
      </div>
    </section>
  );
}
