import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { hactu8Api } from '../services/hactu8Api';
import type { Hactu8Result } from '../services/hactu8Api';

export default function Reports() {
  const [results, setResults] = useState<Hactu8Result[]>([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    hactu8Api.results().then((data) => setResults(data.results)).catch((err: Error) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

  return (
    <section className="page">
      <div className="page-heading"><div><h1>Reports</h1><p>Download one normalized result in human and machine-readable formats.</p></div></div>
      {error && <div className="alert error">{error}</div>}
      <div className="report-list">
        {results.map((result) => <article className="panel report-row" key={result.run_id}>
          <div><strong>{result.skill.owasp} {result.skill.risk}</strong><span>{result.run_id}</span></div>
          <div className="download-group">
            {['markdown', 'html', 'sarif'].map((format) =>
              <a key={format} href={hactu8Api.reportUrl(result.run_id, format)}>{format.toUpperCase()}</a>)}
          </div>
        </article>)}
        {loading && <div className="empty">Loading results...</div>}
        {!loading && !results.length && !error && <div className="empty">No results to report yet. <Link to="/run">Run a lab</Link> first.</div>}
      </div>
    </section>
  );
}
