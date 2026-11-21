import { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import CoverageView from '../components/learn/CoverageView';
import LessonView from '../components/learn/LessonView';
import { hactu8Api } from '../services/hactu8Api';
import type { LearningPath } from '../services/hactu8Api';

export default function Learn() {
  const [path, setPath] = useState<LearningPath | null>(null);
  const [error, setError] = useState('');
  const [params, setParams] = useSearchParams();

  useEffect(() => {
    hactu8Api.path().then(setPath).catch((err: Error) => setError(err.message));
  }, []);

  const steps = path?.stages.flatMap((stage) => stage.skills) || [];
  const showCatalog = params.get('view') === 'catalog';
  const selected = steps.find((s) => s.id === params.get('lab')) || steps.find((s) => s.has_lesson) || steps[0];

  return (
    <section className="page split-page">
      <nav className="run-list learn-path" aria-label="Learning path">
        <button type="button" className={showCatalog ? 'selected' : ''} onClick={() => setParams({ view: 'catalog' })}>
          Attack catalog
          <small>Every known technique and its coverage</small>
        </button>
        <h2>Learning path</h2>
        {error && <div className="alert error">API unavailable: {error}</div>}
        {path?.stages.map((stage) => (
          <div key={stage.id} className="learn-stage">
            <h3>{stage.title}</h3>
            <small className="muted">{stage.summary}</small>
            {stage.skills.length ? (
              <ol start={stage.skills[0].step}>
                {stage.skills.map((s) => (
                  <li key={s.id}>
                    <button type="button" className={!showCatalog && selected?.id === s.id ? 'selected' : ''}
                      onClick={() => setParams({ lab: s.id })}>
                      {s.owasp} {s.risk}
                      <small>{s.has_lesson ? 'Lesson ready' : 'No lesson yet'}</small>
                    </button>
                  </li>
                ))}
              </ol>
            ) : <p className="muted">No labs yet.</p>}
          </div>
        ))}
      </nav>
      <div className="result-detail">
        {showCatalog && <CoverageView onLab={(lab) => setParams({ lab })} />}
        {!showCatalog && selected && (
          <div className="page-heading">
            <div><h1>Step {selected.step}: {selected.owasp}</h1><p>{selected.risk}</p></div>
            <Link className="primary-link" to={`/run?lab=${encodeURIComponent(selected.id)}`}>Run this lab</Link>
          </div>
        )}
        {!showCatalog && selected && (selected.has_lesson ? <LessonView skillId={selected.id} />
          : <div className="panel empty-state"><h2>No lesson yet</h2>
            <p>This lab runs, but its lesson is still to be written. Run it to see the four acts.</p></div>)}
      </div>
    </section>
  );
}
