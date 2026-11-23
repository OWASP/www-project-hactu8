import { useEffect, useMemo, useState } from 'react';
import { hactu8Api } from '../services/hactu8Api';
import type { Hactu8Result, ModelsInfo, Skill } from '../services/hactu8Api';
import RunResult from '../components/results/RunResult';
import LessonView from '../components/learn/LessonView';

const LIVE = 'lamb-live';
const TIERS: { id: string; label: string; backends: string[]; note: string }[] = [
  { id: 'offline', label: 'Offline', backends: ['echo'], note: 'Deterministic stand-in model. No network, no key.' },
  { id: 'local', label: 'Local', backends: ['ollama', 'llamacpp', 'openai-compat', 'strata', 'basalt'],
    note: 'Runs on this machine. Lab text never leaves it.' },
  { id: 'aggregator', label: 'Aggregator', backends: ['openrouter'],
    note: 'Lab text, including payloads, leaves this machine. Paid; confirm spend first.' },
  { id: 'provider', label: 'Provider', backends: ['anthropic', 'openai'],
    note: 'Lab text, including payloads, leaves this machine. Paid; confirm spend first.' },
];

export default function Run() {
  const [skills, setSkills] = useState<Skill[]>([]);
  const [models, setModels] = useState<ModelsInfo | null>(null);
  const [labId, setLabId] = useState(LIVE);
  const [tier, setTier] = useState('offline');
  const [backend, setBackend] = useState('echo');
  const [model, setModel] = useState('');
  const [confirmSpend, setConfirmSpend] = useState(false);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<Hactu8Result | null>(null);
  const [error, setError] = useState('');
  const [view, setView] = useState<'learn' | 'result'>('learn');

  useEffect(() => {
    const wanted = new URLSearchParams(window.location.search).get('lab');
    if (wanted) setLabId(wanted);
    Promise.all([hactu8Api.skills(), hactu8Api.models()])
      .then(([skillData, modelData]) => { setSkills(skillData.skills); setModels(modelData); })
      .catch((err: Error) => setError(err.message));
  }, []);

  const tierInfo = TIERS.find((t) => t.id === tier) || TIERS[0];
  const cloud = models?.cloud.includes(backend) ?? false;
  const catalog = models?.catalogs[backend] || [];
  const availability = useMemo(() => (models?.candidates || []).filter((c) => tierInfo.backends.includes(c.backend)),
    [models, tierInfo]);

  // Why a backend cannot be picked: hardware this host lacks, or a missing key.
  // Such backends stay listed, greyed out, with the reason as the tooltip.
  function blockedReason(name: string): string {
    const hw = models?.hardware?.[name];
    if (hw && !hw.ok) return hw.reason;
    if (models && models.keys_set[name] === false) return 'API key not set';
    return '';
  }

  function optionLabel(name: string): string {
    const hw = models?.hardware?.[name];
    if (hw && !hw.ok) return `${name} (needs ${hw.needs || 'other hardware'})`;
    return models && models.keys_set[name] === false ? `${name} (no key)` : name;
  }

  function chooseTier(id: string) {
    const next = TIERS.find((t) => t.id === id) || TIERS[0];
    setTier(id);
    setBackend(next.backends.find((name) => !blockedReason(name)) || next.backends[0]);
    setModel('');
    setConfirmSpend(false);
  }

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setRunning(true);
    setError('');
    setResult(null);
    try {
      const body = { backend, model, confirm_spend: confirmSpend };
      const doc = labId === LIVE ? await hactu8Api.live(body)
        : await hactu8Api.run({ ...body, skill_id: labId, target_id: 'hactu8-lamb', classifier: 'keyword' });
      setResult(doc);
      setView('result');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Run failed');
    } finally {
      setRunning(false);
    }
  }

  const selectedSkill = skills.find((skill) => skill.id === labId);
  const hasLesson = Boolean(selectedSkill?.has_lesson);
  return (
    <section className="page">
      <div className="page-heading">
        <div><h1>Run</h1><p>Baseline, attack, impact, defense. Same items, same model.</p></div>
      </div>
      <div className="run-layout">
        <form className="panel run-form setup" onSubmit={submit}>
          <label>Lab
            <select id="lab" value={labId} onChange={(e) => setLabId(e.target.value)}>
              <option value={LIVE}>Lamb's MCP surfaces, live (gateway off vs on)</option>
              {skills.map((skill) => <option key={skill.id} value={skill.id}>{skill.owasp} {skill.risk}</option>)}
            </select>
          </label>
          {labId === LIVE ? <div className="skill-description"><strong>Poisoned MCP server</strong>
            <p>Every surface of Lamb's KB-Tools server and its clean control, shown to the model with no defense,
              then through the ProtectoGW gateway. Graded only by the per-run canary.</p></div>
            : selectedSkill && <div className="skill-description"><strong>{selectedSkill.owasp}: {selectedSkill.risk}</strong>
              <p>{selectedSkill.description}</p></div>}

          <div className="field">
            <span>Model tier</span>
            <div className="segmented" role="group" aria-label="Model tier">
              {TIERS.map((t) => <button type="button" key={t.id} aria-pressed={tier === t.id}
                onClick={() => chooseTier(t.id)}>{t.label}</button>)}
            </div>
            <small className="muted">{tierInfo.note}</small>
            {tierInfo.backends.filter((name) => models?.hardware?.[name]?.ok === false).map((name) =>
              <small key={name} className="muted">{name} unavailable: {models?.hardware?.[name]?.reason}.</small>)}
          </div>

          <div className="form-grid">
            <label>Backend
              <select id="backend" value={backend} onChange={(e) => { setBackend(e.target.value); setModel(''); }}>
                {tierInfo.backends.map((name) => <option key={name} value={name}
                  disabled={Boolean(blockedReason(name))} title={blockedReason(name) || undefined}>
                  {optionLabel(name)}</option>)}
              </select>
            </label>
            <label>Model
              {catalog.length ? (
                <select id="model" value={model} onChange={(e) => setModel(e.target.value)}>
                  <option value="">{models?.default_models[backend] || 'default'} (default)</option>
                  {catalog.map((name) => <option key={name} value={name}>{name}</option>)}
                </select>
              ) : (
                <input id="model" value={model} disabled={backend === 'echo'}
                  placeholder={backend === 'echo' ? 'none' : models?.default_models[backend] || 'model name'}
                  onChange={(e) => setModel(e.target.value)} />
              )}
            </label>
          </div>

          {availability.length > 0 && <ul className="availability">
            {availability.map((c) => <li key={`${c.backend}-${c.model}`}>
              <span className={`dot ${c.available ? 'ok' : 'off'}`} />{c.backend}: {c.available ? 'ready' : c.reason}</li>)}
          </ul>}

          {cloud && <label className="checkbox"><input id="confirm-spend" type="checkbox" checked={confirmSpend}
            onChange={(e) => setConfirmSpend(e.target.checked)} />
            I accept that this run sends lab text to {backend} and is billed to my key.</label>}

          {error && <div className="alert error">{error}</div>}
          <button className="primary-button" disabled={running || (cloud && !confirmSpend)}>
            {running ? 'Running...' : 'Run attack, then defense'}
          </button>
        </form>

        <div className="run-output">
          {hasLesson && <div className="segmented run-tabs" role="tablist" aria-label="Lab view">
            <button type="button" role="tab" aria-selected={view === 'learn'} aria-pressed={view === 'learn'}
              onClick={() => setView('learn')}>Learn</button>
            <button type="button" role="tab" aria-selected={view === 'result'} aria-pressed={view === 'result'}
              onClick={() => setView('result')}>Result</button>
          </div>}
          {hasLesson && view === 'learn' ? <LessonView skillId={labId} />
            : result ? <RunResult result={result} />
            : <div className="panel empty-state">
              <h2>No run yet</h2>
              <p>Pick a lab and a model, then run it. The result shows what the model leaked with no defense,
                and what changed once the defense was on.</p>
            </div>}
        </div>
      </div>
    </section>
  );
}
