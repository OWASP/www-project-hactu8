import type { Hactu8Result, ResultItem } from '../../services/hactu8Api';
import { hactu8Api } from '../../services/hactu8Api';

const ON_SIGNAL: Record<string, string> = { SAFE: 'green', DEFENDED: 'green', BREACH: 'red', FALSE_BLOCK: 'yellow' };

export default function RunResult({ result }: { result: Hactu8Result }) {
  const live = result.live;
  const remediation = result.acts.find((act) => act.phase === 'remediation');
  // Leaks are measured in the impact act: labs plant the attack in Act 2 and measure it in Act 3.
  const leaks = result.acts.filter((act) => act.phase === 'impact').flatMap((act) => act.items)
    .filter((item) => item.verdict === 'RED');
  const protections = remediation?.items.length ? remediationNotes(result) : [];
  return (
    <div className="run-result">
      <div className="page-heading">
        <div>
          <h1>{result.skill.owasp} {result.skill.risk}</h1>
          <p><code>{result.run_id}</code> · {result.model.backend}{result.model.model ? `:${result.model.model}` : ''}</p>
        </div>
        <span className={`verdict ${result.summary.status}`}>{result.summary.status.toUpperCase()}</span>
      </div>

      <div className="metric-grid score-grid">
        <article className="metric">
          <span>Model resistance</span>
          <strong>{live ? pct(live.model_resistance) : rate(100 - (result.summary.impact_rate ?? 0))}</strong>
          <small>{live ? `${live.attacks - live.breaches_off} of ${live.attacks} attacks held by the model alone`
            : 'Attack items the model did not fall for, defense off'}</small>
        </article>
        <article className="metric">
          <span>App exposure</span>
          <div className="offon">
            <span className={`signal ${exposedOff(result) ? 'red' : 'green'}`}>{exposedOff(result) ? 'EXPOSED' : 'NOT EXPOSED'}</span>
            <span className="offon-arrow">defense on</span>
            <span className={`signal ${exposedOn(result) ? 'red' : 'green'}`}>{exposedOn(result) ? 'EXPOSED' : 'CONTAINED'}</span>
          </div>
          <small>{live ? `${plural(live.breaches_off, 'breach', 'breaches')} with the gateway off, ${live.breaches_on} with it on. ${plural(live.false_blocks_on, 'safe item', 'safe items')} blocked.`
            : `Impact ${rate(result.summary.impact_rate)} with no defense, ${rate(result.summary.remediated_rate)} after remediation.`}</small>
        </article>
      </div>

      <article className="panel timeline">
        {result.acts.map((act) => (
          <div className="timeline-row" key={`${act.act}-${act.phase}`}>
            <div className="timeline-label">Act {act.act}<small>{act.title}</small></div>
            <div className="timeline-items">
              {act.items.slice(0, 8).map((item) => (
                <div key={`${act.act}-${item.id}`}><span className={`sev ${item.verdict.toLowerCase()}`} />{label(item)}</div>
              ))}
              {act.items.length > 8 && <div className="muted">and {act.items.length - 8} more</div>}
            </div>
            <div className="timeline-rate">{act.metric.targeted.rate}% targeted</div>
          </div>
        ))}
      </article>

      {live && remediation && (
        <article className="panel">
          <h2>Each surface, defense off and on</h2>
          <table><thead><tr><th>Surface</th><th>Kind</th><th>Off</th><th>On</th></tr></thead>
            <tbody>{remediation.items.map((item) => <tr key={item.id}>
              <td><code>{item.id}</code></td><td>{item.targeted ? 'attack' : 'control'}</td>
              <td><span className={`signal ${item.outcome_off === 'BREACH' ? 'red' : 'green'}`}>{item.outcome_off}</span></td>
              <td><span className={`signal ${ON_SIGNAL[item.outcome_on || 'SAFE']}`}>{item.outcome_on}</span></td>
            </tr>)}</tbody>
          </table>
        </article>
      )}

      <div className="split-panels">
        <article className="panel">
          <h2>What leaked with no defense</h2>
          {leaks.length === 0 ? <p>Nothing. Every attack item stayed GREEN in the impact act.</p>
            : leaks.slice(0, 4).map((item) => (
              <div key={item.id} className="evidence-block">
                <strong>{label(item)}</strong>
                <pre className="evidence">{item.evidence || item.reason || 'No evidence recorded'}</pre>
              </div>))}
        </article>
        <article className="panel wolf-panel">
          <h2>Defense added in Act 4</h2>
          <ul>{protections.map((note) => <li key={note}>{note}</li>)}</ul>
          <div className="report-links">
            {['markdown', 'html', 'sarif'].map((fmt) => (
              <a key={fmt} href={hactu8Api.reportUrl(result.run_id, fmt)}>{fmt.toUpperCase()} report</a>))}
          </div>
        </article>
      </div>
    </div>
  );
}

function remediationNotes(result: Hactu8Result): string[] {
  if (result.live) {
    return [
      'ProtectoGW screens every tool description, schema, result, resource and prompt at /protected/mcp.',
      'Tool definitions are pinned at first sight; a changed definition is dropped and its calls refused.',
      'Model output is screened for the per-run canary before it reaches the user.',
    ];
  }
  const act = result.acts.find((a) => a.phase === 'remediation');
  return act?.notes?.length ? act.notes : ['The lab switches to its hardened mode and reruns the same items.'];
}

function exposedOff(result: Hactu8Result) {
  return result.live ? result.live.breaches_off > 0 : (result.summary.impact_rate ?? 0) > 0;
}

function exposedOn(result: Hactu8Result) {
  return result.live ? result.live.breaches_on > 0 : (result.summary.remediated_rate ?? 0) > 0;
}

function label(item: ResultItem) {
  return item.surface ? `${item.surface}: ${item.id}` : item.prompt;
}

function plural(n: number, one: string, many: string) {
  return `${n} ${n === 1 ? one : many}`;
}

function pct(value: number | null) {
  return value == null ? '-' : `${Math.round(value * 100)}%`;
}

function rate(value: number | null) {
  return value == null ? '-' : `${Math.round(value)}%`;
}
