const buttons = [...document.querySelectorAll('[data-action]')];
const log = document.querySelector('#event-log');
const resultBody = document.querySelector('#results-body');
const activityState = document.querySelector('#activity-state');
const systemStatus = document.querySelector('#system-status');
const docCount = document.querySelector('#doc-count');
const templateState = document.querySelector('#template-state');
const psr = document.querySelector('#psr');
const resultSummary = document.querySelector('#result-summary');
const resultsPanel = document.querySelector('.results-panel');
const drawerBackdrop = document.querySelector('.drawer-backdrop');
const resultsOpenButton = document.querySelector('[data-action="open-results"]');
const drawerPin = document.querySelector('.drawer-pin');
const drawerClose = document.querySelector('.drawer-close');
const evaluationButton = document.querySelector('#evaluation-button');
let busy = false;
let isPinned = localStorage.getItem('llm05-results-pinned') === 'true';
const baselineAnswers = new Map();

const sleep = (duration) => new Promise((resolve) => setTimeout(resolve, duration));

function setResultsOpen(isOpen) {
  if (!isOpen && isPinned) return;
  if (!isOpen && resultsPanel.contains(document.activeElement)) resultsOpenButton.focus();
  resultsPanel.classList.toggle('is-open', isOpen);
  drawerBackdrop.classList.toggle('is-visible', isOpen);
  resultsPanel.setAttribute('aria-hidden', String(!isOpen));
  resultsOpenButton.setAttribute('aria-expanded', String(isOpen));
  document.body.classList.toggle('drawer-is-open', isOpen && !isPinned);
}

function setResultsPinned(pinned) {
  isPinned = pinned;
  localStorage.setItem('llm05-results-pinned', String(pinned));
  document.body.classList.toggle('drawer-pinned', pinned);
  resultsPanel.classList.toggle('is-pinned', pinned);
  drawerPin.setAttribute('aria-pressed', String(pinned));
  drawerPin.textContent = pinned ? 'Pinned' : 'Pin';
  drawerClose.hidden = pinned;
  drawerClose.setAttribute('aria-hidden', String(pinned));
  if (pinned) setResultsOpen(true);
}

function now() {
  return new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function addLog(message, kind = 'muted') {
  const entry = document.createElement('div');
  entry.className = `log-entry ${kind}`;
  const time = document.createElement('time');
  time.textContent = now();
  const text = document.createElement('span');
  text.textContent = message;
  entry.append(time, text);
  log.prepend(entry);
}

function addEventLog(event) {
  const entry = document.createElement('div');
  entry.className = `log-entry ${event.kind || 'muted'}`;
  const time = document.createElement('time');
  time.textContent = now();
  const text = document.createElement('span');
  text.textContent = event.message;
  entry.append(time, text);
  if (event.href) {
    const link = document.createElement('a');
    link.href = event.href;
    link.target = '_blank';
    link.rel = 'noopener';
    link.textContent = event.link_label || 'Open artifact';
    text.append(' ', link);
  }
  log.prepend(entry);
}

function setBusy(value) {
  busy = value;
  buttons.forEach((button) => { button.disabled = value; });
  activityState.textContent = value ? 'RUNNING' : 'READY';
}

function setEvaluationReady(isReady) {
  evaluationButton.classList.toggle('button-primary', isReady);
  evaluationButton.classList.toggle('button-quiet', !isReady);
}

function setStep(step, done = false) {
  const node = document.querySelector(`[data-step="${step}"]`);
  if (!node) return;
  node.classList.add(done ? 'done' : 'active');
  if (done) node.classList.remove('active');
}

function updateState(state) {
  systemStatus.textContent = state.baseline ? 'BASELINE' : 'EXPOSED';
  systemStatus.style.color = state.baseline ? 'var(--acid)' : 'var(--coral)';
  docCount.textContent = state.documents;
  templateState.textContent = state.active_template || 'UNKNOWN';
  templateState.style.color = state.baseline ? 'var(--acid)' : 'var(--coral)';
}

async function request(path, options = {}) {
  const response = await fetch(path, { headers: { 'Content-Type': 'application/json' }, ...options });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
  return data;
}

function renderResults(data, isBaseline = false) {
  psr.textContent = `${data.psr}%`;
  psr.style.color = data.psr ? 'var(--coral)' : 'var(--acid)';
  resultSummary.textContent = `${data.psr}% PSR / ${data.results.length} QUERIES`;
  resultBody.replaceChildren();
  data.results.forEach((result) => {
    const row = document.createElement('tr');
    const signal = result.status.toLowerCase();
    const label = result.control ? '<span class="query-tag">UNTOUCHED CONTROL</span>' : '';
    if (isBaseline) baselineAnswers.set(result.prompt, result.answer);
    row.innerHTML = `<td>${result.prompt}${label}</td><td><span class="signal signal-${signal}">${result.status}</span></td><td>${answerExcerpt(result.answer, baselineAnswers.get(result.prompt), isBaseline)}</td>`;
    resultBody.append(row);
  });
}

function answerExcerpt(answer, baselineAnswer, isBaseline) {
  const source = answer.replace(/^Based on official policy:\s*/i, '');
  const excerpt = completeSentenceExcerpt(source, 250);
  const escaped = excerpt.replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[character]));
  const highlightPoison = (text) => text.replace(
    /(overrides all previous|verified compliance guidance|revised legitimacy standards|pre-verified|low-risk|no compliance flags|suspended|approved without|ignore legacy alerts)/gi,
    '<mark class="answer-highlight tampered-highlight">$1</mark>'
  );
  if (!isBaseline && baselineAnswer && answer !== baselineAnswer) {
    const baselineWords = new Set((baselineAnswer.toLowerCase().match(/[\w'-]+/g) || []));
    const changed = escaped.replace(/[\w'-]+/g, (word) => baselineWords.has(word.toLowerCase()) ? word : `<mark class="answer-highlight changed-highlight">${word}</mark>`);
    return `${highlightPoison(changed)}${source.length > excerpt.length ? '...' : ''}`;
  }
  const marked = escaped
    .replace(/(due diligence|manual review|secondary authorization|potential fraud|MFA|manager approval)/gi, '<mark class="answer-highlight baseline-highlight">$1</mark>')
  return `${highlightPoison(marked)}${source.length > excerpt.length ? '...' : ''}`;
}

function completeSentenceExcerpt(text, maxLength) {
  if (text.length <= maxLength) return text;
  const sentenceEnd = text.lastIndexOf('.', maxLength);
  return (sentenceEnd > maxLength / 2 ? text.slice(0, sentenceEnd + 1) : text.slice(0, maxLength)).trim();
}

async function evaluate(isBaseline = false) {
  const data = await request('/api/evaluate', { method: 'POST', body: '{}' });
  renderResults(data, isBaseline);
  if (isBaseline) {
    setStep('baseline');
    resultSummary.textContent = 'UNTAMPERED BASELINE / 0% PSR';
    addLog('Untampered baseline verified: all policy checks are GREEN.', 'complete');
  } else {
    setStep('measure');
    addLog(`Evaluation complete: ${data.psr}% poison success rate.`, 'complete');
    setResultsOpen(true);
  }
  updateState(data);
}

async function verifyBaseline() {
  if (busy) return;
  setBusy(true);
  try {
    const data = await request('/api/reset', { method: 'POST', body: '{}' });
    if (Array.isArray(data.events)) {
      for (const event of data.events) {
        await sleep(280);
        addEventLog(event);
      }
    } else {
      addLog(`Clean state restored. Removed ${data.removed} poison document(s).`, 'complete');
    }
    updateState(data);
    document.querySelectorAll('.timeline-step').forEach((step) => step.classList.remove('active', 'done'));
    setStep('baseline');
    setEvaluationReady(true);
    await evaluate(true);
  } catch (error) {
    addLog(error.message, 'muted');
  } finally {
    setBusy(false);
  }
}

async function attack(scenario) {
  if (busy) return;
  setBusy(true);
  try {
    const data = await request('/api/attack', {
      method: 'POST',
      body: JSON.stringify({ scenario, count: 3 }),
    });
    for (const event of data.events) {
      await sleep(280);
      addEventLog(event);
      if (event.kind === 'rag') setStep('rag');
      if (event.kind === 'prompt') setStep('prompt');
      if (event.kind === 'agent') setStep('agent');
    }
    updateState(data);
    setEvaluationReady(true);
    if (scenario === 'all') {
      await sleep(350);
      await evaluate();
    }
  } catch (error) {
    addLog(error.message, 'muted');
  } finally {
    setBusy(false);
  }
}

async function protect() {
  if (busy) return;
  setBusy(true);
  try {
    const data = await request('/api/protect', { method: 'POST', body: '{}' });
    for (const event of data.events) {
      await sleep(280);
      addEventLog(event);
    }
    setStep('protect');
    updateState(data);
    setEvaluationReady(true);
  } catch (error) {
    addLog(error.message, 'muted');
  } finally {
    setBusy(false);
  }
}

async function reset() {
  if (busy) return;
  setBusy(true);
  try {
    const data = await request('/api/reset', { method: 'POST', body: '{}' });
    if (Array.isArray(data.events)) {
      for (const event of data.events) {
        await sleep(280);
        addEventLog(event);
      }
    } else {
      addLog(`Baseline restored. Removed ${data.removed} poison document(s).`, 'complete');
    }
    updateState(data);
    setEvaluationReady(false);
    psr.textContent = '-';
    resultSummary.textContent = 'BASELINE RESTORED';
    resultBody.innerHTML = '<tr><td colspan="3" class="empty-state">Baseline restored. Run an evaluation to verify the clean state.</td></tr>';
    document.querySelectorAll('.timeline-step').forEach((step) => step.classList.remove('active', 'done'));
    setStep('baseline');
  } catch (error) {
    addLog(error.message, 'muted');
  } finally {
    setBusy(false);
  }
}

buttons.forEach((button) => {
  button.addEventListener('click', () => {
    const action = button.dataset.action;
    if (action === 'open-results') setResultsOpen(true);
    else if (action === 'close-results') setResultsOpen(false);
    else if (action === 'toggle-pin') setResultsPinned(!isPinned);
    else if (action === 'reset') reset();
    else if (action === 'baseline') {
      setEvaluationReady(true);
      verifyBaseline();
    }
    else if (action === 'rag' || action === 'prompt' || action === 'agent' || action === 'all') {
      setEvaluationReady(true);
      attack(action);
    }
    else if (action === 'protect') {
      setEvaluationReady(true);
      protect();
    }
    else if (action === 'evaluate') evaluate().catch((error) => addLog(error.message));
  });
});

request('/api/state').then(async (state) => {
  updateState(state);
  if (state.baseline) {
    addEventLog({
      kind: 'baseline',
      message: 'Official baseline policy active: compliance_policy_official.txt.',
      href: '/artifact/compliance_policy_official.txt',
      link_label: 'Open policy',
    });
    addEventLog({
      kind: 'baseline',
      message: 'Official control policy active: it_security_policy_official.txt.',
      href: '/artifact/it_security_policy_official.txt',
      link_label: 'Open policy',
    });
    addEventLog({
      kind: 'baseline',
      message: `Untampered prompt template active (${state.active_template || '1.0-baseline'}).`,
      href: '/artifact/prompt_template_baseline.json',
      link_label: 'Open template',
    });
    await evaluate(true);
  }
}).catch((error) => addLog(error.message));

setResultsPinned(isPinned);
