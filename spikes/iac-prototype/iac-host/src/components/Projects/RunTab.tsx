import React, { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';

import type {
  CannedProjectDetail,
  ModelConfigSnapshot,
  ProjectRunState,
  ProjectRunStreamEvent,
  ProjectRunTurn,
  TargetSnapshot,
} from '../../types/project';
import type { InstalledSkillPackage } from '../../types/skillPackage';
import type { TestRunResult, TestCaseResult } from '../../types/extensions';
import { listAllSkills } from '../../services/skillPackageService';
import { createProjectRun, getProjectRun, streamMessage } from '../../services/projectRunService';
import resultsService from '../../services/resultsService';
import { StreamEventLog, isToolResultOk, toolResultData } from '../shared/StreamEventLog';
import type { StreamLogBlock } from '../shared/StreamEventLog';

function buildTurnBlocks(turns: ProjectRunTurn[]): StreamLogBlock[] {
  return turns.map((turn, i) =>
    turn.role === 'user'
      ? {
          kind: 'custom' as const,
          key: `turn-${i}`,
          render: (
            <div
              style={{
                background: 'var(--iac-surface)',
                border: '1px solid var(--iac-border)',
                borderRadius: 8,
                padding: '8px 14px',
                marginBottom: 8,
                fontSize: 13,
                color: 'var(--iac-text)',
              }}
            >
              <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--iac-muted)', marginBottom: 2 }}>YOU</div>
              {turn.content}
            </div>
          ),
        }
      : { kind: 'prose' as const, content: turn.content }
  );
}

function buildLiveBlocks(events: ProjectRunStreamEvent[]): StreamLogBlock[] {
  const blocks: StreamLogBlock[] = [];
  for (const event of events) {
    if (event.type === 'text') {
      const last = blocks[blocks.length - 1];
      if (last?.kind === 'prose') {
        last.content += event.content;
      } else {
        blocks.push({ kind: 'prose', content: event.content });
      }
    } else if (event.type === 'tool_call') {
      blocks.push({ kind: 'tool_call', name: event.name, input: event.input });
    } else if (event.type === 'tool_result') {
      blocks.push({
        kind: 'tool_result',
        name: event.name,
        ok: isToolResultOk(event.result),
        data: toolResultData(event.result),
      });
    } else if (event.type === 'error') {
      blocks.push({ kind: 'error', message: event.message });
    }
    // 'complete' carries no visual block of its own — its content is the
    // same text already streamed via 'text' events.
  }
  return blocks;
}

function buildTestRunResult(project: CannedProjectDetail, state: ProjectRunState): TestRunResult {
  const results: TestCaseResult[] = state.findings.map((f, i) => ({
    id: `${f.tool}-${i}`,
    name: f.skill ? `${f.skill} (${f.tool})` : f.tool,
    status: 'pass',
    message: typeof f.data === 'string' ? f.data.slice(0, 500) : JSON.stringify(f.data ?? null).slice(0, 500),
  }));

  return {
    runId: `${state.run_id}-save-${Date.now()}`,
    extensionId: project.id,
    extensionName: project.name,
    timestamp: state.updated_at,
    target: state.scope.target.target_url || state.scope.target.name,
    summary: {
      total: results.length,
      passed: results.length,
      failed: 0,
      errors: 0,
      skipped: 0,
      duration: Math.max(0, new Date(state.updated_at).getTime() - new Date(state.created_at).getTime()),
    },
    results,
  };
}

const RunTab: React.FC<{
  project: CannedProjectDetail;
  target: TargetSnapshot | null;
  model: ModelConfigSnapshot | null;
  runId?: string;
  selectedSkillNames: string[];
  onSelectedSkillNamesChange: (names: string[]) => void;
  onRunCreated: (runId: string) => void;
}> = ({ project, target, model, runId, selectedSkillNames, onSelectedSkillNamesChange, onRunCreated }) => {
  const [availableSkills, setAvailableSkills] = useState<InstalledSkillPackage[]>([]);
  const [skillsLoaded, setSkillsLoaded] = useState(false);
  const [runState, setRunState] = useState<ProjectRunState | null>(null);
  const [liveEvents, setLiveEvents] = useState<ProjectRunStreamEvent[]>([]);
  const [inputText, setInputText] = useState('');
  const [isSending, setIsSending] = useState(false);
  const [isCreating, setIsCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [savedMessage, setSavedMessage] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    listAllSkills()
      .then((skills) => {
        if (cancelled) return;
        setAvailableSkills(skills);
        // Pre-check the project's suggested defaults on first load only.
        if (selectedSkillNames.length === 0) {
          const defaults = project.default_skill_names.filter((n) => skills.some((s) => s.name === n));
          if (defaults.length > 0) onSelectedSkillNamesChange(defaults);
        }
      })
      .catch((err) => setError(err instanceof Error ? err.message : String(err)))
      .finally(() => setSkillsLoaded(true));
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!runId) {
      setRunState(null);
      return;
    }
    let cancelled = false;
    getProjectRun(runId)
      .then((state) => {
        if (!cancelled) setRunState(state);
      })
      .catch((err) => setError(err instanceof Error ? err.message : String(err)));
    return () => {
      cancelled = true;
    };
  }, [runId]);

  const hostSkills = useMemo(() => availableSkills.filter((s) => s.source === 'host'), [availableSkills]);
  const userSkills = useMemo(() => availableSkills.filter((s) => s.source === 'upload'), [availableSkills]);

  const toggleSkill = (name: string) => {
    onSelectedSkillNamesChange(
      selectedSkillNames.includes(name)
        ? selectedSkillNames.filter((n) => n !== name)
        : [...selectedSkillNames, name]
    );
  };

  const handleStartRun = async () => {
    if (!target || !model || selectedSkillNames.length === 0) return;
    setIsCreating(true);
    setError(null);
    try {
      const response = await createProjectRun(project.id, {
        target,
        model,
        skill_names: selectedSkillNames,
      });
      onRunCreated(response.run_id);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setIsCreating(false);
    }
  };

  const handleSend = () => {
    if (!runId || !inputText.trim() || isSending) return;
    const content = inputText.trim();
    setInputText('');
    setIsSending(true);
    setError(null);
    setLiveEvents([]);

    // Track how the turn ended: on 'complete' the exchange is now part of
    // runState.turns (fetched below), so the live blocks are redundant and
    // get cleared. On 'error' no turn was appended server-side — the error
    // block in liveEvents is the only record of what happened, so it must
    // stay visible instead of being wiped.
    let endedInError = false;

    streamMessage(
      runId,
      content,
      (event) => {
        if (event.type === 'error') endedInError = true;
        setLiveEvents((prev) => [...prev, event]);
      },
      () => {
        setIsSending(false);
        if (!endedInError) setLiveEvents([]);
        getProjectRun(runId)
          .then(setRunState)
          .catch((err) => setError(err instanceof Error ? err.message : String(err)));
      },
      (err) => {
        setIsSending(false);
        setError(err.message);
      }
    );
  };

  const handleFinishRun = () => {
    if (!runState) return;
    const result = buildTestRunResult(project, runState);
    resultsService.addResult(result);
    setSavedMessage(`Saved to Assurance Results as run "${result.runId}".`);
  };

  // -------------------------------------------------------------------- //
  // Pre-run: skill selection + Start Run
  // -------------------------------------------------------------------- //

  if (!runId) {
    return (
      <div>
        <p style={{ color: 'var(--iac-text-secondary)', marginTop: 0 }}>
          Pick the skills this Run should have access to, then start it. The model can only see and
          run skills you select here.
        </p>

        {!target && (
          <div style={{ ...noticeStyle, borderColor: 'var(--iac-warning)', color: 'var(--iac-warning)' }}>
            Select a Target on the Target tab first.
          </div>
        )}
        {!model && (
          <div style={{ ...noticeStyle, borderColor: 'var(--iac-warning)', color: 'var(--iac-warning)' }}>
            Select a model on the Execution Model tab first.
          </div>
        )}

        {skillsLoaded && availableSkills.length === 0 && (
          <p style={{ color: 'var(--iac-text-secondary)' }}>
            No skills are installed. Install a Skill Package from the Skills area before starting a Run.
          </p>
        )}

        {hostSkills.length > 0 && (
          <SkillGroup title="Host Skills" skills={hostSkills} selected={selectedSkillNames} onToggle={toggleSkill} />
        )}
        {userSkills.length > 0 && (
          <SkillGroup title="Your Skills" skills={userSkills} selected={selectedSkillNames} onToggle={toggleSkill} />
        )}

        {error && <div style={errorStyle}>{error}</div>}

        <button
          onClick={handleStartRun}
          disabled={!target || !model || selectedSkillNames.length === 0 || isCreating}
          style={{
            ...primaryBtnStyle,
            marginTop: 16,
            opacity: !target || !model || selectedSkillNames.length === 0 || isCreating ? 0.5 : 1,
            cursor: !target || !model || selectedSkillNames.length === 0 || isCreating ? 'not-allowed' : 'pointer',
          }}
        >
          {isCreating ? 'Starting…' : '▶ Start Run'}
        </button>
      </div>
    );
  }

  // -------------------------------------------------------------------- //
  // Active/completed run: conversation
  // -------------------------------------------------------------------- //

  const blocks = [
    ...(runState ? buildTurnBlocks(runState.turns) : []),
    ...buildLiveBlocks(liveEvents),
  ];

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
        <div style={{ fontSize: 12, color: 'var(--iac-muted)' }}>
          Run <code>{runId}</code> · skills: {selectedSkillNames.join(', ') || 'none'}
        </div>
        {runState && runState.findings.length > 0 && (
          <button onClick={handleFinishRun} style={successBtnStyle}>
            ✓ Finish Run &amp; Save Result
          </button>
        )}
      </div>

      {savedMessage && (
        <div style={{ ...noticeStyle, borderColor: 'var(--iac-success)', color: 'var(--iac-success)' }}>
          {savedMessage} <Link to="/assurance" style={{ color: 'var(--iac-link)' }}>View Assurance Results &rarr;</Link>
        </div>
      )}

      <StreamEventLog blocks={blocks} />

      {error && <div style={errorStyle}>{error}</div>}

      <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
        <textarea
          value={inputText}
          onChange={(e) => setInputText(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
              e.preventDefault();
              handleSend();
            }
          }}
          placeholder="Ask the model to investigate something, or tell it what to do next…"
          disabled={isSending}
          style={{
            flex: 1,
            resize: 'vertical',
            minHeight: 44,
            background: 'var(--iac-input-bg)',
            border: '1px solid var(--iac-input-border)',
            borderRadius: 6,
            color: 'var(--iac-text)',
            padding: '8px 10px',
            fontSize: 13,
          }}
        />
        <button
          onClick={handleSend}
          disabled={isSending || !inputText.trim()}
          style={{
            ...primaryBtnStyle,
            opacity: isSending || !inputText.trim() ? 0.5 : 1,
            cursor: isSending || !inputText.trim() ? 'not-allowed' : 'pointer',
          }}
        >
          {isSending ? 'Working…' : 'Send'}
        </button>
      </div>
    </div>
  );
};

const SkillGroup: React.FC<{
  title: string;
  skills: InstalledSkillPackage[];
  selected: string[];
  onToggle: (name: string) => void;
}> = ({ title, skills, selected, onToggle }) => (
  <div style={{ marginBottom: 16 }}>
    <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--iac-muted)', textTransform: 'uppercase', marginBottom: 6 }}>
      {title}
    </div>
    <ul style={{ listStyle: 'none', padding: 0, margin: 0, display: 'flex', flexDirection: 'column', gap: 6 }}>
      {skills.map((s) => (
        <li key={s.name}>
          <label style={{ display: 'flex', alignItems: 'flex-start', gap: 8, cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={selected.includes(s.name)}
              onChange={() => onToggle(s.name)}
              style={{ marginTop: 3 }}
            />
            <span>
              <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--iac-text)' }}>{s.name}</div>
              <div style={{ fontSize: 12, color: 'var(--iac-text-secondary)' }}>{s.manifest.description}</div>
            </span>
          </label>
        </li>
      ))}
    </ul>
  </div>
);

const noticeStyle: React.CSSProperties = {
  border: '1px solid',
  borderRadius: 6,
  padding: '8px 12px',
  fontSize: 13,
  marginBottom: 12,
};

const errorStyle: React.CSSProperties = {
  color: 'var(--iac-error)',
  background: 'var(--iac-error-bg)',
  border: '1px solid var(--iac-error)',
  borderRadius: 6,
  padding: '8px 12px',
  fontSize: 13,
  marginTop: 12,
};

const primaryBtnStyle: React.CSSProperties = {
  background: 'transparent',
  border: '1px solid var(--iac-info)',
  color: 'var(--iac-info)',
  borderRadius: 6,
  padding: '8px 18px',
  fontWeight: 600,
  fontSize: 13,
};

const successBtnStyle: React.CSSProperties = {
  background: 'transparent',
  border: '1px solid var(--iac-success)',
  color: 'var(--iac-success)',
  borderRadius: 6,
  padding: '6px 14px',
  fontWeight: 600,
  fontSize: 12,
  cursor: 'pointer',
};

export default RunTab;
