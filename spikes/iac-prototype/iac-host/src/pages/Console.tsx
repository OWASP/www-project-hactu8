// src/pages/Console.tsx
//
// Native replacement for the retired `iac_mfe_primary/StreamlitConsole` remote
// (see spikes/iac-prototype/REDESIGN_PLAN.md, roadmap item 6).
//
// There is currently no backend "shell"/command/exec endpoint in
// iac-copilot-api (confirmed against agents/router.py and app.py) — the only
// live, streaming surface the app has is the agent-engagement SSE pipeline
// (agentService.streamPhase / AgentContext), which is a fixed phase workflow,
// not an arbitrary command channel. So this console does NOT pretend to be an
// interactive backend shell. It's a local command line: recognized commands
// are handled client-side (some of them, like `status`, surface genuinely
// live app state via AgentContext), and everything else is reported as
// unrecognized rather than silently swallowed. The limitation is stated in
// the UI itself, not just in code comments.

import React, { useEffect, useRef, useState } from 'react';
import { useAgents } from '../contexts/AgentContext';
import { PHASE_LABELS } from '../types/agents';
import type { PhaseEnum } from '../types/agents';

// --------------------------------------------------------------------------- //
// Output line model
// --------------------------------------------------------------------------- //

type LineKind = 'input' | 'output' | 'error' | 'system';

interface Line {
  id: number;
  kind: LineKind;
  text: string;
}

let lineSeq = 0;
const makeLine = (kind: LineKind, text: string): Line => ({ id: lineSeq++, kind, text });

const WELCOME_LINES: Line[] = [
  makeLine('system', 'IAC local console — type "help" to see available commands.'),
  makeLine(
    'system',
    'This console runs entirely in the browser. It is not connected to a live backend shell or agent session.'
  ),
];

const HELP_TEXT = [
  'Available commands:',
  '  help            Show this message',
  '  clear           Clear the console output',
  '  status          Show the current agent engagement state (from this app, if any)',
  '  version         Show console/build info',
  '  echo <text>     Print <text> back',
].join('\n');

// --------------------------------------------------------------------------- //
// Styles
// --------------------------------------------------------------------------- //

const promptStyle: React.CSSProperties = {
  color: 'var(--iac-link)',
  fontWeight: 700,
};

const lineColor = (kind: LineKind): string => {
  switch (kind) {
    case 'input':
      return 'var(--iac-text)';
    case 'error':
      return 'var(--iac-error)';
    case 'system':
      return 'var(--iac-muted)';
    default:
      return 'var(--iac-text-secondary)';
  }
};

// --------------------------------------------------------------------------- //
// Console page
// --------------------------------------------------------------------------- //

const Console: React.FC = () => {
  const [lines, setLines] = useState<Line[]>(WELCOME_LINES);
  const [input, setInput] = useState('');
  const [history, setHistory] = useState<string[]>([]);
  const [historyIndex, setHistoryIndex] = useState<number | null>(null);

  const outputRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const agents = useAgents();

  useEffect(() => {
    if (outputRef.current) {
      outputRef.current.scrollTop = outputRef.current.scrollHeight;
    }
  }, [lines.length]);

  const append = (kind: LineKind, text: string) =>
    setLines((prev) => [...prev, makeLine(kind, text)]);

  const runCommand = (raw: string) => {
    const trimmed = raw.trim();
    if (!trimmed) return;

    append('input', trimmed);
    setHistory((prev) => [...prev, trimmed]);
    setHistoryIndex(null);

    const [cmd, ...rest] = trimmed.split(/\s+/);
    const args = rest.join(' ');

    switch (cmd.toLowerCase()) {
      case 'help':
        append('output', HELP_TEXT);
        break;

      case 'clear':
        setLines([]);
        return;

      case 'status': {
        if (!agents.engagementId) {
          append('output', 'No active agent engagement. Start one from the Agents page.');
          break;
        }
        const phase = agents.currentPhase ? PHASE_LABELS[agents.currentPhase as PhaseEnum] : 'none';
        const complete = agents.phasesComplete.length
          ? agents.phasesComplete.join(', ')
          : 'none';
        append(
          'output',
          [
            `engagement_id : ${agents.engagementId}`,
            `status        : ${agents.status}`,
            `current_phase : ${phase}`,
            `phases_done   : ${complete}`,
          ].join('\n')
        );
        break;
      }

      case 'version':
        append('output', 'iac-host console — local echo mode (no backend command session)');
        break;

      case 'echo':
        append('output', args);
        break;

      default:
        append(
          'error',
          `command not found: "${cmd}" — this console is not connected to a live backend session, so only local commands are recognized. Type "help" for the list.`
        );
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      runCommand(input);
      setInput('');
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (history.length === 0) return;
      const nextIndex = historyIndex === null ? history.length - 1 : Math.max(0, historyIndex - 1);
      setHistoryIndex(nextIndex);
      setInput(history[nextIndex]);
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (historyIndex === null) return;
      const nextIndex = historyIndex + 1;
      if (nextIndex >= history.length) {
        setHistoryIndex(null);
        setInput('');
      } else {
        setHistoryIndex(nextIndex);
        setInput(history[nextIndex]);
      }
    }
  };

  return (
    <div
      style={{
        padding: 24,
        color: 'var(--iac-text)',
        maxWidth: 900,
        height: '100%',
        boxSizing: 'border-box',
        display: 'flex',
        flexDirection: 'column',
      }}
      onClick={() => inputRef.current?.focus()}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
        <h2 style={{ margin: 0, fontSize: 22 }}>Console</h2>
        <span
          style={{
            padding: '2px 10px',
            borderRadius: 10,
            fontSize: 11,
            fontWeight: 700,
            letterSpacing: '0.03em',
            background: 'var(--iac-warning-bg)',
            color: 'var(--iac-warning)',
            border: '1px solid var(--iac-warning)',
          }}
        >
          LOCAL — NOT CONNECTED TO A LIVE BACKEND SESSION
        </span>
      </div>
      <p style={{ color: 'var(--iac-muted)', marginTop: 6, marginBottom: 16, fontSize: 13 }}>
        A small set of local commands runs entirely in this browser tab. There is no backend
        shell or command-execution endpoint behind this page — <code>status</code> reflects this
        app's own agent-engagement state, everything else is client-side only.
      </p>

      <div
        style={{
          flex: 1,
          minHeight: 0,
          display: 'flex',
          flexDirection: 'column',
          background: 'var(--iac-code-bg)',
          border: '1px solid var(--iac-border)',
          borderRadius: 8,
          overflow: 'hidden',
        }}
      >
        <div
          ref={outputRef}
          style={{
            flex: 1,
            minHeight: 0,
            overflowY: 'auto',
            padding: '14px 16px',
            fontFamily:
              'ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace',
            fontSize: 13,
            lineHeight: 1.6,
          }}
        >
          {lines.map((line) => (
            <div key={line.id} style={{ whiteSpace: 'pre-wrap', marginBottom: 2 }}>
              {line.kind === 'input' ? (
                <>
                  <span style={promptStyle}>iac&gt;</span> <span style={{ color: 'var(--iac-text)' }}>{line.text}</span>
                </>
              ) : (
                <span style={{ color: lineColor(line.kind) }}>{line.text}</span>
              )}
            </div>
          ))}
        </div>

        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            borderTop: '1px solid var(--iac-border)',
            padding: '8px 16px',
            background: 'var(--iac-surface)',
          }}
        >
          <span style={{ ...promptStyle, fontFamily: 'monospace', fontSize: 13 }}>iac&gt;</span>
          <input
            ref={inputRef}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder='Type a command ("help" to list what is supported)'
            spellCheck={false}
            autoComplete="off"
            style={{
              flex: 1,
              background: 'transparent',
              border: 'none',
              outline: 'none',
              color: 'var(--iac-text)',
              fontFamily:
                'ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace',
              fontSize: 13,
            }}
          />
        </div>
      </div>
    </div>
  );
};

export default Console;
