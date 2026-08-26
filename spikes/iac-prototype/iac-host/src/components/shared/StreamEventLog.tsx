// src/components/shared/StreamEventLog.tsx
//
// Shared rendering for agent/skill-runner SSE event streams — markdown
// prose, tool_call/tool_result cards, error banners. Originally lived only
// in pages/Agents.tsx; extracted so Project runs (a second, turn-based SSE
// consumer with a narrower event vocabulary — no phase_start/
// awaiting_approval) can reuse the same look without duplicating the block
// styles. Event-to-block mapping stays page-local (the two event
// vocabularies genuinely differ); this component only owns block -> DOM.
import React, { useEffect, useRef } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

export type StreamLogBlock =
  | { kind: 'prose'; content: string }
  | { kind: 'tool_call'; name: string; input: Record<string, unknown> }
  | { kind: 'tool_result'; name: string; ok: boolean; data?: string }
  | { kind: 'info'; text: string; color: string }
  | { kind: 'error'; message: string }
  | { kind: 'custom'; key: string | number; render: React.ReactNode };

export const STREAM_LOG_MD_STYLES = `
.agent-md h1,.agent-md h2,.agent-md h3 { color:var(--iac-info-text); margin:12px 0 6px; }
.agent-md h1 { font-size:17px; border-bottom:1px solid var(--iac-badge-bg); padding-bottom:4px; }
.agent-md h2 { font-size:15px; }
.agent-md h3 { font-size:13px; color:var(--iac-link); }
.agent-md p  { color:var(--iac-text); margin:4px 0; line-height:1.6; }
.agent-md ul,.agent-md ol { color:var(--iac-text); padding-left:20px; margin:4px 0; }
.agent-md li { margin:2px 0; line-height:1.5; }
.agent-md code { background:var(--iac-surface); color:var(--iac-code-text); padding:1px 5px; border-radius:3px; font-size:12px; }
.agent-md pre  { background:var(--iac-code-bg); border:1px solid var(--iac-badge-bg); border-radius:6px; padding:10px 12px; overflow-x:auto; margin:8px 0; }
.agent-md pre code { background:none; color:var(--iac-code-text); padding:0; }
.agent-md table { width:100%; border-collapse:collapse; margin:8px 0; font-size:12px; }
.agent-md th { background:var(--iac-badge-bg); color:var(--iac-info-text); padding:5px 10px; text-align:left; border:1px solid var(--iac-badge-bg); }
.agent-md td { padding:4px 10px; border:1px solid var(--iac-surface); color:var(--iac-text-secondary); }
.agent-md tr:nth-child(even) td { background:var(--iac-bg); }
.agent-md blockquote { border-left:3px solid var(--iac-info); margin:6px 0; padding:4px 12px; color:var(--iac-text-secondary); font-style:italic; }
.agent-md strong { color:var(--iac-text); }
.agent-md hr { border:none; border-top:1px solid var(--iac-surface); margin:10px 0; }
.agent-md a { color:var(--iac-link); }
`;

// A tool_result's payload may be shaped either the legacy way
// ({success: boolean, data: ...}) or the skill-runner way
// ({exit_code, stdout, stderr, timed_out} — run_skill_script has no
// top-level "success" key). Both flow through Agents and Project runs now
// that both use skill_packages/runner.py, so both are checked here.
export function isToolResultOk(result: Record<string, unknown> | undefined): boolean {
  if (!result) return false;
  if (typeof result.success === 'boolean') return result.success;
  if (typeof result.exit_code === 'number') return result.exit_code === 0 && !result.timed_out;
  return false;
}

export function toolResultData(result: Record<string, unknown> | undefined): string | undefined {
  if (!result) return undefined;
  if (result.data !== undefined) return JSON.stringify(result.data, null, 2);
  if (typeof result.stdout === 'string' && result.stdout.trim()) return result.stdout;
  if (typeof result.stderr === 'string' && result.stderr.trim()) return result.stderr;
  return undefined;
}

export const StreamEventLog: React.FC<{ blocks: StreamLogBlock[] }> = ({ blocks }) => {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [blocks.length]);

  if (blocks.length === 0) return null;

  return (
    <>
      <style>{STREAM_LOG_MD_STYLES}</style>
      <div
        ref={containerRef}
        style={{
          background: 'var(--iac-bg)',
          border: '1px solid var(--iac-border)',
          borderRadius: 8,
          padding: '16px 20px',
          maxHeight: 520,
          overflowY: 'auto',
          marginTop: 16,
        }}
      >
        {blocks.map((block, i) => {
          if (block.kind === 'custom') {
            return <React.Fragment key={block.key}>{block.render}</React.Fragment>;
          }

          if (block.kind === 'prose') {
            return (
              <div key={i} className="agent-md" style={{ marginBottom: 8 }}>
                <ReactMarkdown remarkPlugins={[remarkGfm]}>{block.content}</ReactMarkdown>
              </div>
            );
          }

          if (block.kind === 'tool_call') {
            return (
              <div
                key={i}
                style={{
                  background: 'var(--iac-surface)',
                  border: '1px solid var(--iac-border)',
                  borderRadius: 6,
                  padding: '6px 12px',
                  marginBottom: 6,
                  fontFamily: 'monospace',
                  fontSize: 12,
                  color: 'var(--iac-info-text)',
                }}
              >
                <span style={{ opacity: 0.6 }}>⚙ skill: </span>
                <strong>{block.name}</strong>
                <span style={{ opacity: 0.6 }}>(</span>
                {Object.entries(block.input).map(([k, v]) => (
                  <span key={k}> {k}=<em style={{ color: '#a5f3fc' }}>{String(v)}</em></span>
                ))}
                <span style={{ opacity: 0.6 }}>)</span>
              </div>
            );
          }

          if (block.kind === 'tool_result') {
            return (
              <div
                key={i}
                style={{
                  background: block.ok ? 'var(--iac-success-bg)' : 'var(--iac-error-bg)',
                  border: `1px solid ${block.ok ? 'var(--iac-success)' : 'var(--iac-error)'}`,
                  borderRadius: 6,
                  padding: '6px 12px',
                  marginBottom: 10,
                  fontFamily: 'monospace',
                  fontSize: 12,
                }}
              >
                <div style={{ color: block.ok ? 'var(--iac-success)' : 'var(--iac-error)', marginBottom: block.data ? 4 : 0 }}>
                  {block.ok ? '✓' : '✕'} {block.name}
                </div>
                {block.data && (
                  <pre style={{ margin: 0, color: 'var(--iac-text-secondary)', fontSize: 11, whiteSpace: 'pre-wrap', overflowX: 'auto' }}>
                    {block.data.length > 600 ? block.data.slice(0, 600) + '\n…' : block.data}
                  </pre>
                )}
              </div>
            );
          }

          if (block.kind === 'info') {
            return (
              <div key={i} style={{ color: block.color, fontSize: 12, fontStyle: 'italic', marginTop: 8 }}>
                {block.text}
              </div>
            );
          }

          if (block.kind === 'error') {
            return (
              <div
                key={i}
                style={{
                  color: 'var(--iac-error)',
                  background: 'var(--iac-error-bg)',
                  border: '1px solid var(--iac-error)',
                  borderRadius: 6,
                  padding: '6px 12px',
                  fontSize: 13,
                  fontFamily: 'monospace',
                }}
              >
                ✕ {block.message}
              </div>
            );
          }

          return null;
        })}
      </div>
    </>
  );
};

export default StreamEventLog;
