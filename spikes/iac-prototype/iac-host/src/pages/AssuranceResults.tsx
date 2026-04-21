import React, { useState, useEffect, useCallback, useRef } from 'react';
import type { TestRunResult, TestCaseResult, TestResultStatus } from '../types/extensions';
import resultsService from '../services/resultsService';

// ---------------------------------------------------------------------------
// Status helpers
// ---------------------------------------------------------------------------

const STATUS_COLORS: Record<TestResultStatus, string> = {
  pass: 'var(--iac-success)',
  fail: 'var(--iac-error)',
  error: 'var(--iac-warning)',
  skip: 'var(--iac-text-secondary)',
};

const STATUS_BG: Record<TestResultStatus, string> = {
  pass: 'var(--iac-success-bg)',
  fail: 'var(--iac-error-bg)',
  error: 'var(--iac-warning-bg)',
  skip: 'var(--iac-surface)',
};

const STATUS_ICONS: Record<TestResultStatus, string> = {
  pass: '\u2705',
  fail: '\u274c',
  error: '\u26a0\ufe0f',
  skip: '\u23ed\ufe0f',
};

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

function formatTimestamp(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleString();
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

const AssuranceResults: React.FC = () => {
  const [results, setResults] = useState<TestRunResult[]>([]);
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);
  const [filterStatus, setFilterStatus] = useState<TestResultStatus | 'all'>('all');
  const [importError, setImportError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    setResults(resultsService.loadResultsWithMocks());
  }, []);

  // Auto-refresh every 30 seconds
  useEffect(() => {
    const interval = setInterval(() => {
      setResults(resultsService.loadResultsWithMocks());
    }, 30000);
    return () => clearInterval(interval);
  }, []);

  // Listen for postMessage results arriving while this page is visible
  useEffect(() => {
    function handleMessage(event: MessageEvent) {
      if (
        event.data &&
        typeof event.data === 'object' &&
        event.data.type === 'iac-extension-results' &&
        event.data.payload?.runId
      ) {
        // Re-read from localStorage since StreamlitExtension already stored it
        setResults(resultsService.loadResultsWithMocks());
      }
    }
    window.addEventListener('message', handleMessage);
    return () => window.removeEventListener('message', handleMessage);
  }, []);

  const handleRefresh = useCallback(() => {
    setResults(resultsService.loadResultsWithMocks());
  }, []);

  const handleClear = useCallback(() => {
    resultsService.clearResults();
    setResults([]);
    setSelectedRunId(null);
  }, []);

  const handleExportAll = useCallback(() => {
    resultsService.exportAllResults();
  }, []);

  const handleExportRun = useCallback((run: TestRunResult) => {
    resultsService.exportResult(run);
  }, []);

  const handleImportClick = useCallback(() => {
    fileInputRef.current?.click();
  }, []);

  const handleImportFile = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    setImportError(null);
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = () => {
      try {
        const updated = resultsService.importResults(reader.result as string);
        setResults(updated.length > 0 ? updated : resultsService.loadResultsWithMocks());
      } catch (err) {
        setImportError(err instanceof Error ? err.message : 'Failed to import results.');
      }
    };
    reader.readAsText(file);

    // Reset the file input so the same file can be re-imported if needed
    e.target.value = '';
  }, []);

  const selectedRun = results.find((r) => r.runId === selectedRunId) ?? null;

  return (
    <div style={{ display: 'flex', minHeight: '60vh', height: '100%', overflow: 'hidden' }}>
      {/* ---- Sidebar: Run list ---- */}
      <aside style={sidebarStyle}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
          <h3 style={{ color: 'var(--iac-text)', margin: 0 }}>Test Runs</h3>
          <button onClick={handleRefresh} style={smallButtonStyle} title="Refresh">
            Refresh
          </button>
        </div>

        {/* Import / Export toolbar */}
        <div style={{ display: 'flex', gap: '0.35rem', marginBottom: '0.75rem' }}>
          <button onClick={handleImportClick} style={{ ...toolbarButtonStyle }} title="Import results from a JSON file">
            Import
          </button>
          <input
            ref={fileInputRef}
            type="file"
            accept=".json,application/json"
            onChange={handleImportFile}
            style={{ display: 'none' }}
          />
          {results.length > 0 && (
            <button onClick={handleExportAll} style={{ ...toolbarButtonStyle }} title="Export all results as JSON">
              Export All
            </button>
          )}
        </div>

        {importError && (
          <div style={{ padding: '0.5rem', background: 'var(--iac-error-bg)', color: 'var(--iac-error)', borderRadius: '4px', fontSize: '0.75rem', marginBottom: '0.5rem' }}>
            {importError}
          </div>
        )}

        {results.length === 0 ? (
          <p style={{ color: 'var(--iac-text-secondary)', fontSize: '0.875rem' }}>
            No test results yet. Run tests from an installed extension.
          </p>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', overflowY: 'auto', flex: 1 }}>
            {results.map((run) => {
              const isSelected = selectedRunId === run.runId;
              const passRate = run.summary.total > 0
                ? Math.round((run.summary.passed / run.summary.total) * 100)
                : 0;
              return (
                <div
                  key={run.runId}
                  onClick={() => setSelectedRunId(run.runId)}
                  style={{
                    ...cardStyle,
                    borderColor: isSelected ? 'var(--iac-surface-elevated)' : 'var(--iac-border)',
                    background: isSelected ? 'var(--iac-surface-elevated)' : 'var(--iac-surface)',
                    cursor: 'pointer',
                  }}
                >
                  <div style={{ fontWeight: 600, fontSize: '0.85rem', color: 'var(--iac-text)', marginBottom: '0.15rem' }}>
                    {run.extensionName}
                  </div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--iac-text-secondary)', marginBottom: '0.35rem' }}>
                    {formatTimestamp(run.timestamp)}
                  </div>
                  <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                    <PassRateBar rate={passRate} />
                    <span style={{ fontSize: '0.75rem', color: 'var(--iac-text)', fontWeight: 600 }}>
                      {passRate}%
                    </span>
                  </div>
                  <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.35rem', fontSize: '0.7rem' }}>
                    <span style={{ color: STATUS_COLORS.pass }}>{run.summary.passed} passed</span>
                    <span style={{ color: STATUS_COLORS.fail }}>{run.summary.failed} failed</span>
                    {run.summary.errors > 0 && (
                      <span style={{ color: STATUS_COLORS.error }}>{run.summary.errors} errors</span>
                    )}
                  </div>
                </div>
              );
            })}

            {results.length > 0 && (
              <button onClick={handleClear} style={{ ...smallButtonStyle, background: 'var(--iac-error)', marginTop: '0.5rem' }}>
                Clear All
              </button>
            )}
          </div>
        )}
      </aside>

      {/* ---- Main: Run detail ---- */}
      <main style={mainStyle}>
        {!selectedRun ? (
          <div style={{ color: 'var(--iac-text-secondary)', textAlign: 'center', marginTop: '4rem' }}>
            <p>Select a test run to view details.</p>
          </div>
        ) : (
          <RunDetail
            run={selectedRun}
            filterStatus={filterStatus}
            onFilterChange={setFilterStatus}
            onExport={handleExportRun}
          />
        )}
      </main>
    </div>
  );
};

// ---------------------------------------------------------------------------
// Run detail view
// ---------------------------------------------------------------------------

interface RunDetailProps {
  run: TestRunResult;
  filterStatus: TestResultStatus | 'all';
  onFilterChange: (status: TestResultStatus | 'all') => void;
  onExport: (run: TestRunResult) => void;
}

function RunDetail({ run, filterStatus, onFilterChange, onExport }: RunDetailProps) {
  const passRate = run.summary.total > 0
    ? Math.round((run.summary.passed / run.summary.total) * 100)
    : 0;

  const filteredResults = filterStatus === 'all'
    ? run.results
    : run.results.filter((r) => r.status === filterStatus);

  // Sort: fail first, then error, pass, skip
  const statusOrder: Record<string, number> = { fail: 0, error: 1, pass: 2, skip: 3 };
  const sorted = [...filteredResults].sort(
    (a, b) => (statusOrder[a.status] ?? 99) - (statusOrder[b.status] ?? 99)
  );

  return (
    <div>
      {/* Header */}
      <div style={{ marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div>
            <h3 style={{ color: 'var(--iac-text)', fontWeight: 700, fontSize: '1.5rem', margin: '0 0 0.25rem' }}>
              {run.extensionName}
            </h3>
            <p style={{ color: 'var(--iac-text-secondary)', margin: 0, fontSize: '0.875rem' }}>
              Run <code>{run.runId}</code> &bull; {formatTimestamp(run.timestamp)} &bull; Target: <code>{run.target}</code>
            </p>
          </div>
          <button
            onClick={() => onExport(run)}
            style={exportRunButtonStyle}
            title="Export this run as JSON"
          >
            Export JSON
          </button>
        </div>
      </div>

      {/* Summary metrics */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '1rem', marginBottom: '1.5rem' }}>
        <MetricCard label="Total" value={run.summary.total} />
        <MetricCard label="Passed" value={run.summary.passed} color={STATUS_COLORS.pass} />
        <MetricCard label="Failed" value={run.summary.failed} color={STATUS_COLORS.fail} />
        <MetricCard label="Errors" value={run.summary.errors} color={STATUS_COLORS.error} />
        <MetricCard label="Duration" value={formatDuration(run.summary.duration)} />
      </div>

      {/* Pass rate bar */}
      <div style={{ marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.25rem' }}>
          <span style={{ fontSize: '0.875rem', color: 'var(--iac-text)', fontWeight: 600 }}>Pass Rate</span>
          <span style={{ fontSize: '0.875rem', color: 'var(--iac-text)', fontWeight: 700 }}>{passRate}%</span>
        </div>
        <div style={{ height: 12, background: 'var(--iac-surface)', borderRadius: 6, overflow: 'hidden' }}>
          <div style={{
            height: '100%',
            width: `${passRate}%`,
            background: passRate >= 80 ? 'var(--iac-success)' : passRate >= 50 ? 'var(--iac-warning)' : 'var(--iac-error)',
            borderRadius: 6,
            transition: 'width 0.3s',
          }} />
        </div>
      </div>

      {/* Filter */}
      <div style={{ display: 'flex', gap: '0.25rem', marginBottom: '1rem' }}>
        {(['all', 'fail', 'error', 'pass', 'skip'] as const).map((s) => (
          <button
            key={s}
            onClick={() => onFilterChange(s)}
            style={{
              padding: '0.35rem 0.75rem',
              background: filterStatus === s ? 'var(--iac-surface-elevated)' : 'transparent',
              color: filterStatus === s ? 'var(--iac-text)' : 'var(--iac-text)',
              border: '1px solid var(--iac-border)',
              borderRadius: '4px',
              cursor: 'pointer',
              fontWeight: filterStatus === s ? 600 : 400,
              fontSize: '0.8rem',
              textTransform: 'capitalize',
            }}
          >
            {s === 'all' ? `All (${run.results.length})` : `${s} (${run.results.filter((r) => r.status === s).length})`}
          </button>
        ))}
      </div>

      {/* Results table */}
      <div style={{ border: '1px solid var(--iac-border)', borderRadius: '6px', overflow: 'hidden' }}>
        {/* Table header */}
        <div style={tableHeaderStyle}>
          <div style={{ width: 36 }}></div>
          <div style={{ flex: 2 }}>Test</div>
          <div style={{ flex: 1 }}>Status</div>
          <div style={{ width: 100, textAlign: 'right' }}>Duration</div>
        </div>

        {sorted.length === 0 ? (
          <div style={{ padding: '1rem', color: 'var(--iac-text-secondary)', textAlign: 'center' }}>
            No results matching filter.
          </div>
        ) : (
          sorted.map((tc) => <TestCaseRow key={tc.id} testCase={tc} />)
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function TestCaseRow({ testCase }: { testCase: TestCaseResult }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div>
      <div
        onClick={() => setExpanded(!expanded)}
        style={{
          ...tableRowStyle,
          background: expanded ? 'var(--iac-surface)' : 'var(--iac-bg)',
          cursor: 'pointer',
        }}
      >
        <div style={{ width: 36, textAlign: 'center', fontSize: '1rem' }}>
          {STATUS_ICONS[testCase.status]}
        </div>
        <div style={{ flex: 2 }}>
          <div style={{ fontWeight: 500, color: 'var(--iac-text)', fontSize: '0.875rem' }}>{testCase.name}</div>
          <div style={{ fontSize: '0.75rem', color: 'var(--iac-text-secondary)' }}>{testCase.id}</div>
        </div>
        <div style={{ flex: 1 }}>
          <span style={{
            display: 'inline-block',
            padding: '0.15rem 0.5rem',
            borderRadius: '4px',
            background: STATUS_BG[testCase.status],
            color: STATUS_COLORS[testCase.status],
            fontSize: '0.75rem',
            fontWeight: 600,
            textTransform: 'uppercase',
          }}>
            {testCase.status}
          </span>
        </div>
        <div style={{ width: 100, textAlign: 'right', fontSize: '0.85rem', color: 'var(--iac-text)' }}>
          {testCase.duration ? formatDuration(testCase.duration) : '—'}
        </div>
      </div>

      {expanded && (
        <div style={{ padding: '0.75rem 1rem 0.75rem 3rem', background: 'var(--iac-surface)', borderTop: '1px solid var(--iac-border)' }}>
          <p style={{ margin: '0 0 0.25rem', fontSize: '0.85rem', color: 'var(--iac-text)' }}>
            <strong>Message:</strong> {testCase.message}
          </p>
          {testCase.details && (
            <pre style={codeBlockStyle}>{testCase.details}</pre>
          )}
        </div>
      )}
    </div>
  );
}

function MetricCard({ label, value, color }: { label: string; value: string | number; color?: string }) {
  return (
    <div style={{
      padding: '1rem',
      border: '1px solid var(--iac-border)',
      borderRadius: '6px',
      background: 'var(--iac-surface)',
      textAlign: 'center',
    }}>
      <div style={{ fontSize: '0.75rem', color: 'var(--iac-text-secondary)', marginBottom: '0.25rem' }}>{label}</div>
      <div style={{ fontSize: '1.5rem', fontWeight: 700, color: color ?? 'var(--iac-text)' }}>{value}</div>
    </div>
  );
}

function PassRateBar({ rate }: { rate: number }) {
  return (
    <div style={{ flex: 1, height: 6, background: 'var(--iac-surface)', borderRadius: 3, overflow: 'hidden' }}>
      <div style={{
        height: '100%',
        width: `${rate}%`,
        background: rate >= 80 ? 'var(--iac-success)' : rate >= 50 ? 'var(--iac-warning)' : 'var(--iac-error)',
        borderRadius: 3,
      }} />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Styles
// ---------------------------------------------------------------------------

const sidebarStyle: React.CSSProperties = {
  width: 320,
  padding: '1rem',
  background: 'var(--iac-surface)',
  borderRight: '1px solid var(--iac-border)',
  display: 'flex',
  flexDirection: 'column',
  overflowY: 'auto',
};

const mainStyle: React.CSSProperties = {
  flex: 1,
  padding: '2rem',
  overflowY: 'auto',
  background: 'var(--iac-bg)',
};

const cardStyle: React.CSSProperties = {
  padding: '0.75rem',
  border: '1px solid var(--iac-border)',
  borderRadius: '6px',
  background: 'var(--iac-surface)',
};

const smallButtonStyle: React.CSSProperties = {
  padding: '0.3rem 0.6rem',
  background: 'var(--iac-surface-elevated)',
  color: 'var(--iac-text)',
  border: 'none',
  borderRadius: '4px',
  cursor: 'pointer',
  fontWeight: 500,
  fontSize: '0.75rem',
};

const tableHeaderStyle: React.CSSProperties = {
  display: 'flex',
  alignItems: 'center',
  padding: '0.5rem 1rem',
  background: 'var(--iac-surface)',
  borderBottom: '1px solid var(--iac-border)',
  fontSize: '0.75rem',
  fontWeight: 600,
  color: 'var(--iac-text-secondary)',
  textTransform: 'uppercase',
};

const tableRowStyle: React.CSSProperties = {
  display: 'flex',
  alignItems: 'center',
  padding: '0.5rem 1rem',
  borderBottom: '1px solid var(--iac-border)',
};

const codeBlockStyle: React.CSSProperties = {
  padding: '0.5rem 0.75rem',
  background: 'var(--iac-code-bg)',
  color: 'var(--iac-code-text)',
  borderRadius: '4px',
  fontSize: '0.75rem',
  overflowX: 'auto',
  whiteSpace: 'pre-wrap',
  wordBreak: 'break-all',
  margin: '0.5rem 0 0',
};

const toolbarButtonStyle: React.CSSProperties = {
  padding: '0.3rem 0.6rem',
  background: 'var(--iac-surface)',
  color: 'var(--iac-text)',
  border: '1px solid var(--iac-border)',
  borderRadius: '4px',
  cursor: 'pointer',
  fontWeight: 500,
  fontSize: '0.75rem',
};

const exportRunButtonStyle: React.CSSProperties = {
  padding: '0.4rem 0.8rem',
  background: 'var(--iac-surface-elevated)',
  color: 'var(--iac-text)',
  border: 'none',
  borderRadius: '4px',
  cursor: 'pointer',
  fontWeight: 500,
  fontSize: '0.8rem',
  whiteSpace: 'nowrap',
};

export default AssuranceResults;
