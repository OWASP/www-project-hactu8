// src/components/shared/streamResult.ts
//
// tool_result payload helpers shared by StreamEventLog consumers. Kept out of
// StreamEventLog.tsx so that file exports only components (React fast refresh).

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
