import type { Hactu8Result } from '../../services/hactu8Api';

// The Wolf (python -m hactu8 wolf, POST /api/wolf) stores its runs under this skill id.
export const WOLF_SKILL_ID = 'lamb-wolf';

export function isWolfRun(result: Hactu8Result): boolean {
  return result.skill.id === WOLF_SKILL_ID;
}

// What the wolf den captured, from result.wolf.den; null when the result carries no den.
// Only a confirmed capture held the run's canary; the rest are suspected captures (evidence only).
export function denCaptures(result: Hactu8Result): { total: number; confirmed: number } | null {
  const den = result.wolf?.den;
  if (!Array.isArray(den)) return null;
  return { total: den.length, confirmed: den.filter((capture) => capture.confirmed === true).length };
}
