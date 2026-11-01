/**
 * CVE vulnerability tracking — "what does this update fix?" (Updates page).
 *
 * Given an available update (current → latest version of a package) and the
 * stored advisories for that package, decide which advisories the update
 * RESOLVES: ones whose affected ranges cover the CURRENTLY installed version
 * but NOT the target version. Pure functions — no I/O; the route loads the
 * advisory rows + per-device ecosystems and hands them in (see routes/updates.ts).
 */

import type { AffectedRange } from './types';
import { matchesVersion } from './match';

/** The subset of cve_advisories a fix computation needs. */
export interface CveAdvisoryLite {
  id: string;
  severityRank: string;
  affectedRanges: AffectedRange[];
}

/** Aggregated "this update fixes N CVEs" summary for one update row. */
export interface FixesSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
  /** The most severe fixed CVE ids first (for tooltips) — capped by the caller's taste. */
  topIds: string[];
}

const RANK_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };

/**
 * Advisories that `current` is affected by but `latest` is not. Uses the same
 * per-ecosystem comparators as device_cves matching (cve/match.ts), so an update
 * "fixes" exactly the findings the Security page shows for the installed version.
 * A null/empty `current` counts as affected (matchesVersion's conservative rule);
 * a null/empty `latest` can never be confirmed fixed — such advisories are kept
 * OUT of the result (we don't claim a fix we cannot verify).
 */
export function advisoriesFixedBy(
  advisories: CveAdvisoryLite[],
  current: string | null | undefined,
  latest: string | null | undefined,
  ecosystem?: string | null,
): CveAdvisoryLite[] {
  const latestStr = typeof latest === 'string' ? latest.trim() : '';
  if (!latestStr) return []; // no target version — nothing verifiable
  const out: CveAdvisoryLite[] = [];
  for (const a of advisories) {
    if (!matchesVersion(a.affectedRanges, current ?? null, ecosystem)) continue; // not vulnerable now
    if (matchesVersion(a.affectedRanges, latestStr, ecosystem)) continue; // still vulnerable after the update
    out.push(a);
  }
  return out;
}

/** Aggregates a fixed-advisory list into the UI summary shape; null when empty.
 * Advisories are deduped by CVE id first — OSV emits one row per (ecosystem,
 * range-set) variant of the SAME advisory, so e.g. curl's CVE-2026-5773 arrives
 * twice and must count once. Keep-first: the rows for one id carry identical
 * severity data. */
export function summarizeFixes(fixed: CveAdvisoryLite[], topLimit = 8): FixesSummary | null {
  if (fixed.length === 0) return null;
  const byId = new Map<string, CveAdvisoryLite>();
  for (const a of fixed) if (!byId.has(a.id)) byId.set(a.id, a);
  const distinct = [...byId.values()];

  const s: FixesSummary = { total: distinct.length, critical: 0, high: 0, medium: 0, low: 0, unknown: 0, topIds: [] };
  for (const a of distinct) {
    if (a.severityRank in s) s[a.severityRank as 'critical' | 'high' | 'medium' | 'low' | 'unknown'] += 1;
    else s.unknown += 1; // unexpected rank value — bucket it, don't drop it
  }
  const sorted = [...distinct].sort(
    (a, b) => (RANK_ORDER[a.severityRank] ?? 9) - (RANK_ORDER[b.severityRank] ?? 9) || a.id.localeCompare(b.id),
  );
  s.topIds = sorted.slice(0, topLimit).map((a) => a.id);
  return s;
}
