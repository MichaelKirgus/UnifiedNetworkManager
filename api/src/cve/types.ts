/**
 * CVE vulnerability tracking — shared types.
 *
 * The infrastructure is provider-agnostic on purpose: today the only source is
 * OSV.dev (free, no key), but the plan explicitly anticipates commercial
 * providers that accept the WHOLE fleet's package list and return vulnerable
 * packages + CVEs in one shot. `CveProvider` is that contract — a new provider
 * is a new file implementing this interface plus a settings entry to select it;
 * the worker, tables and routes never change.
 */

/**
 * One version bound of an advisory's affected range. The types mirror OSV.dev
 * "events" verbatim ('<' = fixed in / not including, '>' = introduced at):
 *   { type: '<',  version: '1.2.3' }  → all versions below 1.2.3 are affected
 *   { type: '>=', version: '1.0' }    → vulnerability introduced at 1.0
 * Bounds are matched in cve/match.ts (per-ecosystem comparators), never in SQL,
 * so the shape can stay provider-flexible.
 */
export interface AffectedRange {
  type: '<' | '<=' | '>' | '>=';
  version: string;
}

/** One advisory row as returned by a CveProvider (normalized to UNM's shape). */
export interface AdvisoryRow {
  /** Provider ecosystem tag ('DEBIAN', 'ALPINE_LINUX', 'npm', …) — part of the PK. */
  ecosystem: string;
  packageName: string;
  /** Advisory id (e.g. "CVE-2024-1234", "GHSA-xxxx") — part of the PK. */
  id: string;
  /** CVSS base score 0–10, or null when the provider gave none. */
  severityScore: number | null;
  /** Derived bucket: 'critical' | 'high' | 'medium' | 'low' | 'unknown'. */
  severityRank: SeverityRank;
  affectedRanges: AffectedRange[];
  summary?: string | null;
  url?: string | null;
  publishedAt?: string | null;
}

export type SeverityRank = 'critical' | 'high' | 'medium' | 'low' | 'unknown';

/** Maps a CVSS base score onto the coarse rank used for filtering/badges. */
export function severityRankForScore(score: number | null): SeverityRank {
  if (score === null || !Number.isFinite(score)) return 'unknown';
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  return 'low';
}

/** One installed package to look up — the unit of a provider query. */
export interface PackageQuery {
  /** Provider ecosystem tag for this package ('DEBIAN', 'ALPINE_LINUX', …). */
  ecosystem: string;
  name: string;
  /**
   * Installed version, when known. OSV.dev's Debian/Alpine sources only return
   * full advisory metadata (affected ranges + severity) for VERSIONED queries —
   * a versionless query yields bare ids with no data to match against — so the
   * worker passes each distinct installed version and the provider returns the
   * advisories that affect it. Null = unversioned package (the OSV provider
   * skips those; they still match locally if another device's version populated
   * the advisory). Commercial providers may ignore this field entirely.
   */
  version?: string | null;
}

/**
 * A vulnerability-data source. `fetchAdvisories` takes the DISTINCT set of
 * (ecosystem, package) pairs installed anywhere in the fleet and returns every
 * advisory that applies to any of them — the whole-fleet input is deliberate:
 * it is exactly what a commercial provider's API would accept. Implementations
 * must be read-only and idempotent; batching/rate-limiting are their concern.
 */
export interface CveProvider {
  /** Stable id ('osv' today) — stored on each advisory row + shown in the UI. */
  id: string;
  fetchAdvisories(pkgs: PackageQuery[]): Promise<AdvisoryRow[]>;
}
