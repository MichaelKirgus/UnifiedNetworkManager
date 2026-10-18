/**
 * CVE vulnerability tracking — OSV.dev provider (the Phase-1 CveProvider).
 *
 * OSV.dev (https://osv.dev) aggregates the major OS/package vulnerability
 * databases (Debian Security Tracker, Alpine security, NVD, GitHub Advisory DB,
 * …) behind one free, keyless API. We query each DISTINCT (ecosystem, package,
 * version) triple installed in the fleet WITH its version via single
 * `POST /v1/query` calls — a live finding: OSV's Debian/Alpine sources only
 * return full advisory metadata (affected ranges + severity) for VERSIONED
 * queries, and even their batch endpoint (`querybatch`) strips every vuln down
 * to `{id, modified}` regardless of versioning. The worker stores the returned
 * advisories and matches them against each device's installed versions locally
 * (cve/match.ts), so a device upgrade needs no re-fetch — only the next beat's
 * recomputation (and, when it installs a version never seen before, one extra
 * fetch for that triple). Queries run with bounded concurrency; identical
 * triples are deduped first, so fleet size maps to distinct versions, not
 * devices.
 *
 * Egress goes through the web-fetch plugin like every other outbound request:
 * POST /fetch with method 'POST' + JSON body (the 0.2.0 extension).
 */

import { fetchViaWebFetch, resolveWebFetchProvider } from '../webFetchBroker';
import { getEffectiveValues } from '../systemSettings';
import type { AdvisoryRow, AffectedRange, CveProvider, PackageQuery, SeverityRank } from './types';
import { severityRankForScore } from './types';
import { parseCvssVector } from './cvss';
import { mapToOsvEcosystem } from './ecosystems';

const OSV_QUERY_URL = 'https://api.osv.dev/v1/query';
/** Concurrent in-flight /v1/query calls — polite to the free API and the plugin. */
const CONCURRENCY = 4;

// ── OSV response normalization ───────────────────────────────────────────────
// (CVSS v3 vector scoring lives in ./cvss.ts — pure, provider-agnostic.)

/** Coarse word → rank fallback for sources that publish words instead of vectors. */
function rankFromWord(word: string | null | undefined): SeverityRank | null {
  const w = (word ?? '').trim().toLowerCase();
  if (!w) return null;
  if (w.includes('critical')) return 'critical';
  if (w.includes('high')) return 'high';
  if (w.includes('medium') || w.includes('moderate') || w.includes('important')) return 'medium';
  if (w.includes('low') || w.includes('minor')) return 'low';
  return null;
}

interface OsvAffected {
  package?: { ecosystem?: string; name?: string };
  ranges?: Array<{ type?: string; events?: Array<Record<string, unknown>> }>;
}
interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  published?: string;
  affected?: OsvAffected[];
  severity?: Array<{ type?: string; score?: string }>;
  database_specific?: Record<string, unknown>;
}

/** Merges OSV "events" ({introduced}/{fixed}) into UNM AffectedRange bounds. */
function eventsToRanges(vuln: OsvVuln, pkgName: string): AffectedRange[] {
  const ranges: AffectedRange[] = [];
  for (const aff of vuln.affected ?? []) {
    // A single advisory can list several packages — keep only the one we asked about.
    if ((aff.package?.name ?? '').toLowerCase() !== pkgName.toLowerCase()) continue;
    for (const range of aff.ranges ?? []) {
      for (const ev of range.events ?? []) {
        const introduced = typeof ev['introduced'] === 'string' ? (ev['introduced'] as string) : null;
        const fixed = typeof ev['fixed'] === 'string' ? (ev['fixed'] as string) : null;
        if (introduced !== null && introduced.trim() !== '') ranges.push({ type: '>', version: introduced });
        if (fixed !== null && fixed.trim() !== '') ranges.push({ type: '<', version: fixed });
      }
    }
  }
  return ranges;
}

/** Resolves the display id — prefer a CVE alias, then an embedded CVE (Debian/Alpine source ids like `DEBIAN-CVE-2022-2274` carry no aliases field). */
function displayId(vuln: OsvVuln): string {
  const cve = (vuln.aliases ?? []).find((a) => /^CVE-\d{4}-\d+$/i.test(a));
  if (cve) return cve.toUpperCase();
  const embedded = vuln.id.match(/(CVE-\d{4}-\d+)/i);
  return embedded ? embedded[1].toUpperCase() : vuln.id;
}

/** Extracts the best severity (score + rank) from one OSV vulnerability entry. */
function extractSeverity(vuln: OsvVuln): { score: number | null; rank: SeverityRank } {
  for (const sev of vuln.severity ?? []) {
    if (!sev.type || !/CVSS/i.test(sev.type) || typeof sev.score !== 'string') continue;
    const parsed = parseCvssVector(sev.score);
    if (parsed !== null) return { score: parsed, rank: severityRankForScore(parsed) };
  }
  // Fallback: word-based severity from the source database (e.g. Alpine's tracker).
  const word = vuln.database_specific?.['severity'];
  const rank = rankFromWord(typeof word === 'string' ? word : null);
  return { score: null, rank: rank ?? 'unknown' };
}

/** Normalizes one OSV vulnerability entry for the package we queried. */
function toAdvisoryRow(vuln: OsvVuln, pkg: PackageQuery): AdvisoryRow | null {
  if (!vuln || typeof vuln.id !== 'string') return null;
  const ranges = eventsToRanges(vuln, pkg.name);
  const { score, rank } = extractSeverity(vuln);
  let summary = (vuln.summary ?? '').trim();
  if (!summary && vuln.details) summary = vuln.details.trim().slice(0, 500);
  return {
    ecosystem: pkg.ecosystem, // the OSV ecosystem we queried with (stable PK part)
    packageName: pkg.name,
    id: displayId(vuln),
    severityScore: score,
    severityRank: rank,
    affectedRanges: ranges,
    summary: summary || null,
    url: `https://osv.dev/vulnerability/${encodeURIComponent(vuln.id)}`,
    publishedAt: vuln.published ?? null,
  };
}

// ── The provider ─────────────────────────────────────────────────────────────

/** Runs `fn` over the items with at most `limit` in-flight calls. */
async function mapWithConcurrency<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out = new Array<R>(items.length);
  let next = 0;
  async function worker(): Promise<void> {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]);
    }
  }
  const workers: Promise<void>[] = [];
  for (let i = 0; i < Math.min(limit, items.length); i++) workers.push(worker());
  await Promise.all(workers);
  return out;
}

/**
 * Fetches every advisory for the given (ecosystem, package) pairs from OSV.dev.
 * Throws on transport/HTTP failure or when EVERY query failed — a partial
 * success (some queries errored) still returns what succeeded; the worker logs
 * the per-query errors. Read-only + idempotent by construction.
 */
export const osvProvider: CveProvider = {
  id: 'osv',

  async fetchAdvisories(pkgs: PackageQuery[]): Promise<AdvisoryRow[]> {
    if (pkgs.length === 0) return [];

    // Map onto OSV ecosystems, dropping tags with no known source AND unversioned
    // packages — OSV's Debian/Alpine sources need a version to return metadata.
    const seen = new Set<string>();
    const queries: Array<{ pkg: PackageQuery; osvEcosystem: string }> = [];
    for (const p of pkgs) {
      const eco = mapToOsvEcosystem(p.ecosystem);
      if (!eco) continue;
      const version = typeof p.version === 'string' ? p.version.trim() : '';
      if (!version) continue; // unversioned — cannot be queried (see PackageQuery.version)
      const key = `${eco}|${p.name.toLowerCase()}|${version}`;
      if (seen.has(key)) continue; // same triple reported by several devices → one query
      seen.add(key);
      queries.push({ pkg: { ...p, version }, osvEcosystem: eco });
    }
    if (queries.length === 0) return []; // nothing mappable — not an error

    const provider = await resolveWebFetchProvider();
    if (!provider) {
      throw new Error('No web-fetch plugin is registered/online — start the web-fetch-plugin service');
    }
    const values = await getEffectiveValues();
    const proxyUrl = String(values.webFetchProxyUrl ?? '').trim() || undefined;
    const timeoutMs = Number(values.webFetchTimeoutMs) || 120_000;

    // One POST /v1/query per distinct triple (querybatch strips metadata — see header).
    let failedQueries = 0;
    const results = await mapWithConcurrency(queries, CONCURRENCY, async ({ pkg, osvEcosystem }) => {
      try {
        const { bytes } = await fetchViaWebFetch(provider, {
          url: OSV_QUERY_URL,
          method: 'POST',
          body: { package: { ecosystem: osvEcosystem, name: pkg.name }, version: pkg.version ?? undefined },
          proxyUrl,
          timeoutMs,
        });
        return JSON.parse(bytes.toString('utf8')) as { vulns?: OsvVuln[]; error?: string };
      } catch (err) {
        failedQueries += 1;
        // eslint-disable-next-line no-console
        console.warn(`[cve] OSV query ${osvEcosystem}/${pkg.name}@${pkg.version} failed:`, (err as Error).message);
        return null;
      }
    });

    const out: AdvisoryRow[] = [];
    for (let i = 0; i < queries.length; i++) {
      const entry = results[i];
      if (!entry) continue; // transport failure — already counted/logged
      if (entry.error) {
        // eslint-disable-next-line no-console
        console.warn(`[cve] OSV query ${queries[i].pkg.ecosystem}/${queries[i].pkg.name}@${queries[i].pkg.version}: ${entry.error}`);
        continue;
      }
      for (const vuln of entry.vulns ?? []) {
        const row = toAdvisoryRow(vuln, queries[i].pkg);
        if (row) out.push(row);
      }
    }

    if (failedQueries > 0 && out.length === 0) {
      throw new Error(`All ${failedQueries} OSV quer(ies) failed — no advisories retrieved`);
    }
    return out;
  },
};
