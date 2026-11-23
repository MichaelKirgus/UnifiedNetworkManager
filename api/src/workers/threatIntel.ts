/**
 * Threat intelligence — background worker (leader-gated, key 9023).
 *
 * Two jobs on one beat:
 *
 *   FETCH — every enabled IOC feed source (threat_intel_sources rows, managed
 *     via POST /v1/threat-intel/sources) is re-fetched through the web-fetch
 *     broker (`webFetchBroker`, same egress path as OSV/GeoIP) at the
 *     `threatIntelFetchIntervalMinutes` cadence. After each successful fetch
 *     the RAW feed bytes are stored in the central file repository (category
 *     'threat-intel', one current snapshot per source — superseded files are
 *     pruned, identical content dedupes to a no-op) so the exact list behind
 *     any finding is auditable/downloadable; the parsed indicator tables stay
 *     authoritative for matching and a repo failure never breaks the cycle.
 *     Supported formats:
 *       - ip-list     — one IPv4/IPv6 address or CIDR per line (# and ; comments,
 *         blank lines and URLs skipped);
 *       - stix        — STIX 2.x bundle; equality patterns of type indicators are
 *         extracted ([ipv4-addr:value = '…'] / [ipv6-addr:…]);
 *       - domain-list — plain-text domain blocklist: bare domains (Pi-hole/
 *         AdGuard style) plus Adblock/EasyList filter rules (||evil.com^, |host,
 *         $options, [section] headers; unblock @@ rules and regex filters are
 *         skipped). Domains land in threat_domain_iocs (threat_iocs.ioc is INET
 *         and cannot hold names); a listed domain matches itself AND every subdomain.
 *     A fetch is an authoritative SNAPSHOT per source: all parsed values are
 *     upserted into the format's table, then rows not re-upserted in the cycle
 *     are pruned by lastSeenAt — indicators a feed drops disappear automatically.
 *
 *   MATCH — flow destinations (flow_agg_5m, same bucket-lag convention as the
 *     rollup worker), firewall-event IPs (firewall_events tsMs axis) and DNS
 *     query events (dns_query_events tsMs axis, pushed by plugins from the
 *     appliance resolver) are checked against the active indicator set, which
 *     is cached in memory (exact host addresses + CIDR containment for v4/v6,
 *     plus domain suffix matching). Every hit upserts a finding of kind
 *     'ioc-hit' or 'dns-ioc-hit' into flow_security_findings — the SAME table,
 *     auto-resolve sweep and securityFinding automation trigger as the flow
 *     security detectors — so hits raise one notification when first seen and
 *     can drive automation rules (block plans, webhooks) without extra wiring.
 *
 * Timing: cursors start at "now" on boot (pre-existing history is never
 * re-scanned — same convention as every other worker). Findings not
 * re-observed for 24 h auto-resolve via the flow-security sweep; retention is
 * shared with the other finding kinds.
 */

import { v4 as uuidv4 } from 'uuid';
import { pool } from '../db';
import { getEffectiveValues } from '../systemSettings';
import { emitNotification } from '../notifications';
import { addRepoFile, deleteRepoFile, sanitizeTags } from '../fileRepo';
import { resolveWebFetchProvider, fetchViaWebFetch } from '../webFetchBroker';
import { LEADER_KEYS } from './leader';
import { initWorker, trackBeat } from './stats';
import { upsertFinding, type FindingInput } from './flowSecurity';
// All IP parsing/math lives in the shared SDK module — never re-implement it here.
import { ipToWords, ipv4FromInt, ipv6FromWords, splitCidr, stripZoneId, wordsContain } from '@unm/plugin-sdk';

const BEAT_MS = 60_000;
const BUCKET_MS = 300_000; // flow_agg_5m bucket size
/** A bucket may be matched only once it closed at least one full rollup interval ago. */
const PROCESS_LAG_MS = 2 * BUCKET_MS;
/** Download bound per feed (the broker enforces it on the plugin side too).
 * Public blocklists run to many MB — keep this comfortably above them. */
const MAX_FETCH_BYTES = 64 * 1_048_576; // 64 MiB
const FETCH_TIMEOUT_MS = 300_000; // large lists stream slowly through proxies
/** Active-IOC cache lifetime — also invalidated after every successful fetch. */
const IOC_CACHE_TTL_MS = 15 * 60_000;
/** An EMPTY set is re-checked much sooner — a newly added/enabled source should
 * start matching within one beat, not wait out the full TTL. */
const IOC_CACHE_EMPTY_TTL_MS = 30_000;
/** Max firewall-event rows scanned per beat (the watermark advances past them). */
const FW_SCAN_LIMIT = 20_000;
/** Max DNS query rows scanned per beat (same convention as the firewall pass). */
const DNS_SCAN_LIMIT = 20_000;

export const THREAT_INTEL_FORMATS = ['ip-list', 'stix', 'domain-list'] as const;
export type ThreatIntelFormat = (typeof THREAT_INTEL_FORMATS)[number];

/**
 * File name for the raw feed snapshot stored in the central file repository
 * (category 'threat-intel'). Date-suffixed like the geoip worker: a changed
 * feed on the same day gets addRepoFile's numeric collision suffix instead of
 * overwriting, and unchanged content dedupes to the existing row by sha256.
 */
export function threatIntelFileName(sourceName: string, format: ThreatIntelFormat): string {
  const base = sourceName.replace(/[^\w.\-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 80) || 'feed';
  const ext = format === 'stix' ? 'json' : 'txt';
  return `threat-intel-${base}-${new Date().toISOString().slice(0, 10)}.${ext}`;
}

// ── State ────────────────────────────────────────────────────────────────────

/** Last matched flow bucket START (ms). Only buckets after boot are scanned. */
let cursorBucketMs = Math.floor(Date.now() / BUCKET_MS) * BUCKET_MS;
/** firewall_events tsMs watermark — rows with tsMs > this are unscanned. */
let fwWatermarkMs = Date.now();
/** dns_query_events tsMs watermark — rows with tsMs > this are unscanned. */
let dnsWatermarkMs = Date.now();
/** Per-source last fetch ATTEMPT (ms) — bounds retry frequency on failure. */
const attemptAt = new Map<string, number>();
let iocCache: IocCache | null = null;
let lastRunAt: string | null = null;
let lastError: string | null = null;

/** Snapshot for GET /v1/threat-intel (worker status line). */
export function getThreatIntelStats(): {
  lastRunAt: string | null;
  lastError: string | null;
  iocTotal: number;
  cursorBucketMs: number;
  /** firewall_events tsMs watermark — events with tsMs > this have been scanned. */
  fwWatermarkMs: number;
  /** dns_query_events tsMs watermark — queries with tsMs > this have been scanned. */
  dnsWatermarkMs: number;
} {
  return { lastRunAt, lastError, iocTotal: iocCache?.total ?? 0, cursorBucketMs, fwWatermarkMs, dnsWatermarkMs };
}

// ── IP / CIDR matching (v4 + v6) ─────────────────────────────────────────────
// Address parsing and containment math live in @unm/plugin-sdk (ip.ts); this
// module only adds threat-intel semantics on top (exact-vs-CIDR entries, the
// canonical exact-match key, source attribution).

/** One active indicator set: exact host addresses + CIDR networks + domains. */
export interface IocCache {
  /** Canonical address string → source names containing it. */
  exact: Map<string, string[]>;
  cidrs: Array<{ words: number[]; prefix: number; family: 'v4' | 'v6'; sources: string[] }>;
  /** Normalized domain (lowercase, no trailing dot) → source names listing it. */
  domains: Map<string, string[]>;
  /** Source name → notification severity for findings raised by that feed. */
  severities: Map<string, string>;
  loadedAt: number;
  total: number;
}

/**
 * Parses a bare IP or CIDR into matchable form. Returns null for anything that
 * is not a valid IPv4/IPv6 address (or network) — callers count those as
 * skipped, never throw on feed noise. A /32 or /128 "network" collapses to an
 * exact host entry (prefix null). `key` is the canonical literal (dotted quad
 * for v4, RFC 5952 compressed form for v6) used as the exact-match map key.
 */
export function parseIocValue(raw: string): { key: string; words: number[]; prefix: number | null; family: 'v4' | 'v6' } | null {
  const addr = stripZoneId(String(raw).trim());
  if (!addr) return null;
  let netPart = addr;
  let prefix: number | null = null;
  const slash = addr.indexOf('/');
  if (slash >= 0) {
    const s = splitCidr(addr); // validates the prefix range for the address family
    if (!s) return null;
    netPart = s.net;
    prefix = s.prefix;
  }
  const p = ipToWords(netPart);
  if (!p) return null;
  const maxPrefix = p.family === 'v6' ? 128 : 32;
  // A /32 or /128 "network" is just a host — treat it as an exact entry.
  if (prefix !== null && prefix === maxPrefix) prefix = null;
  const key = p.family === 'v4' ? ipv4FromInt(((p.words[6] << 16) | p.words[7]) >>> 0) : ipv6FromWords(p.words);
  return { key, words: p.words, prefix, family: p.family };
}

/** Matches one IP against the cache; returns the source names when listed. */
export function matchIoc(ipRaw: string | null | undefined, cache: IocCache): { ip: string; sources: string[] } | null {
  if (!ipRaw) return null;
  const p = parseIocValue(String(ipRaw));
  if (!p) return null;
  const exactSources = cache.exact.get(p.key);
  if (exactSources && exactSources.length > 0) return { ip: p.key, sources: exactSources };
  const hits: string[] = [];
  for (const c of cache.cidrs) {
    if (c.family !== p.family) continue;
    if (wordsContain(p.words, c.words, c.prefix, p.family)) hits.push(...c.sources);
  }
  if (hits.length === 0) return null;
  return { ip: p.key, sources: [...new Set(hits)] };
}

/**
 * Matches one queried name against the domain set with Pi-hole semantics: a
 * listed domain matches itself AND every subdomain. Walks the name's parent
 * suffixes (a.b.evil.com → b.evil.com → evil.com) collecting EVERY level that
 * is listed, so source attribution covers feeds at multiple depths. Returns
 * the most specific matched domain plus the union of listing sources.
 */
export function matchDomain(nameRaw: string | null | undefined, cache: IocCache): { domain: string; sources: string[] } | null {
  if (!nameRaw || cache.domains.size === 0) return null;
  let name = String(nameRaw).trim().toLowerCase().replace(/\.$/, '');
  const hits: Array<{ domain: string; sources: string[] }> = [];
  while (name.length > 0) {
    const sources = cache.domains.get(name);
    if (sources && sources.length > 0) hits.push({ domain: name, sources });
    // Parent suffix = drop the FIRST label (a.b.evil.com → b.evil.com). The
    // walk goes most-specific to least-specific, so hits[0] is the deepest match.
    const dot = name.indexOf('.');
    if (dot < 0) break; // single label left — checked above, no parent to walk to
    name = name.slice(dot + 1);
  }
  if (hits.length === 0) return null;
  return { domain: hits[0].domain, sources: [...new Set(hits.flatMap((h) => h.sources))] };
}

// ── Feed parsing ─────────────────────────────────────────────────────────────

export interface ParsedFeed {
  values: string[]; // deduped raw IP/CIDR strings (validated)
  skipped: number; // unparseable lines / entries over the cap
}

/** Plain-text blocklist: one address or CIDR per line. */
export function parseIpList(bytes: Buffer, maxIocs: number): ParsedFeed {
  const values = new Set<string>();
  let skipped = 0;
  for (const rawLine of bytes.toString('utf8').split(/\r?\n/)) {
    if (values.size >= maxIocs) {
      skipped += 1; // count the remainder without parsing it
      continue;
    }
    const line = rawLine.trim().replace(/,+$/, '');
    if (!line || line.startsWith('#') || line.startsWith(';') || /^https?:\/\//i.test(line)) continue;
    if (parseIocValue(line) === null) {
      skipped += 1;
      continue;
    }
    values.add(line);
  }
  return { values: [...values], skipped };
}

/** STIX 2.x bundle — equality patterns of ipv4/ipv6 indicators. */
export function parseStix(bytes: Buffer, maxIocs: number): ParsedFeed {
  let bundle: unknown;
  try {
    bundle = JSON.parse(bytes.toString('utf8'));
  } catch {
    throw new Error('feed is not valid JSON (STIX expected)');
  }
  const rawObjects = Array.isArray(bundle) ? bundle : (bundle as { objects?: unknown }).objects;
  if (!Array.isArray(rawObjects)) throw new Error('STIX bundle has no objects array');
  const objects: unknown[] = rawObjects;
  // No leading '[' anchor: STIX OR patterns repeat the object reference
  // WITHOUT a bracket (…'a' OR ipv4-addr:value = 'b'), and every equality
  // value in an indicator's pattern is wanted. Negations (!=) never match.
  const patternRe = /(?:ipv4|ipv6)-addr:value\s*=\s*'([^']+)'/g;
  const values = new Set<string>();
  let skipped = 0;
  for (const obj of objects) {
    if (!obj || typeof obj !== 'object') continue;
    const o = obj as { type?: unknown; pattern?: unknown };
    if (o.type !== 'indicator' || typeof o.pattern !== 'string') continue;
    let m: RegExpExecArray | null;
    patternRe.lastIndex = 0;
    while ((m = patternRe.exec(o.pattern)) !== null) {
      const v = m[1];
      if (parseIocValue(v) === null) {
        skipped += 1;
        continue;
      }
      if (values.size >= maxIocs) {
        skipped += 1;
        continue;
      }
      values.add(v);
    }
  }
  return { values: [...values], skipped };
}

/**
 * Normalizes one domain-list line to its matchable form, or null when it is not
 * a usable domain. Lowercases, strips a leading "*." wildcard (a listed domain
 * matches itself AND every subdomain — the wildcard adds nothing) and a
 * trailing FQDN dot. Labels must be RFC-1035 alnum/hyphen; the TLD must be at
 * least two letters (rejects bare labels like "localhost" and IP literals).
 */
export function normalizeDomain(raw: string): string | null {
  let d = String(raw).trim().toLowerCase();
  if (!d) return null;
  d = d.replace(/^\*\./, '').replace(/\.$/, '');
  if (d.length < 3 || d.length > 253) return null;
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/.test(d)) return null;
  if (!d.includes('.')) return null; // bare labels (localhost, …) are not blocklist domains
  const tld = d.slice(d.lastIndexOf('.') + 1);
  if (!/^[a-z]{2,}$/.test(tld)) return null;
  return d;
}

/**
 * Normalizes one domain-list line in EITHER style to its matchable form, or
 * null when it carries no usable domain. Bare domains (Pi-hole/AdGuard) go
 * straight through normalizeDomain; Adblock/EasyList filter rules are reduced
 * first — $options dropped at the first `$`, leading URL anchors (`|` / `||`)
 * and the trailing `^` boundary stripped, path-scoped rules collapsed to their
 * host part (the same approximation Pi-hole makes when importing adblock
 * lists). Regex filters (/…/) carry no literal domain.
 */
export function normalizeDomainLine(raw: string): string | null {
  let line = String(raw);
  if (line.startsWith('/')) return null; // regex filter — nothing to ingest
  const dollar = line.indexOf('$');
  if (dollar >= 0) line = line.slice(0, dollar); // $document, $third-party, …
  line = line.replace(/^\|\|?/, ''); // leading URL anchor(s)
  const cut = line.search(/[/^]/);
  if (cut >= 0) line = line.slice(0, cut); // ^ boundary or /path… scope
  return normalizeDomain(line);
}

/**
 * Plain-text domain blocklist: bare domains (Pi-hole/AdGuard format) and
 * Adblock/EasyList filter rules. [section] headers are structural; unblock
 * rules (@@…) and regex filters are counted as skipped entries.
 */
export function parseDomainList(bytes: Buffer, maxIocs: number): ParsedFeed {
  const values = new Set<string>();
  let skipped = 0;
  for (const rawLine of bytes.toString('utf8').split(/\r?\n/)) {
    if (values.size >= maxIocs) {
      skipped += 1; // count the remainder without parsing it
      continue;
    }
    const line = rawLine.trim().replace(/,+$/, '');
    // Pi-hole lists use "!" comments in addition to # and ;. Adblock lists add
    // [section] headers ([Adblock Plus], [header], …) — structural, not entries.
    if (!line || line.startsWith('#') || line.startsWith(';') || line.startsWith('!') || /^\[.*\]$/.test(line) || /^https?:\/\//i.test(line)) continue;
    // Adblock unblock rules are allow-rules — never block indicators.
    if (line.startsWith('@@') || line.startsWith('#@!')) {
      skipped += 1;
      continue;
    }
    const d = normalizeDomainLine(line);
    if (d === null) {
      skipped += 1;
      continue;
    }
    values.add(d);
  }
  return { values: [...values], skipped };
}

// ── Fetch cycle ──────────────────────────────────────────────────────────────

interface SourceRow {
  id: string;
  name: string;
  url: string;
  format: ThreatIntelFormat;
  enabled: boolean;
  lastSuccessAt: string | null;
  /** Central file-repo row holding the raw snapshot of the last successful fetch (null = none yet). */
  repoFileId: string | null;
}

async function markSourceError(id: string, message: string): Promise<void> {
  try {
    await pool.query(`UPDATE threat_intel_sources SET "lastError" = $1 WHERE id = $2`, [message.slice(0, 500), id]);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('[threat-intel] failed to record source error:', err);
  }
}

/**
 * Fetches ONE source and replaces its indicator set (snapshot semantics).
 * Throws on any failure — callers mark the source's lastError.
 */
async function fetchSource(source: SourceRow): Promise<void> {
  const values = await getEffectiveValues();
  const maxIocs = Number(values.threatIntelMaxIocsPerSource) || 250_000;

  const provider = await resolveWebFetchProvider();
  if (!provider) throw new Error('no web-fetch plugin online — egress unavailable');

  const cycleStartIso = new Date().toISOString(); // rows not re-upserted after this are stale
  const { bytes } = await fetchViaWebFetch(provider, { url: source.url, maxBytes: MAX_FETCH_BYTES, timeoutMs: FETCH_TIMEOUT_MS });

  // Domain-list feeds store names in threat_domain_iocs (threat_iocs.ioc is
  // INET and cannot hold them); ip/stix feeds keep using the address table.
  const isDomain = source.format === 'domain-list';
  const parsed: ParsedFeed = isDomain ? parseDomainList(bytes, maxIocs) : source.format === 'stix' ? parseStix(bytes, maxIocs) : parseIpList(bytes, maxIocs);
  if (parsed.values.length === 0 && parsed.skipped > 0) {
    throw new Error(`feed returned no usable indicators (${parsed.skipped} unparseable entries)`);
  }

  // Batched upsert — deduped values only (intra-statement duplicates would
  // trip ON CONFLICT with "cannot affect row a second time").
  for (let i = 0; i < parsed.values.length; i += 1_000) {
    const chunk = parsed.values.slice(i, i + 1_000);
    const ids = chunk.map(() => uuidv4());
    if (isDomain) {
      await pool.query(
        `INSERT INTO threat_domain_iocs (id, "sourceId", domain, "firstSeenAt", "lastSeenAt")
         SELECT u.id, $1, u.val, $2, $2
         FROM unnest($3::text[], $4::text[]) AS u(id, val)
         ON CONFLICT ("sourceId", domain) DO UPDATE SET "lastSeenAt" = EXCLUDED."lastSeenAt"`,
        [source.id, cycleStartIso, ids, chunk]
      );
    } else {
      await pool.query(
        `INSERT INTO threat_iocs (id, "sourceId", ioc, "firstSeenAt", "lastSeenAt")
         SELECT u.id, $1, u.val::inet, $2, $2
         FROM unnest($3::text[], $4::text[]) AS u(id, val)
         ON CONFLICT ("sourceId", ioc) DO UPDATE SET "lastSeenAt" = EXCLUDED."lastSeenAt"`,
        [source.id, cycleStartIso, ids, chunk]
      );
    }
  }

  // Snapshot prune — indicators the feed no longer lists.
  const table = isDomain ? 'threat_domain_iocs' : 'threat_iocs';
  await pool.query(`DELETE FROM ${table} WHERE "sourceId" = $1 AND "lastSeenAt" < $2`, [source.id, cycleStartIso]);
  const countRes = await pool.query(`SELECT COUNT(*)::int AS n FROM ${table} WHERE "sourceId" = $1`, [source.id]);
  await pool.query(
    `UPDATE threat_intel_sources SET "iocCount" = $1, "lastSuccessAt" = $2, "lastError" = NULL WHERE id = $3`,
    [Number(countRes.rows[0]?.n ?? 0), cycleStartIso, source.id]
  );

  // Raw snapshot → central file repository (category 'threat-intel'): the exact
  // feed content behind this fetch stays auditable/downloadable. One current
  // snapshot per source — a superseded file is pruned after the new one lands,
  // and unchanged content dedupes to the existing row by sha256 (no-op). The
  // parsed indicator tables above remain authoritative for matching, so a repo
  // failure must never break or roll back the fetch cycle.
  try {
    const { entry } = await addRepoFile({
      data: bytes,
      name: threatIntelFileName(source.name, source.format),
      category: 'threat-intel',
      // Flat feature tags — group/filter these snapshots in the Files page
      // without any folder structure (portable across repo backends).
      tags: ['threat-intel', ...sanitizeTags([source.name])],
      uploadedBy: 'plugin',
    });
    if (source.repoFileId && source.repoFileId !== entry.id) {
      await deleteRepoFile(source.repoFileId).catch(() => undefined); // superseded — keep only the current snapshot
    }
    await pool.query(`UPDATE threat_intel_sources SET "repoFileId" = $1 WHERE id = $2`, [entry.id, source.id]);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.warn(`[threat-intel] raw snapshot for "${source.name}" not stored in the file repo:`, (err as Error).message);
  }

  iocCache = null; // the active set changed — rebuild on next use
  // eslint-disable-next-line no-console
  console.log(`[threat-intel] fetched "${source.name}": ${parsed.values.length} indicators (${parsed.skipped} skipped)`);
}

/** Fetches every enabled source whose interval has elapsed. One failure never breaks the beat. */
async function fetchDueSources(intervalMs: number): Promise<void> {
  const now = Date.now();
  const res = await pool.query<SourceRow>(`SELECT id, name, url, format, enabled, "lastSuccessAt", "repoFileId" FROM threat_intel_sources WHERE enabled`);
  for (const s of res.rows) {
    // Due when neither the last success nor the last attempt is recent — a
    // source that never succeeded fetches immediately; failures retry at the
    // same cadence instead of hammering the feed every minute.
    const lastOk = s.lastSuccessAt ? Date.parse(s.lastSuccessAt) : NaN;
    const reference = Math.max(Number.isFinite(lastOk) ? lastOk : 0, attemptAt.get(s.id) ?? 0);
    if (reference > 0 && now - reference < intervalMs) continue;
    attemptAt.set(s.id, now); // mark the attempt BEFORE running it
    try {
      await fetchSource(s);
    } catch (err) {
      const msg = (err as Error).message;
      // eslint-disable-next-line no-console
      console.error(`[threat-intel] fetch of "${s.name}" failed:`, msg);
      void markSourceError(s.id, msg);
    }
  }
}

/**
 * Triggers an immediate fetch cycle (POST /v1/threat-intel/fetch and new
 * source creation). Fire-and-forget per source — the route returns as soon as
 * the work is queued; outcomes surface in each source's lastSuccessAt/lastError.
 */
export async function triggerThreatIntelFetch(sourceId?: string): Promise<{ triggered: number }> {
  const sql = sourceId ? `SELECT id, name, url, format, enabled, "lastSuccessAt", "repoFileId" FROM threat_intel_sources WHERE enabled AND id = $1` : `SELECT id, name, url, format, enabled, "lastSuccessAt", "repoFileId" FROM threat_intel_sources WHERE enabled`;
  const res = await pool.query<SourceRow>(sql, sourceId ? [sourceId] : []);
  for (const s of res.rows) {
    attemptAt.set(s.id, Date.now());
    void fetchSource(s).catch((err) => {
      // eslint-disable-next-line no-console
      console.error(`[threat-intel] manual fetch of "${s.name}" failed:`, (err as Error).message);
      void markSourceError(s.id, (err as Error).message);
    });
  }
  return { triggered: res.rows.length };
}

// ── Active-IOC cache ─────────────────────────────────────────────────────────

/** Drops the in-memory IOC set — called after route-level changes that do not
 * go through a fetch (enabling a stored source, deleting one). */
export function invalidateIocCache(): void {
  iocCache = null;
}

async function ensureIocCache(): Promise<IocCache | null> {
  const ttl = iocCache && iocCache.total === 0 ? IOC_CACHE_EMPTY_TTL_MS : IOC_CACHE_TTL_MS;
  if (iocCache && Date.now() - iocCache.loadedAt < ttl) return iocCache;
  // Disabled feeds do not contribute to matching (their rows stay stored so a
  // re-enable restores the indicators without a re-fetch). Both indicator
  // tables load in parallel — address feeds and domain-list feeds are common.
  const [res, domRes] = await Promise.all([
    pool.query<{ ioc: string; name: string; severity: string }>(
      `SELECT t.ioc::text AS ioc, s.name, s.severity FROM threat_iocs t JOIN threat_intel_sources s ON s.id = t."sourceId" WHERE s.enabled`
    ),
    pool.query<{ domain: string; name: string; severity: string }>(
      `SELECT t.domain, s.name, s.severity FROM threat_domain_iocs t JOIN threat_intel_sources s ON s.id = t."sourceId" WHERE s.enabled`
    ),
  ]);
  const exact = new Map<string, string[]>();
  const cidrs: IocCache['cidrs'] = [];
  for (const r of res.rows) {
    const p = parseIocValue(String(r.ioc));
    if (!p) continue; // defensive — the column is INET so this should not happen
    if (p.prefix === null) {
      const list = exact.get(p.key) ?? [];
      list.push(r.name);
      exact.set(p.key, list);
    } else {
      cidrs.push({ words: p.words, prefix: p.prefix, family: p.family, sources: [r.name] });
    }
  }
  const domains = new Map<string, string[]>();
  for (const r of domRes.rows) {
    const d = normalizeDomain(String(r.domain));
    if (!d) continue; // defensive — rows are normalized at parse time
    const list = domains.get(d) ?? [];
    list.push(r.name);
    domains.set(d, list);
  }
  // Per-feed notification severity (a source only ever appears in ONE table,
  // but set() is idempotent so merging both row sets is safe).
  const severities = new Map<string, string>();
  for (const r of res.rows) severities.set(r.name, String(r.severity));
  for (const r of domRes.rows) severities.set(r.name, String(r.severity));
  iocCache = { exact, cidrs, domains, severities, loadedAt: Date.now(), total: res.rows.length + domRes.rows.length };
  // eslint-disable-next-line no-console
  console.log(`[threat-intel] IOC cache built: ${iocCache.total} active indicator(s) (${domains.size} domain)`);
  return iocCache;
}

// ── Matching passes ──────────────────────────────────────────────────────────
/** Severity ranks for finding escalation (a hit against any matched feed at a higher rank wins). */
const SEVERITY_RANK: Record<'info' | 'warning' | 'critical', number> = { info: 0, warning: 1, critical: 2 };

/** Worst notification severity among the matched sources — defaults to 'warning' when unknown. */
export function worstSeverity(sources: string[], severities: Map<string, string>): 'info' | 'warning' | 'critical' {
  let rank = -1;
  for (const s of sources) {
    const r = SEVERITY_RANK[(severities.get(s) ?? '') as 'info' | 'warning' | 'critical'];
    if (r !== undefined && r > rank) rank = r;
  }
  return rank === 0 ? 'info' : rank === 2 ? 'critical' : 'warning';
}
function humanBytes(n: number): string {
  if (!Number.isFinite(n) || n <= 0) return '0 B';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v >= 100 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}

/** Emits the one-shot notification for a freshly detected IOC hit. Best-effort. */
async function notifyIocHit(f: FindingInput): Promise<void> {
  try {
    const hits = (f.context.iocHits as Array<{ ip: string; sources: string[] }> | undefined) ?? [];
    const listed = hits.length > 0 ? hits.map((h) => h.ip).join(', ') : String(f.dstIp ?? f.srcIp);
    const sources = [...new Set(hits.flatMap((h) => h.sources))].join(', ');
    await emitNotification({
      severity: f.severity, // per-feed severity (escalated across matched feeds)
      source: f.deviceId ? 'device' : 'system',
      deviceId: f.deviceId ?? undefined,
      title: `Threat-intel hit: ${listed}`,
      message: `${f.detail}${sources ? ` (feed${sources.length > 1 ? 's' : ''}: ${sources})` : ''}`,
      dedupeKey: `flow-security:ioc-hit:${f.srcIp}:${f.dstIp ?? ''}`,
      context: { ...f.context, srcIp: f.srcIp, dstIp: f.dstIp },
    });
  } catch (err) {
    // Notifications are best-effort by contract — never break the beat.
    lastError = `notification failed: ${(err as Error).message}`;
    // eslint-disable-next-line no-console
    console.error('[threat-intel] notification emission failed:', err);
  }
}

/** Flow pass — distinct destinations in the closed buckets vs the active set. */
async function matchFlows(fromIso: string, toIso: string): Promise<void> {
  const cache = await ensureIocCache();
  if (!cache || cache.total === 0) return; // no indicators yet — nothing to match

  const dstRes = await pool.query<{ ip: string }>(`SELECT DISTINCT "dstIp"::text AS ip FROM flow_agg_5m WHERE bucket >= $1 AND bucket < $2`, [fromIso, toIso]);
  const hits: string[] = [];
  for (const r of dstRes.rows) {
    if (matchIoc(r.ip, cache)) hits.push(String(r.ip));
  }
  if (hits.length === 0) return;

  // Peer context for the hit destinations — one batched query.
  const pairRes = await pool.query<{ src: string; dst: string; bytes: string | null; hostname: string | null; device_id: string | null }>(
    `SELECT "srcIp"::text AS src, "dstIp"::text AS dst, SUM("estBytes")::bigint AS bytes,
            MAX("srcHostname") AS hostname, MAX("srcDeviceId") AS device_id
     FROM flow_agg_5m
     WHERE bucket >= $1 AND bucket < $2 AND "dstIp" = ANY($3::inet[])
     GROUP BY 1, 2`,
    [fromIso, toIso, hits]
  );

  for (const r of pairRes.rows) {
    if (!r.src || !String(r.src).trim()) continue; // findings require a valid source address
    const m = matchIoc(r.dst, cache); // known hit — re-resolve the source names
    if (!m) continue;
    const srcIp = String(r.src);
    const dstIp = String(r.dst);
    const estBytes = Number(r.bytes ?? 0);
    const hostname = r.hostname ? String(r.hostname) : null;
    const deviceId = r.device_id ? String(r.device_id) : null;
    const detail = `Traffic from ${hostname ?? srcIp} to threat-intel listed destination ${dstIp} — ${humanBytes(estBytes)} in the triggering window.`;
    const input: FindingInput = {
      kind: 'ioc-hit',
      srcIp,
      dstIp,
      severity: worstSeverity(m.sources, cache.severities),
      detail,
      context: { iocHits: [{ ip: m.ip, sources: m.sources }], estBytes, srcHostname: hostname },
      deviceId,
    };
    const isNew = await upsertFinding(input);
    if (isNew) {
      // eslint-disable-next-line no-console
      console.log(`[threat-intel] ioc-hit finding: ${input.srcIp} → ${input.dstIp ?? '-'}`);
      await notifyIocHit(input);
    }
  }
}

/** Firewall pass — event IPs since the watermark vs the active set. */
async function matchFirewallEvents(): Promise<void> {
  const cache = await ensureIocCache();
  if (!cache || cache.total === 0) return;

  // tsMs is BIGINT epoch ms (plugins stamp it); a +5 min guard keeps future-
  // skewed rows from being scanned twice.
  const res = await pool.query<{ srcIp: string; dstIp: string; action: string; deviceId: string; tsMs: string | number }>(
    `SELECT "srcIp", "dstIp", action, "deviceId", "tsMs"
     FROM firewall_events
     WHERE "tsMs" > $1 AND "tsMs" <= $2
     ORDER BY "tsMs" ASC LIMIT ${FW_SCAN_LIMIT}`,
    [fwWatermarkMs, Date.now() + 300_000]
  );
  if (res.rows.length === 0) return;

  let maxTs = fwWatermarkMs;
  // eslint-disable-next-line no-console
  console.log(`[threat-intel] fw scan: ${res.rows.length} event(s) since ${new Date(fwWatermarkMs).toISOString()}`);
  // One finding per observed (src,dst) tuple — context lists every side/IP that hit.
  const tuples = new Map<string, { src: string; dst: string; action: string; deviceId: string; hits: Array<{ ip: string; sources: string[]; side: 'src' | 'dst' }> }>();
  for (const row of res.rows) {
    const ts = Number(row.tsMs);
    if (Number.isFinite(ts)) maxTs = Math.max(maxTs, ts);
    const hits: Array<{ ip: string; sources: string[]; side: 'src' | 'dst' }> = [];
    for (const side of ['src', 'dst'] as const) {
      const m = matchIoc(side === 'src' ? row.srcIp : row.dstIp, cache);
      if (m) hits.push({ ip: m.ip, sources: m.sources, side });
    }
    if (hits.length === 0) continue;
    const key = `${row.srcIp}|${row.dstIp}`;
    const existing = tuples.get(key);
    if (existing) {
      for (const h of hits) if (!existing.hits.some((e) => e.ip === h.ip && e.side === h.side)) existing.hits.push(h);
    } else {
      tuples.set(key, { src: String(row.srcIp), dst: String(row.dstIp), action: String(row.action ?? 'unknown'), deviceId: String(row.deviceId), hits });
    }
  }

  for (const t of tuples.values()) {
    const ips = [...new Set(t.hits.map((h) => h.ip))].join(', ');
    const detail = `Firewall event (${t.action}) involving threat-intel listed IP${ips.includes(',') ? 's' : ''} ${ips}` +
      (t.src && t.dst ? ` — ${t.src} → ${t.dst}.` : '.');
    const input: FindingInput = {
      kind: 'ioc-hit',
      srcIp: t.src || t.hits.find((h) => h.side === 'src')?.ip || '0.0.0.0',
      dstIp: t.dst || (t.hits.some((h) => h.side === 'dst') ? t.hits.find((h) => h.side === 'dst')!.ip : null),
      severity: worstSeverity([...new Set(t.hits.flatMap((h) => h.sources))], cache.severities),
      detail,
      context: { iocHits: t.hits, action: t.action },
      deviceId: t.deviceId || null,
    };
    const isNew = await upsertFinding(input);
    if (isNew) {
      // eslint-disable-next-line no-console
      console.log(`[threat-intel] ioc-hit finding: ${input.srcIp} → ${input.dstIp ?? '-'}`);
      await notifyIocHit(input);
    }
  }

  fwWatermarkMs = maxTs; // advance past everything scanned — each row is examined once
}

/** Emits the one-shot notification for a freshly detected DNS IOC hit. Best-effort. */
async function notifyDnsIocHit(f: FindingInput): Promise<void> {
  try {
    const hits = (f.context.iocHits as Array<{ domain: string; sources: string[] }> | undefined) ?? [];
    const listed = hits.length > 0 ? hits.map((h) => h.domain).join(', ') : String(f.context.domain ?? '');
    const sources = [...new Set(hits.flatMap((h) => h.sources))].join(', ');
    await emitNotification({
      severity: f.severity, // per-feed severity (escalated across matched feeds)
      source: f.deviceId ? 'device' : 'system',
      deviceId: f.deviceId ?? undefined,
      title: `Threat-intel hit: ${listed}`,
      message: `${f.detail}${sources ? ` (feed${sources.length > 1 ? 's' : ''}: ${sources})` : ''}`,
      dedupeKey: `flow-security:dns-ioc-hit:${f.srcIp}:${String(f.context.domain ?? '')}`,
      context: { ...f.context, srcIp: f.srcIp },
    });
  } catch (err) {
    // Notifications are best-effort by contract — never break the beat.
    lastError = `notification failed: ${(err as Error).message}`;
    // eslint-disable-next-line no-console
    console.error('[threat-intel] notification emission failed:', err);
  }
}

/** Resolves hostname clients to IPs via the hosts table (one batched lookup,
 * newest lastSeenAt wins per name). The appliance's REST API substitutes a
 * reverse-resolved hostname for the client IP, so findings — which need an INET
 * source address — require this hop. Exported: workers/dnsSecurity.ts reuses it
 * for its DGA / tunneling findings. */
export async function resolveClientHostnames(names: string[]): Promise<Map<string, string>> {
  if (names.length === 0) return new Map();
  try {
    const res = await pool.query<{ h: string; ip: string; seen: string }>(
      `SELECT lower(hostname) AS h, ip, "lastSeenAt" AS seen FROM hosts WHERE hostname IS NOT NULL AND lower(hostname) = ANY($1::text[])`,
      [names]
    );
    // A name can map to several IPs (DHCP churn across sources) — newest lastSeenAt wins.
    const best = new Map<string, { ip: string; seen: string }>();
    for (const r of res.rows) {
      const cur = best.get(r.h);
      if (!cur || String(r.seen) > cur.seen) best.set(r.h, { ip: String(r.ip), seen: String(r.seen) });
    }
    return new Map([...best.entries()].map(([h, v]) => [h, v.ip]));
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('[threat-intel] client hostname resolution failed:', err);
    return new Map();
  }
}

/** DNS pass — queried domains since the watermark vs the active domain set. */
async function matchDnsQueries(): Promise<void> {
  const cache = await ensureIocCache();
  if (!cache || cache.domains.size === 0) return; // no domain indicators yet — nothing to match

  // tsMs is epoch ms (appliance unix seconds × 1000, always UTC); a +5 min guard
  // keeps future-skewed rows from being scanned twice.
  const res = await pool.query<{ client: string; domain: string; qtype: string | null; action: string; rcode: string | null; deviceId: string; tsMs: string | number }>(
    `SELECT client, domain, qtype, action, rcode, "deviceId", "tsMs"
     FROM dns_query_events
     WHERE "tsMs" > $1 AND "tsMs" <= $2
     ORDER BY "tsMs" ASC LIMIT ${DNS_SCAN_LIMIT}`,
    [dnsWatermarkMs, Date.now() + 300_000]
  );
  if (res.rows.length === 0) return;

  let maxTs = dnsWatermarkMs;
  // eslint-disable-next-line no-console
  console.log(`[threat-intel] dns scan: ${res.rows.length} quer(y/ies) since ${new Date(dnsWatermarkMs).toISOString()}`);
  // One finding per observed (client, domain) tuple — context lists every matching feed.
  const tuples = new Map<string, { client: string; domain: string; qtype: string | null; action: string; rcode: string | null; deviceId: string; hits: Array<{ domain: string; sources: string[] }> }>();
  for (const row of res.rows) {
    const ts = Number(row.tsMs);
    if (Number.isFinite(ts)) maxTs = Math.max(maxTs, ts);
    const m = matchDomain(row.domain, cache);
    if (!m) continue;
    const key = `${row.client}|${row.domain}`;
    const existing = tuples.get(key);
    if (existing) {
      for (const h of [m]) if (!existing.hits.some((e) => e.domain === h.domain)) existing.hits.push(h);
    } else {
      tuples.set(key, { client: String(row.client), domain: String(row.domain), qtype: row.qtype ? String(row.qtype) : null, action: String(row.action ?? 'pass'), rcode: row.rcode ? String(row.rcode) : null, deviceId: String(row.deviceId), hits: [m] });
    }
  }
  if (tuples.size === 0) {
    dnsWatermarkMs = maxTs; // nothing matched — still advance past the scanned rows
    return;
  }

  // Hostname clients need an IP for the finding's INET source column.
  const unresolved = [...new Set([...tuples.values()].map((t) => t.client))].filter((c) => ipToWords(c) === null);
  const resolved = await resolveClientHostnames(unresolved.map((n) => n.toLowerCase()));

  for (const t of tuples.values()) {
    const clientIp = ipToWords(t.client) !== null ? t.client : resolved.get(t.client.toLowerCase());
    if (!clientIp) continue; // no address to attribute the finding to — the event stays visible in the DNS view
    const m = t.hits[0];
    const detail = `DNS query from ${t.client} to threat-listed domain ${m.domain}` +
      (t.qtype ? ` (${t.qtype})` : '') + '.';
    const input: FindingInput = {
      kind: 'dns-ioc-hit',
      srcIp: clientIp,
      dstIp: null,
      severity: worstSeverity(t.hits.flatMap((h) => h.sources), cache.severities),
      detail,
      context: { iocHits: t.hits, domain: m.domain, client: t.client, qtype: t.qtype, action: t.action, rcode: t.rcode },
      deviceId: t.deviceId || null,
    };
    const isNew = await upsertFinding(input);
    if (isNew) {
      // eslint-disable-next-line no-console
      console.log(`[threat-intel] dns-ioc-hit finding: ${t.client} → ${m.domain}`);
      await notifyDnsIocHit(input);
    }
  }

  dnsWatermarkMs = maxTs; // advance past everything scanned — each row is examined once
}

// ── Beat ─────────────────────────────────────────────────────────────────────

async function beat(): Promise<void> {
  try {
    const values = await getEffectiveValues();
    if (values.threatIntelEnabled !== true) return; // master switch off — no fetch, no matching

    const nowMs = Date.now();
    const intervalMs = Number(values.threatIntelFetchIntervalMinutes) * 60_000 || 3_600_000;
    await fetchDueSources(intervalMs);

    // Flow buckets closed at least one full rollup interval ago.
    const newestProcessableMs = Math.floor((nowMs - PROCESS_LAG_MS) / BUCKET_MS) * BUCKET_MS;
    if (newestProcessableMs > cursorBucketMs) {
      const fromIso = new Date(cursorBucketMs + BUCKET_MS).toISOString();
      const toIso = new Date(newestProcessableMs + BUCKET_MS).toISOString();
      await matchFlows(fromIso, toIso);
      cursorBucketMs = newestProcessableMs;
    }

    await matchFirewallEvents();
    await matchDnsQueries();

    lastRunAt = new Date().toISOString();
    lastError = null;
  } catch (err) {
    lastError = (err as Error).message;
    // eslint-disable-next-line no-console
    console.error('[threat-intel] beat failed:', err);
    throw err; // trackBeat records the error; cursors stay put → next beat retries
  }
}

/**
 * Starts the threat-intel worker. Must be called only after the API has bound
 * its port (same rule as every other worker — see index.ts app.listen).
 */
export function startThreatIntelWorker(): () => void {
  initWorker('threatIntel', LEADER_KEYS.threatIntel);
  // eslint-disable-next-line no-console
  console.log('[threat-intel] worker started');

  void trackBeat('threatIntel', beat).catch((err) => {
    // eslint-disable-next-line no-console
    console.error('[threat-intel] initial beat failed:', err);
  });

  const timer = setInterval(() => {
    void trackBeat('threatIntel', beat).catch((err) => {
      // eslint-disable-next-line no-console
      console.error('[threat-intel] beat failed:', err);
    });
  }, BEAT_MS);

  return () => clearInterval(timer);
}
