/**
 * Threat intelligence — background worker (leader-gated, key 9023).
 *
 * Two jobs on one beat:
 *
 *   FETCH — every enabled IOC feed source (threat_intel_sources rows, managed
 *     via POST /v1/threat-intel/sources) is re-fetched through the web-fetch
 *     broker (`webFetchBroker`, same egress path as OSV/GeoIP) at the
 *     `threatIntelFetchIntervalMinutes` cadence. Supported formats:
 *       - ip-list — one IPv4/IPv6 address or CIDR per line (# and ; comments,
 *         blank lines and URLs skipped);
 *       - stix    — STIX 2.x bundle; equality patterns of type indicators are
 *         extracted ([ipv4-addr:value = '…'] / [ipv6-addr:…]).
 *     A fetch is an authoritative SNAPSHOT per source: all parsed values are
 *     upserted into threat_iocs, then rows not re-upserted in the cycle are
 *     pruned by lastSeenAt — indicators a feed drops disappear automatically.
 *
 *   MATCH — flow destinations (flow_agg_5m, same bucket-lag convention as the
 *     rollup worker) and firewall-event IPs (firewall_events tsMs axis) are
 *     checked against the active indicator set, which is cached in memory
 *     (exact host addresses + CIDR containment for v4/v6). Every hit upserts a
 *     finding of kind 'ioc-hit' into flow_security_findings — the SAME table,
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
/** Download bound per feed (the broker enforces it on the plugin side too). */
const MAX_FETCH_BYTES = 10 * 1_048_576; // 10 MiB
const FETCH_TIMEOUT_MS = 120_000;
/** Active-IOC cache lifetime — also invalidated after every successful fetch. */
const IOC_CACHE_TTL_MS = 15 * 60_000;
/** An EMPTY set is re-checked much sooner — a newly added/enabled source should
 * start matching within one beat, not wait out the full TTL. */
const IOC_CACHE_EMPTY_TTL_MS = 30_000;
/** Max firewall-event rows scanned per beat (the watermark advances past them). */
const FW_SCAN_LIMIT = 20_000;

export const THREAT_INTEL_FORMATS = ['ip-list', 'stix'] as const;
export type ThreatIntelFormat = (typeof THREAT_INTEL_FORMATS)[number];

// ── State ────────────────────────────────────────────────────────────────────

/** Last matched flow bucket START (ms). Only buckets after boot are scanned. */
let cursorBucketMs = Math.floor(Date.now() / BUCKET_MS) * BUCKET_MS;
/** firewall_events tsMs watermark — rows with tsMs > this are unscanned. */
let fwWatermarkMs = Date.now();
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
} {
  return { lastRunAt, lastError, iocTotal: iocCache?.total ?? 0, cursorBucketMs, fwWatermarkMs };
}

// ── IP / CIDR matching (v4 + v6) ─────────────────────────────────────────────
// Address parsing and containment math live in @unm/plugin-sdk (ip.ts); this
// module only adds threat-intel semantics on top (exact-vs-CIDR entries, the
// canonical exact-match key, source attribution).

/** One active indicator set: exact host addresses + CIDR networks. */
export interface IocCache {
  /** Canonical address string → source names containing it. */
  exact: Map<string, string[]>;
  cidrs: Array<{ words: number[]; prefix: number; family: 'v4' | 'v6'; sources: string[] }>;
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

// ── Fetch cycle ──────────────────────────────────────────────────────────────

interface SourceRow {
  id: string;
  name: string;
  url: string;
  format: ThreatIntelFormat;
  enabled: boolean;
  lastSuccessAt: string | null;
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

  const parsed: ParsedFeed = source.format === 'stix' ? parseStix(bytes, maxIocs) : parseIpList(bytes, maxIocs);
  if (parsed.values.length === 0 && parsed.skipped > 0) {
    throw new Error(`feed returned no usable indicators (${parsed.skipped} unparseable entries)`);
  }

  // Batched upsert — deduped values only (intra-statement duplicates would
  // trip ON CONFLICT with "cannot affect row a second time").
  for (let i = 0; i < parsed.values.length; i += 1_000) {
    const chunk = parsed.values.slice(i, i + 1_000);
    const ids = chunk.map(() => uuidv4());
    await pool.query(
      `INSERT INTO threat_iocs (id, "sourceId", ioc, "firstSeenAt", "lastSeenAt")
       SELECT u.id, $1, u.val::inet, $2, $2
       FROM unnest($3::text[], $4::text[]) AS u(id, val)
       ON CONFLICT ("sourceId", ioc) DO UPDATE SET "lastSeenAt" = EXCLUDED."lastSeenAt"`,
      [source.id, cycleStartIso, ids, chunk]
    );
  }

  // Snapshot prune — indicators the feed no longer lists.
  await pool.query(`DELETE FROM threat_iocs WHERE "sourceId" = $1 AND "lastSeenAt" < $2`, [source.id, cycleStartIso]);
  const countRes = await pool.query(`SELECT COUNT(*)::int AS n FROM threat_iocs WHERE "sourceId" = $1`, [source.id]);
  await pool.query(
    `UPDATE threat_intel_sources SET "iocCount" = $1, "lastSuccessAt" = $2, "lastError" = NULL WHERE id = $3`,
    [Number(countRes.rows[0]?.n ?? 0), cycleStartIso, source.id]
  );

  iocCache = null; // the active set changed — rebuild on next use
  // eslint-disable-next-line no-console
  console.log(`[threat-intel] fetched "${source.name}": ${parsed.values.length} indicators (${parsed.skipped} skipped)`);
}

/** Fetches every enabled source whose interval has elapsed. One failure never breaks the beat. */
async function fetchDueSources(intervalMs: number): Promise<void> {
  const now = Date.now();
  const res = await pool.query<SourceRow>(`SELECT id, name, url, format, enabled, "lastSuccessAt" FROM threat_intel_sources WHERE enabled`);
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
  const sql = sourceId ? `SELECT id, name, url, format, enabled, "lastSuccessAt" FROM threat_intel_sources WHERE enabled AND id = $1` : `SELECT id, name, url, format, enabled, "lastSuccessAt" FROM threat_intel_sources WHERE enabled`;
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
  // re-enable restores the indicators without a re-fetch).
  const res = await pool.query<{ ioc: string; name: string }>(
    `SELECT t.ioc::text AS ioc, s.name FROM threat_iocs t JOIN threat_intel_sources s ON s.id = t."sourceId" WHERE s.enabled`
  );
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
  iocCache = { exact, cidrs, loadedAt: Date.now(), total: res.rows.length };
  // eslint-disable-next-line no-console
  console.log(`[threat-intel] IOC cache built: ${iocCache.total} active indicator(s)`);
  return iocCache;
}

// ── Matching passes ──────────────────────────────────────────────────────────

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
      severity: 'warning',
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
      severity: 'warning',
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
      severity: 'warning',
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
