/**
 * Flow security insights — background worker (leader-gated, key 9021).
 *
 * Deterministic heuristics over the ENRICHED flow tiers (flow_agg_5m /
 * flow_agg_1h) that turn the raw traffic data into security findings:
 *
 *   1. new-destination — an internet destination IP never seen before on this
 *      network (checked against every dst stored in either agg tier). Always
 *      RECORDED; raises a notification only when the source moved at least
 *      `flowSecurityNewDstAlertMinBytes` to it in the triggering window
 *      (normal web browsing visits new sites constantly — volume is what makes
 *      a first-time destination interesting).
 *   2. port-scan       — one internal source talking to ≥ `flowSecurityScanMinDsts`
 *      DISTINCT destinations within a single 5-minute bucket (horizontal scan;
 *      critical at three times the threshold).
 *   3. egress-baseline — a (source → internet destination) pair whose average
 *      per-hour rate inside a rolling window (`flowSecurityEgressWindowHours`)
 *      exceeds its historical per-hour median (lookback `flowSecurityEgressBaselineDays`
 *      over the hourly tier) by at least `flowSecurityEgressBaselineMultiple`,
 *      with an absolute candidate floor of `flowSecurityEgressMinBytes`.
 *   4. beacon          — a (source → internet destination) pair active in ≥
 *      `flowSecurityBeaconMinBuckets` five-minute buckets inside a rolling window
 *      (`flowSecurityBeaconWindowHours`) with near-constant spacing (inter-bucket
 *      jitter ≤ `flowSecurityBeaconMaxJitterPercent`, coefficient of variation).
 *      The classic C2 check-in signature; heavy sustained transfers are excluded
 *      via `flowSecurityBeaconMaxAvgBytesPerBucket` (that's detector 3's domain).
 *
 * Findings land in flow_security_findings (one row per distinct condition,
 * upserted while it persists). A finding raises ONE notification when first
 * detected; rows not re-observed for 24 h auto-resolve and are pruned by the
 * retention setting. The Flows page "Security" section renders them via
 * GET /v1/flows/security, and automation rules can react to new findings with
 * a `securityFinding` trigger (workers/automations.ts).
 *
 * Timing: buckets are only analyzed once they closed at least one full rollup
 * interval ago — by then the flows worker's 5-minute rollup tick covering them
 * has definitely run. The cursor starts at "now truncated" on boot (same
 * convention as the rollup cursors): pre-existing history is never re-analyzed,
 * and the new-destination seen-set is loaded from ALL stored data so a restart
 * cannot re-flag long-known destinations.
 */

import { v4 as uuidv4 } from 'uuid';
import { pool } from '../db';
import { getEffectiveValues } from '../systemSettings';
import { emitNotification } from '../notifications';
import { LEADER_KEYS } from './leader';
import { initWorker, trackBeat } from './stats';

const BEAT_MS = 60_000;
const BUCKET_MS = 300_000; // flow_agg_5m bucket size
/** A bucket may be analyzed only once it closed at least one full rollup interval ago. */
const PROCESS_LAG_MS = 2 * BUCKET_MS;
/** Findings not re-observed for this long are no longer active conditions. */
const AUTO_RESOLVE_AFTER_MS = 86_400_000; // 24 h
/** Detector 3 (egress baseline) is throttled — the rolling window moves slowly. */
const EGRESS_CHECK_INTERVAL_MS = 30 * 60_000;

// 'ioc-hit' rows are written by workers/threatIntel.ts (threat-intel matching),
// 'dns-ioc-hit' rows by its DNS pass (queried domains vs domain-list feeds),
// 'dga' + 'dns-tunnel' rows by workers/dnsSecurity.ts (DNS heuristics over
// dns_query_events) and 'log-rule' rows by workers/logRules.ts (Sigma rules
// over ingested log lines) — they share this table, the auto-resolve sweep and
// the securityFinding automation trigger with the flow detectors.
export const FLOW_SECURITY_KINDS = ['new-destination', 'port-scan', 'egress-baseline', 'beacon', 'ioc-hit', 'dns-ioc-hit', 'dga', 'dns-tunnel', 'log-rule'] as const;
export type FlowSecurityKind = (typeof FLOW_SECURITY_KINDS)[number];

const SEVERITY_RANK: Record<'info' | 'warning' | 'critical', number> = { info: 0, warning: 1, critical: 2 };

// ── State ────────────────────────────────────────────────────────────────────

/** Last processed bucket START (ms). Only buckets after boot are analyzed. */
let cursorBucketMs = Math.floor(Date.now() / BUCKET_MS) * BUCKET_MS;
/** Every dst IP stored in either agg tier at load time + everything processed since. */
let seenDstIps: Set<string> | null = null;
let lastEgressCheckMs = 0;
/** Active-bucket history per (src → internet dst) pair for the beacon detector.
 * Key `${srcIp}|${dstIp}` — IP strings never contain '|'. Values are sorted,
 * deduplicated bucket START times inside the rolling window. */
const beaconHistory = new Map<string, number[]>();
/** Safety cap on tracked pairs — a runaway fleet must not grow the map unbounded. */
const BEACON_MAX_TRACKED_PAIRS = 200_000;
/** Overlap guard — a slow beat must not pile up unbounded concurrent scans. */
let busy = false;
let lastRunAt: string | null = null;
let lastError: string | null = null;

/** Snapshot for GET /v1/flows/security (worker status line). */
export function getFlowSecurityStats(): {
  lastRunAt: string | null;
  lastError: string | null;
  cursorBucketMs: number;
  seenDstCount: number;
  beaconTrackedPairs: number;
} {
  return {
    lastRunAt,
    lastError,
    cursorBucketMs,
    seenDstCount: seenDstIps?.size ?? 0,
    beaconTrackedPairs: beaconHistory.size,
  };
}

/**
 * Clears and IMMEDIATELY reloads the seen-destination baseline from current
 * aggregate data (POST /flows/security/baseline/reset). The lazy boot-time load
 * races with anything that writes to flow_agg_5m/1h afterwards — rows inserted
 * after the load are "known", so a freshly seeded test destination is never
 * flagged as new. An eager reload right before seeding makes detection
 * deterministic; operationally it also re-baselines after backfills or
 * retention changes.
 */
export async function resetFlowSecurityBaseline(): Promise<{ reloaded: boolean; size: number }> {
  seenDstIps = null;
  const ok = await ensureSeenSet(); // mutates seenDstIps — read the size via a fresh call
  return { reloaded: ok, size: getFlowSecurityStats().seenDstCount };
}

// ── Helpers ──────────────────────────────────────────────────────────────────

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

function medianOf(values: number[]): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 1 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

/** Verdict for one candidate pair in detectEgressBaseline. */
export interface EgressVerdict {
  severity: 'warning' | 'critical';
  /** avgHourly / baselineMedian, rounded to one decimal; null when the median is zero. */
  ratio: number | null;
  /** Median of the pair's per-hour baseline totals (bytes/hour). */
  baselineMedianBytes: number;
}

/**
 * Pure decision core of detectEgressBaseline — extracted for unit testing.
 * Returns null when NO finding is warranted: no baseline history at all
 * (first-time pairs are detector 1's job) or the window average stays below
 * `multiple`× the median. A zero-median baseline means ANY transfer above the
 * floor is anomalous for this pair; ratio ≥ 10 escalates to critical.
 */
export function egressVerdict(
  totalBytes: number,
  windowHours: number,
  baselineHourlyValues: number[],
  multiple: number
): EgressVerdict | null {
  if (baselineHourlyValues.length === 0) return null;
  const median = medianOf(baselineHourlyValues);
  const avgHourly = totalBytes / windowHours;
  // A zero-median baseline (pair was quiet in most active hours) means ANY
  // transfer above the floor is anomalous for this pair.
  if (median > 0 && avgHourly < median * multiple) return null;
  const ratio = median > 0 ? Math.round((avgHourly / median) * 10) / 10 : null;
  const severity: 'warning' | 'critical' = ratio !== null && ratio >= 10 ? 'critical' : 'warning';
  return { severity, ratio, baselineMedianBytes: median };
}

/** Verdict for one candidate pair in detectBeacons. */
export interface BeaconVerdict {
  severity: 'warning' | 'critical';
  /** Mean inter-bucket interval expressed in minutes (bucket units × 5). */
  periodMinutes: number;
  /** Number of active 5-minute buckets inside the rolling window. */
  bucketCount: number;
  /** Span from first to last active bucket, in hours (one decimal). */
  spanHours: number;
  /** Coefficient of variation of the inter-bucket intervals (0–1, three decimals). */
  jitterCv: number;
}

/**
 * Pure decision core of detectBeacons — extracted for unit testing.
 * `bucketStartsMs` are the START times (ms) of every 5-minute bucket in which
 * the pair was active, sorted ascending and deduplicated. Returns null when NO
 * finding is warranted: fewer than `minBuckets` active buckets, or the
 * inter-bucket intervals jitter by more than `maxJitterPercent` (coefficient
 * of variation × 100). Perfectly periodic activity over at least twice the
 * minimum bucket count escalates to critical — exact regularity is very strong
 * C2 evidence. Note: because buckets are 5-minute slots, a beacon with any
 * sub-5-minute period shows up in EVERY bucket (interval = 1 unit); longer
 * periods show up every k-th bucket.
 */
export function beaconVerdict(
  bucketStartsMs: number[],
  minBuckets: number,
  maxJitterPercent: number
): BeaconVerdict | null {
  if (bucketStartsMs.length < minBuckets) return null;
  const units: number[] = [];
  for (let i = 1; i < bucketStartsMs.length; i++) units.push((bucketStartsMs[i] - bucketStartsMs[i - 1]) / BUCKET_MS);
  const mean = units.reduce((a, b) => a + b, 0) / units.length;
  if (mean <= 0) return null;
  // Population std dev — the samples are small and we want a conservative
  // (slightly higher) jitter estimate, so no Bessel correction.
  const variance = units.reduce((a, b) => a + (b - mean) ** 2, 0) / units.length;
  const cv = Math.sqrt(variance) / mean;
  if (cv * 100 > maxJitterPercent) return null;
  const periodMinutes = Math.round(mean * (BUCKET_MS / 60_000));
  const spanHours = Math.round(((bucketStartsMs[bucketStartsMs.length - 1] - bucketStartsMs[0]) / 3_600_000) * 10) / 10;
  const severity: 'warning' | 'critical' = cv === 0 && bucketStartsMs.length >= minBuckets * 2 ? 'critical' : 'warning';
  return { severity, periodMinutes, bucketCount: bucketStartsMs.length, spanHours, jitterCv: Math.round(cv * 1_000) / 1_000 };
}

async function lookupDeviceName(deviceId: string): Promise<string | null> {
  try {
    const res = await pool.query(`SELECT name FROM devices WHERE id = $1`, [deviceId]);
    return res.rows.length > 0 ? String(res.rows[0].name) : null;
  } catch {
    return null;
  }
}

/**
 * Loads the set of every destination IP stored in either aggregate tier.
 * Called once (lazily on the first beat). Failures keep `null` — the next beat
 * retries, and a missing seen-set simply means detector 1 skips that window
 * rather than flagging everything as new.
 */
async function ensureSeenSet(): Promise<boolean> {
  if (seenDstIps) return true;
  try {
    const [a5m, a1h] = await Promise.all([
      pool.query(`SELECT DISTINCT "dstIp" FROM flow_agg_5m`),
      pool.query(`SELECT DISTINCT "dstIp" FROM flow_agg_1h`),
    ]);
    const set = new Set<string>();
    // Quoted DDL column names keep their case in pg result rows (r.dstIp, not r.dstip).
    for (const r of a5m.rows) set.add(String(r.dstIp));
    for (const r of a1h.rows) set.add(String(r.dstIp));
    seenDstIps = set;
    // eslint-disable-next-line no-console
    console.log(`[flow-security] seen-destination baseline loaded (${set.size} distinct dst IPs)`);
    return true;
  } catch (err) {
    lastError = `seen-set load failed: ${(err as Error).message}`;
    // eslint-disable-next-line no-console
    console.error('[flow-security] seen-set load failed:', err);
    return false;
  }
}

/** Shared finding shape — also used by workers/threatIntel.ts ('ioc-hit') and
 * workers/logRules.ts ('log-rule'). */
export interface FindingInput {
  kind: FlowSecurityKind;
  /** Null for findings that are not IP-centric (e.g. a log-rule hit on a line without a source address). */
  srcIp: string | null;
  dstIp: string | null;
  severity: 'info' | 'warning' | 'critical';
  detail: string;
  context: Record<string, unknown>;
  deviceId: string | null;
  /** Stable identity of the ongoing condition. When present it is the upsert key INSTEAD of (kind, srcIp, dstIp) — used by log-rule findings. */
  dedupeKey?: string | null;
}

/**
 * Creates or refreshes a finding row for (kind, srcIp, dstIp) — or for the
 * explicit `dedupeKey` when one is given. Returns true when the row was NEW
 * (first detection of this condition) — callers raise the notification only in
 * that case so a persisting condition never re-spams.
 */
export async function upsertFinding(f: FindingInput): Promise<boolean> {
  const nowIso = new Date().toISOString();
  // Explicit dedupe key (log-rule findings): identity is the key itself, IP
  // columns are plain attributes and may be NULL.
  if (f.dedupeKey) {
    const existingK = await pool.query(
      `SELECT id, severity FROM flow_security_findings WHERE "dedupeKey" = $1 AND status = 'open'`,
      [f.dedupeKey]
    );
    if (existingK.rows.length > 0) {
      const row = existingK.rows[0];
      const currentRank = SEVERITY_RANK[(row.severity as 'info' | 'warning' | 'critical')] ?? 1;
      const newSeverity = SEVERITY_RANK[f.severity] > currentRank ? f.severity : row.severity;
      await pool.query(
        `UPDATE flow_security_findings
         SET "lastSeenAt" = $1, occurrences = occurrences + 1, severity = $2, detail = $3, context = $4, status = 'open', "resolvedAt" = NULL
         WHERE id = $5`,
        [nowIso, newSeverity, f.detail.slice(0, 2_048), JSON.stringify(f.context), row.id]
      );
      return false;
    }
    await pool.query(
      `INSERT INTO flow_security_findings (id, kind, severity, "srcIp", "dstIp", detail, context, "deviceId", "firstSeenAt", "lastSeenAt", occurrences, status, "dedupeKey")
       VALUES ($1, $2, $3, $4::inet, $5::inet, $6, $7, $8, $9, $9, 1, 'open', $10)`,
      [uuidv4(), f.kind, f.severity, f.srcIp, f.dstIp, f.detail.slice(0, 2_048), JSON.stringify(f.context), f.deviceId, nowIso, f.dedupeKey]
    );
    return true;
  }

  const existing = await pool.query(
    `SELECT id, severity FROM flow_security_findings
     WHERE kind = $1 AND "srcIp" = $2::inet AND ("dstIp" IS NOT DISTINCT FROM $3::inet) AND status = 'open'`,
    [f.kind, f.srcIp, f.dstIp]
  );
  if (existing.rows.length > 0) {
    const row = existing.rows[0];
    // Never downgrade the severity of a live finding.
    const currentRank = SEVERITY_RANK[(row.severity as 'info' | 'warning' | 'critical')] ?? 1;
    const newSeverity = SEVERITY_RANK[f.severity] > currentRank ? f.severity : row.severity;
    await pool.query(
      `UPDATE flow_security_findings
       SET "lastSeenAt" = $1, occurrences = occurrences + 1, severity = $2, detail = $3, context = $4, status = 'open', "resolvedAt" = NULL
       WHERE id = $5`,
      [nowIso, newSeverity, f.detail.slice(0, 2_048), JSON.stringify(f.context), row.id]
    );
    return false;
  }
  await pool.query(
    `INSERT INTO flow_security_findings (id, kind, severity, "srcIp", "dstIp", detail, context, "deviceId", "firstSeenAt", "lastSeenAt", occurrences, status)
     VALUES ($1, $2, $3, $4::inet, $5::inet, $6, $7, $8, $9, $9, 1, 'open')`,
    [uuidv4(), f.kind, f.severity, f.srcIp, f.dstIp, f.detail.slice(0, 2_048), JSON.stringify(f.context), f.deviceId, nowIso]
  );
  return true;
}

/** Emits the one-shot notification for a freshly detected finding. Best-effort. */
async function notifyFinding(f: FindingInput): Promise<void> {
  try {
    const deviceName = f.deviceId ? await lookupDeviceName(f.deviceId) : null;
    const srcLabel = (f.context.srcHostname as string | undefined) ?? f.srcIp;
    let title = '';
    let message = f.detail;
    switch (f.kind) {
      case 'new-destination':
        title = `New internet destination from ${srcLabel}`;
        break;
      case 'port-scan':
        title = `Possible port scan from ${srcLabel} (${f.srcIp})`;
        break;
      case 'egress-baseline':
        title = `Unusual egress volume from ${srcLabel} to ${f.dstIp}`;
        break;
      case 'beacon':
        title = `Possible beaconing from ${srcLabel} to ${f.dstIp}`;
        break;
    }
    await emitNotification({
      severity: f.severity,
      source: f.deviceId ? 'device' : 'system',
      deviceId: f.deviceId ?? undefined,
      title,
      message,
      dedupeKey: `flow-security:${f.kind}:${f.srcIp}:${f.dstIp ?? ''}`,
      context: { ...f.context, srcIp: f.srcIp, dstIp: f.dstIp },
    });
  } catch (err) {
    // Notifications are best-effort by contract — never break the beat.
    lastError = `notification failed: ${(err as Error).message}`;
    // eslint-disable-next-line no-console
    console.error('[flow-security] notification emission failed:', err);
  }
}

// ── Detector 1: new internet destinations ───────────────────────────────────

async function detectNewDestinations(fromIso: string, toIso: string): Promise<void> {
  const values = await getEffectiveValues();
  const minAlertBytes = Number(values.flowSecurityNewDstAlertMinBytes) || 0;

  // Per (src → dst) pair in the window — only internet destinations are
  // interesting here (internal first-seen pairs are normal network growth).
  const res = await pool.query(
    `SELECT "srcIp", "dstIp", SUM("estBytes")::bigint AS est_bytes,
            MAX("dstCountryCode") AS country, MAX("srcHostname") AS hostname,
            MAX("srcDeviceId") AS device_id
     FROM flow_agg_5m
     WHERE bucket >= $1 AND bucket < $2
       AND "dstClass" = 'internet' AND "srcClass" IN ('internal', 'unknown')
     GROUP BY 1, 2`,
    [fromIso, toIso]
  );

  for (const r of res.rows) {
    const srcIp = String(r.srcIp);
    const dstIp = String(r.dstIp);
    if (seenDstIps!.has(dstIp)) continue; // known destination — not a finding
    const estBytes = Number(r.est_bytes ?? 0);
    const country = r.country ? String(r.country) : null;
    const hostname = r.hostname ? String(r.hostname) : null;
    const deviceId = r.device_id ? String(r.device_id) : null;

    // A threshold of 0 means "notify for every new destination" (opt-in noise).
    const alertable = minAlertBytes <= 0 ? estBytes > 0 : estBytes >= minAlertBytes;
    const detail = `First observed traffic from ${hostname ?? srcIp} to internet destination ${dstIp}` +
      `${country ? ` (${country})` : ''} — ${humanBytes(estBytes)} in the triggering window.`;
    const isNew = await upsertFinding({
      kind: 'new-destination',
      srcIp,
      dstIp,
      severity: alertable ? 'warning' : 'info',
      detail,
      context: { estBytes, countryCode: country, srcHostname: hostname },
      deviceId,
    });
    if (isNew && alertable) await notifyFinding({ kind: 'new-destination', srcIp, dstIp, severity: 'warning', detail, context: { estBytes, countryCode: country, srcHostname: hostname }, deviceId });
  }

  // Extend the seen-set with every destination in this window so later windows
  // (and restarts' initial load) treat them as known.
  const allDst = await pool.query(`SELECT DISTINCT "dstIp" FROM flow_agg_5m WHERE bucket >= $1 AND bucket < $2`, [fromIso, toIso]);
  for (const r of allDst.rows) seenDstIps!.add(String(r.dstIp));
}

// ── Detector 2: horizontal port scans ───────────────────────────────────────

async function detectPortScans(fromIso: string, toIso: string): Promise<void> {
  const values = await getEffectiveValues();
  const minDsts = Number(values.flowSecurityScanMinDsts) || 10;

  // Per BUCKET × source — the scan condition is defined within one 5-minute
  // window (a catch-up batch must not merge several buckets into one count).
  const res = await pool.query(
    `SELECT "srcIp", COUNT(DISTINCT "dstIp")::int AS dsts,
            COUNT(DISTINCT CASE WHEN "dstClass" = 'internal' THEN "dstIp" END)::int AS internal_dsts,
            SUM("estBytes")::bigint AS est_bytes,
            MAX("srcHostname") AS hostname, MAX("srcDeviceId") AS device_id
     FROM flow_agg_5m
     WHERE bucket >= $1 AND bucket < $2 AND "srcClass" IN ('internal', 'unknown')
     GROUP BY bucket, "srcIp"
     HAVING COUNT(DISTINCT "dstIp") >= $3`,
    [fromIso, toIso, minDsts]
  );

  for (const r of res.rows) {
    const srcIp = String(r.srcIp);
    const dsts = Number(r.dsts ?? 0);
    const internalDsts = Number(r.internal_dsts ?? 0);
    const estBytes = Number(r.est_bytes ?? 0);
    const hostname = r.hostname ? String(r.hostname) : null;
    const deviceId = r.device_id ? String(r.device_id) : null;
    // Three times the threshold is treated as an active scan, not a candidate.
    const severity: 'warning' | 'critical' = dsts >= minDsts * 3 ? 'critical' : 'warning';
    const detail = `${hostname ?? srcIp} contacted ${dsts} distinct destinations within one 5-minute flow bucket` +
      ` (${internalDsts} internal) — possible horizontal port scan.`;
    const input: FindingInput = {
      kind: 'port-scan',
      srcIp,
      dstIp: null, // the condition aggregates over many destinations
      severity,
      detail,
      context: { distinctDsts: dsts, internalDsts, estBytes, srcHostname: hostname },
      deviceId,
    };
    const isNew = await upsertFinding(input);
    if (isNew) await notifyFinding(input);
  }
}

// ── Detector 3: sustained-egress baseline breach ────────────────────────────

async function detectEgressBaseline(windowEndMs: number): Promise<void> {
  const values = await getEffectiveValues();
  const windowHours = Number(values.flowSecurityEgressWindowHours) || 6;
  const minBytes = Number(values.flowSecurityEgressMinBytes) || 262_144_000;
  const baselineDays = Number(values.flowSecurityEgressBaselineDays) || 14;
  const multiple = Number(values.flowSecurityEgressBaselineMultiple) || 3;

  const windowStartMs = windowEndMs - windowHours * 3_600_000;
  // Candidate pairs: internal/unknown source → internet destination moving at
  // least the floor inside the rolling window. Bounded to the busiest 20 — a
  // baseline query per candidate is only worth it for real volume.
  const candRes = await pool.query(
    `SELECT "srcIp", "dstIp", SUM("estBytes")::bigint AS total,
            MAX("dstCountryCode") AS country, MAX("srcHostname") AS hostname,
            MAX("srcDeviceId") AS device_id
     FROM flow_agg_5m
     WHERE bucket >= $1 AND bucket < $2
       AND "dstClass" = 'internet' AND "srcClass" IN ('internal', 'unknown')
     GROUP BY 1, 2
     HAVING SUM("estBytes") >= $3
     ORDER BY total DESC LIMIT 20`,
    [new Date(windowStartMs).toISOString(), new Date(windowEndMs).toISOString(), minBytes]
  );

  // Baseline for ALL candidates in ONE pass over the lookback BEFORE the
  // window (agg_1h only stores hours that had traffic — median over each pair's
  // active hours). One hash-joined scan instead of one full partition scan per
  // candidate: on large fleets the per-pair loop was the dominant IO source.
  const bFromMs = windowStartMs - baselineDays * 86_400_000;
  const baseRes = await pool.query(
    `SELECT f."srcIp", f."dstIp", array_agg(f."estBytes") AS hours
     FROM flow_agg_1h f
     JOIN (SELECT * FROM unnest($1::inet[], $2::inet[]) AS u(src, dst)) u
       ON f."srcIp" = u.src AND f."dstIp" = u.dst
     WHERE f.bucket >= $3 AND f.bucket < $4
     GROUP BY f."srcIp", f."dstIp"`,
    [candRes.rows.map((r) => String(r.srcIp)), candRes.rows.map((r) => String(r.dstIp)), new Date(bFromMs).toISOString(), new Date(windowStartMs).toISOString()]
  );
  const baseByPair = new Map<string, number[]>();
  for (const b of baseRes.rows) {
    baseByPair.set(`${b.srcIp}|${b.dstIp}`, (b.hours ?? []).map((x: unknown) => Number(x)));
  }

  for (const r of candRes.rows) {
    const srcIp = String(r.srcIp);
    const dstIp = String(r.dstIp);
    const total = Number(r.total ?? 0);
    const country = r.country ? String(r.country) : null;
    const hostname = r.hostname ? String(r.hostname) : null;
    const deviceId = r.device_id ? String(r.device_id) : null;

    // No history → first-time pair (detector 1's job); within the normal range
    // → no finding. The verdict math is pure — unit-tested in flowSecurity.test.ts.
    const verdict = egressVerdict(total, windowHours, baseByPair.get(`${srcIp}|${dstIp}`) ?? [], multiple);
    if (!verdict) continue;
    const { severity, ratio } = verdict;
    const detail = `${hostname ?? srcIp} sent ${humanBytes(total)} to ${dstIp}${country ? ` (${country})` : ''} over the last ${windowHours} h — ` +
      (ratio !== null ? `about ${ratio}× its usual per-hour rate (median ${humanBytes(verdict.baselineMedianBytes)}/h).` : 'the pair had no meaningful history in the baseline window.');
    const input: FindingInput = {
      kind: 'egress-baseline',
      srcIp,
      dstIp,
      severity,
      detail,
      context: { windowHours, estBytes: total, baselineMedianBytes: Math.round(verdict.baselineMedianBytes), ratio, countryCode: country, srcHostname: hostname },
      deviceId,
    };
    const isNew = await upsertFinding(input);
    if (isNew) await notifyFinding(input);
  }
}

// ── Detector 4: beaconing (periodic C2-style check-ins) ─────────────────────

/**
 * Tracks which 5-minute buckets each (src → internet dst) pair was active in
 * and flags near-constant spacing — the classic command-and-control check-in
 * signature. Pure periodicity math lives in beaconVerdict (unit-tested); this
 * function only maintains the rolling per-pair history and attributes findings.
 * Heavy sustained transfers are deliberately excluded (avg bytes per active
 * bucket above `flowSecurityBeaconMaxAvgBytesPerBucket`) — those are
 * exfiltration candidates, detector 3's domain.
 */
async function detectBeacons(fromMs: number, toMs: number): Promise<void> {
  const values = await getEffectiveValues();
  const minBuckets = Number(values.flowSecurityBeaconMinBuckets) || 6;
  const maxJitterPercent = Number.isFinite(Number(values.flowSecurityBeaconMaxJitterPercent)) ? Number(values.flowSecurityBeaconMaxJitterPercent) : 25;
  const windowHours = Number(values.flowSecurityBeaconWindowHours) || 24;
  const maxAvgBytes = Number(values.flowSecurityBeaconMaxAvgBytesPerBucket) || 4_194_304; // 4 MiB

  // Prune history older than the rolling window (and cap the map size).
  const windowStartMs = toMs - windowHours * 3_600_000;
  for (const [key, arr] of beaconHistory) {
    while (arr.length > 0 && arr[0] < windowStartMs) arr.shift();
    if (arr.length === 0) beaconHistory.delete(key);
  }
  if (beaconHistory.size > BEACON_MAX_TRACKED_PAIRS) {
    // eslint-disable-next-line no-console
    console.warn(`[flow-security] beacon history exceeded ${BEACON_MAX_TRACKED_PAIRS} pairs — resetting`);
    beaconHistory.clear();
  }

  // Every (bucket, src → internet dst) triple in the processed range.
  const res = await pool.query(
    `SELECT bucket, "srcIp", "dstIp", MAX("srcHostname") AS hostname, MAX("srcDeviceId") AS device_id
     FROM flow_agg_5m
     WHERE bucket >= $1 AND bucket < $2
       AND "dstClass" = 'internet' AND "srcClass" IN ('internal', 'unknown')
     GROUP BY 1, 2, 3 ORDER BY 1`,
    [new Date(fromMs).toISOString(), new Date(toMs).toISOString()]
  );

  const touched = new Map<string, { srcIp: string; dstIp: string; hostname: string | null; deviceId: string | null }>();
  for (const r of res.rows) {
    const bucketMs = new Date(String(r.bucket)).getTime();
    if (!Number.isFinite(bucketMs)) continue;
    const srcIp = String(r.srcIp);
    const dstIp = String(r.dstIp);
    const key = `${srcIp}|${dstIp}`;
    let arr = beaconHistory.get(key);
    if (!arr) { arr = []; beaconHistory.set(key, arr); }
    // One row per (bucket, pair) thanks to GROUP BY — the last-element check
    // keeps the array sorted + unique even on a retried beat.
    if (arr[arr.length - 1] !== bucketMs) arr.push(bucketMs);
    touched.set(key, {
      srcIp,
      dstIp,
      hostname: r.hostname ? String(r.hostname) : null,
      deviceId: r.device_id ? String(r.device_id) : null,
    });
  }
  if (touched.size === 0) return;

  // Average per-bucket bytes for the touched pairs over the WHOLE window — a
  // sustained heavy transfer is not a beacon. One hash-joined scan, same
  // pattern as detectEgressBaseline's baseline query.
  const keys = [...touched.keys()];
  const avgRes = await pool.query(
    `SELECT f."srcIp", f."dstIp", AVG(f."estBytes") AS avg_bytes
     FROM flow_agg_5m f
     JOIN (SELECT * FROM unnest($1::inet[], $2::inet[]) AS u(src, dst)) u
       ON f."srcIp" = u.src AND f."dstIp" = u.dst
     WHERE f.bucket >= $3 AND f.bucket < $4
     GROUP BY f."srcIp", f."dstIp"`,
    [keys.map((k) => k.split('|')[0]), keys.map((k) => k.split('|')[1]), new Date(windowStartMs).toISOString(), new Date(toMs).toISOString()]
  );
  const avgByPair = new Map<string, number>();
  for (const a of avgRes.rows) avgByPair.set(`${a.srcIp}|${a.dstIp}`, Number(a.avg_bytes ?? 0));

  for (const [key, meta] of touched) {
    const arr = beaconHistory.get(key);
    if (!arr || arr.length === 0) continue;
    // The verdict math is pure — unit-tested in flowSecurity.test.ts.
    const verdict = beaconVerdict(arr, minBuckets, maxJitterPercent);
    if (!verdict) continue;
    const avgBytes = avgByPair.get(key);
    if (avgBytes !== undefined && avgBytes > maxAvgBytes) continue; // sustained heavy transfer — not a beacon

    const detail = `${meta.hostname ?? meta.srcIp} contacted ${meta.dstIp} in ${verdict.bucketCount} of the last ${windowHours} h with near-constant spacing` +
      ` (≈ every ${verdict.periodMinutes} min, jitter ${(verdict.jitterCv * 100).toFixed(0)}%) — possible beaconing / C2 check-in.`;
    const input: FindingInput = {
      kind: 'beacon',
      srcIp: meta.srcIp,
      dstIp: meta.dstIp,
      severity: verdict.severity,
      detail,
      context: { periodMinutes: verdict.periodMinutes, bucketCount: verdict.bucketCount, spanHours: verdict.spanHours, jitterCv: verdict.jitterCv, avgBytesPerBucket: Math.round(avgBytes ?? 0), srcHostname: meta.hostname },
      deviceId: meta.deviceId,
    };
    const isNew = await upsertFinding(input);
    if (isNew) await notifyFinding(input);
  }
}

// ── Maintenance sweeps ───────────────────────────────────────────────────────

/** Auto-resolves stale findings and prunes rows past retention. Runs every beat. */
async function autoResolveAndPrune(): Promise<void> {
  const values = await getEffectiveValues();
  const nowIso = new Date().toISOString();
  const staleCutoff = new Date(Date.now() - AUTO_RESOLVE_AFTER_MS).toISOString();
  await pool.query(
    `UPDATE flow_security_findings SET status = 'resolved', "resolvedAt" = $1
     WHERE status = 'open' AND "lastSeenAt" < $2`,
    [nowIso, staleCutoff]
  );
  const retentionDays = Number(values.flowSecurityFindingsRetentionDays) || 30;
  const cutoff = new Date(Date.now() - retentionDays * 86_400_000).toISOString();
  await pool.query(`DELETE FROM flow_security_findings WHERE "lastSeenAt" < $1`, [cutoff]);
}

// ── Beat ─────────────────────────────────────────────────────────────────────

async function beat(): Promise<void> {
  if (busy) return; // previous beat still running — skip this tick
  busy = true;
  try {
    const values = await getEffectiveValues();
    await autoResolveAndPrune();
    if (values.flowSecurityEnabled !== true) return; // master switch off — no new detections

    const nowMs = Date.now();
    // Newest bucket START that closed at least one full rollup interval ago.
    const newestProcessableMs = Math.floor((nowMs - PROCESS_LAG_MS) / BUCKET_MS) * BUCKET_MS;
    if (newestProcessableMs <= cursorBucketMs) return; // nothing new to analyze

    const fromMs = cursorBucketMs + BUCKET_MS; // first unprocessed bucket start
    const toMs = newestProcessableMs + BUCKET_MS; // exclusive end of the last one
    const fromIso = new Date(fromMs).toISOString();
    const toIso = new Date(toMs).toISOString();

    if (!(await ensureSeenSet())) return; // seen-set unavailable — retry next beat

    await detectNewDestinations(fromIso, toIso);
    await detectPortScans(fromIso, toIso);
    await detectBeacons(fromMs, toMs);
    if (nowMs - lastEgressCheckMs >= EGRESS_CHECK_INTERVAL_MS) {
      await detectEgressBaseline(toMs);
      lastEgressCheckMs = nowMs;
    }

    cursorBucketMs = newestProcessableMs;
    lastRunAt = new Date().toISOString();
    lastError = null;
  } catch (err) {
    lastError = (err as Error).message;
    // eslint-disable-next-line no-console
    console.error('[flow-security] beat failed:', err);
    throw err; // trackBeat records the error; cursor stays put → next beat retries
  } finally {
    busy = false;
  }
}

/**
 * Starts the flow security worker. Must be called only after the API has bound
 * its port (same rule as every other worker — see index.ts app.listen).
 */
export function startFlowSecurityWorker(): () => void {
  initWorker('flowSecurity', LEADER_KEYS.flowSecurity);
  // eslint-disable-next-line no-console
  console.log('[flow-security] worker started');

  void trackBeat('flowSecurity', beat).catch((err) => {
    // eslint-disable-next-line no-console
    console.error('[flow-security] initial beat failed:', err);
  });

  const timer = setInterval(() => {
    void trackBeat('flowSecurity', beat).catch((err) => {
      // eslint-disable-next-line no-console
      console.error('[flow-security] beat failed:', err);
    });
  }, BEAT_MS);

  return () => clearInterval(timer);
}
