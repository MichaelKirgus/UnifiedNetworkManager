import { pool } from '../db';
import { getEffectiveSettingValue } from '../systemSettings';

/**
 * Flow-data worker (sFlow/NetFlow collector feature).
 *
 * Owns everything that happens AFTER the flow-collector plugin pushes a batch
 * of pre-aggregated tuples to POST /plugin/flows:
 *
 *   A. ingest drain  — the internal route only ENQUEUES (O(1), no DB work on
 *      the request path, so high-volume flow traffic can never stall the main
 *      API). This loop batch-inserts queued rows into `flow_micro` (~5k-row
 *      multi-value INSERTs with ON CONFLICT summing for duplicate tuples).
 *   B. 5-min rollup  — every 5 minutes, completed windows are aggregated from
 *      flow_micro into flow_agg_5m WITH enrichment: each endpoint IP is joined
 *      against an in-memory map built from the hosts / device_ips / devices
 *      (managementAddress) / networks inventory (refreshed every 60 s) and
 *      classified internal | internet | unknown; estBytes = reported bytes ×
 *      sampling rate.
 *   C. hourly rollup — rolls flow_agg_5m into flow_agg_1h (long-term tier).
 *   D. partitions    — ensures the next weeks' range partitions exist on all
 *      three tables and drops expired ones (retention = instant DROP PARTITION,
 *      no multi-GB cutoff DELETE / VACUUM pressure).
 *
 * The flow tables deliberately use real timestamptz + weekly RANGE partitions +
 * BRIN indexes — see the DDL in initDb() (api/src/db.ts) for why they are an
 * exception to the repo's TEXT-timestamp convention.
 */

// ── Ingest queue (shared with routes/internal.ts POST /plugin/flows) ────────

export interface FlowMicroRow {
  ts: string; // ISO-8601 instant of the tuple window start
  collectorId: string;
  srcIp: string;
  dstIp: string;
  proto: number;
  bytes: number;
  packets: number;
  sampleCount: number;
  sampleRate: number;
}

const MAX_QUEUE_ROWS = 100_000; // bounded memory; overflow drops OLDEST rows
let queue: FlowMicroRow[] = [];
let enqueuedTotal = 0;
let droppedTotal = 0;
let insertedTotal = 0;
let lastInsertAt: string | null = null;
let lastError: string | null = null;

/** Enqueue one batch from the internal route. Drops oldest rows on overflow. */
export function enqueueFlowRows(rows: FlowMicroRow[]): void {
  if (rows.length === 0) return;
  enqueuedTotal += rows.length;
  queue.push(...rows);
  const overflow = queue.length - MAX_QUEUE_ROWS;
  if (overflow > 0) {
    queue.splice(0, overflow);
    droppedTotal += overflow;
  }
}

/** Snapshot for GET /v1/flow-collectors + diagnostics. */
export function getFlowIngestStats(): {
  queueDepth: number;
  enqueuedTotal: number;
  droppedTotal: number;
  insertedTotal: number;
  lastInsertAt: string | null;
  lastError: string | null;
} {
  return {
    queueDepth: queue.length,
    enqueuedTotal,
    droppedTotal,
    insertedTotal,
    lastInsertAt,
    lastError,
  };
}

// ── IPv4 helpers (enrichment CIDR matching — no external dependency) ────────

function ipv4ToInt(ip: string): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m) return null;
  let n = 0;
  for (let i = 1; i <= 4; i++) {
    const octet = Number(m[i]);
    if (octet > 255) return null;
    n = (n << 8) | octet;
  }
  return n >>> 0;
}

/** Prefix network + mask for "a.b.c.d/p" (or bare IP → /32). */
function ipv4CidrToNetMask(cidr: string): { net: number; mask: number } | null {
  const [ipPart, prefixPart] = cidr.split('/');
  const ip = ipv4ToInt(ipPart.trim());
  if (ip === null) return null;
  const prefix = prefixPart !== undefined ? Number(prefixPart) : 32;
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null;
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  return { net: (ip & mask) >>> 0, mask };
}

// ── Enrichment map (inventory → IP classification) ──────────────────────────

interface CidrEntry {
  net: number;
  mask: number;
  prefixLen: number; // longest-prefix wins on ties
  deviceId: string | null;
}

interface EnrichmentMap {
  /** Exact-IP hits (hosts + device_ips): ip → first-seen deviceId. */
  exact: Map<string, string>;
  /** IPv4 CIDR entries from the networks inventory (longest-prefix match). */
  cidrs: CidrEntry[];
}

let enrichment: EnrichmentMap = { exact: new Map(), cidrs: [] };
let lastEnrichmentRefresh = 0;

/**
 * Rebuilds the in-memory IP→device map from the live inventory. Called at most
 * once per minute (rollup cadence is coarser). Failures keep the previous map
 * — enrichment must never break the rollup cycle.
 */
async function refreshEnrichment(): Promise<void> {
  const now = Date.now();
  if (now - lastEnrichmentRefresh < 60_000) return;

  try {
    const [hosts, deviceIps, devices, networks] = await Promise.all([
      pool.query(`SELECT ip, "deviceId" FROM hosts WHERE ip <> ''`),
      // device_ips stores the address in `address` (not `ip`) — alias it.
      pool.query(`SELECT address AS ip, "deviceId" FROM device_ips WHERE address IS NOT NULL AND address <> ''`),
      // A device's PRIMARY address is devices.managementAddress — exporters
      // report flows against exactly these IPs, so they must enrich too.
      pool.query(
        `SELECT "managementAddress" AS ip, id AS "deviceId" FROM devices WHERE "managementAddress" <> '' AND enabled = TRUE`
      ),
      pool.query(
        `SELECT ip, prefix, version, "deviceId" FROM networks WHERE ip <> '' AND prefix IS NOT NULL`
      ),
    ]);

    // First-seen wins; most specific first (probe-derived hosts > secondary
    // device_ips > primary management address).
    const exact = new Map<string, string>();
    for (const r of hosts.rows) {
      if (!exact.has(r.ip)) exact.set(String(r.ip), String(r.deviceId));
    }
    for (const r of deviceIps.rows) {
      if (!exact.has(r.ip)) exact.set(String(r.ip), String(r.deviceId));
    }
    for (const r of devices.rows) {
      if (!exact.has(r.ip)) exact.set(String(r.ip), String(r.deviceId));
    }

    const cidrs: CidrEntry[] = [];
    for (const r of networks.rows) {
      // Only IPv4 participates in the CIDR match; v6 inventory is skipped.
      if (String(r.version ?? '').toLowerCase() === 'v6') continue;
      const cm = ipv4CidrToNetMask(`${r.ip}/${Number(r.prefix)}`);
      if (!cm) continue;
      cidrs.push({ net: cm.net, mask: cm.mask, prefixLen: Number(r.prefix), deviceId: String(r.deviceId) });
    }

    enrichment = { exact, cidrs };
    lastEnrichmentRefresh = now;
  } catch (err) {
    // eslint-disable-next-line no-console
    console.warn('[flows] enrichment refresh failed:', (err as Error).message);
  }
}

/** Classify one endpoint IP: internal (known device/network) | internet | unknown. */
function classifyIp(ip: string): { cls: 'internal' | 'internet' | 'unknown'; deviceId: string | null } {
  const exactHit = enrichment.exact.get(ip);
  if (exactHit) return { cls: 'internal', deviceId: exactHit };

  const n = ipv4ToInt(ip);
  if (n !== null) {
    // RFC1918 private ranges are internal by definition (even without an
    // inventory match). NOTE: `&` yields a SIGNED int32 in JS, so both sides of
    // each comparison must be normalized with `>>> 0` — otherwise masks whose
    // result has the high bit set (172.16/12, 192.168/16, …) compare against a
    // positive literal and never match.
    if (((n & 0xff00_0000) >>> 0) === 0x0a00_0000 || // 10/8
        ((n & 0xfff0_0000) >>> 0) === 0xac10_0000 || // 172.16/12
        ((n & 0xffff_0000) >>> 0) === 0xc0a8_0000) { // 192.168/16
      return { cls: 'internal', deviceId: null };
    }
    if (((n & 0xffff_ff00) >>> 0) === 0xa9fe_0000 || // 169.254/16 link-local
        ((n & 0xff00_0000) >>> 0) === 0x0000_0000 || // 0.0.0.0/8
        ((n & 0xf800_0000) >>> 0) === 0xe000_0000 || // 224/4 multicast + 240/4 reserved
        ((n & 0xff00_0000) >>> 0) === 0xff00_0000) { // 255.255.255.x
      return { cls: 'unknown', deviceId: null };
    }

    let best: CidrEntry | null = null;
    for (const c of enrichment.cidrs) {
      // Same signed-int32 caveat as above — normalize both sides.
      if (((n & c.mask) >>> 0) === c.net && (!best || c.prefixLen > best.prefixLen)) best = c;
    }
    if (best) return { cls: 'internal', deviceId: best.deviceId };

    // Public IPv4 that matches no internal network → internet.
    return { cls: 'internet', deviceId: null };
  }

  // IPv6 or unparseable: not link-local/ULA we can cheaply test here — treat as
  // unknown (v6 internet classification is a deliberate v1 simplification).
  if (ip.includes(':')) return { cls: 'unknown', deviceId: null };
  return { cls: 'unknown', deviceId: null };
}

// ── Loop A: ingest drain ─────────────────────────────────────────────────────

const DRAIN_INTERVAL_MS = 1_000;
const INSERT_BATCH_SIZE = 5_000;

async function drainQueue(): Promise<void> {
  if (queue.length === 0) return;

  const batch = queue.splice(0, Math.min(queue.length, INSERT_BATCH_SIZE));
  // Chunk the batch into statement-sized pieces.
  for (let i = 0; i < batch.length; i += 1_000) {
    const chunk = batch.slice(i, i + 1_000);
    const params: unknown[] = [];
    let p = 1;
    const values = chunk.map((r) => {
      params.push(r.ts, r.collectorId, r.srcIp, r.dstIp, r.proto, r.bytes, r.packets, r.sampleCount, r.sampleRate);
      return `($${p++}, $${p++}, $${p++}::inet, $${p++}::inet, $${p++}, $${p++}, $${p++}, $${p++}, $${p++})`;
    });

    try {
      await pool.query(
        `INSERT INTO flow_micro (ts, "collectorId", "srcIp", "dstIp", proto, bytes, packets, "sampleCount", "sampleRate")
         VALUES ${values.join(', ')}
         ON CONFLICT (ts, "srcIp", "dstIp", proto, "collectorId") DO UPDATE SET
           bytes = flow_micro.bytes + EXCLUDED.bytes,
           packets = flow_micro.packets + EXCLUDED.packets,
           "sampleCount" = flow_micro."sampleCount" + EXCLUDED."sampleCount",
           "sampleRate" = GREATEST(flow_micro."sampleRate", EXCLUDED."sampleRate")`,
        params
      );
      insertedTotal += chunk.length;
      lastInsertAt = new Date().toISOString();
    } catch (err) {
      // Re-queue the failed chunk at the FRONT so no data is lost; the next
      // drain retries. lastError surfaces on GET /v1/flow-collectors.
      queue.unshift(...chunk);
      lastError = (err as Error).message;
      break;
    }
  }
}

// ── Loop B: 5-minute rollup with enrichment ──────────────────────────────────

const ROLLUP_5M_INTERVAL_MS = 5 * 60_000;
// Cursor of the last COMPLETED 5-min bucket boundary already rolled up. On a
// fresh start it is "now truncated to 5 min" — i.e. only NEW data rolls, and a
// missed beat (API restart) simply catches up on the next cycle.
let lastRolled5mBucketMs = Math.floor(Date.now() / 300_000) * 300_000;
const ROLLUP_MAX_CATCHUP_MS = 24 * 3600_000; // never roll more than a day at once

async function rollupTo5m(): Promise<void> {
  await refreshEnrichment();

  const nowBucketMs = Math.floor(Date.now() / 300_000) * 300_000;
  if (nowBucketMs <= lastRolled5mBucketMs) return; // nothing new yet

  const fromMs = Math.max(lastRolled5mBucketMs, nowBucketMs - ROLLUP_MAX_CATCHUP_MS);
  const rows = await pool.query(
    `SELECT date_trunc('minute', ts) AS minute, "srcIp", "dstIp", proto,
            SUM(bytes)::bigint AS bytes, SUM(packets)::bigint AS packets,
            MAX("sampleRate")::int AS sample_rate
     FROM flow_micro
     WHERE ts >= $1 AND ts < $2
     GROUP BY 1, 2, 3, 4`,
    [new Date(fromMs).toISOString(), new Date(nowBucketMs).toISOString()]
  );

  if (!rows.rows.length) {
    lastRolled5mBucketMs = nowBucketMs; // empty window — advance the cursor anyway
    return;
  }

  // Group by 5-minute bucket in JS (the query returns per-minute rows).
  interface AggRow {
    bucket: string;
    srcIp: string;
    dstIp: string;
    proto: number;
    bytes: number;
    packets: number;
    sampleRate: number;
  }
  // Defensive normalization: node-postgres normally returns timestamptz as a JS
  // Date, but in some process states (pg-types parser state) it can come back
  // as the raw text. Accept both — and log once if we ever see a non-Date so
  // the discrepancy is diagnosable instead of crashing every rollup tick.
  let minuteTypeLogged = false;

  const byKey = new Map<string, AggRow>();
  for (const r of rows.rows) {
    const rawMinute: unknown = r.minute;
    if (!minuteTypeLogged && !(rawMinute instanceof Date)) {
      minuteTypeLogged = true;
      // eslint-disable-next-line no-console
      console.warn(`[flows] rollup: "minute" arrived as ${typeof rawMinute} (${JSON.stringify(rawMinute)}) — normalizing`);
    }
    const d: Date = rawMinute instanceof Date ? rawMinute : new Date(String(rawMinute));
    if (Number.isNaN(d.getTime())) continue; // unparseable timestamp — skip, don't crash the tick
    const bucketMs = Math.floor(d.getTime() / 300_000) * 300_000;
    const key = `${bucketMs}|${r.srcIp}|${r.dstIp}|${r.proto}`;
    let a = byKey.get(key);
    if (!a) {
      a = { bucket: new Date(bucketMs).toISOString(), srcIp: String(r.srcIp), dstIp: String(r.dstIp), proto: Number(r.proto), bytes: 0, packets: 0, sampleRate: 1 };
      byKey.set(key, a);
    }
    a.bytes += Number(r.bytes);
    a.packets += Number(r.packets);
    if (Number(r.sample_rate) > a.sampleRate) a.sampleRate = Number(r.sample_rate);
  }

  const params: unknown[] = [];
  let p = 1;
  const values: string[] = [];
  for (const a of byKey.values()) {
    const src = classifyIp(a.srcIp);
    const dst = classifyIp(a.dstIp);
    // estBytes: reported bytes × sampling rate, capped at int8.
    const estBytes = Math.min(Number.MAX_SAFE_INTEGER, a.bytes * a.sampleRate);
    params.push(
      a.bucket, a.srcIp, a.dstIp, a.proto, a.bytes, a.packets, estBytes,
      src.deviceId, dst.deviceId, src.cls, dst.cls
    );
    values.push(`($${p++}, $${p++}::inet, $${p++}::inet, $${p++}, $${p++}, $${p++}, $${p++}, $${p++}, $${p++}, $${p++}, $${p++})`);
  }

  await pool.query(
    `INSERT INTO flow_agg_5m (bucket, "srcIp", "dstIp", proto, bytes, packets, "estBytes", "srcDeviceId", "dstDeviceId", "srcClass", "dstClass")
     VALUES ${values.join(', ')}
     ON CONFLICT (bucket, "srcIp", "dstIp", proto) DO UPDATE SET
       bytes = flow_agg_5m.bytes + EXCLUDED.bytes,
       packets = flow_agg_5m.packets + EXCLUDED.packets,
       "estBytes" = flow_agg_5m."estBytes" + EXCLUDED."estBytes"`,
    params
  );

  lastRolled5mBucketMs = nowBucketMs;
  // eslint-disable-next-line no-console
  console.log(`[flows] rolled ${byKey.size} tuple(s) into flow_agg_5m (up to ${new Date(nowBucketMs).toISOString()})`);
}

// ── Loop C: hourly rollup (pure SQL — enrichment already stored in 5m rows) ──

const ROLLUP_1H_INTERVAL_MS = 60 * 60_000;
// Cursor of the last COMPLETED hour boundary already rolled up.
let lastRolled1hBucketMs = Math.floor(Date.now() / 3600_000) * 3600_000;
const ROLLUP_1H_MAX_CATCHUP_MS = 72 * 3600_000; // never roll more than 3 days at once

async function rollupTo1h(): Promise<void> {
  const nowBucketMs = Math.floor(Date.now() / 3600_000) * 3600_000;
  if (nowBucketMs <= lastRolled1hBucketMs) return; // nothing new yet

  const fromMs = Math.max(lastRolled1hBucketMs, nowBucketMs - ROLLUP_1H_MAX_CATCHUP_MS);
  const res = await pool.query(
    `INSERT INTO flow_agg_1h (bucket, "srcIp", "dstIp", proto, bytes, packets, "estBytes", "srcDeviceId", "dstDeviceId", "srcClass", "dstClass")
     SELECT date_trunc('hour', bucket), "srcIp", "dstIp", proto,
            SUM(bytes)::bigint, SUM(packets)::bigint, SUM("estBytes")::bigint,
            MAX("srcDeviceId"), MAX("dstDeviceId"),
            -- 'internal' wins over 'internet'/'unknown' when a tuple's endpoints
            -- were classified differently across the hour (inventory changed).
            CASE WHEN BOOL_OR("srcClass" = 'internal') THEN 'internal'
                 WHEN BOOL_OR("srcClass" = 'internet') THEN 'internet' ELSE 'unknown' END,
            CASE WHEN BOOL_OR("dstClass" = 'internal') THEN 'internal'
                 WHEN BOOL_OR("dstClass" = 'internet') THEN 'internet' ELSE 'unknown' END
     FROM flow_agg_5m
     WHERE bucket >= $1 AND bucket < $2
     GROUP BY 1, 2, 3, 4
     ON CONFLICT (bucket, "srcIp", "dstIp", proto) DO UPDATE SET
       bytes = flow_agg_1h.bytes + EXCLUDED.bytes,
       packets = flow_agg_1h.packets + EXCLUDED.packets,
       "estBytes" = flow_agg_1h."estBytes" + EXCLUDED."estBytes"`,
    [new Date(fromMs).toISOString(), new Date(nowBucketMs).toISOString()]
  );

  lastRolled1hBucketMs = nowBucketMs;
  if (res.rowCount) {
    // eslint-disable-next-line no-console
    console.log(`[flows] rolled ${res.rowCount} tuple(s) into flow_agg_1h`);
  }
}

// ── Loop D: partition maintenance (create upcoming, drop expired) ────────────

const PARTITION_INTERVAL_MS = 60 * 60_000; // hourly + once at startup

/** Monday 00:00 UTC of the week containing `d`. */
function startOfWeek(d: Date): Date {
  const day = (d.getUTCDay() + 6) % 7; // Mon=0 … Sun=6
  const out = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
  out.setUTCDate(out.getUTCDate() - day);
  return out;
}

function isoWeekBounds(weekStart: Date): { from: string; to: string } {
  const from = weekStart.toISOString();
  const to = new Date(weekStart.getTime() + 7 * 86_400_000).toISOString();
  return { from, to };
}

async function ensureFlowPartitions(): Promise<void> {
  const now = new Date();
  const currentWeek = startOfWeek(now);

  // Create partitions for the current week + the next two (covers rollup lag).
  for (let w = 0; w <= 2; w++) {
    const ws = new Date(currentWeek.getTime() + w * 7 * 86_400_000);
    const { from, to } = isoWeekBounds(ws);
    const suffix = `_${ws.toISOString().slice(0, 10).replace(/-/g, '')}`; // e.g. _20261005
    for (const [table, col] of [
      ['flow_micro', 'ts'],
      ['flow_agg_5m', 'bucket'],
      ['flow_agg_1h', 'bucket'],
    ] as const) {
      // DDL does not support bind parameters — inline the internally-generated ISO strings.
      await pool.query(
        `CREATE TABLE IF NOT EXISTS ${table}${suffix} PARTITION OF ${table} FOR VALUES FROM ('${from}') TO ('${to}')`
      );
    }
  }

  // Drop expired partitions per retention setting.
  const microDays = Number(await getEffectiveSettingValue('flowMicroRetentionDays')) || 7;
  const agg5mDays = Number(await getEffectiveSettingValue('flowAgg5mRetentionDays')) || 30;
  const agg1hDays = Number(await getEffectiveSettingValue('flowAgg1hRetentionDays')) || 180;

  for (const [table, col, days] of [
    ['flow_micro', 'ts', microDays],
    ['flow_agg_5m', 'bucket', agg5mDays],
    ['flow_agg_1h', 'bucket', agg1hDays],
  ] as const) {
    const cutoff = new Date(Date.now() - days * 86_400_000);
    // Find child partitions whose upper bound is fully before the cutoff.
    const found = await pool.query(
      `SELECT c.relname AS name, (regexp_match(c.relname, '_([0-9]{8})$'))[1] AS week_start
       FROM pg_inherits i
       JOIN pg_class p ON p.oid = i.inhparent
       JOIN pg_class c ON c.oid = i.inhrelid
       WHERE p.relname = $1 AND c.relkind = 'r'`,
      [table]
    );
    for (const r of found.rows) {
      const weekStartNum = Number(r.week_start); // partition named by its START date, e.g. flow_micro_20261005
      if (!Number.isFinite(weekStartNum)) continue;
      const start = new Date(`${String(r.week_start).slice(0, 4)}-${String(r.week_start).slice(4, 6)}-${String(r.week_start).slice(6, 8)}T00:00:00.000Z`);
      const end = new Date(start.getTime() + 7 * 86_400_000);
      if (end <= cutoff) {
        await pool.query(`DROP TABLE IF EXISTS ${table}_${r.week_start}`);
        // eslint-disable-next-line no-console
        console.log(`[flows] dropped expired partition ${table}_${r.week_start} (${col} retention ${days}d)`);
      }
    }
  }
}

// ── Worker lifecycle ─────────────────────────────────────────────────────────

/**
 * Starts the flows worker. Must be called only after the API has bound its port
 * (same rule as every other worker — see index.ts app.listen). Returns a stop
 * function that clears all timers.
 */
export function startFlowsWorker(): () => void {
  // eslint-disable-next-line no-console
  console.log('[flows] worker started (ingest drain + rollups + partition maintenance)');

  const drainTimer = setInterval(() => {
    void drainQueue().catch((err) => {
      lastError = (err as Error).message;
      // eslint-disable-next-line no-console
      console.error('[flows] ingest drain failed:', err);
    });
  }, DRAIN_INTERVAL_MS);

  const rollup5mTimer = setInterval(() => {
    void rollupTo5m().catch((err) => {
      lastError = (err as Error).message;
      // eslint-disable-next-line no-console
      console.error('[flows] 5-min rollup failed:', err);
    });
  }, ROLLUP_5M_INTERVAL_MS);

  const rollup1hTimer = setInterval(() => {
    void rollupTo1h().catch((err) => {
      lastError = (err as Error).message;
      // eslint-disable-next-line no-console
      console.error('[flows] hourly rollup failed:', err);
    });
  }, ROLLUP_1H_INTERVAL_MS);

  const partitionTimer = setInterval(() => {
    void ensureFlowPartitions().catch((err) => {
      lastError = (err as Error).message;
      // eslint-disable-next-line no-console
      console.error('[flows] partition maintenance failed:', err);
    });
  }, PARTITION_INTERVAL_MS);

  // First pass: partitions immediately (so the first ingest can land), rollups
  // on their normal cadence.
  void ensureFlowPartitions().catch((err) => {
    lastError = (err as Error).message;
    // eslint-disable-next-line no-console
    console.error('[flows] initial partition maintenance failed:', err);
  });

  return () => {
    clearInterval(drainTimer);
    clearInterval(rollup5mTimer);
    clearInterval(rollup1hTimer);
    clearInterval(partitionTimer);
  };
}
