import { pool } from '../db';
import { getEffectiveSettingValue, getEffectiveValues } from '../systemSettings';
import { lookupGeoIp } from '../utils/geoIp';
import {
  classifyIp,
  ipv4CidrToNetMask,
  lookupNetworkContext,
  parseCidrList,
  type NetworkEntry,
  type RangeLists,
} from '../utils/ipClassification';

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
  /** L4 ports (0 when the sample carried no transport header). NOT part of the PK — see db.ts. */
  srcPort: number;
  dstPort: number;
  bytes: number;
  packets: number;
  sampleCount: number;
  sampleRate: number;
  /**
   * Exporter identity (multi-exporter dedup): the exporter whose counters were
   * kept for this tuple — when several devices on the path export the SAME flow,
   * every one sees ~100% of its packets, so summing all exporters would
   * overcount ×N. The collector plugin already dedups per window (best
   * observation = highest estimated bytes) and reports agentCount = how many
   * distinct exporters saw the tuple (>1 = deduped). NULL/0 on rows from older
   * collector versions that predate exporter tracking.
   */
  agentIp: string | null;
  agentCount: number;
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

// ── Enrichment map (inventory → IP classification) ──────────────────────────
// The pure classifier + range parsing live in utils/ipClassification.ts so
// they can be unit-tested without a database.

interface EnrichmentMap {
  /** Exact-IP hits (hosts + device_ips + devices.managementAddress): ip → first-seen deviceId. */
  exact: Map<string, string>;
  /** IPv4 CIDR entries from the networks inventory (longest-prefix match). */
  cidrs: NetworkEntry[];
  /** Per-IP hostnames from the live hosts inventory — identifies WHICH host on a
   *  device an IP belongs to (e.g. container "torserver01" on KIRGUSBANDE), not
   *  just which device. Newest lastSeenAt wins per ip. */
  hostnames: Map<string, string>;
}

let enrichment: EnrichmentMap = { exact: new Map(), cidrs: [], hostnames: new Map() };
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
      // Hostname + deviceId in one pass — the hostname is what identifies the
      // actual host behind an IP (container/VM name from the docker plugin,
      // DHCP/WLAN lease names from routers).
      pool.query(`SELECT ip, "deviceId", hostname FROM hosts WHERE ip <> '' ORDER BY "lastSeenAt" DESC NULLS LAST`),
      // device_ips stores the address in `address` (not `ip`) — alias it.
      pool.query(`SELECT address AS ip, "deviceId" FROM device_ips WHERE address IS NOT NULL AND address <> ''`),
      // A device's PRIMARY address is devices.managementAddress — exporters
      // report flows against exactly these IPs, so they must enrich too.
      pool.query(
        `SELECT "managementAddress" AS ip, id AS "deviceId" FROM devices WHERE "managementAddress" <> '' AND enabled = TRUE`
      ),
      pool.query(
        `SELECT ip, prefix, version, name, "vlanId", "deviceId" FROM networks WHERE ip <> '' AND prefix IS NOT NULL`
      ),
    ]);

    // First-seen wins; most specific first (probe-derived hosts > secondary
    // device_ips > primary management address).
    const exact = new Map<string, string>();
    // Newest lease wins per ip — the query is ordered by lastSeenAt DESC.
    const hostnames = new Map<string, string>();
    for (const r of hosts.rows) {
      if (!exact.has(r.ip)) exact.set(String(r.ip), String(r.deviceId));
      if (r.hostname && !hostnames.has(String(r.ip))) hostnames.set(String(r.ip), String(r.hostname));
    }
    for (const r of deviceIps.rows) {
      if (!exact.has(r.ip)) exact.set(String(r.ip), String(r.deviceId));
    }
    for (const r of devices.rows) {
      if (!exact.has(r.ip)) exact.set(String(r.ip), String(r.deviceId));
    }

    const cidrs: NetworkEntry[] = [];
    for (const r of networks.rows) {
      // Only IPv4 participates in the CIDR match; v6 inventory is skipped.
      if (String(r.version ?? '').toLowerCase() === 'v6') continue;
      const cm = ipv4CidrToNetMask(`${r.ip}/${Number(r.prefix)}`);
      if (!cm) continue;
      cidrs.push({
        net: cm.net, mask: cm.mask, prefixLen: Number(r.prefix), deviceId: String(r.deviceId),
        name: r.name ? String(r.name) : null,
        vlanId: r.vlanId !== null && r.vlanId !== undefined ? Number(r.vlanId) : null,
      });
    }

    enrichment = { exact, cidrs, hostnames };
    lastEnrichmentRefresh = now;
  } catch (err) {
    // eslint-disable-next-line no-console
    console.warn('[flows] enrichment refresh failed:', (err as Error).message);
  }
}

/** Load the configured internal/external range lists (settings, cached). */
async function loadRangeLists(): Promise<RangeLists> {
  try {
    const values = await getEffectiveValues();
    return {
      internal: parseCidrList(String(values.flowInternalRanges)),
      external: parseCidrList(String(values.flowExternalRanges)),
    };
  } catch (err) {
    // Malformed stored value — fall back to RFC1918 defaults; never break the rollup.
    console.warn('[flows] invalid flow range settings, using RFC1918 defaults:', (err as Error).message);
    return { internal: parseCidrList('10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16'), external: [] };
  }
}

// ── Loop A: ingest drain ─────────────────────────────────────────────────────

const DRAIN_INTERVAL_MS = 1_000;
const INSERT_BATCH_SIZE = 5_000;

async function drainQueue(): Promise<void> {
  if (queue.length === 0) return;

  const rawBatch = queue.splice(0, Math.min(queue.length, INSERT_BATCH_SIZE));
  // The plugin pre-aggregates per (src|dst|proto|sp|dp), but flow_micro's PK is
  // (ts, srcIp, dstIp, proto, collectorId) — ports are NOT key columns. One push
  // can therefore carry several rows with the SAME pk and different ports; a
  // single multi-row INSERT rejects that ("ON CONFLICT DO UPDATE command cannot
  // affect row a second time"). Merge duplicates by PK first — same math as the
  // DO UPDATE clause (sum counters, GREATEST rate/ports).
  const merged = new Map<string, FlowMicroRow>();
  for (const r of rawBatch) {
    const key = `${r.ts}|${r.collectorId}|${r.srcIp}|${r.dstIp}|${r.proto}`;
    const m = merged.get(key);
    if (!m) {
      merged.set(key, { ...r });
    } else {
      const prevBytes = m.bytes;
      m.bytes += r.bytes;
      m.packets += r.packets;
      m.sampleCount += r.sampleCount;
      if (r.sampleRate > m.sampleRate) m.sampleRate = r.sampleRate;
      if (r.srcPort > m.srcPort) m.srcPort = r.srcPort;
      if (r.dstPort > m.dstPort) m.dstPort = r.dstPort;
      // Exporter identity: keep the agent of the larger contribution; counts
      // merge as a union approximation (same agent → max, distinct → sum).
      const hasM = m.agentIp !== null && m.agentIp !== '';
      const hasR = r.agentIp !== null && r.agentIp !== '';
      if (!hasM && hasR) {
        m.agentIp = r.agentIp;
        m.agentCount = Math.max(m.agentCount, r.agentCount);
      } else if (hasM && hasR && m.agentIp !== r.agentIp) {
        // Two different best agents for the same 5-tuple — keep the bigger
        // contributor's identity and union-approximate the counts.
        if (r.bytes > prevBytes) m.agentIp = r.agentIp;
        m.agentCount += r.agentCount;
      } else {
        m.agentCount = Math.max(m.agentCount, r.agentCount);
      }
    }
  }
  const batch = [...merged.values()];
  // Chunk the batch into statement-sized pieces.
  for (let i = 0; i < batch.length; i += 1_000) {
    const chunk = batch.slice(i, i + 1_000);
    const params: unknown[] = [];
    let p = 1;
    const values = chunk.map((r) => {
      params.push(r.ts, r.collectorId, r.srcIp, r.dstIp, r.proto, r.bytes, r.packets, r.sampleCount, r.sampleRate, r.srcPort, r.dstPort, r.agentIp ?? null, Math.max(0, r.agentCount | 0));
      return `($${p++}, $${p++}, $${p++}::inet, $${p++}::inet, $${p++}, $${p++}, $${p++}, $${p++}, $${p++}, $${p++}, $${p++}, $${p++}, $${p++})`;
    });

    try {
      await pool.query(
        `INSERT INTO flow_micro (ts, "collectorId", "srcIp", "dstIp", proto, bytes, packets, "sampleCount", "sampleRate", "srcPort", "dstPort", "agentIp", "agentCount")
         VALUES ${values.join(', ')}
         ON CONFLICT (ts, "srcIp", "dstIp", proto, "collectorId") DO UPDATE SET
           bytes = flow_micro.bytes + EXCLUDED.bytes,
           packets = flow_micro.packets + EXCLUDED.packets,
           "sampleCount" = flow_micro."sampleCount" + EXCLUDED."sampleCount",
           "sampleRate" = GREATEST(flow_micro."sampleRate", EXCLUDED."sampleRate"),
           -- Ports are not key columns: on a merge keep the highest seen so a
           -- real port is never overwritten by a 0 from an ICMP/UDP-less sample.
           "srcPort" = GREATEST(flow_micro."srcPort", EXCLUDED."srcPort"),
           "dstPort" = GREATEST(flow_micro."dstPort", EXCLUDED."dstPort"),
           -- Exporter identity: fill gaps, never overwrite known values; the
           -- count is a union approximation across re-pushed windows.
           "agentIp" = COALESCE(flow_micro."agentIp", EXCLUDED."agentIp"),
           "agentCount" = GREATEST(flow_micro."agentCount", EXCLUDED."agentCount")`,
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
  // Grouped per EXPORTER (agentIp) as well — the JS pass below keeps only the
  // best observation per tuple (multi-exporter dedup, see db.ts comment).
  const rows = await pool.query(
    `SELECT date_trunc('minute', ts) AS minute, "srcIp", "dstIp", proto,
            COALESCE("agentIp", '') AS agent_ip,
            SUM(bytes)::bigint AS bytes, SUM(packets)::bigint AS packets,
            MAX("sampleRate")::int AS sample_rate,
            -- Representative ports: highest seen in the window (0 = no transport header).
            MAX("srcPort")::int AS src_port, MAX("dstPort")::int AS dst_port,
            -- Union-approximate observer count from the plugin (per-window
            -- distinct exporters) — an agent that never WON best-observation
            -- in any window is still counted here.
            MAX(GREATEST("agentCount", 0))::int AS agent_count
     FROM flow_micro
     WHERE ts >= $1 AND ts < $2
     GROUP BY 1, 2, 3, 4, 5`,
    [new Date(fromMs).toISOString(), new Date(nowBucketMs).toISOString()]
  );

  if (!rows.rows.length) {
    lastRolled5mBucketMs = nowBucketMs; // empty window — advance the cursor anyway
    return;
  }

  // Group by 5-minute bucket in JS (the query returns per-minute rows),
  // keeping the counters PER EXPORTER so the best observation can be picked.
  interface AgentAgg {
    bytes: number;
    packets: number;
    sampleRate: number;
    srcPort: number;
    dstPort: number;
  }
  interface AggRow {
    bucket: string;
    srcIp: string;
    dstIp: string;
    proto: number;
    /** Per-exporter counters; '' = unknown (rows from pre-dedup collectors). */
    agents: Map<string, AgentAgg>;
    /** Max of the plugin's per-window union counts across this bucket. */
    maxAgentCount: number;
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
      a = { bucket: new Date(bucketMs).toISOString(), srcIp: String(r.srcIp), dstIp: String(r.dstIp), proto: Number(r.proto), agents: new Map(), maxAgentCount: 0 };
      byKey.set(key, a);
    }
    const ac = Number(r.agent_count ?? 0);
    if (ac > a.maxAgentCount) a.maxAgentCount = ac;
    const agentKey = String(r.agent_ip ?? '');
    let ag = a.agents.get(agentKey);
    if (!ag) {
      ag = { bytes: 0, packets: 0, sampleRate: 1, srcPort: 0, dstPort: 0 };
      a.agents.set(agentKey, ag);
    }
    ag.bytes += Number(r.bytes);
    ag.packets += Number(r.packets);
    if (Number(r.sample_rate) > ag.sampleRate) ag.sampleRate = Number(r.sample_rate);
    // Representative ports — MAX across the minutes of this 5-min bucket.
    const sp = Number(r.src_port ?? 0), dp = Number(r.dst_port ?? 0);
    if (sp > ag.srcPort) ag.srcPort = sp;
    if (dp > ag.dstPort) ag.dstPort = dp;
  }

  // Load the configured range lists once per tick (settings are cached).
  const ranges = await loadRangeLists();

  interface RollupRow {
    bucket: string; srcIp: string; dstIp: string; proto: number; bytes: number; packets: number; estBytes: number;
    srcPort: number; dstPort: number;
    agentIp: string | null; agentCount: number;
    srcDeviceId: string | null; dstDeviceId: string | null; srcClass: string; dstClass: string;
    srcNetworkName: string | null; dstNetworkName: string | null; srcVlanId: number | null; dstVlanId: number | null;
    srcHostname: string | null; dstHostname: string | null;
    /** Stored GeoIP country (ISO-3166 alpha-2) — enables the /flows/internet
     *  country aggregation without per-request lookups. */
    srcCountryCode: string | null; dstCountryCode: string | null;
  }
  const aggRows: RollupRow[] = [];
  for (const a of byKey.values()) {
    // Multi-exporter dedup — several devices on the path export the SAME flow
    // and each sees ~100% of its packets, so summing all exporters would
    // overcount ×N. Keep only the BEST OBSERVATION: the exporter with the
    // highest estimated bytes (reported × rate; comparable across different
    // sampling rates — an agent whose port was down part of the window has
    // fewer bytes and loses). agentCount = distinct exporters that saw it.
    let bestIp = '';
    let best: AgentAgg | null = null;
    for (const [ip, ag] of a.agents) {
      if (!best || ag.bytes * ag.sampleRate > best.bytes * best.sampleRate) {
        bestIp = ip;
        best = ag;
      }
    }
    const src = classifyIp(a.srcIp, enrichment.exact.get(a.srcIp) ?? null, enrichment.cidrs, ranges);
    const dst = classifyIp(a.dstIp, enrichment.exact.get(a.dstIp) ?? null, enrichment.cidrs, ranges);
    // Network display context (name + VLAN) via longest-prefix inventory match.
    const srcNet = lookupNetworkContext(a.srcIp, enrichment.cidrs);
    const dstNet = lookupNetworkContext(a.dstIp, enrichment.cidrs);
    // Stored GeoIP country for EXTERNAL endpoints only — internal/unknown IPs
    // never get a code (they are not internet destinations). Best-effort: no
    // active database → null, and the geoip worker backfills later. The lookup
    // is cached per IP in-process, so repeated tuples cost nothing.
    const [srcGeo, dstGeo] = await Promise.all([
      src.cls === 'internet' ? lookupGeoIp(a.srcIp) : Promise.resolve(null),
      dst.cls === 'internet' ? lookupGeoIp(a.dstIp) : Promise.resolve(null),
    ]);
    // estBytes: reported bytes × sampling rate, capped at int8.
    aggRows.push({
      bucket: a.bucket, srcIp: a.srcIp, dstIp: a.dstIp, proto: a.proto, bytes: best!.bytes, packets: best!.packets,
      estBytes: Math.min(Number.MAX_SAFE_INTEGER, best!.bytes * best!.sampleRate),
      srcPort: best!.srcPort, dstPort: best!.dstPort,
      // Distinct agents that WON at least one window + the plugin's per-window
      // union count (catches agents that observed but never won) — take the
      // stronger lower bound of both.
      agentIp: bestIp === '' ? null : bestIp, agentCount: Math.max(a.agents.size, a.maxAgentCount),
      srcDeviceId: src.deviceId, dstDeviceId: dst.deviceId, srcClass: src.cls, dstClass: dst.cls,
      srcNetworkName: srcNet?.name ?? null, dstNetworkName: dstNet?.name ?? null,
      srcVlanId: srcNet?.vlanId ?? null, dstVlanId: dstNet?.vlanId ?? null,
      // Which host on the device — container/VM name or DHCP lease hostname.
      srcHostname: enrichment.hostnames.get(a.srcIp) ?? null, dstHostname: enrichment.hostnames.get(a.dstIp) ?? null,
      srcCountryCode: srcGeo?.countryCode ?? null, dstCountryCode: dstGeo?.countryCode ?? null,
    });
  }

  // Chunk the INSERT — Postgres caps bind parameters at 65535 (int16) per
  // statement; a busy catch-up window can easily exceed that. 2_500 rows ×
  // 23 params = 57.5k, safely under the limit (same pattern as drainQueue).
  const ROLLUP_INSERT_CHUNK_ROWS = 2_500;
  for (let i = 0; i < aggRows.length; i += ROLLUP_INSERT_CHUNK_ROWS) {
    const chunk = aggRows.slice(i, i + ROLLUP_INSERT_CHUNK_ROWS);
    const params: unknown[] = [];
    let p = 1;
    const values = chunk.map((r) => {
      params.push(r.bucket, r.srcIp, r.dstIp, r.proto, r.bytes, r.packets, r.estBytes, r.srcPort, r.dstPort, r.agentIp ?? null, Math.max(0, r.agentCount | 0), r.srcDeviceId, r.dstDeviceId, r.srcClass, r.dstClass, r.srcNetworkName, r.dstNetworkName, r.srcVlanId, r.dstVlanId, r.srcHostname, r.dstHostname, r.srcCountryCode ?? null, r.dstCountryCode ?? null);
      return `($${p++}, $${p++}::inet, $${p++}::inet, $${p++}, $${p++}, $${p++}, $${p++}, $${p++}, $${p++}, $${p++}, $${p++}, $${p++}, $${p++}, $${p++}, $${p++}, $${p++}, $${p++}, $${p++}, $${p++}, $${p++}, $${p++}, $${p++}, $${p++})`;
    });
    await pool.query(
      `INSERT INTO flow_agg_5m (bucket, "srcIp", "dstIp", proto, bytes, packets, "estBytes", "srcPort", "dstPort", "agentIp", "agentCount", "srcDeviceId", "dstDeviceId", "srcClass", "dstClass", "srcNetworkName", "dstNetworkName", "srcVlanId", "dstVlanId", "srcHostname", "dstHostname", "srcCountryCode", "dstCountryCode")
       VALUES ${values.join(', ')}
       ON CONFLICT (bucket, "srcIp", "dstIp", proto) DO UPDATE SET
         bytes = flow_agg_5m.bytes + EXCLUDED.bytes,
         packets = flow_agg_5m.packets + EXCLUDED.packets,
         "estBytes" = flow_agg_5m."estBytes" + EXCLUDED."estBytes",
         -- Representative ports: keep the highest seen across ticks.
         "srcPort" = GREATEST(flow_agg_5m."srcPort", EXCLUDED."srcPort"),
         "dstPort" = GREATEST(flow_agg_5m."dstPort", EXCLUDED."dstPort"),
         -- Exporter identity: fill gaps, never overwrite known values; the
         -- count is a union approximation across ticks.
         "agentIp" = COALESCE(flow_agg_5m."agentIp", EXCLUDED."agentIp"),
         "agentCount" = GREATEST(flow_agg_5m."agentCount", EXCLUDED."agentCount"),
         -- Network context may have been NULL on an earlier tick (inventory
         -- was empty then) — fill gaps, never overwrite known values.
         "srcNetworkName" = COALESCE(EXCLUDED."srcNetworkName", flow_agg_5m."srcNetworkName"),
         "dstNetworkName" = COALESCE(EXCLUDED."dstNetworkName", flow_agg_5m."dstNetworkName"),
         "srcVlanId" = COALESCE(EXCLUDED."srcVlanId", flow_agg_5m."srcVlanId"),
         "dstVlanId" = COALESCE(EXCLUDED."dstVlanId", flow_agg_5m."dstVlanId"),
         -- Hostnames: fill gaps, never overwrite known values.
         "srcHostname" = COALESCE(EXCLUDED."srcHostname", flow_agg_5m."srcHostname"),
         "dstHostname" = COALESCE(EXCLUDED."dstHostname", flow_agg_5m."dstHostname"),
         -- Stored GeoIP country: fill gaps, never overwrite known values.
         "srcCountryCode" = COALESCE(EXCLUDED."srcCountryCode", flow_agg_5m."srcCountryCode"),
         "dstCountryCode" = COALESCE(EXCLUDED."dstCountryCode", flow_agg_5m."dstCountryCode")`,
      params
    );
  }

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
     `INSERT INTO flow_agg_1h (bucket, "srcIp", "dstIp", proto, bytes, packets, "estBytes", "srcPort", "dstPort", "agentIp", "agentCount", "srcDeviceId", "dstDeviceId", "srcClass", "dstClass", "srcNetworkName", "dstNetworkName", "srcVlanId", "dstVlanId", "srcHostname", "dstHostname", "srcCountryCode", "dstCountryCode")
     SELECT date_trunc('hour', bucket), "srcIp", "dstIp", proto,
            SUM(bytes)::bigint, SUM(packets)::bigint, SUM("estBytes")::bigint,
            MAX("srcPort"), MAX("dstPort"),
            -- Exporter identity: the agent of the largest 5-min observation
            // wins (NULL-safe). MAX (not SUM) across buckets — the exporter set
            // on a path is stable within an hour, so summing would overcount ×N.
            (ARRAY_AGG("agentIp" ORDER BY bytes DESC NULLS LAST))[1], MAX(GREATEST("agentCount", 0))::int,
            MAX("srcDeviceId"), MAX("dstDeviceId"),
            -- 'internal' wins over 'internet'/'unknown' when a tuple's endpoints
            -- were classified differently across the hour (inventory changed).
            CASE WHEN BOOL_OR("srcClass" = 'internal') THEN 'internal'
                 WHEN BOOL_OR("srcClass" = 'internet') THEN 'internet' ELSE 'unknown' END,
            CASE WHEN BOOL_OR("dstClass" = 'internal') THEN 'internal'
                 WHEN BOOL_OR("dstClass" = 'internet') THEN 'internet' ELSE 'unknown' END,
            MAX("srcNetworkName"), MAX("dstNetworkName"),
            MAX("srcVlanId"), MAX("dstVlanId"),
            MAX("srcHostname"), MAX("dstHostname"),
            -- Stored GeoIP country: an IP's country is stable within an hour —
            -- MAX ignores NULLs, so a partially-filled hour still carries the code.
            MAX("srcCountryCode"), MAX("dstCountryCode")
     FROM flow_agg_5m
     WHERE bucket >= $1 AND bucket < $2
     GROUP BY 1, 2, 3, 4
     ON CONFLICT (bucket, "srcIp", "dstIp", proto) DO UPDATE SET
       bytes = flow_agg_1h.bytes + EXCLUDED.bytes,
       packets = flow_agg_1h.packets + EXCLUDED.packets,
       "estBytes" = flow_agg_1h."estBytes" + EXCLUDED."estBytes",
       -- Representative ports: keep the highest seen across ticks.
       "srcPort" = GREATEST(flow_agg_1h."srcPort", EXCLUDED."srcPort"),
       "dstPort" = GREATEST(flow_agg_1h."dstPort", EXCLUDED."dstPort"),
       -- Exporter identity: fill gaps, never overwrite known values.
       "agentIp" = COALESCE(flow_agg_1h."agentIp", EXCLUDED."agentIp"),
       "agentCount" = GREATEST(flow_agg_1h."agentCount", EXCLUDED."agentCount"),
       -- Network context: prefer what is already stored (a later tick may have
       -- rolled a window whose rows predate the inventory enrichment).
       "srcNetworkName" = COALESCE(flow_agg_1h."srcNetworkName", EXCLUDED."srcNetworkName"),
       "dstNetworkName" = COALESCE(flow_agg_1h."dstNetworkName", EXCLUDED."dstNetworkName"),
       "srcVlanId" = COALESCE(flow_agg_1h."srcVlanId", EXCLUDED."srcVlanId"),
       "dstVlanId" = COALESCE(flow_agg_1h."dstVlanId", EXCLUDED."dstVlanId"),
       -- Hostnames: prefer what is already stored.
       "srcHostname" = COALESCE(flow_agg_1h."srcHostname", EXCLUDED."srcHostname"),
       "dstHostname" = COALESCE(flow_agg_1h."dstHostname", EXCLUDED."dstHostname"),
       -- Stored GeoIP country: fill gaps, never overwrite known values.
       "srcCountryCode" = COALESCE(EXCLUDED."srcCountryCode", flow_agg_1h."srcCountryCode"),
       "dstCountryCode" = COALESCE(EXCLUDED."dstCountryCode", flow_agg_1h."dstCountryCode")`,
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
