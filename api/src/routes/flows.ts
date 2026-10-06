import { Router, Request, Response } from 'express';
import { pool } from '../db';
import { requireAuth, requirePermission } from '../auth/middleware';
import { pluginAxios } from '../utils/pluginHttp';
import { reverseLookup } from '../utils/reverseDns';
import { lookupGeoIp } from '../utils/geoIp';
import { getFlowIngestStats } from '../workers/flows';
import { mergeNetworkRows } from './networks';
import type { MergedNetwork } from './networks';
import { ipInCidr } from '@unm/plugin-sdk';

/**
 * Flows page routes (sFlow/NetFlow traffic visibility).
 *
 * All queries hit the AGGREGATE tables only (flow_agg_5m / flow_agg_1h) — the
 * raw flow_micro tier is worker-internal. The 5-minute table serves ranges up
 * to its retention window; anything older auto-falls back to the hourly table.
 * Bucketing/aggregation happens in SQL (GROUP BY on the bucket column) — this
 * is the first time-series aggregation feature in the API; existing history
 * endpoints return raw rows with small LIMITs and no SQL grouping.
 */

const router = Router();

/** Parse an ISO date param into epoch ms, or null when absent/invalid. */
function parseTimeParam(v: unknown): number | null {
  if (typeof v !== 'string' || !v.trim()) return null;
  const t = Date.parse(v);
  return Number.isFinite(t) ? t : null;
}

/** Resolved query window: [fromMs, toMs), clamped to sane bounds. */
function resolveWindow(q: Record<string, unknown>): { fromMs: number; toMs: number } {
  const now = Date.now();
  let toMs = parseTimeParam(q.to) ?? now;
  let fromMs = parseTimeParam(q.from) ?? toMs - 3600_000; // default: last hour
  if (fromMs >= toMs) fromMs = toMs - 3600_000;
  const MAX_RANGE_MS = 400 * 86_400_000; // hard cap — the hourly table's retention ceiling
  if (toMs - fromMs > MAX_RANGE_MS) fromMs = toMs - MAX_RANGE_MS;
  return { fromMs, toMs };
}

function parseLimit(v: unknown, fallback: number, max: number): number {
  const n = Number(v);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(1, Math.min(max, Math.floor(n)));
}

/** Device display info for enrichment columns (id → name). */
async function loadDeviceNames(deviceIds: string[]): Promise<Map<string, string>> {
  const map = new Map<string, string>();
  if (deviceIds.length === 0) return map;
  const res = await pool.query(`SELECT id, name FROM devices WHERE id = ANY($1::text[])`, [deviceIds]);
  for (const r of res.rows) map.set(String(r.id), String(r.name));
  return map;
}

/**
 * Resolves a `?siteId=` query param into a SQL fragment for flow queries.
 * Same pattern as /networks, /tunnels & co.: the site's (enabled) device ids
 * are bound as one text[] parameter and matched against the stored
 * srcDeviceId/dstDeviceId enrichment columns.
 *
 *   - no `siteId` param → { kind: 'none' } (no filtering)
 *   - unknown site id   → { kind: 'unknown' } (caller answers 400)
 *   - otherwise         → { kind: 'ok', clause, empty }: the ids are appended
 *     to `params` and `clause` is the AND-fragment. `empty` is true when the
 *     site has no devices — callers should short-circuit with empty results
 *     instead of running a query that matches nothing.
 *
 * `both` = match rows where EITHER endpoint belongs to the site (top talkers,
 * pairs); otherwise only the SOURCE device must belong to it (internet egress
 * and timeseries are about traffic FROM this site).
 */
async function resolveSiteFilter(
  params: unknown[],
  q: Record<string, unknown>,
  both: boolean,
): Promise<{ kind: 'none' } | { kind: 'unknown' } | { kind: 'ok'; clause: string; empty: boolean }> {
  const siteId = typeof q.siteId === 'string' ? q.siteId : '';
  if (!siteId) return { kind: 'none' };
  const site = await pool.query(`SELECT id FROM sites WHERE id = $1`, [siteId]);
  if (!site.rows.length) return { kind: 'unknown' };
  const res = await pool.query(`SELECT id FROM devices WHERE "siteId" = $1 AND enabled = TRUE`, [siteId]);
  const deviceIds = res.rows.map((r) => String(r.id));
  params.push(deviceIds);
  const n = params.length;
  const clause = both
    ? ` AND ("srcDeviceId" = ANY($${n}::text[]) OR "dstDeviceId" = ANY($${n}::text[]))`
    : ` AND "srcDeviceId" = ANY($${n}::text[])`;
  return { kind: 'ok', clause, empty: deviceIds.length === 0 };
}

/**
 * GET /v1/flows/top-talkers?from&to&limit — top source AND destination IPs by
 * estimated bytes over the window. Auto-picks flow_agg_5m (range ≤ its data)
 * or falls back to flow_agg_1h for older ranges.
 */
router.get('/flows/top-talkers', requireAuth, requirePermission('flows:read'), async (req: Request, res: Response) => {
  const q = req.query as Record<string, unknown>;
  const { fromMs, toMs } = resolveWindow(q);
  const limit = parseLimit(q.limit, 20, 100);

  try {
    // Prefer the finer tier when it plausibly covers the whole window.
    const use5m = toMs - fromMs <= 31 * 86_400_000;
    const table = use5m ? 'flow_agg_5m' : 'flow_agg_1h';

    // Site filter: either endpoint may belong to the site (a talker is
    // interesting when it talks TO or FROM this site).
    const params: unknown[] = [new Date(fromMs).toISOString(), new Date(toMs).toISOString()];
    const site = await resolveSiteFilter(params, q, true);
    if (site.kind === 'unknown') return res.status(400).json({ error: `Unknown site id: ${String(q.siteId)}` });

    let srcRes: { rows: any[] };
    let dstRes: { rows: any[] };
    if (site.kind === 'ok' && site.empty) {
      srcRes = { rows: [] };
      dstRes = { rows: [] };
    } else {
      const siteClause = site.kind === 'ok' ? site.clause : '';
      [srcRes, dstRes] = await Promise.all([
        pool.query(
          `SELECT "srcIp" AS ip, SUM("estBytes")::bigint AS est_bytes, SUM(bytes)::bigint AS reported_bytes,
                  MAX("srcDeviceId") AS device_id, BOOL_OR("srcClass" = 'internal') AS is_internal,
                  MAX("srcNetworkName") AS network_name, MAX("srcVlanId") AS vlan_id,
                  MAX("srcHostname") AS hostname,
                  -- Multi-exporter dedup: how many distinct exporters observed
                  -- this IP's flows (0/NULL = pre-dedup data or single exporter).
                  GREATEST(MAX(COALESCE("agentCount", 0)), 0)::int AS agent_count
           FROM ${table} WHERE bucket >= $1 AND bucket < $2${siteClause}
           GROUP BY "srcIp" ORDER BY est_bytes DESC LIMIT $${params.length + 1}`,
          [...params, limit]
        ),
        pool.query(
          `SELECT "dstIp" AS ip, SUM("estBytes")::bigint AS est_bytes, SUM(bytes)::bigint AS reported_bytes,
                  MAX("dstDeviceId") AS device_id, BOOL_OR("dstClass" = 'internal') AS is_internal,
                  MAX("dstNetworkName") AS network_name, MAX("dstVlanId") AS vlan_id,
                  MAX("dstHostname") AS hostname,
                  GREATEST(MAX(COALESCE("agentCount", 0)), 0)::int AS agent_count
           FROM ${table} WHERE bucket >= $1 AND bucket < $2${siteClause}
           GROUP BY "dstIp" ORDER BY est_bytes DESC LIMIT $${params.length + 1}`,
          [...params, limit]
        ),
      ]);
    }

    const deviceIds = [...new Set([
      ...srcRes.rows.map((r) => r.device_id),
      ...dstRes.rows.map((r) => r.device_id),
    ].filter(Boolean))];
    const names = await loadDeviceNames(deviceIds);

    const shape = (rows: any[]) => rows.map((r): {
      ip: string; estBytes: number; reportedBytes: number; deviceId: string | null; deviceName: string | null;
      internal: boolean; hostname: string | null; hostnameSource: 'inventory' | 'reverse-dns' | null;
      networkName: string | null; vlanId: number | null; observedBy: number;
      countryCode: string | null; countryName: string | null; city: string | null;
    } => ({
      ip: String(r.ip),
      estBytes: Number(r.est_bytes),
      reportedBytes: Number(r.reported_bytes),
      deviceId: r.device_id ? String(r.device_id) : null,
      deviceName: r.device_id ? names.get(String(r.device_id)) ?? null : null,
      internal: Boolean(r.is_internal),
      // >1 = the same flows were exported by several devices on the path and
      // deduplicated to a single best observation (see workers/flows.ts).
      observedBy: Number(r.agent_count ?? 0),
      // Inventory hostname (hosts table — container/VM name, DHCP lease). For
      // external talkers this is usually null and filled below via reverse DNS.
      hostname: r.hostname !== null && r.hostname !== undefined ? String(r.hostname) : null,
      hostnameSource: r.hostname !== null && r.hostname !== undefined ? 'inventory' : null,
      networkName: r.network_name !== null && r.network_name !== undefined ? String(r.network_name) : null,
      vlanId: r.vlan_id === null || r.vlan_id === undefined ? null : Number(r.vlan_id),
      // Filled below for external talkers via the active GeoIP database.
      countryCode: null,
      countryName: null,
      city: null,
    }));

    const sources = shape(srcRes.rows);
    const destinations = shape(dstRes.rows);

    // Best-effort reverse DNS for EXTERNAL talkers WITHOUT an inventory name —
    // internal IPs are already identified by their hosts-inventory hostname.
    // Lookups run in parallel, each capped at 2 s; a dead resolver degrades to
    // hostname: null and never fails the request.
    const allRows = [...sources, ...destinations];
    const externalIps = new Set(allRows.filter((r) => !r.internal && !r.deviceId && !r.hostname).map((r) => r.ip));
    if (externalIps.size > 0) {
      const hostnames = await Promise.all(
        [...externalIps].map(async (ip) => [ip, await reverseLookup(ip)] as const),
      );
      const byIp = new Map(hostnames);
      for (const row of allRows) {
        if (!row.hostname && !row.internal && !row.deviceId) {
          const h = byIp.get(row.ip) ?? null;
          row.hostname = h;
          if (h) row.hostnameSource = 'reverse-dns';
        }
      }
    }

    // Best-effort GeoIP for EXTERNAL talkers — country/city from the active
    // database file (Settings → GeoIP). lookupGeoIp is a no-op returning null
    // while geoipEnabled=false or no active file, so this block degrades to
    // all-null fields when the feature is off. Results are cached per IP 10 min.
    const externalTalkers = new Set(allRows.filter((r) => !r.internal && !r.deviceId).map((r) => r.ip));
    if (externalTalkers.size > 0) {
      const geos = await Promise.all(
        [...externalTalkers].map(async (ip) => [ip, await lookupGeoIp(ip)] as const),
      );
      const geoByIp = new Map(geos);
      for (const row of allRows) {
        if (!row.internal && !row.deviceId) {
          const g = geoByIp.get(row.ip) ?? null;
          row.countryCode = g?.countryCode ?? null;
          row.countryName = g?.countryName ?? null;
          row.city = g?.city ?? null;
        }
      }
    }

    res.status(200).json({ fromMs, toMs, table, sources, destinations });
  } catch (error) {
    console.error('Error querying top talkers:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * GET /v1/flows/internet?deviceId=&from&to — per-device egress to the internet
 * (dstClass='internet') + the total. `deviceId` filters to one device's traffic.
 */
router.get('/flows/internet', requireAuth, requirePermission('flows:read'), async (req: Request, res: Response) => {
  const q = req.query as Record<string, unknown>;
  const { fromMs, toMs } = resolveWindow(q);
  const deviceId = typeof q.deviceId === 'string' && q.deviceId ? q.deviceId : null;

  try {
    const use5m = toMs - fromMs <= 31 * 86_400_000;
    const table = use5m ? 'flow_agg_5m' : 'flow_agg_1h';

    const params: unknown[] = [new Date(fromMs).toISOString(), new Date(toMs).toISOString()];
    let deviceClause = '';
    if (deviceId) {
      params.push(deviceId);
      deviceClause = `AND "srcDeviceId" = $${params.length}`;
    }
    // Site filter: egress FROM this site → the source device must belong to it.
    const site = await resolveSiteFilter(params, q, false);
    if (site.kind === 'unknown') return res.status(400).json({ error: `Unknown site id: ${String(q.siteId)}` });

    let perDevice;
    let totalRes;
    if (site.kind === 'ok' && site.empty) {
      perDevice = { rows: [] };
      totalRes = { rows: [{ est_bytes: 0, distinct_destinations: 0 }] };
    } else {
      const siteClause = site.kind === 'ok' ? site.clause : '';
      perDevice = await pool.query(
        `SELECT "srcDeviceId", SUM("estBytes")::bigint AS est_bytes, COUNT(DISTINCT "dstIp")::int AS distinct_destinations
         FROM ${table}
         WHERE bucket >= $1 AND bucket < $2 AND "dstClass" = 'internet' AND "srcDeviceId" IS NOT NULL ${deviceClause}${siteClause}
         GROUP BY "srcDeviceId" ORDER BY est_bytes DESC LIMIT 50`,
        params
      );

      totalRes = await pool.query(
        `SELECT COALESCE(SUM("estBytes"), 0)::bigint AS est_bytes, COUNT(DISTINCT "dstIp")::int AS distinct_destinations
         FROM ${table}
         WHERE bucket >= $1 AND bucket < $2 AND "dstClass" = 'internet' ${deviceClause}${siteClause}`,
        params
      );
    }

    const deviceIds = perDevice.rows.map((r) => String(r.src_device_id ?? r.srcDeviceId));
    const names = await loadDeviceNames(deviceIds);

    res.status(200).json({
      fromMs,
      toMs,
      table,
      total: { estBytes: Number(totalRes.rows[0]?.est_bytes ?? 0), distinctDestinations: Number(totalRes.rows[0]?.distinct_destinations ?? 0) },
      perDevice: perDevice.rows.map((r) => {
        const id = String(r.src_device_id ?? r.srcDeviceId);
        return { deviceId: id, deviceName: names.get(id) ?? null, estBytes: Number(r.est_bytes), distinctDestinations: Number(r.distinct_destinations) };
      }),
    });
  } catch (error) {
    console.error('Error querying internet egress:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * GET /v1/flows/pairs?from&to&limit — top internal device-to-device pairs by
 * estimated bytes (both endpoints classified internal with a known device).
 */
router.get('/flows/pairs', requireAuth, requirePermission('flows:read'), async (req: Request, res: Response) => {
  const q = req.query as Record<string, unknown>;
  const { fromMs, toMs } = resolveWindow(q);
  const limit = parseLimit(q.limit, 20, 100);

  try {
    const use5m = toMs - fromMs <= 31 * 86_400_000;
    const table = use5m ? 'flow_agg_5m' : 'flow_agg_1h';

    // Site filter: a pair is interesting when EITHER endpoint belongs to the site.
    const params: unknown[] = [new Date(fromMs).toISOString(), new Date(toMs).toISOString()];
    const site = await resolveSiteFilter(params, q, true);
    if (site.kind === 'unknown') return res.status(400).json({ error: `Unknown site id: ${String(q.siteId)}` });

    let res2;
    let topRes = { rows: [] as any[] };
    if (site.kind === 'ok' && site.empty) {
      res2 = { rows: [] };
    } else {
      const siteClause = site.kind === 'ok' ? site.clause : '';
      [res2, topRes] = await Promise.all([
        pool.query(
          `SELECT "srcDeviceId", "dstDeviceId", SUM("estBytes")::bigint AS est_bytes, COUNT(DISTINCT ("srcIp" || '|' || "dstIp"))::int AS distinct_pairs
           FROM ${table}
           WHERE bucket >= $1 AND bucket < $2
             AND "srcClass" = 'internal' AND "dstClass" = 'internal'
             AND "srcDeviceId" IS NOT NULL AND "dstDeviceId" IS NOT NULL
             AND "srcDeviceId" <> "dstDeviceId"${siteClause}
           GROUP BY "srcDeviceId", "dstDeviceId" ORDER BY est_bytes DESC LIMIT $${params.length + 1}`,
          [...params, limit]
        ),
        // The single busiest IP on each side of every pair — the actual host
        // (container/VM) behind the device-level rollup. Same filters as above;
        // ranked per (srcDeviceId, dstDeviceId) by estBytes.
        pool.query(
          `WITH ranked AS (
             SELECT "srcDeviceId", "dstDeviceId", "srcIp", "dstIp",
                    SUM("estBytes")::bigint AS pair_bytes,
                    MAX("srcHostname") AS src_hostname, MAX("dstHostname") AS dst_hostname,
                    ROW_NUMBER() OVER (PARTITION BY "srcDeviceId", "dstDeviceId" ORDER BY SUM("estBytes") DESC) AS rn
             FROM ${table}
             WHERE bucket >= $1 AND bucket < $2
               AND "srcClass" = 'internal' AND "dstClass" = 'internal'
               AND "srcDeviceId" IS NOT NULL AND "dstDeviceId" IS NOT NULL
               AND "srcDeviceId" <> "dstDeviceId"${siteClause}
             GROUP BY "srcDeviceId", "dstDeviceId", "srcIp", "dstIp"
           )
           SELECT * FROM ranked WHERE rn = 1`,
          params
        ),
      ]);
    }

    const deviceIds = [...new Set(res2.rows.flatMap((r) => [String(r.src_device_id ?? r.srcDeviceId), String(r.dst_device_id ?? r.dstDeviceId)]))];
    const names = await loadDeviceNames(deviceIds);

    // Top-IP lookup keyed by (srcDeviceId|dstDeviceId).
    const topByPair = new Map<string, any>();
    for (const t of topRes.rows) {
      topByPair.set(`${String(t.src_device_id ?? t.srcDeviceId)}|${String(t.dst_device_id ?? t.dstDeviceId)}`, t);
    }

    res.status(200).json({
      fromMs,
      toMs,
      table,
      pairs: res2.rows.map((r) => {
        const s = String(r.src_device_id ?? r.srcDeviceId);
        const d = String(r.dst_device_id ?? r.dstDeviceId);
        const t = topByPair.get(`${s}|${d}`);
        return {
          srcDeviceId: s, dstDeviceId: d, srcName: names.get(s) ?? null, dstName: names.get(d) ?? null,
          estBytes: Number(r.est_bytes), distinctPairs: Number(r.distinct_pairs),
          // The busiest host on each side — "which container/VM actually talks".
          srcTopIp: t ? String(t.src_ip ?? t.srcIp) : null,
          srcTopHost: t && (t.src_hostname ?? t.srcHostname) != null ? String(t.src_hostname ?? t.srcHostname) : null,
          dstTopIp: t ? String(t.dst_ip ?? t.dstIp) : null,
          dstTopHost: t && (t.dst_hostname ?? t.dstHostname) != null ? String(t.dst_hostname ?? t.dstHostname) : null,
        };
      }),
    });
  } catch (error) {
    console.error('Error querying device pairs:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * GET /v1/flows/timeseries?from&to&bucket=5m|1h&deviceId=&class=internet|internal —
 * bucketed estimated-bytes series for charts. `class` filters on the DESTINATION
 * classification (e.g. "internet" = total egress to the internet over time).
 */
router.get('/flows/timeseries', requireAuth, requirePermission('flows:read'), async (req: Request, res: Response) => {
  const q = req.query as Record<string, unknown>;
  const { fromMs, toMs } = resolveWindow(q);
  const bucket = q.bucket === '1h' ? '1h' : '5m';
  const table = bucket === '1h' ? 'flow_agg_1h' : 'flow_agg_5m';
  const deviceId = typeof q.deviceId === 'string' && q.deviceId ? q.deviceId : null;
  const cls = q.class === 'internet' || q.class === 'internal' ? String(q.class) : null;

  try {
    const params: unknown[] = [new Date(fromMs).toISOString(), new Date(toMs).toISOString()];
    let whereExtra = '';
    if (deviceId) { params.push(deviceId); whereExtra += ` AND "srcDeviceId" = $${params.length}`; }
    if (cls) { params.push(cls); whereExtra += ` AND "dstClass" = $${params.length}`; }
    // Site filter: traffic FROM this site → the source device must belong to it.
    const site = await resolveSiteFilter(params, q, false);
    if (site.kind === 'unknown') return res.status(400).json({ error: `Unknown site id: ${String(q.siteId)}` });

    let points: { bucket: string; estBytes: number }[];
    const stepMs = bucket === '1h' ? 3600_000 : 300_000;
    if (site.kind === 'ok' && site.empty) {
      // Site has no devices — return a zero-filled series so the chart stays continuous.
      points = [];
      for (let t = Math.ceil(fromMs / stepMs) * stepMs; t < toMs; t += stepMs) {
        points.push({ bucket: new Date(t).toISOString(), estBytes: 0 });
      }
    } else {
      const siteClause = site.kind === 'ok' ? site.clause : '';
      const res2 = await pool.query(
        `SELECT bucket, SUM("estBytes")::bigint AS est_bytes FROM ${table}
         WHERE bucket >= $1 AND bucket < $2${whereExtra}${siteClause} GROUP BY bucket ORDER BY bucket`,
        params
      );

      // Fill gaps with zeros so the chart's x-axis is continuous.
      const byBucket = new Map<number, number>();
      for (const r of res2.rows) {
        // timestamptz normally arrives as a JS Date — but drizzle's pool setup can
        // leave pg-types returning the raw text in this process, so accept both.
        const b: unknown = r.bucket;
        const d: Date = b instanceof Date ? b : new Date(String(b));
        if (Number.isNaN(d.getTime())) continue;
        byBucket.set(Math.floor(d.getTime() / stepMs) * stepMs, Number(r.est_bytes));
      }
      points = [];
      for (let t = Math.ceil(fromMs / stepMs) * stepMs; t < toMs; t += stepMs) {
        points.push({ bucket: new Date(t).toISOString(), estBytes: byBucket.get(t) ?? 0 });
      }
    }

    res.status(200).json({ fromMs, toMs, table, bucket, points });
  } catch (error) {
    console.error('Error querying flow timeseries:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * GET /v1/flows/ports?from&to&limit&ip=&siteId= — top L4 ports by estimated
 * bytes, separately for SOURCE and DESTINATION ports. `ip` drills down to one
 * host (its outgoing source ports + incoming destination ports). Port 0 means
 * "no transport header" (ICMP etc.) and is included so totals add up.
 */
router.get('/flows/ports', requireAuth, requirePermission('flows:read'), async (req: Request, res: Response) => {
  const q = req.query as Record<string, unknown>;
  const { fromMs, toMs } = resolveWindow(q);
  const limit = parseLimit(q.limit, 20, 100);
  const ip = typeof q.ip === 'string' && q.ip ? q.ip : null;

  try {
    const use5m = toMs - fromMs <= 31 * 86_400_000;
    const table = use5m ? 'flow_agg_5m' : 'flow_agg_1h';

    // Shared params (window + site filter) — both direction queries reference
    // them. The ip drilldown param is pushed into a PER-QUERY array: one shared
    // array would leave an unreferenced bind parameter in each query ("could
    // not determine data type of parameter $N").
    const params: unknown[] = [new Date(fromMs).toISOString(), new Date(toMs).toISOString()];
    if (ip) {
      try {
        // Validate early — an invalid inet literal would fail deep in the query.
        await pool.query(`SELECT $1::inet`, [ip]);
      } catch {
        return res.status(400).json({ error: `Invalid ip: ${ip}` });
      }
    }

    const site = await resolveSiteFilter(params, q, true);
    if (site.kind === 'unknown') return res.status(400).json({ error: `Unknown site id: ${String(q.siteId)}` });

    let srcRes;
    let dstRes;
    if (site.kind === 'ok' && site.empty) {
      srcRes = { rows: [] };
      dstRes = { rows: [] };
    } else {
      const siteClause = site.kind === 'ok' ? site.clause : '';
      const srcParams = ip ? [...params, ip] : params;
      const dstParams = ip ? [...params, ip] : params;
      const ipClauseSrc = ip ? ` AND "srcIp" = $${srcParams.length}::inet` : '';
      const ipClauseDst = ip ? ` AND "dstIp" = $${dstParams.length}::inet` : '';
      [srcRes, dstRes] = await Promise.all([
        pool.query(
          `SELECT "srcPort"::int AS port, proto, SUM("estBytes")::bigint AS est_bytes, SUM(bytes)::bigint AS reported_bytes
           FROM ${table} WHERE bucket >= $1 AND bucket < $2${ipClauseSrc}${siteClause}
           GROUP BY 1, 2 ORDER BY est_bytes DESC LIMIT $${srcParams.length + 1}`,
          [...srcParams, limit]
        ),
        pool.query(
          `SELECT "dstPort"::int AS port, proto, SUM("estBytes")::bigint AS est_bytes, SUM(bytes)::bigint AS reported_bytes
           FROM ${table} WHERE bucket >= $1 AND bucket < $2${ipClauseDst}${siteClause}
           GROUP BY 1, 2 ORDER BY est_bytes DESC LIMIT $${dstParams.length + 1}`,
          [...dstParams, limit]
        ),
      ]);
    }

    const shape = (rows: any[]) => rows.map((r) => ({
      port: Number(r.port),
      proto: Number(r.proto),
      estBytes: Number(r.est_bytes),
      reportedBytes: Number(r.reported_bytes),
    }));

    res.status(200).json({ fromMs, toMs, table, ip: ip ?? undefined, sourcePorts: shape(srcRes.rows), destinationPorts: shape(dstRes.rows) });
  } catch (error) {
    console.error('Error querying flow ports:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/** One logical network group with its subnets + VLANs (for flow mapping). */
interface FlowNetworkGroup {
  /** Display label — the group's NAMED interface when one exists (e.g.
   *  "NET_DMZ_WAN01"), else the canonical subnet, else "VLAN <id>". Physical
   *  port names (optN/ensN/ethN/wlan) are deliberately not used as labels. */
  label: string;
  vlanId: number | null; // single-VLAN groups only
  subnets: { cidr: string; prefixLen: number }[];
}

/** Physical interface names that carry no meaning for a traffic summary. */
const PHYSICAL_IF_RE = /^(opt\d+|ens\w+|eth\d+|enp\S*|wl[a-z]*\d*|lo|vnet\d+)$/i;

/** The group's preferred display name: first non-physical member interface. */
function preferredLabel(g: MergedNetwork): string {
  for (const d of g.devices) {
    for (const ifc of d.interfaces) {
      if (ifc && !PHYSICAL_IF_RE.test(ifc)) return ifc;
    }
  }
  return g.name; // canonical subnet / "VLAN <id>" / physical name
}

/**
 * Builds the logical-network index used by /flows/networks — the SAME grouping
 * as GET /networks (mergeNetworkRows: subnet + VLAN-bridge + union-find over
 * shared subnets), so "Traffic per network" summarizes per LOGICAL network
 * instead of per physical interface (opt19 on 10.100.0.0/16 shows up under
 * NET_DMZ_WAN01, not as its own row). Cached for 30 s — inventory changes are
 * slow and this route is polled by the page.
 */
let flowNetIndex: { at: number; groups: FlowNetworkGroup[]; vlanToLabel: Map<number, string> } | null = null;
async function loadFlowNetworkGroups(): Promise<FlowNetworkGroup[]> {
  if (flowNetIndex && Date.now() - flowNetIndex.at < 30_000) return flowNetIndex.groups;
  const res = await pool.query(
    `SELECT "deviceId", "pluginId", name, ip, prefix, version, "vlanId", mac, status, "collectedAt"
     FROM networks`
  );
  // ALL rows — exactly what GET /networks feeds mergeNetworkRows. IP-less
  // named interfaces (e.g. a router's tagged port with only a VLAN id) are
  // essential: they bridge VLAN→subnet in pass 2 and supply the group's label.
  const merged = mergeNetworkRows(res.rows as any[]) as MergedNetwork[];
  const groups: FlowNetworkGroup[] = merged.map((g) => ({
    label: preferredLabel(g),
    vlanId: g.vlanId,
    subnets: g.subnets.map((cidr) => ({ cidr, prefixLen: Number(cidr.split('/')[1] ?? 0) })),
  }));
  // VLAN → label index for the fallback match (single-VLAN groups only).
  const vlanToLabel = new Map<number, string>();
  for (const g of groups) if (g.vlanId !== null) vlanToLabel.set(g.vlanId, g.label);
  flowNetIndex = { at: Date.now(), groups, vlanToLabel };
  return groups;
}

/**
 * Maps one endpoint IP to its logical network label. Longest-prefix match over
 * ALL subnets of all groups (family-agnostic — a merged dual-stack group
 * carries both v4 and v6 CIDRs); falls back to the stored VLAN id when no
 * subnet matches. Returns null → "(unknown)".
 */
function mapIpToLogicalNetwork(ip: string, vlanId: number | null, groups: FlowNetworkGroup[]): string | null {
  let best: { label: string; prefixLen: number } | null = null;
  for (const g of groups) {
    for (const s of g.subnets) {
      if (!ipInCidr(ip, s.cidr)) continue;
      if (!best || s.prefixLen > best.prefixLen) best = { label: g.label, prefixLen: s.prefixLen };
    }
  }
  if (best) return best.label;
  // VLAN fallback — the rollup stored the interface's vlanId even when its
  // name was unknown; a group keyed on that VLAN is still the right bucket.
  if (vlanId !== null && vlanId > 0 && flowNetIndex?.vlanToLabel.has(vlanId)) {
    return flowNetIndex.vlanToLabel.get(vlanId)!;
  }
  return null;
}

/**
 * GET /v1/flows/networks?from&to&limit&siteId= — traffic per LOGICAL network
 * (the same grouping as the Networks page: several interfaces on one subnet /
 * VLAN collapse into one row), split by direction. Endpoints classified as
 * 'internet' aggregate under "(external)"; internal endpoints without a match
 * fall back to "(unknown)".
 */
router.get('/flows/networks', requireAuth, requirePermission('flows:read'), async (req: Request, res: Response) => {
  const q = req.query as Record<string, unknown>;
  const { fromMs, toMs } = resolveWindow(q);
  const limit = parseLimit(q.limit, 20, 100);

  try {
    const use5m = toMs - fromMs <= 31 * 86_400_000;
    const table = use5m ? 'flow_agg_5m' : 'flow_agg_1h';

    const params: unknown[] = [new Date(fromMs).toISOString(), new Date(toMs).toISOString()];
    const site = await resolveSiteFilter(params, q, true);
    if (site.kind === 'unknown') return res.status(400).json({ error: `Unknown site id: ${String(q.siteId)}` });

    // Aggregate per ENDPOINT IP (not per stored interface name) — the mapping
    // into logical network groups happens in JS below. Distinct IPs over a
    // window stay small enough for an in-memory pass; SQL still does the heavy
    // lifting (window + site filter + SUM).
    let srcRes;
    let dstRes;
    if (site.kind === 'ok' && site.empty) {
      srcRes = { rows: [] };
      dstRes = { rows: [] };
    } else {
      const siteClause = site.kind === 'ok' ? site.clause : '';
      [srcRes, dstRes] = await Promise.all([
        pool.query(
          `SELECT host("srcIp") AS ip, MAX("srcVlanId")::int AS vlan_id,
                  MAX("srcClass") AS ip_class, SUM("estBytes")::bigint AS est_bytes
           FROM ${table} WHERE bucket >= $1 AND bucket < $2${siteClause}
           GROUP BY 1 ORDER BY est_bytes DESC LIMIT 50000`,
          params
        ),
        pool.query(
          `SELECT host("dstIp") AS ip, MAX("dstVlanId")::int AS vlan_id,
                  MAX("dstClass") AS ip_class, SUM("estBytes")::bigint AS est_bytes
           FROM ${table} WHERE bucket >= $1 AND bucket < $2${siteClause}
           GROUP BY 1 ORDER BY est_bytes DESC LIMIT 50000`,
          params
        ),
      ]);
    }

    // Map every endpoint IP to its logical network (Networks-page grouping).
    // Endpoints the rollup classified as 'internet' are not part of any
    // internal network — they aggregate under "(external)".
    const groups = await loadFlowNetworkGroups();
    const byNet = new Map<string, { name: string; srcEstBytes: number; dstEstBytes: number }>();
    const add = (ip: unknown, vlanId: unknown, ipClass: unknown, bytes: unknown, dir: 's' | 'd') => {
      const label = ipClass === 'internet'
        ? '(external)'
        : mapIpToLogicalNetwork(String(ip), vlanId === null || vlanId === undefined ? null : Number(vlanId), groups) ?? '(unknown)';
      let row = byNet.get(label);
      if (!row) {
        row = { name: label, srcEstBytes: 0, dstEstBytes: 0 };
        byNet.set(label, row);
      }
      const v = Number(bytes);
      if (dir === 's') row.srcEstBytes += v; else row.dstEstBytes += v;
    };
    for (const r of srcRes.rows) add(r.ip, r.vlan_id, r.ip_class, r.est_bytes, 's');
    for (const r of dstRes.rows) add(r.ip, r.vlan_id, r.ip_class, r.est_bytes, 'd');

    // Attach the group's subnets + single VLAN id to each row.
    const byLabel = new Map(groups.map((g) => [g.label, g] as const));
    const networks = [...byNet.values()]
      .map((r) => {
        const g = r.name === '(unknown)' || r.name === '(external)' ? null : byLabel.get(r.name);
        return {
          name: r.name,
          vlanId: g?.vlanId ?? null,
          subnets: g ? g.subnets.map((s) => s.cidr) : [],
          srcEstBytes: r.srcEstBytes,
          dstEstBytes: r.dstEstBytes,
          estBytes: r.srcEstBytes + r.dstEstBytes,
        };
      })
      .sort((a, b) => b.estBytes - a.estBytes)
      .slice(0, limit);

    res.status(200).json({ fromMs, toMs, table, networks });
  } catch (error) {
    console.error('Error querying flow networks:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/**
 * GET /v1/flow-collectors — per-collector ingest stats. Combines the flows
 * worker's in-process queue counters (this replica) with each flow-collector
 * plugin's latest self-metrics sample (push rate, drops, queue depth).
 */
router.get('/flow-collectors', requireAuth, requirePermission('flows:read'), async (_req: Request, res: Response) => {
  try {
    const ingest = getFlowIngestStats();

    // Flow collectors are the plugins whose base uuid is the flow-collector one
    // (multi-instance ids carry a ":<instanceId>" suffix). Their custom gauges
    // ride on GET /metrics (SDK selfMetricsExtra) but are NOT persisted in
    // plugin_metrics — so fetch them live from each collector.
    const pluginsRes = await pool.query(
      `SELECT p.id, p.name, p.endpoint FROM plugins p WHERE split_part(p.id, ':', 1) = '00000000-0000-4000-8000-0000000012'`
    );

    const collectors: unknown[] = [];
    for (const p of pluginsRes.rows) {
      let live: Record<string, unknown> = {};
      try {
        const mres = await pluginAxios(p.endpoint).get<Record<string, unknown>>('/metrics', { timeout: 3000 });
        live = mres.data ?? {};
      } catch {
        // Collector unreachable — report it with zeroed gauges rather than failing the page.
      }
      collectors.push({
        id: p.id,
        name: p.name,
        reachable: Object.keys(live).length > 0,
        samplesPerSec: Number(live.flowSamplesPerSec ?? 0),
        tuplesPerSec: Number(live.flowTuplesPerSec ?? 0),
        droppedTuplesTotal: Number(live.flowDroppedTuplesTotal ?? 0),
        queueDepth: Number(live.flowQueueDepth ?? 0),
        pushesTotal: Number(live.flowPushesTotal ?? 0),
        pushFailuresTotal: Number(live.flowPushFailuresTotal ?? 0),
      });
    }

    res.status(200).json({ ingest, collectors });
  } catch (error) {
    console.error('Error querying flow collectors:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;
