import { Router, Request, Response } from 'express';
import { pool } from '../db';
import { requireAuth, requirePermission } from '../auth/middleware';
import { pluginAxios } from '../utils/pluginHttp';
import { getFlowIngestStats } from '../workers/flows';

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

    const [srcRes, dstRes] = await Promise.all([
      pool.query(
        `SELECT "srcIp" AS ip, SUM("estBytes")::bigint AS est_bytes, SUM(bytes)::bigint AS reported_bytes,
                MAX("srcDeviceId") AS device_id, BOOL_OR("srcClass" = 'internal') AS is_internal
         FROM ${table} WHERE bucket >= $1 AND bucket < $2
         GROUP BY "srcIp" ORDER BY est_bytes DESC LIMIT $3`,
        [new Date(fromMs).toISOString(), new Date(toMs).toISOString(), limit]
      ),
      pool.query(
        `SELECT "dstIp" AS ip, SUM("estBytes")::bigint AS est_bytes, SUM(bytes)::bigint AS reported_bytes,
                MAX("dstDeviceId") AS device_id, BOOL_OR("dstClass" = 'internal') AS is_internal
         FROM ${table} WHERE bucket >= $1 AND bucket < $2
         GROUP BY "dstIp" ORDER BY est_bytes DESC LIMIT $3`,
        [new Date(fromMs).toISOString(), new Date(toMs).toISOString(), limit]
      ),
    ]);

    const deviceIds = [...new Set([
      ...srcRes.rows.map((r) => r.device_id),
      ...dstRes.rows.map((r) => r.device_id),
    ].filter(Boolean))];
    const names = await loadDeviceNames(deviceIds);

    const shape = (rows: any[]) => rows.map((r) => ({
      ip: String(r.ip),
      estBytes: Number(r.est_bytes),
      reportedBytes: Number(r.reported_bytes),
      deviceId: r.device_id ? String(r.device_id) : null,
      deviceName: r.device_id ? names.get(String(r.device_id)) ?? null : null,
      internal: Boolean(r.is_internal),
    }));

    res.status(200).json({ fromMs, toMs, table, sources: shape(srcRes.rows), destinations: shape(dstRes.rows) });
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

    const perDevice = await pool.query(
      `SELECT "srcDeviceId", SUM("estBytes")::bigint AS est_bytes, COUNT(DISTINCT "dstIp")::int AS distinct_destinations
       FROM ${table}
       WHERE bucket >= $1 AND bucket < $2 AND "dstClass" = 'internet' AND "srcDeviceId" IS NOT NULL ${deviceClause}
       GROUP BY "srcDeviceId" ORDER BY est_bytes DESC LIMIT 50`,
      params
    );

    const totalRes = await pool.query(
      `SELECT COALESCE(SUM("estBytes"), 0)::bigint AS est_bytes, COUNT(DISTINCT "dstIp")::int AS distinct_destinations
       FROM ${table}
       WHERE bucket >= $1 AND bucket < $2 AND "dstClass" = 'internet' ${deviceClause}`,
      params
    );

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

    const res2 = await pool.query(
      `SELECT "srcDeviceId", "dstDeviceId", SUM("estBytes")::bigint AS est_bytes, COUNT(DISTINCT ("srcIp" || '|' || "dstIp"))::int AS distinct_pairs
       FROM ${table}
       WHERE bucket >= $1 AND bucket < $2
         AND "srcClass" = 'internal' AND "dstClass" = 'internal'
         AND "srcDeviceId" IS NOT NULL AND "dstDeviceId" IS NOT NULL
         AND "srcDeviceId" <> "dstDeviceId"
       GROUP BY "srcDeviceId", "dstDeviceId" ORDER BY est_bytes DESC LIMIT $3`,
      [new Date(fromMs).toISOString(), new Date(toMs).toISOString(), limit]
    );

    const deviceIds = [...new Set(res2.rows.flatMap((r) => [String(r.src_device_id ?? r.srcDeviceId), String(r.dst_device_id ?? r.dstDeviceId)]))];
    const names = await loadDeviceNames(deviceIds);

    res.status(200).json({
      fromMs,
      toMs,
      table,
      pairs: res2.rows.map((r) => {
        const s = String(r.src_device_id ?? r.srcDeviceId);
        const d = String(r.dst_device_id ?? r.dstDeviceId);
        return { srcDeviceId: s, dstDeviceId: d, srcName: names.get(s) ?? null, dstName: names.get(d) ?? null, estBytes: Number(r.est_bytes), distinctPairs: Number(r.distinct_pairs) };
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

    const res2 = await pool.query(
      `SELECT bucket, SUM("estBytes")::bigint AS est_bytes FROM ${table}
       WHERE bucket >= $1 AND bucket < $2${whereExtra} GROUP BY bucket ORDER BY bucket`,
      params
    );

    // Fill gaps with zeros so the chart's x-axis is continuous.
    const stepMs = bucket === '1h' ? 3600_000 : 300_000;
    const byBucket = new Map<number, number>();
    for (const r of res2.rows) {
      // timestamptz normally arrives as a JS Date — but drizzle's pool setup can
      // leave pg-types returning the raw text in this process, so accept both.
      const b: unknown = r.bucket;
      const d: Date = b instanceof Date ? b : new Date(String(b));
      if (Number.isNaN(d.getTime())) continue;
      byBucket.set(Math.floor(d.getTime() / stepMs) * stepMs, Number(r.est_bytes));
    }
    const points: { bucket: string; estBytes: number }[] = [];
    for (let t = Math.ceil(fromMs / stepMs) * stepMs; t < toMs; t += stepMs) {
      points.push({ bucket: new Date(t).toISOString(), estBytes: byBucket.get(t) ?? 0 });
    }

    res.status(200).json({ fromMs, toMs, table, bucket, points });
  } catch (error) {
    console.error('Error querying flow timeseries:', error);
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
