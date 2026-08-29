import axios from 'axios';
import { v4 as uuidv4 } from 'uuid';
import { db } from '../db';
import * as schema from '../db/schema';
import { resolvePluginEndpoint } from '../utils/pluginEndpoint';
import { LEADER_KEYS } from './leader';
import { initWorker, trackBeat } from './stats';

/**
 * Plugin self-metrics poller.
 *
 * Every registered plugin exposes GET /metrics (auto-mounted by the shared
 * @unm/plugin-sdk — see packages/plugin-sdk/src/selfMetrics.ts) with its own
 * runtime health: CPU%, heap/RSS memory, event-loop lag, in-flight work
 * requests, last-poll duration + error rate, emitted metric count and log
 * queue depth. This worker fetches that endpoint for every plugin row on a
 * fixed cadence (same 30s beat as the telemetry worker) and stores one sample
 * per poll in `plugin_metrics`. The webapp's Plugins page renders the latest
 * sample + a short history sparkline from GET /plugins/:id/self-metrics.
 *
 * A plugin without the endpoint (e.g. an old image that predates the SDK
 * feature) simply yields no samples — its row stays stale and the UI shows
 * "no data" instead of failing. One dead plugin must never break the cycle.
 */

const POLL_INTERVAL_MS = 30_000; // same beat as telemetry — one sample per poll cycle
const FETCH_TIMEOUT_MS = 5_000; // /metrics is local + trivial; anything slower is already a problem signal

/** Numeric coercion that never throws (plugin payloads are untrusted). */
function num(v: unknown): number | null {
  return typeof v === 'number' && Number.isFinite(v) ? v : null;
}

async function pollOne(pluginId: string, endpoint: string): Promise<void> {
  try {
    const url = `${resolvePluginEndpoint(endpoint).replace(/\/+$/, '')}/metrics`;
    const res = await axios.get<Record<string, unknown>>(url, { timeout: FETCH_TIMEOUT_MS });
    const d = res.data ?? {};

    await db.insert(schema.pluginMetrics).values({
      id: uuidv4(),
      pluginId,
      uptimeSeconds: num(d.uptimeSeconds),
      heapUsedBytes: num(d.heapUsedBytes),
      heapTotalBytes: num(d.heapTotalBytes),
      rssBytes: num(d.rssBytes),
      cpuPercent: num(d.cpuPercent),
      eventLoopLagMs: num(d.eventLoopLagMs),
      inFlight: num(d.inFlight),
      lastPollMs: num(d.lastPollMs),
      errorRatePercent: num(d.errorRatePercent),
      emittedMetricsCount: num(d.emittedMetricsCount),
      logQueueDepth: num(d.logQueueDepth),
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    // No sample this cycle — the plugin is offline or predates /metrics.
    // Silent by design: discovery already tracks online/offline via lastSeenAt,
    // and logging every 30s per dead plugin would be pure noise.
    void err;
  }
}

async function pollAllPlugins(): Promise<void> {
  const plugins = await db.query.plugins.findMany();
  if (plugins.length === 0) return;
  await Promise.all(
    plugins.map((p) => pollOne(p.id, p.endpoint))
  );
}

/**
 * Starts the self-metrics polling loop. Must be called only after the API has
 * bound its port (same rule as every other worker — see index.ts app.listen).
 */
export function startPluginMetricsWorker(): () => void {
  initWorker('pluginMetrics', LEADER_KEYS.pluginMetrics);
  // eslint-disable-next-line no-console
  console.log(`[plugin-metrics] worker started, polling /metrics every ${POLL_INTERVAL_MS / 1000}s`);

  void trackBeat('pluginMetrics', pollAllPlugins).catch((err) => {
    // eslint-disable-next-line no-console
    console.error('[plugin-metrics] initial poll failed:', err);
  });

  const timer = setInterval(() => {
    void trackBeat('pluginMetrics', pollAllPlugins).catch((err) => {
      // eslint-disable-next-line no-console
      console.error('[plugin-metrics] poll cycle failed:', err);
    });
  }, POLL_INTERVAL_MS);

  return () => clearInterval(timer);
}
