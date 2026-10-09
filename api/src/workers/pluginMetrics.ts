import { v4 as uuidv4 } from 'uuid';
import { db } from '../db';
import * as schema from '../db/schema';
import { pluginAxios } from '../utils/pluginHttp';
import { registerLeaf, pruneStale } from '../ca/registry';
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

/**
 * Mirrors the plugin's OWN CA-issued leaf (reported as `tlsCert` in /metrics
 * by mTLS-enabled SDK builds) into the ca_certificates registry — the backing
 * data for the Certificates page's "mtls" rows. Best-effort: a parse failure
 * must never break the metrics cycle, and old plugin images simply carry no
 * tlsCert key (no-op).
 */
function ingestTlsCert(pluginName: string, d: Record<string, unknown>): void {
  const cert = d['tlsCert'];
  if (!cert || typeof cert !== 'object') return;
  const c = cert as Record<string, unknown>;
  const serial = typeof c.serial === 'string' ? c.serial.trim() : '';
  const notBefore = typeof c.notBefore === 'string' ? c.notBefore : '';
  const notAfter = typeof c.notAfter === 'string' ? c.notAfter : '';
  if (!serial || !notBefore || !notAfter) return; // malformed — skip silently
  void registerLeaf({
    serial,
    sans: Array.isArray(c.sans) ? (c.sans as unknown[]).filter((s): s is string => typeof s === 'string') : [],
    issuer: typeof c.issuer === 'string' ? c.issuer : '',
    notBefore,
    notAfter,
    subject: pluginName,
    source: 'plugin',
  }).catch((err) => {
    // eslint-disable-next-line no-console
    console.warn(`[plugin-metrics] failed to register tlsCert for ${pluginName}:`, (err as Error).message);
  });
}

async function pollOne(pluginId: string, pluginName: string, endpoint: string): Promise<void> {
  try {
    // mTLS (Stage 1): pluginAxios resolves the host-dev rewrite + transport.
    const res = await pluginAxios(endpoint).get<Record<string, unknown>>('/metrics', { timeout: FETCH_TIMEOUT_MS });
    const d = res.data ?? {};

    ingestTlsCert(pluginName, d);

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
      sampledAt: new Date().toISOString(),
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
    plugins.map((p) => pollOne(p.id, p.name, p.endpoint))
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

  // Prune superseded/expired CA-registry leaves once an hour (120 cycles at
  // the 30s beat) — re-enrolled plugins leave their old serial behind.
  const PRUNE_EVERY_CYCLES = Math.max(1, Math.round(3_600_000 / POLL_INTERVAL_MS));
  let cycle = 0;

  const timer = setInterval(() => {
    void trackBeat('pluginMetrics', pollAllPlugins).catch((err) => {
      // eslint-disable-next-line no-console
      console.error('[plugin-metrics] poll cycle failed:', err);
    });
    if (++cycle % PRUNE_EVERY_CYCLES === 0) {
      void pruneStale().then((n) => {
        if (n > 0) console.log(`[plugin-metrics] pruned ${n} stale CA-registry leaf(s)`);
      }).catch(() => undefined);
    }
  }, POLL_INTERVAL_MS);

  return () => clearInterval(timer);
}
