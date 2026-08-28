/**
 * Self-metrics — a plugin's own runtime health, exposed at GET /metrics.
 *
 * The UNM API polls every registered plugin's `/metrics` endpoint on its own
 * cadence and persists the samples in `plugin_metrics`, so the webapp can show
 * per-plugin CPU/memory/event-loop-lag/poll-duration without any per-plugin
 * code: createPluginServer() mounts this endpoint automatically.
 *
 * What is measured (and why):
 *   - heapUsed/heapTotal/rss — process.memoryUsage(). Monotonic heap growth =
 *     leak; in a single-node-process container RSS ≈ container memory usage.
 *   - cpuPercent — delta of process.cpuUsage() over the last sample window,
 *     expressed as % of ONE core (can exceed 100 on multi-core hosts).
 *   - eventLoopLagMs — drift between a 1s setInterval and real time; the
 *     classic Node overload indicator. Catches blocking work (big JSON parses,
 *     synchronous waits) that CPU% alone misses. Moving average of the last
 *     samples so one hiccup doesn't spike the reported value.
 *   - inFlight — number of /monitoring + /config + /plan requests currently
 *     being handled. >1 means a poll is taking longer than the API's 30s cycle
 *     → slow device or stuck walk; directly explains telemetry gaps.
 *   - lastPollMs / errorRatePercent — duration and failure rate of the most
 *     recent N work requests (ring buffer). Distinguishes "plugin overloaded"
 *     from "device unresponsive".
 *   - emittedMetricsCount — number of metric keys in the LAST /monitoring
 *     response payload. The actual per-poll telemetry weight (vs. the declared
 *     descriptor count) — grows as metrics are added; a proxy for DB write cost.
 *   - logQueueDepth — pending entries in the plugin logger's queue, when one
 *     was registered via registerPluginLogger(). A full queue means log
 *     shipping is falling behind (backpressure).
 *
 * Plugins that want custom gauges can pass `selfMetrics.extra` to
 * createPluginServer() — an object or a function returning an object of
 * numbers, merged into the response under its own keys. Nothing needs it on
 * day one; everything above is collected generically in the SDK.
 */

import type { RequestHandler } from 'express';

/** The wire shape of GET /metrics (what the API persists per sample). */
export interface PluginSelfMetrics {
  /** Seconds since process start (context after restarts — cold caches, etc.). */
  uptimeSeconds: number;
  heapUsedBytes: number;
  heapTotalBytes: number;
  rssBytes: number;
  /** % of one core over the last sample window. */
  cpuPercent: number;
  /** Moving average event-loop lag in ms (0 = healthy). */
  eventLoopLagMs: number;
  /** Work requests (/monitoring, /config, /plan) currently being handled. */
  inFlight: number;
  /** Duration of the last completed work request in ms (null before the first). */
  lastPollMs: number | null;
  /** Failure rate of the last N work requests, 0–100 (null before the first). */
  errorRatePercent: number | null;
  /** Number of metric keys in the last /monitoring payload (null before the first). */
  emittedMetricsCount: number | null;
  /** Pending entries in the plugin logger queue (absent when no logger registered). */
  logQueueDepth?: number;
}

export interface SelfMetricsOptions {
  /** Extra custom gauges, merged into the response. May be a function for dynamic values. */
  extra?: Record<string, number> | (() => Record<string, number>);
  /** How many work requests to keep in the ring buffer (default 20). */
  windowSize?: number;
  /** Pending log-queue depth getter (wired to the plugin logger by createPluginServer). */
  logQueueDepth?: () => number;
}

/** A logger with an inspectable queue depth (satisfied by createPluginLogger's return value). */
export interface SelfMetricsLoggerLike {
  readonly logQueueDepth: number;
}

interface WorkSample {
  durationMs: number;
  ok: boolean;
}

const DEFAULT_WINDOW = 20;
const LAG_SAMPLES = 10; // moving-average window for event-loop lag

// Process-wide log-queue-depth getter. createPluginLogger() registers its own
// queue length here, so any plugin that has a logger automatically exposes
// `logQueueDepth` in GET /metrics with zero extra wiring (one process per
// container = one logger, no ambiguity).
let registeredLogQueueDepth: (() => number) | null = null;

/** Registers the pending-log-entries getter (called by createPluginLogger). */
export function registerSelfMetricsLogQueueDepth(getter: () => number): void {
  registeredLogQueueDepth = getter;
}

/**
 * Creates the self-metrics collector + Express handler. Call `track()` from a
 * middleware around the work routes and mount `handler` at GET /metrics.
 */
export function createSelfMetrics(opts: SelfMetricsOptions = {}) {
  const startedAt = Date.now();
  let lastCpu = process.cpuUsage();
  let lastCpuTime = Date.now();
  let inFlight = 0;
  const lagSamples: number[] = [];
  const workSamples: WorkSample[] = [];

  // Event-loop lag: a 1s interval that fires late means the loop was blocked.
  let lastTick = Date.now();
  const lagTimer = setInterval(() => {
    const now = Date.now();
    const lag = Math.max(0, now - lastTick - 1000);
    lastTick = now;
    lagSamples.push(lag);
    if (lagSamples.length > LAG_SAMPLES) lagSamples.shift();
  }, 1000);
  // Don't keep the process alive just for sampling (plugins exit on demand).
  if (typeof lagTimer.unref === 'function') lagTimer.unref();

  /** Records one completed work request (/monitoring, /config, /plan). */
  function track(durationMs: number, ok: boolean): void {
    workSamples.push({ durationMs, ok });
    if (workSamples.length > (opts.windowSize ?? DEFAULT_WINDOW)) workSamples.shift();
  }

  /** Current snapshot — safe to call at any time. */
  function collect(): PluginSelfMetrics {
    const mem = process.memoryUsage();
    const now = Date.now();
    const cpu = process.cpuUsage();
    // cpuUsage() is in MICROseconds — the wall-clock delta must be converted too.
    const elapsedUs = Math.max(1, (now - lastCpuTime) * 1000);
    const usedUs = (cpu.user - lastCpu.user) + (cpu.system - lastCpu.system);
    // % of one core: 1e6 µs per second.
    const cpuPercent = Math.round((usedUs / elapsedUs) * 100 * 10) / 10;
    lastCpu = cpu;
    lastCpuTime = now;

    const avgLag = lagSamples.length > 0 ? lagSamples.reduce((a, b) => a + b, 0) / lagSamples.length : 0;

    let lastPollMs: number | null = null;
    let errorRatePercent: number | null = null;
    if (workSamples.length > 0) {
      lastPollMs = workSamples[workSamples.length - 1].durationMs;
      const failures = workSamples.filter((s) => !s.ok).length;
      errorRatePercent = Math.round((failures / workSamples.length) * 1000) / 10;
    }

    let logQueueDepth: number | undefined;
    const depthGetter = opts.logQueueDepth ?? registeredLogQueueDepth;
    if (depthGetter) {
      try {
        const depth = depthGetter();
        if (typeof depth === 'number' && Number.isFinite(depth)) logQueueDepth = Math.max(0, Math.floor(depth));
      } catch {
        // a broken getter must never break /metrics
      }
    }

    return {
      uptimeSeconds: Math.floor((now - startedAt) / 1000),
      heapUsedBytes: mem.heapUsed,
      heapTotalBytes: mem.heapTotal,
      rssBytes: mem.rss,
      cpuPercent,
      eventLoopLagMs: Math.round(avgLag * 10) / 10,
      inFlight,
      lastPollMs,
      errorRatePercent,
      emittedMetricsCount: emittedCount, // maintained by trackMiddleware on /monitoring responses
      ...(logQueueDepth !== undefined ? { logQueueDepth } : {}),
    };
  }

  // Number of metric keys in the last /monitoring payload (null before the first).
  let emittedCount: number | null = null;

  /**
   * Express middleware for the work routes. Increments in-flight while the
   * request is handled and records duration + success afterwards. For
   * /monitoring it also counts the metric keys of the JSON payload (the
   * per-poll telemetry weight) by intercepting res.json — no plugin code needed.
   */
  const trackMiddleware: RequestHandler = (req, res, next) => {
    if (!['/monitoring', '/config', '/plan'].includes(req.path)) return next();

    // Count emitted metric keys on /monitoring responses (best-effort).
    if (req.path === '/monitoring') {
      const originalJson = res.json.bind(res);
      res.json = ((body?: unknown) => {
        try {
          if (body && typeof body === 'object' && 'metrics' in (body as Record<string, unknown>)) {
            const metrics = (body as Record<string, unknown>)['metrics'];
            if (metrics && typeof metrics === 'object') {
              emittedCount = Object.keys(metrics).length;
            }
          }
        } catch {
          // counting is best-effort — never break the response
        }
        return originalJson(body);
      }) as typeof res.json;
    }

    inFlight += 1;
    const startedAtMs = Date.now();
    let done = false;
    // 'finish' fires before 'close'; a client abort closes without finishing.
    // Track on whichever comes first — exactly once per request.
    const finish = (): void => {
      if (done) return;
      done = true;
      inFlight -= 1;
      // Plugins normally answer 200 with health semantics, so a non-2xx status
      // or an aborted response is a real failure worth counting.
      const ok = res.writableEnded && res.statusCode < 400;
      track(Date.now() - startedAtMs, ok);
    };
    res.on('finish', finish);
    res.on('close', finish);
    next();
  }

  /** The GET /metrics handler. */
  const handler: RequestHandler = (_req, res) => {
    const snapshot = collect();
    if (opts.extra) {
      try {
        const extra = typeof opts.extra === 'function' ? opts.extra() : opts.extra;
        for (const [key, value] of Object.entries(extra)) {
          if (typeof value === 'number' && Number.isFinite(value)) {
            (snapshot as unknown as Record<string, unknown>)[key] = value;
          }
        }
      } catch {
        // a broken extra() must never break /metrics
      }
    }
    res.status(200).json(snapshot);
  };

  return { trackMiddleware, handler, collect };
}
