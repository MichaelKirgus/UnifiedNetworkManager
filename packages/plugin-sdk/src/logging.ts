/**
 * createPluginLogger — structured log shipping from a plugin to the UNM API.
 *
 * Plugins call `logger.info/warn/error(...)` at the same sites they already
 * write to console; entries are batched in memory and POSTed to the internal
 * `POST /plugin/logs` endpoint (shared x-plugin-api-key auth, self-reported
 * pluginId = identity.effectiveUuid). The API persists them in `plugin_logs`,
 * where they power the per-device Logs section and the global Logs page.
 *
 * Semantics:
 *   - Fire-and-forget: log() NEVER throws or blocks — logging must not break a
 *     poll, config job, or plan step.
 *   - Drop-on-failure: if the API is unreachable (or rejects the batch), each
 *     entry gets exactly ONE retry; after that it is silently dropped.
 *   - Bounded queue: at most MAX_QUEUE entries are kept; overflow drops the
 *     OLDEST entries so a chatty plugin can never grow memory unboundedly.
 *   - Toggleable at runtime via setEnabled() — plugins wire this to their
 *     `logToApi` option (default true), which flows through the settings loop,
 *     so it works globally and per-device with zero extra plumbing.
 */

import { createApiClient } from './apiClient';
import { registerSelfMetricsLogQueueDepth } from './selfMetrics';
import type { PluginIdentity } from './identity';

export const LOG_LEVELS = ['debug', 'info', 'warn', 'error'] as const;
export type LogLevel = (typeof LOG_LEVELS)[number];

/** One log entry on the wire (matches the API's POST /plugin/logs contract). */
export interface PluginLogEntry {
  pluginId: string;
  deviceId?: string | null;
  level: LogLevel;
  message: string;
  context?: Record<string, unknown> | null;
  timestamp: string; // ISO-8601, plugin-side clock
}

export interface PluginLoggerOptions {
  /** Base URL of the API (default: UNM_API_URL env or http://localhost:3000/v1). */
  baseUrl?: string;
  /** Shared plugin API key (default: PLUGIN_API_KEY env). */
  apiKey?: string;
  /** Flush cadence in ms (default 2000). */
  flushIntervalMs?: number;
}

export interface PluginLogger {
  log(level: LogLevel, message: string, opts?: LogCallOptions): void;
  debug(message: string, opts?: LogCallOptions): void;
  info(message: string, opts?: LogCallOptions): void;
  warn(message: string, opts?: LogCallOptions): void;
  error(message: string, opts?: LogCallOptions): void;
  /** Runtime toggle (wired to the plugin's `logToApi` option). */
  setEnabled(enabled: boolean): void;
  enabled: boolean;
  /** Entries waiting in the queue — read by the SDK self-metrics endpoint. */
  readonly logQueueDepth: number;
}

export interface LogCallOptions {
  /** Device the entry relates to, when known. */
  deviceId?: string | null;
  /** Structured details ({endpoint, httpStatus, oid, ...}). */
  context?: Record<string, unknown> | null;
}

const MAX_QUEUE = 500; // overflow drops oldest
const MAX_BATCH = 100; // API caps requests at 100 entries
const DEFAULT_FLUSH_INTERVAL_MS = 2000;
const MAX_RETRIES_PER_ENTRY = 1;

interface QueuedEntry {
  entry: PluginLogEntry;
  retries: number;
}

export function createPluginLogger(identity: PluginIdentity, opts: PluginLoggerOptions = {}): PluginLogger {
  // The internal endpoint requires the shared plugin key. Without it every
  // POST would 403 — degrade to a no-op instead of generating pointless traffic.
  const apiKey = opts.apiKey ?? process.env.PLUGIN_API_KEY;
  if (!apiKey) {
    console.warn(
      `[${identity.displayName}] PLUGIN_API_KEY not set — plugin logging is disabled (entries will be dropped)`
    );
  }

  const http = createApiClient({ baseUrl: opts.baseUrl, apiKey });
  let queue: QueuedEntry[] = [];
  let enabled = true;
  let flushing = false;
  let warnedDrops = false;

  // Expose the pending-entries count to the auto-mounted GET /metrics endpoint
  // (self-metrics reads it at request time, so registration order doesn't matter).
  registerSelfMetricsLogQueueDepth(() => queue.length);

  async function flush(): Promise<void> {
    if (flushing || queue.length === 0) return;
    flushing = true;
    let batch: QueuedEntry[] = [];
    try {
      batch = queue.splice(0, MAX_BATCH);
      const entries: PluginLogEntry[] = batch.map((q) => q.entry);
      await http.post('/plugin/logs', { pluginId: identity.effectiveUuid, entries });
      // Remaining queued entries (if any) go out on the next tick.
    } catch {
      // Drop-on-failure: re-queue for one retry each; anything already retried
      // is dropped silently — logging must never break a poll or config job.
      const keep: QueuedEntry[] = [];
      for (const q of batch) {
        if (q.retries < MAX_RETRIES_PER_ENTRY) keep.push({ entry: q.entry, retries: q.retries + 1 });
      }
      queue = [...keep, ...queue];
    } finally {
      flushing = false;
    }
  }

  const timer = setInterval(() => {
    void flush();
  }, opts.flushIntervalMs ?? DEFAULT_FLUSH_INTERVAL_MS);
  // Don't keep the process alive just for log flushing (plugins exit on demand).
  if (typeof timer.unref === 'function') timer.unref();

  function log(level: LogLevel, message: string, callOpts?: LogCallOptions): void {
    if (!enabled || !apiKey) return;
    const entry: PluginLogEntry = {
      pluginId: identity.effectiveUuid,
      deviceId: callOpts?.deviceId ?? null,
      level,
      message,
      context: callOpts?.context ?? null,
      timestamp: new Date().toISOString(),
    };
    queue.push({ entry, retries: 0 });
    if (queue.length > MAX_QUEUE) {
      const dropped = queue.splice(0, queue.length - MAX_QUEUE);
      if (!warnedDrops) {
        warnedDrops = true; // one warning per process lifetime — don't spam the very thing we log about
        console.warn(`[${identity.displayName}] log queue overflow — dropped ${dropped.length} oldest entries`);
      }
    }
  }

  return {
    log,
    debug: (message, callOpts) => log('debug', message, callOpts),
    info: (message, callOpts) => log('info', message, callOpts),
    warn: (message, callOpts) => log('warn', message, callOpts),
    error: (message, callOpts) => log('error', message, callOpts),
    setEnabled(next: boolean) {
      if (enabled && !next) queue = []; // turning off stops emission; pending entries are dropped
      enabled = next;
    },
    get enabled() {
      return enabled;
    },
    get logQueueDepth() {
      return queue.length;
    },
  };
}
