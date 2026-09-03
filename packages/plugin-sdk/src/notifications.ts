/**
 * createNotifier — push notifications from a plugin into the UNM notification
 * center (bell badge + Notifications page).
 *
 * Plugins use this for appliance-level events that are NOT derivable by the
 * API from telemetry alone — e.g. TrueNAS `alert.list` entries, firmware
 * update availability, or any vendor-specific warning. Device-state mirroring
 * (offline/degraded/critical) is done API-side automatically; do not push it
 * yourself.
 *
 * Semantics mirror createPluginLogger:
 *   - Fire-and-forget: notify() NEVER throws or blocks — a notification must
 *     not break a poll, config job, or plan step.
 *   - Bounded queue (MAX_QUEUE) with drop-oldest overflow; batches of up to
 *     MAX_BATCH are POSTed to the internal `POST /plugin/notifications`.
 *   - Dedupe: pass a stable `dedupeKey` for ongoing conditions — the API
 *     upserts the existing row while it persists instead of creating new ones.
 */

import { createApiClient } from './apiClient';
import type { PluginIdentity } from './identity';

export const NOTIFICATION_SEVERITIES = ['info', 'warning', 'critical'] as const;
export type NotificationSeverity = (typeof NOTIFICATION_SEVERITIES)[number];

/** One notification on the wire (matches the API's POST /plugin/notifications contract). */
export interface PluginNotification {
  severity?: NotificationSeverity; // default 'info'
  title: string;
  message?: string;
  /** Stable identity of an ongoing condition (API prefixes it with plugin:<uuid>:). */
  dedupeKey?: string | null;
  deviceId?: string | null;
  context?: Record<string, unknown> | null;
}

export interface NotifierOptions {
  baseUrl?: string;
  apiKey?: string;
  /** Flush cadence in ms (default 2000). */
  flushIntervalMs?: number;
}

export interface PluginNotifier {
  notify(n: PluginNotification): void;
  info(title: string, opts?: Omit<PluginNotification, 'title' | 'severity'>): void;
  warning(title: string, opts?: Omit<PluginNotification, 'title' | 'severity'>): void;
  critical(title: string, opts?: Omit<PluginNotification, 'title' | 'severity'>): void;
  /**
   * Mark ongoing conditions as cleared — the API resolves their live rows.
   * Pass the SAME dedupeKeys you used when notifying (without any prefix).
   */
  resolve(dedupeKeys: string[]): void;
  /** Runtime toggle (wire to a plugin option like `logToApi`). */
  setEnabled(enabled: boolean): void;
  enabled: boolean;
}

const MAX_QUEUE = 200; // overflow drops oldest
const MAX_BATCH = 50; // API caps requests at 100 entries
const DEFAULT_FLUSH_INTERVAL_MS = 2_000;

export function createNotifier(identity: PluginIdentity, opts: NotifierOptions = {}): PluginNotifier {
  const apiKey = opts.apiKey ?? process.env.PLUGIN_API_KEY;
  if (!apiKey) {
    console.warn(
      `[${identity.displayName}] PLUGIN_API_KEY not set — plugin notifications are disabled (entries will be dropped)`
    );
  }

  const http = createApiClient({ baseUrl: opts.baseUrl, apiKey });
  let queue: PluginNotification[] = [];
  let resolveKeys = new Set<string>();
  let enabled = true;
  let flushing = false;

  async function flush(): Promise<void> {
    if (flushing || (queue.length === 0 && resolveKeys.size === 0)) return;
    flushing = true;
    const batch = queue.splice(0, MAX_BATCH);
    const resolves = Array.from(resolveKeys).slice(0, 200);
    resolveKeys.clear();
    try {
      await http.post('/plugin/notifications', {
        pluginId: identity.effectiveUuid,
        notifications: batch,
        ...(resolves.length > 0 ? { resolve: resolves } : {}),
      });
    } catch {
      // Drop-on-failure (one retry would re-order against newer entries — the
      // notification center is best-effort by contract).
    } finally {
      flushing = false;
    }
  }

  const timer = setInterval(() => void flush(), opts.flushIntervalMs ?? DEFAULT_FLUSH_INTERVAL_MS);
  if (typeof timer === 'object' && 'unref' in timer) timer.unref();

  function push(n: PluginNotification): void {
    if (!enabled || !apiKey) return;
    if (!n?.title || typeof n.title !== 'string') return;
    queue.push({ ...n, severity: n.severity ?? 'info' });
    if (queue.length > MAX_QUEUE) queue = queue.slice(queue.length - MAX_QUEUE); // drop oldest
  }

  const notifier: PluginNotifier = {
    notify: push,
    info: (title, o = {}) => push({ title, severity: 'info', ...o }),
    warning: (title, o = {}) => push({ title, severity: 'warning', ...o }),
    critical: (title, o = {}) => push({ title, severity: 'critical', ...o }),
    resolve(dedupeKeys: string[]) {
      if (!enabled || !apiKey) return;
      for (const k of dedupeKeys) {
        if (typeof k === 'string' && k) resolveKeys.add(k);
      }
    },
    setEnabled(value: boolean) {
      // Assign the CLOSURE variable — `notifier.enabled` is getter-only.
      enabled = value;
    },
    get enabled() {
      return enabled;
    },
  };

  // Flush on process exit so a short-lived plugin doesn't lose its last batch.
  const shutdown = () => void flush();
  process.once('SIGTERM', shutdown);
  process.once('SIGINT', shutdown);

  return notifier;
}
