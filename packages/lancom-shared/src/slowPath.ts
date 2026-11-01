/**
 * The LANCOM slow-path runner — the shared orchestration skeleton previously
 * copy-pasted (with small wording differences) in lancom-lcos, lancom-lx and
 * lancom-sx `get*Inventory()`:
 *
 *   1. serve a fresh TTL-cached snapshot when available;
 *   2. otherwise run the plugin's PROBE GATE (diverges per plugin — a single
 *      scalar snmpGet for lcos/lx, two-OID variant detection for sx);
 *   3. merge one combined GetBulk walk of the inventory subtrees into the map
 *      seeded by the probe;
 *   4. optional best-effort enrichment walks (e.g. opt-in Q-BRIDGE FDB);
 *   5. quality-gate before caching — a partial-failure artifact is returned
 *      once and retried next cycle, never served from cache for the whole TTL;
 *   6. on total failure fall back to the last-known snapshot (stale).
 *
 * Only the pieces that genuinely differ are injected: the probe step, the walk
 * list (may depend on a detected variant), the parser, the completeness gate,
 * and the vendor-specific error strings. Everything else — cache discipline,
 * stale fallback, failure counting, empty-result handling — lives here once so
 * all three plugins follow identical invariants.
 */

import { SnmpCredentials, SnmpValue, TransportOptions, snmpWalkMulti } from '@unm/snmp-client';
import type { SnapshotCaches } from './snapshotCache';

/** Optional structured-log sink for walk failures (wired to the plugin logger). */
export interface LcosLogSink {
  log(level: 'warn' | 'error', message: string, context?: Record<string, unknown>): void;
}

/** The three possible outcomes of a probe gate. */
export type ProbeOutcome =
  /** Unreachable host / rejected credentials — serve the stale snapshot. */
  | { kind: 'transport-error'; error: string }
  /** Agent answered but exposes no LANCOM tree for this plugin — not our device. */
  | { kind: 'not-device' }
  /** Probe succeeded; `seed` is merged into the walk output, `ctx` threads through. */
  | { kind: 'ok'; seed: Map<string, SnmpValue>; ctx?: unknown };

/** Vendor-specific error strings (wording differs per plugin). */
export interface SlowPathErrors {
  /** Combined inventory walk threw and nothing was collected. */
  walkFailed: string;
  /** Agent answered but has no MIB data for this device type. */
  notDevice: string;
  /** Walks partially failed — snapshot returned once, retried next cycle. */
  partial: string;
}

/** The injected, per-plugin pieces of the slow path. */
export interface SlowPathConfig<V> {
  host: string;
  creds: SnmpCredentials;
  opts: TransportOptions & { inventoryTtlMs: number };
  log?: LcosLogSink;
  /** Probe gate — diverges per plugin (scalar snmpGet vs variant detection). */
  probe(): Promise<ProbeOutcome>;
  /** The subtrees to walk, given the probe ctx (e.g. a detected variant). */
  walks(ctx?: unknown): string[];
  /** Optional best-effort enrichment walks — failures are ignored by design. */
  enrich?(out: Map<string, SnmpValue>, ctx?: unknown): Promise<void>;
  /** Parses the merged walk output into a typed snapshot. */
  parse(out: Map<string, SnmpValue>, ctx?: unknown): V;
  /** Quality gate — only cache complete snapshots (e.g. serial present). */
  isComplete(snapshot: V, walkFailures: number): boolean;
  errors: SlowPathErrors;
  /** Called whenever the runner concludes "not a device" (probe or empty walks). */
  onNotDevice?: () => void;
  /**
   * Bypass the TTL cache and re-walk NOW. Set by forced refreshes ("Check now" /
   * POST /devices/refresh): an explicit user request for FRESH data must not be
   * answered from a snapshot that is up to `inventoryTtlMs` (15 min) old — e.g. a
   * DNS entry written via CLI seconds ago would otherwise stay invisible on the
   * cross-device pages until the next scheduled inventory window.
   */
  force?: boolean;
}

/** The slow-path result envelope (matches every plugin's get*Inventory return). */
export interface SlowPathResult<V> {
  snapshot: V | null;
  fromCache: boolean;
  error?: string;
}

/** Runs the shared LANCOM slow path for one host. Never throws — degrades to stale/empty data with an explanatory error. */
export async function runSlowPath<V>(caches: SnapshotCaches<V>, cfg: SlowPathConfig<V>): Promise<SlowPathResult<V>> {
  const { host, creds, opts, log } = cfg;

  // A forced refresh bypasses the TTL cache — see SlowPathConfig.force.
  const cached = cfg.force ? undefined : caches.inventory.get(host, opts.inventoryTtlMs);
  if (cached) return { snapshot: cached, fromCache: true };
  const stale = caches.getStale(host); // expired-but-usable fallback

  const probe = await cfg.probe();
  if (probe.kind === 'transport-error') {
    return { snapshot: stale ?? null, fromCache: stale !== undefined, error: probe.error };
  }
  if (probe.kind === 'not-device') {
    cfg.onNotDevice?.();
    return { snapshot: null, fromCache: false, error: cfg.errors.notDevice };
  }

  // Reuse the probed scalar(s), then merge ALL inventory subtrees in ONE combined
  // GetBulk stream on a single shared session. The stream is strictly sequential
  // (one PDU at a time) — the safe mode verified live on LANCOM agents, whose
  // tiny concurrent-request queues corrupt DisplayString values under parallelism.
  const out = new Map<string, SnmpValue>(probe.seed);
  let failures = 0;
  try {
    const walked = await snmpWalkMulti(host, creds, cfg.walks(probe.ctx), opts);
    for (const [k, v] of walked) out.set(k, v);
  } catch (err) {
    failures++;
    const msg = err instanceof Error ? err.message : String(err ?? 'unknown error');
    console.error('[lancom-shared] inventory walk failed:', msg);
    log?.log('warn', `SNMP inventory walk failed on ${host}: ${msg}`, { host });
  }

  if (cfg.enrich) await cfg.enrich(out, probe.ctx);

  if (out.size === 0 && failures > 0) {
    return { snapshot: stale ?? null, fromCache: stale !== undefined, error: cfg.errors.walkFailed };
  }
  if (out.size === 0) {
    // Walks succeeded but returned nothing — this device is not the target type.
    cfg.onNotDevice?.();
    return { snapshot: null, fromCache: false, error: cfg.errors.notDevice };
  }

  const snapshot = cfg.parse(out, probe.ctx);

  // Quality gate before caching (see module header): a partial-failure artifact
  // must never be served from cache for the whole TTL.
  const complete = cfg.isComplete(snapshot, failures);
  if (complete) {
    caches.inventory.set(host, snapshot);
    caches.rememberLastKnown(host, snapshot);
  }

  return { snapshot, fromCache: false, error: complete ? undefined : cfg.errors.partial };
}
