import type { PoolClient } from 'pg';
import { pool } from '../db';
import { initWorker, setLeaderState } from './stats';

/**
 * Leader election for background workers, built on Postgres advisory locks.
 *
 * The API is designed to run as N replicas (HA) while only ONE of them runs
 * the background workers (telemetry polling, plan execution, retention
 * sweeps, plugin discovery). Every worker calls `runAsLeader()` at startup:
 * it attempts a NON-BLOCKING session-level advisory lock. The first instance
 * to win becomes the leader and starts its work loop; the others log that
 * they are standby and simply serve HTTP traffic (all routes are stateless —
 * jobs land in Postgres, not in process memory).
 *
 * Failover is automatic: if the leader's connection drops (crash, OOM,
 * `docker compose down`), Postgres releases its advisory locks. Each standby
 * re-attempts every RETRY_INTERVAL_MS and takes over within one interval —
 * no external coordination service required. A 60s verification query guards
 * against the rarer case where only the leader's DB connection dies while the
 * process lives (e.g. a Postgres restart): it steps down if the lock is gone.
 *
 * Overhead in a single-replica deployment: one extra `pg_try_advisory_lock`
 * per worker at startup plus one verification query per minute — effectively
 * zero. The lock rides on ONE dedicated pinned pool connection (never returned
 * to the idle list), because node-postgres destroys pooled connections that sit
 * idle for 5 minutes and would silently release session-scoped locks with it.
 */

const RETRY_INTERVAL_MS = 15_000; // standby re-attempts leadership this often
const VERIFY_INTERVAL_MS = 60_000; // leader re-verifies the lock this often

/** One stable key per worker — distinct from each other, stable across restarts. */
export const LEADER_KEYS = {
  telemetry: 9001,
  planExecutor: 9002,
  retention: 9003,
  discovery: 9004,
  pluginMetrics: 9005,
  telemetryRetention: 9006,
  notifications: 9007,
  inactiveUsers: 9008,
  planScheduler: 9009,
  ntpReferences: 9010,
  flows: 9011,
  geoip: 9012,
  firewallEventRetention: 9013,
  hostStateRetention: 9014,
  stackUpdates: 9015,
  replication: 9016,
  autoBackup: 9017,
  cve: 9018,
  automationEvaluator: 9019,
} as const;

/**
 * The single connection that holds all of this process's leadership locks.
 * It is checked out from the pool and NEVER released while held, so it can
 * never be recycled by the pool's idle timeout (which would drop the locks).
 */
let pinnedClient: PoolClient | null = null;

/**
 * Global serialization over the pinned connection. node-postgres does NOT
 * support concurrent queries on one client (pg@8 warns, pg@9 will throw) — and
 * crossed responses on a shared socket are exactly what stalled every worker
 * at once in 2026-08: all six verify timers start phase-aligned at boot and
 * fire together every 60 s, racing each other's `pg_try_advisory_lock` calls.
 * The corrupted client then failed every later query with a message that did
 * not match the reconnect pattern below → all workers stayed standby forever
 * while Postgres showed no advisory locks at all (the desynced backend had
 * already been recycled by the pool). Every query funnels through this chain.
 */
let pinnedQueryChain: Promise<unknown> = Promise.resolve();

function withPinnedConnection<T>(fn: (client: PoolClient) => Promise<T>): Promise<T> {
  const run = async (): Promise<T> => {
    if (!pinnedClient) {
      // Fresh checkout — or reconnect after a dropped connection. A dead
      // backend already had its locks released by Postgres, so re-acquiring on
      // the new backend is safe (it only succeeds when nobody else holds it).
      pinnedClient = await pool.connect();
    }
    try {
      return await fn(pinnedClient);
    } catch (err) {
      discardPinnedClient();
      // ANY failed query leaves the session suspect (dead backend, protocol
      // desync, …) — retry ONCE on a fresh connection. Locks held by a dead
      // backend were released by Postgres already; if nobody else holds the
      // key the re-acquire simply succeeds.
      pinnedClient = await pool.connect();
      return fn(pinnedClient);
    }
  };
  const result = pinnedQueryChain.then(run, run);
  pinnedQueryChain = result.catch(() => undefined);
  return result;
}

function discardPinnedClient(): void {
  if (!pinnedClient) return;
  try {
    pinnedClient.release(); // returns it (or ends it, if already dead) to the pool
  } catch {
    // Already ended — nothing to do.
  }
  pinnedClient = null;
}

/**
 * Attempts to become leader for `key`. Resolves `true` when this instance
 * holds the lock — just acquired it, or already held it (idempotent per
 * backend, which is what makes the periodic verification a simple re-call).
 * Never throws: a transient DB error counts as "not leader right now".
 */
export async function tryAcquireLeadership(key: number): Promise<boolean> {
  try {
    return await withPinnedConnection(async (client) => {
      const res = await client.query('SELECT pg_try_advisory_lock($1) AS acquired', [key]);
      return Boolean(res.rows?.[0]?.acquired);
    });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.warn(`[leader] leadership check failed for key ${key}:`, (err as Error).message);
    return false;
  }
}

/** Releases the lock explicitly (graceful shutdown / step-down). Best-effort. */
export async function releaseLeadership(key: number): Promise<void> {
  if (!pinnedClient) return; // no pinned connection — nothing to unlock
  try {
    await withPinnedConnection((client) => client.query('SELECT pg_advisory_unlock($1)', [key]));
  } catch {
    // Connection gone — Postgres released the lock with it.
  }
}

/** Returns the pinned connection to the pool (after all locks are unlocked). */
export function releasePinnedConnection(): void {
  discardPinnedClient();
}

/**
 * Runs a worker under leadership for `key`.
 *
 * Contract:
 * - Retries acquisition every RETRY_INTERVAL_MS until won (logging standby).
 * - Once leader, calls `startWork()` exactly once. `startWork` owns the
 *   worker's own pacing (its setInterval) and returns a stop function.
 * - Re-verifies the lock every VERIFY_INTERVAL_MS; if it was lost (DB
 *   connection died), stops the work loop and resumes standby retries.
 * - Returns a stop function that halts everything, unlocks, and unpins the
 *   connection — used on SIGTERM so a rolling deploy fails over immediately.
 */
export async function runAsLeader(
  key: number,
  name: string,
  startWork: () => (() => void) | Promise<() => void>
): Promise<() => Promise<void>> {
  initWorker(name, key);
  let stopped = false;
  let retryTimer: NodeJS.Timeout | null = null;
  let verifyTimer: NodeJS.Timeout | null = null;
  let stopWork: (() => void) | null = null;

  async function attempt(): Promise<void> {
    if (stopped) return;
    if (!(await tryAcquireLeadership(key))) {
      retryTimer = setTimeout(() => void attempt(), RETRY_INTERVAL_MS);
      return;
    }
    // eslint-disable-next-line no-console
    console.log(`[leader] "${name}" acquired leadership (key ${key})`);
    setLeaderState(name, true);
    try {
      stopWork = await startWork();
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error(`[leader] "${name}" failed to start work:`, err);
      stopWork = null;
      retryTimer = setTimeout(() => void attempt(), RETRY_INTERVAL_MS);
      return;
    }
    verifyTimer = setInterval(() => void verify(), VERIFY_INTERVAL_MS);
  }

  async function verify(): Promise<void> {
    if (stopped) return;
    const held = await tryAcquireLeadership(key); // idempotent: true while we hold it
    if (!held) {
      // eslint-disable-next-line no-console
      console.warn(`[leader] "${name}" lost leadership — stepping down to standby`);
      setLeaderState(name, false);
      if (verifyTimer) clearInterval(verifyTimer);
      stopWork?.();
      stopWork = null;
      retryTimer = setTimeout(() => void attempt(), RETRY_INTERVAL_MS);
    }
  }

  // eslint-disable-next-line no-console
  console.log(`[leader] "${name}" waiting for leadership (key ${key})...`);
  void attempt();

  return async () => {
    stopped = true;
    if (retryTimer) clearTimeout(retryTimer);
    if (verifyTimer) clearInterval(verifyTimer);
    stopWork?.();
    await releaseLeadership(key);
  };
}
