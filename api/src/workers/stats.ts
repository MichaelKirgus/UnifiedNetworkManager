import { pool } from '../db';

/**
 * In-process observability for the worker infrastructure (Workers page).
 *
 * Every leader-gated worker registers here and reports its beat cadence,
 * leadership transitions, and errors. State is per-instance by design — the
 * status endpoint answers "what is THIS replica doing", which is exactly what
 * an operator needs when debugging HA behavior. A small ring buffer of events
 * (leadership acquired/lost, beat failures) gives a recent audit trail without
 * persisting anything.
 */

export interface WorkerRuntime {
  name: string;
  leaderKey: number;
  /** true while this instance holds the advisory lock for this worker. */
  isLeader: boolean;
  becameLeaderAt: string | null;
  beatsCompleted: number;
  lastBeatStartedAt: string | null;
  lastBeatFinishedAt: string | null;
  lastBeatDurationMs: number | null;
  beatErrors: number;
  lastError: string | null;
}

export interface TelemetryCycleStats {
  /** Completed /monitoring polls (all time since worker start). */
  cyclesCompleted: number;
  /** Beats skipped because the previous cycle was still running (cycle guard). */
  cyclesSkippedOverlap: number;
  devicesPolledLastCycle: number;
  assignmentsPolledLastCycle: number;
  lastCycleDurationMs: number | null;
  /** /monitoring calls currently in flight (dispatcher budget gauge). */
  pollsInFlight: number;
  /** Successful + failed polls completed in the trailing 60 s. */
  pollsPerMinute: number;
  /** Assignments whose metrics deadline has passed but are waiting for a free slot. */
  overdueWaiting: number;
  /** Duration of the most recent single /monitoring call (ms). */
  lastPollDurationMs: number | null;
}

export type SystemEventType =
  | 'leadership-acquired'
  | 'leadership-lost'
  | 'worker-started'
  | 'beat-error';

export interface SystemEvent {
  id: number;
  at: string;
  type: SystemEventType;
  worker: string | null;
  message: string;
}

const runtimes = new Map<string, WorkerRuntime>();
const events: SystemEvent[] = [];
let nextEventId = 1;
const MAX_EVENTS = 200;

export const telemetryStats: TelemetryCycleStats = {
  cyclesCompleted: 0,
  cyclesSkippedOverlap: 0,
  devicesPolledLastCycle: 0,
  assignmentsPolledLastCycle: 0,
  lastCycleDurationMs: null,
  pollsInFlight: 0,
  pollsPerMinute: 0,
  overdueWaiting: 0,
  lastPollDurationMs: null,
};

/** Rolling window of poll completion timestamps (trailing-60s rate). */
const pollCompletionTimes: number[] = [];

/** Records one completed /monitoring call (success or failure). */
export function recordTelemetryPoll(durationMs: number): void {
  telemetryStats.cyclesCompleted += 1;
  telemetryStats.lastPollDurationMs = durationMs;
  const now = Date.now();
  pollCompletionTimes.push(now);
  // Drop timestamps older than the trailing window.
  while (pollCompletionTimes.length > 0 && pollCompletionTimes[0] < now - 60_000) {
    pollCompletionTimes.shift();
  }
  telemetryStats.pollsPerMinute = pollCompletionTimes.length;
}

/** Registers a worker (idempotent — restarts reset its counters). */
export function initWorker(name: string, leaderKey: number): void {
  if (!runtimes.has(name)) {
    runtimes.set(name, {
      name,
      leaderKey,
      isLeader: false,
      becameLeaderAt: null,
      beatsCompleted: 0,
      lastBeatStartedAt: null,
      lastBeatFinishedAt: null,
      lastBeatDurationMs: null,
      beatErrors: 0,
      lastError: null,
    });
  }
}

/** Records a leadership transition (called by the leader-election layer). */
export function setLeaderState(name: string, isLeader: boolean): void {
  const rt = runtimes.get(name);
  if (!rt || rt.isLeader === isLeader) return;
  rt.isLeader = isLeader;
  rt.becameLeaderAt = isLeader ? new Date().toISOString() : null;
  recordEvent(
    isLeader ? 'leadership-acquired' : 'leadership-lost',
    `worker "${name}" ${isLeader ? 'acquired leadership' : 'lost leadership (stepped down to standby)'}`,
    name
  );
}

/** Wraps one worker beat: timestamps it, counts successes/errors. */
export async function trackBeat<T>(name: string, fn: () => Promise<T>): Promise<T> {
  const rt = runtimes.get(name);
  if (!rt) return fn();
  rt.lastBeatStartedAt = new Date().toISOString();
  const started = Date.now();
  try {
    const result = await fn();
    rt.beatsCompleted += 1;
    rt.lastBeatFinishedAt = new Date().toISOString();
    rt.lastBeatDurationMs = Date.now() - started;
    return result;
  } catch (err) {
    rt.beatErrors += 1;
    const message = (err as Error)?.message ?? String(err);
    rt.lastError = message;
    recordEvent('beat-error', `worker "${name}" beat failed: ${message}`, name);
    throw err;
  }
}

/** Records a telemetry poll cycle's outcome (called by workers/telemetry.ts). */
export function recordTelemetryCycle(devicesPolled: number, assignmentsPolled: number, durationMs: number): void {
  telemetryStats.devicesPolledLastCycle = devicesPolled;
  telemetryStats.assignmentsPolledLastCycle = assignmentsPolled;
  telemetryStats.lastCycleDurationMs = durationMs;
}

/** Records a beat skipped by the cycle guard (previous cycle still running). */
export function recordSkippedTelemetryBeat(): void {
  telemetryStats.cyclesSkippedOverlap += 1;
}

/** Appends to the event ring buffer (newest last, capped at MAX_EVENTS). */
export function recordEvent(type: SystemEventType, message: string, worker: string | null = null): void {
  events.push({ id: nextEventId++, at: new Date().toISOString(), type, worker, message });
  if (events.length > MAX_EVENTS) events.splice(0, events.length - MAX_EVENTS);
}

/** Snapshot of all registered workers (stable order). */
export function getWorkerRuntimes(): WorkerRuntime[] {
  return Array.from(runtimes.values());
}

/** Recent events, newest first. */
export function getEvents(limit = 50): SystemEvent[] {
  return events.slice(-limit).reverse();
}

// --- Postgres health (read-only introspection) -------------------------------

// All user tables are listed (no fixed allow-list) — see getPostgresStats.

/**
 * One user table (or one partition, when returned in `partitions`). Regular
 * and partitioned-parent rows carry isPartitioned/partitionCount/partitionKey;
 * partition child rows carry bound + parent instead.
 */
export interface PostgresTableStat {
  name: string;
  approxRows: number;
  totalSizeBytes: number;
  totalSizePretty: string;
  /** True for partitioned parent tables (relkind 'p'). */
  isPartitioned?: boolean;
  /** Direct partition count (0/undefined when not partitioned). */
  partitionCount?: number;
  /** PARTITION BY definition, e.g. "RANGE (ts)" — set on partitioned parents only. */
  partitionKey?: string | null;
  /** Partition bound (e.g. "FOR VALUES FROM (...) TO (...)") — set on partition child rows only. */
  bound?: string | null;
  /** Parent table name — set on partition child rows only. */
  parent?: string;
}

export interface PostgresStats {
  version: string;
  databaseName: string;
  databaseSizePretty: string;
  maxConnections: number;
  connectionsTotal: number;
  connectionsActive: number;
  connectionsIdle: number;
  tables: PostgresTableStat[];
  /** One row per partition of every user partitioned table (for expandable rows). */
  partitions: PostgresTableStat[];
}

/** One-shot read-only snapshot of the Postgres instance (pg_catalog only). */
export async function getPostgresStats(): Promise<PostgresStats> {
  const [versionRes, sizeRes, maxConnRes, activityRes, tablesRes, partitionsRes] = await Promise.all([
    pool.query('SELECT version() AS v'),
    pool.query("SELECT current_database() AS db, pg_size_pretty(pg_database_size(current_database())) AS size"),
    pool.query("SELECT setting::int AS n FROM pg_settings WHERE name = 'max_connections'"),
    pool.query(`
      SELECT count(*)::int AS total,
             count(*) FILTER (WHERE state = 'active')::int AS active,
             count(*) FILTER (WHERE state = 'idle')::int AS idle
      FROM pg_stat_activity`),
    // ALL user tables (regular + partitioned parents). A partitioned parent's own
    // storage is 0 — its data lives in the partitions — so size/rows are summed
    // over the parent PLUS all direct partition children via a LATERAL aggregate.
    pool.query(`
      SELECT c.relname AS name,
             (COALESCE(s.n_live_tup, 0) + COALESCE(p.part_rows, 0))::bigint AS rows,
             (pg_total_relation_size(c.oid) + COALESCE(p.part_bytes, 0))::bigint AS size_bytes,
             pg_size_pretty(pg_total_relation_size(c.oid) + COALESCE(p.part_bytes, 0)) AS size_pretty,
             (c.relkind = 'p') AS is_partitioned,
             COALESCE(p.partition_count, 0)::int AS partition_count,
             CASE WHEN c.relkind = 'p' THEN pg_get_partkeydef(c.oid) ELSE NULL END AS part_key
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
      LEFT JOIN pg_stat_user_tables s ON s.relid = c.oid
      LEFT JOIN LATERAL (
        SELECT count(*)::int AS partition_count,
               sum(pg_total_relation_size(i.inhrelid)) AS part_bytes,
               sum(COALESCE(cs.n_live_tup, 0))::bigint AS part_rows
        FROM pg_inherits i
        LEFT JOIN pg_stat_user_tables cs ON cs.relid = i.inhrelid
        WHERE i.inhparent = c.oid
      ) p ON true
      WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg_%'
        AND c.relkind IN ('r', 'p')
        -- Partition CHILDREN are not top-level tables — they appear under their
        -- parent (expandable) and are already summed into the parent's rows/size.
        AND NOT EXISTS (SELECT 1 FROM pg_inherits i2 WHERE i2.inhrelid = c.oid)
      ORDER BY (pg_total_relation_size(c.oid) + COALESCE(p.part_bytes, 0)) DESC`),
    // One row per partition of every user partitioned table — the expandable
    // detail under each parent on the Workers page.
    pool.query(`
      SELECT parent.relname AS parent_name,
             c.relname AS name,
             pg_get_expr(c.relpartbound, c.oid) AS bound,
             COALESCE(s.n_live_tup, 0)::bigint AS rows,
             pg_total_relation_size(c.oid)::bigint AS size_bytes,
             pg_size_pretty(pg_total_relation_size(c.oid)) AS size_pretty
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
      LEFT JOIN pg_stat_user_tables s ON s.relid = c.oid
      JOIN pg_inherits i ON i.inhrelid = c.oid
      JOIN pg_class parent ON parent.oid = i.inhparent
      WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg_%'
        AND c.relkind IN ('r', 'p')
      ORDER BY parent_name, name`),
  ]);

  const tables: PostgresTableStat[] = (tablesRes.rows ?? []).map((r) => ({
    name: String(r.name),
    approxRows: Number(r.rows),
    totalSizeBytes: Number(r.size_bytes),
    totalSizePretty: String(r.size_pretty),
    isPartitioned: Boolean(r.is_partitioned),
    partitionCount: Number(r.partition_count ?? 0),
    partitionKey: r.part_key ? String(r.part_key) : null,
  }));

  const partitions: PostgresTableStat[] = (partitionsRes.rows ?? []).map((r) => ({
    name: String(r.name),
    parent: String(r.parent_name),
    approxRows: Number(r.rows),
    totalSizeBytes: Number(r.size_bytes),
    totalSizePretty: String(r.size_pretty),
    bound: r.bound ? String(r.bound) : null,
  }));

  return {
    version: String(versionRes.rows?.[0]?.v ?? 'unknown'),
    databaseName: String(sizeRes.rows?.[0]?.db ?? ''),
    databaseSizePretty: String(sizeRes.rows?.[0]?.size ?? '?'),
    maxConnections: Number(maxConnRes.rows?.[0]?.n ?? 100),
    connectionsTotal: Number(activityRes.rows?.[0]?.total ?? 0),
    connectionsActive: Number(activityRes.rows?.[0]?.active ?? 0),
    connectionsIdle: Number(activityRes.rows?.[0]?.idle ?? 0),
    tables,
    partitions,
  };
}
