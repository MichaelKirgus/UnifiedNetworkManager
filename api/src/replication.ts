import { randomUUID } from 'crypto';
import { eq } from 'drizzle-orm';
import { db } from './db';
import * as schema from './db/schema';
import { BackupArchive, SectionMergeReport, applyArchive, assertPortableSections, buildArchive, PORTABLE_SECTIONS } from './backup';

/**
 * One-way replication between UNM instances (e.g. dev → prod).
 *
 * A target row stores the peer's base URL + a Bearer token that must carry the
 * `instance:backup` permission on the PEER side. Two directions per target:
 *   push — build a portable export here, POST it to the peer's /replication/inbound
 *   pull — GET the peer's /replication/export and merge-apply it locally
 * Both paths use the SAME safe merge engine as restore (upsert by PK, absent
 * rows untouched). Only PORTABLE sections may cross instances; live inventory
 * is always regenerated locally. The target's `excludeKeys` list filters
 * system_settings keys BEFORE sending/applying so stack-dependent settings
 * (instance name, update feed, provider bindings, …) never leak across stacks.
 */

/** Stack-dependent setting keys that must NOT replicate by default (editable per target). */
export const DEFAULT_REPLICATION_EXCLUDES: string[] = [
  'instanceName',
  'updateFeedUrl',
  'updateFeedWebFetchProviderId',
  'fileRepoDefaultProviderId',
  'ntpReferenceServers',
  'webFetchProxyUrl',
  'geoipActiveFileId',
];

export interface SyncReport {
  status: 'ok' | 'error';
  at: string;
  direction: 'push' | 'pull';
  sections?: string[];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  tables?: any[];
  warnings?: string[];
  error?: string;
}

/** Drops excluded setting keys from an archive's settings section (in place). */
export function filterExcludedSettings(archive: BackupArchive, excludeKeys: ReadonlySet<string>): number {
  const rows = archive.data.settings?.['system_settings'];
  if (!Array.isArray(rows) || excludeKeys.size === 0) return 0;
  let dropped = 0;
  for (let i = rows.length - 1; i >= 0; i -= 1) {
    const key = String((rows[i] as Record<string, unknown>)['key'] ?? '');
    if (excludeKeys.has(key)) {
      rows.splice(i, 1);
      dropped += 1;
    }
  }
  return dropped;
}

/** Builds a portable export for the given sections (default: all portable). */
export async function buildPortableExport(sections?: string[]): Promise<BackupArchive> {
  const wanted = sections && sections.length > 0 ? sections : [...PORTABLE_SECTIONS];
  assertPortableSections(wanted);
  return buildArchive(wanted);
}

// ---------------------------------------------------------------------------
// Target CRUD (token is never returned in list responses)
// ---------------------------------------------------------------------------

export type ReplicationTargetRow = typeof schema.replicationTargets.$inferSelect;

function toView(row: ReplicationTargetRow): Record<string, unknown> {
  let excludeKeys: string[] = [];
  try {
    const parsed = JSON.parse(row.excludeKeys);
    if (Array.isArray(parsed)) excludeKeys = parsed.filter((k): k is string => typeof k === 'string');
  } catch {
    /* keep [] */
  }
  let lastReport: Record<string, unknown> = {};
  try {
    const parsed = JSON.parse(row.lastReport);
    if (parsed && typeof parsed === 'object') lastReport = parsed as Record<string, unknown>;
  } catch {
    /* keep {} */
  }
  // Never leak the peer token in API responses.
  const { token: _token, ...rest } = row;
  return { ...rest, excludeKeys, lastReport };
}

export async function listTargets(): Promise<Record<string, unknown>[]> {
  const rows = await db.select().from(schema.replicationTargets).orderBy(schema.replicationTargets.createdAt);
  return rows.map(toView);
}

export interface TargetInput {
  name: string;
  baseUrl: string;
  token: string;
  direction?: 'push' | 'pull';
  enabled?: boolean;
  intervalMinutes?: number | null;
  excludeKeys?: string[];
}

/** Creates or updates a target (upsert by id when provided). */
export async function upsertTarget(input: TargetInput, id?: string): Promise<Record<string, unknown>> {
  const name = input.name.trim();
  if (!name) throw new Error('Name is required');
  let baseUrl = input.baseUrl.trim().replace(/\/+$/, '');
  if (!/^https?:\/\//.test(baseUrl)) throw new Error('Base URL must start with http:// or https://');
  // Tolerate a pasted /v1 suffix — the sync job appends it itself.
  baseUrl = baseUrl.replace(/\/v1$/, '');
  const token = input.token.trim();
  if (!token) throw new Error('Token is required (a peer API token carrying instance:backup)');
  const direction = input.direction === 'pull' ? 'pull' : 'push';
  const enabled = input.enabled !== false;
  let intervalMinutes: number | null = null;
  if (input.intervalMinutes != null) {
    const n = Number(input.intervalMinutes);
    if (!Number.isFinite(n) || n < 1 || n > 24 * 60) throw new Error('Interval must be between 1 and 1440 minutes');
    intervalMinutes = Math.floor(n);
  }
  const excludeKeys = Array.isArray(input.excludeKeys) ? input.excludeKeys.filter((k): k is string => typeof k === 'string') : DEFAULT_REPLICATION_EXCLUDES;

  if (id) {
    const rows = await db.select().from(schema.replicationTargets).where(eq(schema.replicationTargets.id, id));
    if (rows.length === 0) throw Object.assign(new Error('Target not found'), { status: 404 });
    await db.update(schema.replicationTargets)
      .set({ name, baseUrl, token, direction, enabled, intervalMinutes, excludeKeys: JSON.stringify(excludeKeys) })
      .where(eq(schema.replicationTargets.id, id));
    const updated = (await db.select().from(schema.replicationTargets).where(eq(schema.replicationTargets.id, id)))[0];
    return toView(updated);
  }

  const newId = randomUUID();
  const row = await db.insert(schema.replicationTargets)
    .values({
      id: newId,
      name,
      baseUrl,
      token,
      direction,
      enabled,
      intervalMinutes,
      excludeKeys: JSON.stringify(excludeKeys),
      lastReport: '{}',
      createdAt: new Date().toISOString(),
    })
    .returning();
  return toView(row[0]);
}

export async function deleteTarget(id: string): Promise<boolean> {
  const result = await db.delete(schema.replicationTargets).where(eq(schema.replicationTargets.id, id)).returning();
  return result.length > 0;
}

// ---------------------------------------------------------------------------
// Sync job (manual trigger + scheduler share this)
// ---------------------------------------------------------------------------

const SYNC_TIMEOUT_MS = 120_000; // portable exports can be multi-MB JSON

/** In-process guard so the scheduler and a manual "Sync now" never run one target concurrently. */
const inFlightTargets = new Set<string>();

function normalizePeerError(status: number, bodyText: string): string {
  let message = `peer answered ${status}`;
  try {
    const parsed = JSON.parse(bodyText) as { error?: unknown };
    if (typeof parsed.error === 'string' && parsed.error.length > 0) message = parsed.error;
  } catch {
    /* keep default */
  }
  return message;
}

/** Runs one sync for a target and persists the outcome on its row. Returns the report. */
export async function runTargetSync(targetId: string): Promise<SyncReport> {
  const rows = await db.select().from(schema.replicationTargets).where(eq(schema.replicationTargets.id, targetId));
  if (rows.length === 0) throw Object.assign(new Error('Target not found'), { status: 404 });
  const target = rows[0];
  const direction: 'push' | 'pull' = target.direction === 'pull' ? 'pull' : 'push';

  if (inFlightTargets.has(targetId)) {
    return { status: 'error', at: new Date().toISOString(), direction, error: 'A sync for this target is already running' };
  }
  inFlightTargets.add(targetId);
  const report: SyncReport = { status: 'ok', at: new Date().toISOString(), direction };

  try {
    let excludeKeys: string[] = [];
    try {
      const parsed = JSON.parse(target.excludeKeys);
      if (Array.isArray(parsed)) excludeKeys = parsed.filter((k): k is string => typeof k === 'string');
    } catch {
      /* keep [] */
    }

    if (target.direction === 'push') {
      let archive = await buildPortableExport();
      const dropped = filterExcludedSettings(archive, new Set(excludeKeys));
      report.sections = Object.keys(archive.data);
      const res = await fetch(`${target.baseUrl}/v1/replication/inbound`, {
        method: 'POST',
        headers: { authorization: `Bearer ${target.token}`, 'content-type': 'application/json' },
        body: JSON.stringify({ manifest: archive.manifest, data: archive.data }),
        signal: AbortSignal.timeout(SYNC_TIMEOUT_MS),
      });
      if (!res.ok) throw new Error(normalizePeerError(res.status, await res.text().catch(() => '')));
      const applied = (await res.json()) as { report?: SectionMergeReport[] };
      // Same shape as pull mode: per-table merge entries.
      report.tables = Array.isArray(applied?.report) ? applied.report.flatMap((r) => r.tables ?? []) : [];
      if (dropped > 0) report.warnings = [`${dropped} excluded setting key(s) filtered before sending`];
    } else {
      const res = await fetch(`${target.baseUrl}/v1/replication/export`, {
        headers: { authorization: `Bearer ${target.token}` },
        signal: AbortSignal.timeout(SYNC_TIMEOUT_MS),
      });
      if (!res.ok) throw new Error(normalizePeerError(res.status, await res.text().catch(() => '')));
      const archive = (await res.json()) as BackupArchive;
      assertPortableSections(Object.keys(archive.data ?? {}));
      const dropped = filterExcludedSettings(archive, new Set(excludeKeys));
      report.sections = Object.keys(archive.data);
      const reports = await applyArchive(archive);
      report.tables = reports.flatMap((r) => r.tables);
      if (dropped > 0) report.warnings = [`${dropped} excluded setting key(s) filtered before applying`];
    }
  } catch (err) {
    const e = err as Error & { name?: string };
    report.status = 'error';
    report.error = e.name === 'TimeoutError' ? `Peer did not answer within ${SYNC_TIMEOUT_MS / 1000}s` : e.message;
  } finally {
    inFlightTargets.delete(targetId);
    await db.update(schema.replicationTargets)
      .set({ lastSyncAt: report.at, lastSyncStatus: report.status, lastError: report.error ?? null, lastReport: JSON.stringify(report) })
      .where(eq(schema.replicationTargets.id, targetId));
  }

  return report;
}

/** Finds enabled targets whose interval is due (for the scheduler worker). */
export async function findDueTargets(now = new Date()): Promise<ReplicationTargetRow[]> {
  const rows = await db.select().from(schema.replicationTargets);
  return rows.filter((t) => {
    if (!t.enabled || t.intervalMinutes == null) return false;
    if (!t.lastSyncAt) return true; // never synced → due immediately
    const last = Date.parse(t.lastSyncAt);
    if (Number.isNaN(last)) return true;
    return now.getTime() - last >= t.intervalMinutes * 60_000;
  });
}
