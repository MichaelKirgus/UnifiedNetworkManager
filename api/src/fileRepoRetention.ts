/**
 * File-repo retention lifecycle — policies that control how long repo files are kept.
 *
 * A RETENTION POLICY is a named template with optional matchers (category, name
 * regex) and two optional enforcement dimensions:
 *   - maxAgeDays          → delete files older than this many days
 *   - keepLatestPerDevice → per device key, keep only the newest N matching files
 *
 * Policies are ASSIGNED to files — never matched implicitly at sweep time. A
 * file whose `repo_files.retentionPolicyId` is NULL has NO policy and is kept
 * FOREVER (the worker only ever touches rows that carry a policy id). Files get
 * a policy three ways:
 *   1. explicitly in the UI / API (PATCH /files/:id/retention),
 *   2. automatically at plugin-upload time when the default-policy setting
 *      points at an enabled policy whose matchers fit the file (intent-created
 *      backups — see routes/files.ts POST /plugin/files),
 *   3. bulk backfill of existing files (POST /files/retention-policies/:id/apply).
 *
 * The hourly worker (workers/fileRepoRetention.ts) and the manual sweep route
 * both call `sweepFileRepoRetention()`, which deletes violators through
 * deleteRepoFile() — so bytes are removed from whichever file-repo provider
 * owns them (or the api-local volume), for every plugin with the `fileRepo`
 * capability. No SDK or plugin change is involved.
 */

import { randomUUID } from 'crypto';
import { asc, eq, isNotNull, isNull, sql } from 'drizzle-orm';
import { db } from './db';
import * as schema from './db/schema';
import { deleteRepoFile } from './fileRepo';
import { getEffectiveSettingValue, updateSetting } from './systemSettings';

/** One retention policy (the row shape the webapp consumes). */
export interface RetentionPolicy {
  id: string;
  name: string;
  description: string | null;
  /** Exact category slug this policy is meant for (null = any). */
  category: string | null;
  /** JS regex source matched against the file name (null = any). */
  namePattern: string | null;
  /** Delete files older than this many days (null/0 = no age limit). */
  maxAgeDays: number | null;
  /** Per device key, keep only the newest N matching files (null/0 = none). */
  keepLatestPerDevice: number | null;
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
  /** Number of repo files currently assigned to this policy (computed on list). */
  fileCount?: number;
}

/** Create/update payload for a retention policy. */
export interface RetentionPolicyInput {
  name: string;
  description?: string | null;
  category?: string | null;
  namePattern?: string | null;
  maxAgeDays?: number | null;
  keepLatestPerDevice?: number | null;
  enabled?: boolean;
}

/** Error carrying an HTTP status so routes can map it directly. */
export class RetentionError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

/** One policy's sweep outcome. */
export interface PolicySweepOutcome {
  policyId: string;
  name: string;
  deleted: number;
}

/** The result of one full retention sweep (worker or manual). */
export interface RetentionSweepResult {
  sweptAt: string;
  totalDeleted: number;
  perPolicy: PolicySweepOutcome[];
}

// ── Validation + normalization ───────────────────────────────────────────────

/** Validates a policy input and returns the normalized column values. */
function normalizeInput(input: RetentionPolicyInput): {
  name: string;
  description: string | null;
  category: string | null;
  namePattern: string | null;
  maxAgeDays: number | null;
  keepLatestPerDevice: number | null;
  enabled: boolean;
} {
  const name = (input.name ?? '').trim();
  if (!name) throw new RetentionError(400, 'name is required');
  if (name.length > 100) throw new RetentionError(400, 'name must be at most 100 characters');

  const description = input.description === undefined ? null : input.description?.trim() || null;
  if (description && description.length > 500) throw new RetentionError(400, 'description must be at most 500 characters');

  let category: string | null = null;
  if (input.category !== undefined && input.category !== null) {
    const c = String(input.category).trim().toLowerCase().replace(/[^a-z0-9\-_]+/g, '-').replace(/^-+|-+$/g, '');
    if (!c) throw new RetentionError(400, 'category must be a non-empty slug');
    category = c.slice(0, 40);
  }

  let namePattern: string | null = null;
  if (input.namePattern !== undefined && input.namePattern !== null) {
    const p = String(input.namePattern).trim();
    if (!p) throw new RetentionError(400, 'namePattern must be a non-empty regex');
    try {
      // eslint-disable-next-line no-new
      new RegExp(p);
    } catch (err) {
      throw new RetentionError(400, `invalid namePattern: ${(err as Error).message}`);
    }
    namePattern = p;
  }

  const maxAgeDays = input.maxAgeDays === undefined || input.maxAgeDays === null ? null : Number(input.maxAgeDays);
  if (maxAgeDays !== null && (!Number.isInteger(maxAgeDays) || maxAgeDays < 1)) {
    throw new RetentionError(400, 'maxAgeDays must be a positive integer or null');
  }

  const keepLatestPerDevice = input.keepLatestPerDevice === undefined || input.keepLatestPerDevice === null ? null : Number(input.keepLatestPerDevice);
  if (keepLatestPerDevice !== null && (!Number.isInteger(keepLatestPerDevice) || keepLatestPerDevice < 1)) {
    throw new RetentionError(400, 'keepLatestPerDevice must be a positive integer or null');
  }

  // A policy with no enforcement dimension would never delete anything.
  if (maxAgeDays === null && keepLatestPerDevice === null) {
    throw new RetentionError(400, 'at least one of maxAgeDays / keepLatestPerDevice is required');
  }

  return { name, description, category, namePattern, maxAgeDays, keepLatestPerDevice, enabled: input.enabled !== false };
}

function toPolicy(row: typeof schema.repoRetentionPolicies.$inferSelect): RetentionPolicy {
  return {
    id: row.id,
    name: row.name,
    description: row.description ?? null,
    category: row.category ?? null,
    namePattern: row.namePattern ?? null,
    maxAgeDays: row.maxAgeDays ?? null,
    keepLatestPerDevice: row.keepLatestPerDevice ?? null,
    enabled: !!row.enabled,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

// ── CRUD ─────────────────────────────────────────────────────────────────────

/** Lists all policies (name order) with the count of files assigned to each. */
export async function listRetentionPolicies(): Promise<RetentionPolicy[]> {
  const rows = await db.query.repoRetentionPolicies.findMany({ orderBy: [asc(schema.repoRetentionPolicies.name)] });
  const policies = rows.map(toPolicy);
  if (policies.length === 0) return policies;

  // One aggregate query for all file counts.
  const counts = await db
    .select({ policyId: schema.repoFiles.retentionPolicyId, n: sql<number>`count(*)` })
    .from(schema.repoFiles)
    .where(isNotNull(schema.repoFiles.retentionPolicyId))
    .groupBy(schema.repoFiles.retentionPolicyId);
  const byPolicy = new Map<string, number>();
  for (const c of counts) if (c.policyId) byPolicy.set(c.policyId, Number(c.n));
  for (const p of policies) p.fileCount = byPolicy.get(p.id) ?? 0;
  return policies;
}

/** Fetches one policy by id (null when absent). */
export async function getRetentionPolicy(id: string): Promise<RetentionPolicy | null> {
  const row = await db.query.repoRetentionPolicies.findFirst({ where: (t) => eq(t.id, id) });
  return row ? toPolicy(row) : null;
}

/** Creates a policy. 409 on duplicate name. */
export async function createRetentionPolicy(input: RetentionPolicyInput): Promise<RetentionPolicy> {
  const v = normalizeInput(input);
  const existing = await db.query.repoRetentionPolicies.findFirst({ where: (t) => eq(t.name, v.name) });
  if (existing) throw new RetentionError(409, `a retention policy named "${v.name}" already exists`);

  const id = randomUUID();
  const now = new Date().toISOString();
  await db.insert(schema.repoRetentionPolicies).values({
    id,
    name: v.name,
    description: v.description,
    category: v.category,
    namePattern: v.namePattern,
    maxAgeDays: v.maxAgeDays,
    keepLatestPerDevice: v.keepLatestPerDevice,
    enabled: v.enabled,
    createdAt: now,
    updatedAt: now,
  });
  const row = await db.query.repoRetentionPolicies.findFirst({ where: (t) => eq(t.id, id) });
  if (!row) throw new RetentionError(500, 'Policy vanished after insert');
  return toPolicy(row);
}

/** Updates a policy (partial). 404 when absent, 409 on duplicate name. */
export async function updateRetentionPolicy(id: string, input: Partial<RetentionPolicyInput>): Promise<RetentionPolicy> {
  const row = await db.query.repoRetentionPolicies.findFirst({ where: (t) => eq(t.id, id) });
  if (!row) throw new RetentionError(404, 'Retention policy not found');

  // Merge over the current values so "clear this field" works as null.
  const merged = normalizeInput({
    name: input.name ?? row.name,
    description: input.description === undefined ? row.description : input.description,
    category: input.category === undefined ? row.category : input.category,
    namePattern: input.namePattern === undefined ? row.namePattern : input.namePattern,
    maxAgeDays: input.maxAgeDays === undefined ? row.maxAgeDays : input.maxAgeDays,
    keepLatestPerDevice: input.keepLatestPerDevice === undefined ? row.keepLatestPerDevice : input.keepLatestPerDevice,
    enabled: input.enabled ?? !!row.enabled,
  });

  if (merged.name !== row.name) {
    const clash = await db.query.repoRetentionPolicies.findFirst({ where: (t) => eq(t.name, merged.name) });
    if (clash && clash.id !== id) throw new RetentionError(409, `a retention policy named "${merged.name}" already exists`);
  }

  await db.update(schema.repoRetentionPolicies).set({ ...merged, updatedAt: new Date().toISOString() }).where(eq(schema.repoRetentionPolicies.id, id));
  const updated = await db.query.repoRetentionPolicies.findFirst({ where: (t) => eq(t.id, id) });
  if (!updated) throw new RetentionError(404, 'Retention policy not found');
  return toPolicy(updated);
}

/**
 * Deletes a policy. Its files are UNASSIGNED first (they become "no policy →
 * kept forever" — never deleted by the act of removing their template), and the
 * default-policy setting is cleared when it pointed at this policy.
 */
export async function deleteRetentionPolicy(id: string): Promise<void> {
  const row = await db.query.repoRetentionPolicies.findFirst({ where: (t) => eq(t.id, id) });
  if (!row) throw new RetentionError(404, 'Retention policy not found');

  // Unassign — the files stay, they just lose their lifetime rule.
  await db.update(schema.repoFiles).set({ retentionPolicyId: null }).where(eq(schema.repoFiles.retentionPolicyId, id));

  await db.delete(schema.repoRetentionPolicies).where(eq(schema.repoRetentionPolicies.id, id));

  // Clear the default pointer if it referenced this policy (best-effort — a
  // settings write failure must not fail the delete itself).
  try {
    const current = String((await getEffectiveSettingValue('fileRepoDefaultRetentionPolicyId')) ?? '');
    if (current === id) await updateSetting('fileRepoDefaultRetentionPolicyId', '');
  } catch { /* best-effort */ }
}

// ── Assignment ───────────────────────────────────────────────────────────────

/** True when the policy's matchers fit a file (category exact, name regex). */
export function policyMatches(policy: Pick<RetentionPolicy, 'category' | 'namePattern'>, file: { name: string; category: string }): boolean {
  if (policy.category && policy.category !== file.category) return false;
  if (policy.namePattern) {
    try {
      if (!new RegExp(policy.namePattern).test(file.name)) return false;
    } catch { /* malformed stored pattern → no match, never throw */ }
  }
  return true;
}

/**
 * Resolves the default policy for a freshly uploaded file (plugin/intent
 * uploads only — see routes/files.ts). Returns null when no default is set, it
 * points at a missing/disabled policy, or the policy's matchers don't fit.
 */
export async function resolveDefaultPolicyId(name: string, category: string): Promise<string | null> {
  const raw = await getEffectiveSettingValue('fileRepoDefaultRetentionPolicyId');
  const id = typeof raw === 'string' ? raw.trim() : '';
  if (!id) return null;
  const policy = await getRetentionPolicy(id);
  if (!policy || !policy.enabled) return null;
  return policyMatches(policy, { name, category }) ? id : null;
}

/** Assigns (or clears, with null) the retention policy of one file. */
export async function setFileRetentionPolicy(fileId: string, policyId: string | null): Promise<void> {
  const row = await db.query.repoFiles.findFirst({ where: (t) => eq(t.id, fileId) });
  if (!row) throw new RetentionError(404, 'File not found');
  if (policyId !== null && !(await getRetentionPolicy(policyId))) {
    throw new RetentionError(404, `Retention policy ${policyId} not found`);
  }
  await db.update(schema.repoFiles).set({ retentionPolicyId: policyId }).where(eq(schema.repoFiles.id, fileId));
}

/**
 * Bulk-assigns a policy to currently UNASSIGNED files that match. The effective
 * matchers are the request overrides (when given) falling back to the policy's
 * own — at least one matcher must be effective so an any/any policy can never
 * silently claim the whole repo in one click.
 */
export async function applyPolicyToMatching(
  policyId: string,
  override?: { category?: string | null; namePattern?: string | null }
): Promise<{ assigned: number }> {
  const policy = await getRetentionPolicy(policyId);
  if (!policy) throw new RetentionError(404, 'Retention policy not found');

  const category = override?.category !== undefined ? (override.category ?? null) : policy.category;
  const namePattern = override?.namePattern !== undefined ? (override.namePattern ?? null) : policy.namePattern;
  if (!category && !namePattern) {
    throw new RetentionError(400, 'this policy has no matchers — pass category or namePattern to bound the backfill');
  }

  const rows = await db.query.repoFiles.findMany({ where: (t) => isNull(t.retentionPolicyId) });
  let assigned = 0;
  for (const f of rows) {
    if (!policyMatches({ category, namePattern }, { name: f.name, category: f.category })) continue;
    await db.update(schema.repoFiles).set({ retentionPolicyId: policyId }).where(eq(schema.repoFiles.id, f.id));
    assigned++;
  }
  return { assigned };
}

// ── Sweep ────────────────────────────────────────────────────────────────────

/**
 * Device key for keepLatestPerDevice grouping. The SDK config-backup convention
 * is `<device>__config-backup-<UTC-ts>.<ext>` — the part before the first `__`
 * IS the device. Anything else groups by full name minus its last extension, so
 * e.g. repeated uploads of "debian-12.iso" (with -1/-2 suffixes) stay one group.
 */
export function deviceKeyFor(name: string): string {
  const base = (name ?? '').trim();
  if (!base) return 'unknown';
  const i = base.indexOf('__');
  if (i > 0) return base.slice(0, i);
  const dot = base.lastIndexOf('.');
  return dot > 1 ? base.slice(0, dot) : base;
}

/**
 * Runs one full retention sweep: for every ENABLED policy with at least one
 * enforcement dimension, deletes the assigned files that violate it (age and/or
 * per-device count — union of both). Deletion goes through deleteRepoFile(), so
 * provider-backed bytes are removed from the owning file-repo plugin. Never
 * throws on individual file failures — a stuck blob must not wedge the sweep.
 */
export async function sweepFileRepoRetention(): Promise<RetentionSweepResult> {
  const policies = await db.query.repoRetentionPolicies.findMany({ where: (t) => eq(t.enabled, true) });
  const perPolicy: PolicySweepOutcome[] = [];
  let totalDeleted = 0;

  for (const pol of policies) {
    const maxAgeDays = pol.maxAgeDays ?? 0;
    const keepN = pol.keepLatestPerDevice ?? 0;
    if (maxAgeDays <= 0 && keepN <= 0) continue; // nothing to enforce

    const files = await db.query.repoFiles.findMany({ where: (t) => eq(t.retentionPolicyId, pol.id) });
    if (files.length === 0) {
      perPolicy.push({ policyId: pol.id, name: pol.name, deleted: 0 });
      continue;
    }

    const toDelete = new Set<string>();

    // Age dimension — ISO-8601 strings compare lexicographically.
    if (maxAgeDays > 0) {
      const cutoff = new Date(Date.now() - maxAgeDays * 24 * 60 * 60 * 1000).toISOString();
      for (const f of files) if (f.createdAt < cutoff) toDelete.add(f.id);
    }

    // Count dimension — newest N per device key survive, the rest go.
    if (keepN > 0) {
      const groups = new Map<string, Array<typeof files[number]>>();
      for (const f of [...files].sort((a, b) => b.createdAt.localeCompare(a.createdAt))) {
        const k = deviceKeyFor(f.name);
        const g = groups.get(k);
        if (g) g.push(f);
        else groups.set(k, [f]);
      }
      for (const group of groups.values()) {
        for (let i = keepN; i < group.length; i++) toDelete.add(group[i].id);
      }
    }

    let deleted = 0;
    for (const id of toDelete) {
      try {
        await deleteRepoFile(id);
        deleted++;
      } catch { /* tolerate — orphaned blobs are harmless, row stays for retry */ }
    }
    totalDeleted += deleted;
    perPolicy.push({ policyId: pol.id, name: pol.name, deleted });

    if (deleted > 0) {
      // eslint-disable-next-line no-console
      console.log(`[file-retention] policy "${pol.name}" removed ${deleted} expired file(s)`);
    }
  }

  return { sweptAt: new Date().toISOString(), totalDeleted, perPolicy };
}
