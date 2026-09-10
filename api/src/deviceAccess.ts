import type { Request } from 'express';
import { eq, inArray } from 'drizzle-orm';
import { db } from './db';
import * as schema from './db/schema';

/**
 * Device-level access control.
 *
 * Users and roles can carry a `deviceScope` (JSON: `{siteIds?, tags?, deviceIds?}`).
 * A caller may see a device when it matches ANY of their effective rules — the
 * union of their own scope and the scopes of every role they hold. Callers whose
 * effective permissions include `devices:all` bypass scoping entirely (the built-in
 * admin role carries it; it is backfilled additively to all pre-existing users and
 * roles, so removing it is what activates an account's restrictions).
 *
 * PERFORMANCE MODEL — no per-request permission queries:
 *   - The devices table is snapshotted into memory (id + siteId + tags only) and
 *     refreshed at most once every SNAPSHOT_TTL_MS per process.
 *   - Each user's resolved allowed-id set is cached for ALLOWED_CACHE_TTL_MS, so a
 *     hot request costs one Map lookup plus an O(devices) in-memory scan.
 *   - Scope rules are resolved LIVE from the DB (not frozen into JWTs), mirroring
 *     the require2FA policy pattern: admin edits to users/roles apply to ALL
 *     existing sessions and API tokens within ~5 s — no re-login, no revocation.
 *   - Device mutations call invalidateDeviceAccessCache() so tag/site changes are
 *     picked up immediately instead of waiting out the TTLs.
 *
 * FAIL-CLOSED: any lookup error yields an EMPTY allowed set (scoped callers see
 * nothing) rather than a crash or an accidental grant; unrestricted callers never
 * touch the DB at all.
 */

/** Device-scope rules as stored on users.deviceScope / roles.deviceScope. */
export interface DeviceScope {
  /** Visible devices assigned to any of these site ids (devices.siteId). */
  siteIds?: string[];
  /** Visible devices carrying ANY of these tags (intersection with device tags). */
  tags?: string[];
  /** Explicitly visible device ids. */
  deviceIds?: string[];
}

/** Permission that bypasses all device-scope checks. */
export const UNRESTRICTED_PERMISSION = 'devices:all';

/** How often the in-memory devices snapshot may be stale (per process). */
const SNAPSHOT_TTL_MS = 5_000;
/** How long a user's resolved allowed-id set stays cached. */
const ALLOWED_CACHE_TTL_MS = 5_000;

interface DeviceRowLite {
  id: string;
  siteId: string | null;
  tags: string[];
}

interface SnapshotEntry {
  rows: DeviceRowLite[];
  cachedAt: number;
}
let deviceSnapshot: SnapshotEntry | null = null;

const allowedCache = new Map<string, { ids: Set<string>; cachedAt: number }>();

/** Coerce a stored JSON string array into a clean string[] (defensive). */
function parseStringArray(raw: unknown): string[] {
  let value: unknown = raw;
  if (typeof raw === 'string') {
    try {
      value = JSON.parse(raw);
    } catch {
      return [];
    }
  }
  if (!Array.isArray(value)) return [];
  const seen = new Set<string>();
  for (const entry of value) {
    if (typeof entry === 'string' && entry.length > 0) seen.add(entry);
  }
  return [...seen];
}

/** Coerce unknown JSON into a clean DeviceScope (defensive against corrupt rows). */
export function parseDeviceScope(raw: unknown): DeviceScope {
  let obj: unknown = raw;
  if (typeof raw === 'string') {
    try {
      obj = JSON.parse(raw);
    } catch {
      return {};
    }
  }
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return {};

  const clean = (value: unknown): string[] => {
    if (!Array.isArray(value)) return [];
    const seen = new Set<string>();
    for (const entry of value) {
      if (typeof entry === 'string' && entry.length > 0) seen.add(entry);
    }
    return [...seen];
  };

  const record = obj as Record<string, unknown>;
  const scope: DeviceScope = {};
  const siteIds = clean(record.siteIds);
  const tags = clean(record.tags);
  const deviceIds = clean(record.deviceIds);
  if (siteIds.length > 0) scope.siteIds = siteIds;
  if (tags.length > 0) scope.tags = tags;
  if (deviceIds.length > 0) scope.deviceIds = deviceIds;
  return scope;
}

/** True when a scope carries no rules at all (= unrestricted on its own). */
export function isScopeEmpty(scope: DeviceScope): boolean {
  return (
    (scope.siteIds?.length ?? 0) === 0 &&
    (scope.tags?.length ?? 0) === 0 &&
    (scope.deviceIds?.length ?? 0) === 0
  );
}

/** Union of several scopes (deduped, order-stable). */
export function mergeDeviceScopes(scopes: DeviceScope[]): DeviceScope {
  const merged: DeviceScope = {};
  for (const scope of scopes) {
    if (!scope || typeof scope !== 'object') continue;
    for (const key of ['siteIds', 'tags', 'deviceIds'] as const) {
      const values = scope[key];
      if (!Array.isArray(values)) continue;
      merged[key] ??= [];
      for (const v of values) {
        if (typeof v === 'string' && !merged[key]!.includes(v)) merged[key]!.push(v);
      }
    }
  }
  return merged;
}

/** True when the caller bypasses device scoping entirely. */
export function isUnrestricted(req: Request): boolean {
  return (req.user?.permissions ?? []).includes(UNRESTRICTED_PERMISSION);
}

/** In-memory snapshot of all devices (id + siteId + tags), TTL-gated. */
async function getDeviceSnapshot(): Promise<DeviceRowLite[]> {
  const now = Date.now();
  if (deviceSnapshot && now - deviceSnapshot.cachedAt < SNAPSHOT_TTL_MS) return deviceSnapshot.rows;

  const rows = await db.query.devices.findMany({
    columns: { id: true, siteId: true, tags: true },
  });
  deviceSnapshot = {
    rows: rows.map((r) => ({ id: r.id, siteId: r.siteId, tags: parseStringArray(r.tags) })),
    cachedAt: now,
  };
  return deviceSnapshot.rows;
}

/** Effective scope for a user = their own rules ∪ every role's rules. */
async function resolveEffectiveScope(userId: string): Promise<DeviceScope> {
  const user = await db.query.users.findFirst({ where: eq(schema.users.id, userId) });
  if (!user) return {}; // deleted account — nothing visible (auth rejects it anyway)

  let roleNames: string[] = [];
  try {
    const parsed: unknown = JSON.parse(user.roles);
    if (Array.isArray(parsed)) roleNames = parsed.filter((r): r is string => typeof r === 'string');
  } catch {
    /* corrupt roles column — treat as none */
  }

  const scopes: DeviceScope[] = [parseDeviceScope(user.deviceScope)];
  if (roleNames.length > 0) {
    const roleRows = await db.query.roles.findMany({
      where: inArray(schema.roles.name, roleNames),
      columns: { deviceScope: true },
    });
    for (const row of roleRows) scopes.push(parseDeviceScope(row.deviceScope));
  }
  return mergeDeviceScopes(scopes);
}

/**
 * Resolves the set of device ids the caller may access.
 *   - `null`  → unrestricted (devices:all — see every device).
 *   - `Set`   → exactly these ids (may be empty = sees nothing).
 * Never throws; lookup failures fail closed to an empty set.
 */
export async function allowedDeviceIds(req: Request): Promise<Set<string> | null> {
  if (isUnrestricted(req)) return null;

  const userId = req.user?.sub;
  if (!userId) return new Set(); // unauthenticated — fail closed

  try {
    const now = Date.now();
    const cached = allowedCache.get(userId);
    if (cached && now - cached.cachedAt < ALLOWED_CACHE_TTL_MS) return cached.ids;

    const scope = await resolveEffectiveScope(userId);
    const rows = await getDeviceSnapshot();

    // No rules at all → unrestricted by convention ('{}' is the column default,
    // so pre-feature accounts keep full visibility even without devices:all).
    if (isScopeEmpty(scope)) return null;

    const siteSet = new Set(scope.siteIds ?? []);
    const tagSet = new Set(scope.tags ?? []);
    const idSet = new Set<string>(scope.deviceIds ?? []);
    for (const row of rows) {
      if ((row.siteId !== null && siteSet.has(row.siteId)) || row.tags.some((t) => tagSet.has(t))) {
        idSet.add(row.id);
      }
    }

    const entry = { ids: idSet, cachedAt: now };
    allowedCache.set(userId, entry);
    if (allowedCache.size > 512) allowedCache.clear(); // unbounded-growth guard
    return idSet;
  } catch (err) {
    // eslint-disable-next-line no-console
    console.warn('[device-access] scope resolution failed — failing closed:', (err as Error).message);
    return new Set();
  }
}

/** True when the caller may access the given device. */
export async function canAccessDevice(req: Request, deviceId: string): Promise<boolean> {
  const allowed = await allowedDeviceIds(req);
  return allowed === null || allowed.has(deviceId);
}

/** Filters rows carrying a `deviceId` down to what the caller may see. */
export async function filterByDeviceScope<T extends { deviceId: string }>(
  rows: readonly T[],
  req: Request
): Promise<T[]> {
  const allowed = await allowedDeviceIds(req);
  if (allowed === null) return [...rows];
  return rows.filter((row) => allowed.has(row.deviceId));
}

/** Drops the snapshot + all per-user caches. Call after device mutations. */
export function invalidateDeviceAccessCache(): void {
  deviceSnapshot = null;
  allowedCache.clear();
}
