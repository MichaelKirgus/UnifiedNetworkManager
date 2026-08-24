import crypto from 'node:crypto';
import { eq } from 'drizzle-orm';
import { db } from '../db';
import * as schema from '../db/schema';
import { expandRolePermissions } from '../routes/roles';

/**
 * Long-lived API tokens for agents and scripts (MCP server, CI).
 *
 * A token is a bearer credential bound to ONE user. Its permission set is
 * fixed at creation time as an explicit list — or left empty, which means
 * "inherit the creator's full effective permissions". On every request the
 * granted set is intersected with the user's CURRENT effective permissions
 * (explicit + roles), so demoting a user immediately narrows their tokens
 * without needing to revoke them.
 *
 * The raw token value (`unm_…`) is returned exactly once at creation; only
 * its SHA-256 hash is stored, so a DB leak does not leak working credentials.
 */

const TOKEN_PREFIX = 'unm_';
/** Display prefix length (first chars of the raw value) for list views. */
const DISPLAY_PREFIX_LEN = 10;
/** Positive-resolution cache TTL — token lookups are per-request on hot paths. */
const RESOLVE_CACHE_TTL_MS = 30_000;
/** Throttle lastUsedAt writes to at most once per minute per token. */
const LAST_USED_THROTTLE_MS = 60_000;

export interface ApiTokenPayload {
  sub: string;
  username: string;
  roles: string[];
  permissions: string[];
  /** Distinguishes API-token sessions from JWT sessions (no TOTP possible). */
  amr: string[];
}

/** Public token row shape — never includes the hash. */
export interface ApiTokenView {
  id: string;
  userId: string;
  username?: string | null;
  label: string | null;
  tokenPrefix: string | null;
  permissions: string[];
  /** True when permissions is empty (inherit the user's full effective set). */
  inheritsAllPermissions: boolean;
  expiresAt: string | null;
  lastUsedAt: string | null;
  createdAt: string;
}

function parseJsonArray(raw: string): string[] {
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as unknown[]).filter((p): p is string => typeof p === 'string') : [];
  } catch {
    return [];
  }
}

function toView(row: typeof schema.apiTokens.$inferSelect, username?: string | null): ApiTokenView {
  const permissions = parseJsonArray(row.permissions);
  return {
    id: row.id,
    userId: row.userId,
    ...(username !== undefined ? { username } : {}),
    label: row.label ?? null,
    tokenPrefix: row.tokenPrefix ?? null,
    permissions,
    inheritsAllPermissions: permissions.length === 0,
    expiresAt: row.expiresAt,
    lastUsedAt: row.lastUsedAt,
    createdAt: row.createdAt,
  };
}

/** Creates a new token for the given user. Returns the raw value ONCE. */
export async function createApiToken(input: {
  userId: string;
  label?: string | null;
  /** Explicit permission grant (subset of the creator's effective set). Empty/omitted = inherit all. */
  permissions?: string[];
  /** ISO timestamp or null for no expiry. */
  expiresAt?: string | null;
}): Promise<{ rawToken: string } & ApiTokenView> {
  const user = await db.query.users.findFirst({
    where: (users, { eq }) => eq(users.id, input.userId),
  });
  if (!user) throw Object.assign(new Error('User not found'), { status: 404 });

  // Validate the requested grant against the creator's CURRENT effective set —
  // a token can never exceed what its creator has right now.
  const roles = parseJsonArray(user.roles);
  const explicit = parseJsonArray(user.permissions);
  const effective = new Set(await expandRolePermissions(roles, explicit));
  let granted: string[];
  if (input.permissions && input.permissions.length > 0) {
    for (const p of input.permissions) {
      if (!effective.has(p)) {
        throw Object.assign(new Error(`Cannot grant permission "${p}" — not in your effective permissions`), { status: 400 });
      }
    }
    granted = [...new Set(input.permissions)];
  } else {
    granted = []; // inherit-all marker
  }

  const rawToken = `${TOKEN_PREFIX}${crypto.randomBytes(32).toString('base64url')}`;
  const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
  const now = new Date().toISOString();

  await db.insert(schema.apiTokens).values({
    id: crypto.randomUUID(),
    userId: input.userId,
    label: input.label?.trim() || null,
    tokenHash,
    tokenPrefix: rawToken.slice(0, DISPLAY_PREFIX_LEN),
    permissions: JSON.stringify(granted),
    expiresAt: input.expiresAt ?? null,
    lastUsedAt: null,
    createdAt: now,
  });

  // Re-fetch by hash (the id was generated internally).
  const created = await db.query.apiTokens.findFirst({ where: eq(schema.apiTokens.tokenHash, tokenHash) });
  if (!created) throw new Error('Token creation failed');

  return { rawToken, ...toView(created, user.username) };
}

/** Lists tokens for a user (or all users when `all` is set). */
export async function listApiTokens(userId: string, opts?: { all?: boolean }): Promise<ApiTokenView[]> {
  const rows = await db.query.apiTokens.findMany({
    where: opts?.all ? undefined : eq(schema.apiTokens.userId, userId),
  });
  if (!opts?.all) return rows.map((r) => toView(r));

  // Enrich with usernames in one pass.
  const userRows = await db.query.users.findMany();
  const byId = new Map(userRows.map((u) => [u.id, u.username] as const));
  return rows.map((r) => toView(r, byId.get(r.userId) ?? null));
}

/** Revokes a token. Non-admins may only revoke their own tokens. */
export async function revokeApiToken(tokenId: string, requesterUserId: string, opts?: { admin?: boolean }): Promise<void> {
  const row = await db.query.apiTokens.findFirst({ where: eq(schema.apiTokens.id, tokenId) });
  if (!row) throw Object.assign(new Error('Token not found'), { status: 404 });
  if (!opts?.admin && row.userId !== requesterUserId) {
    throw Object.assign(new Error('Not your token'), { status: 403 });
  }
  await db.delete(schema.apiTokens).where(eq(schema.apiTokens.id, tokenId));
  invalidateApiTokenCache(row.tokenHash);
}

// --- Resolution (called from the auth middleware on every request) ----------

interface CachedResolution {
  payload: ApiTokenPayload | null;
  cachedAt: number;
}
const resolutionCache = new Map<string, CachedResolution>();

/**
 * Resolves a raw bearer token to an API-token payload, or null when it is not
 * a valid (non-expired) token. Positive AND negative results are cached briefly
 * so garbage tokens don't hit the DB on every request.
 */
export async function resolveApiTokenPayload(rawToken: string): Promise<ApiTokenPayload | null> {
  if (!rawToken.startsWith(TOKEN_PREFIX)) return null; // fast path — never a token

  const hash = crypto.createHash('sha256').update(rawToken).digest('hex');
  const now = Date.now();
  const cached = resolutionCache.get(hash);
  if (cached && now - cached.cachedAt < RESOLVE_CACHE_TTL_MS) return cached.payload;

  let payload: ApiTokenPayload | null = null;
  try {
    const row = await db.query.apiTokens.findFirst({ where: eq(schema.apiTokens.tokenHash, hash) });
    if (row && (!row.expiresAt || Date.parse(row.expiresAt) > now)) {
      const user = await db.query.users.findFirst({ where: eq(schema.users.id, row.userId) });
      if (user) {
        const roles = parseJsonArray(user.roles);
        const explicit = parseJsonArray(user.permissions);
        const effective = new Set(await expandRolePermissions(roles, explicit));
        const granted = parseJsonArray(row.permissions);
        // Empty grant list = inherit the user's full current effective set.
        const permissions = granted.length === 0 ? [...effective] : granted.filter((p) => effective.has(p));
        payload = {
          sub: user.id,
          username: user.username,
          roles,
          permissions,
          amr: ['token'],
        };

        // Throttled lastUsedAt update (fire-and-forget — never blocks auth).
        const lastUsed = row.lastUsedAt ? Date.parse(row.lastUsedAt) : 0;
        if (now - lastUsed > LAST_USED_THROTTLE_MS) {
          db.update(schema.apiTokens)
            .set({ lastUsedAt: new Date(now).toISOString() })
            .where(eq(schema.apiTokens.id, row.id))
            .catch(() => undefined);
        }
      }
    }
  } catch (err) {
    // eslint-disable-next-line no-console
    console.warn('[api-tokens] token resolution failed:', (err as Error).message);
  }

  if (resolutionCache.size > 512) resolutionCache.clear(); // unbounded-growth guard
  resolutionCache.set(hash, { payload, cachedAt: now });
  return payload;
}

/** Invalidates the resolution cache for a token hash (used on revocation). */
export function invalidateApiTokenCache(tokenHash?: string): void {
  if (tokenHash) resolutionCache.delete(tokenHash);
  else resolutionCache.clear();
}
