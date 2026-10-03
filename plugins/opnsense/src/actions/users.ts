/**
 * Local user management for OPNsense — the audit gap fill (RouterOS parity).
 *
 * Version-aware: 26.x moved users to the MVC Auth controller (`/api/auth/user/*`);
 * older firmware serves them at `/api/core/user/*`. Both expose the same row
 * shape (uuid, uid, name, disabled, scope, shell, group_memberships, …), so one
 * parser covers both — the client probes which base responds and caches it per
 * action run. Verified live on 26.4.x: search works with a READONLY key; add/
 * set/del require write ACL (the controller's throwReadOnly gates only some
 * endpoints, but user writes need the `page-all`/usermanager ACL in practice).
 */

import { get, post, OpnsenseApiResult } from '../client/http';
import type { ActionContext, ActionDescriptor, ActionResult } from './types';

/** One local user row (both API generations share this shape). */
export interface OpnsenseUserRow {
  uuid: string;
  uid?: number | string;
  name: string;
  disabled?: boolean | '0' | '1';
  scope?: string; // system | ldap | radius …
  shell?: string;
  groupMemberships?: string[];
  isAdmin?: boolean;
  expires?: string | null;
}

/** Normalizes a raw search row (both generations) into the shared shape. */
export function parseUserRow(raw: Record<string, unknown>): OpnsenseUserRow {
  const groups = raw['group_memberships'];
  return {
    uuid: String(raw['uuid'] ?? ''),
    uid: typeof raw['uid'] === 'number' ? raw['uid'] : (typeof raw['uid'] === 'string' && raw['uid'] !== '' ? Number(raw['uid']) || undefined : undefined),
    name: String(raw['name'] ?? ''),
    disabled: raw['disabled'] === true || raw['disabled'] === '1' ? true : raw['disabled'] === false || raw['disabled'] === '0' ? false : undefined,
    scope: typeof raw['scope'] === 'string' && raw['scope'] !== '' ? raw['scope'] : undefined,
    shell: typeof raw['shell'] === 'string' && raw['shell'] !== '' ? raw['shell'] : undefined,
    groupMemberships: Array.isArray(groups) ? groups.map(String) : (typeof groups === 'string' && groups !== '' ? groups.split(',').map((g) => g.trim()).filter(Boolean) : undefined),
    isAdmin: raw['is_admin'] === '1' || raw['is_admin'] === 1,
    expires: typeof raw['expires'] === 'string' && raw['expires'] !== '' ? raw['expires'] : null,
  };
}

/**
 * Resolves the user API base for this appliance — `/api/auth/user` (26.x MVC) or
 * `/api/core/user` (legacy). Probes search on both; caches per host in-process.
 */
const apiBaseCache = new Map<string, string>();
async function resolveUserApiBase(ctx: ActionContext): Promise<{ base: string } | { error: string }> {
  const cached = apiBaseCache.get(ctx.host);
  if (cached) return { base: cached };
  for (const candidate of ['/api/auth/user', '/api/core/user']) {
    const res = await get<Record<string, unknown>>(ctx.client, `${candidate}/search`, { rowCount: 1 });
    if (res.ok && Array.isArray((res.data as Record<string, unknown>)['rows'])) {
      apiBaseCache.set(ctx.host, candidate);
      return { base: candidate };
    }
  }
  return { error: 'Could not locate the user API — neither /api/auth/user/search (26.x) nor /api/core/user/search (legacy) responded.' };
}

/** GET <base>/search → normalized rows. */
async function searchUsers(ctx: ActionContext, base: string): Promise<OpnsenseUserRow[]> {
  const res = await get<{ rows?: Record<string, unknown>[] }>(ctx.client, `${base}/search`, { rowCount: 500 });
  if (!res.ok || !Array.isArray(res.data?.rows)) return [];
  return res.data.rows.map(parseUserRow);
}

// --- system.users.read -----------------------------------------------------------------

const systemUsersRead: ActionDescriptor = {
  id: 'system.users.read',
  label: 'Read local users',
  description:
    "Lists the appliance's user accounts (version-aware: /api/auth/user on 26.x, /api/core/user on older firmware) — name, uid, scope, disabled state, shell and group memberships. Passwords are never returned. Works with a readonly API key.",
  module: 'System',
  riskLevel: 'read',
  deviceCount: 1,
  timeoutMs: 30_000,
  inputSchema: {},
  async execute(ctx): Promise<ActionResult> {
    const resolved = await resolveUserApiBase(ctx);
    if ('error' in resolved) return { success: false, error: resolved.error };
    const users = (await searchUsers(ctx, resolved.base)).filter((u) => u.scope === 'system');
    return { success: true, details: { count: users.length, users } };
  },
};

// --- system.user.add --------------------------------------------------------------------

const systemUserAdd: ActionDescriptor = {
  id: 'system.user.add',
  label: 'Create or update a local user',
  description:
    "Creates a local (scope=system) user — idempotent by name: an existing user is updated in place. The password is set on create and re-set when provided on update; omit it to leave the current password untouched. Requires write ACL on the API key.",
  module: 'System',
  riskLevel: 'write',
  deviceCount: 1,
  timeoutMs: 30_000,
  inputSchema: {
    name: { type: 'string', required: true, minLength: 2, maxLength: 64, description: 'Username' },
    password: { type: 'string', minLength: 1, maxLength: 256, description: 'Password (set on create; re-set on update when provided)' },
    disabled: { type: 'boolean', description: 'Create the user in a disabled state' },
    shell: { type: 'string', description: "Login shell (default '/usr/sbin/nologin')" },
  },
  async execute(ctx, input): Promise<ActionResult> {
    const name = String(input.name ?? '').trim();
    if (!/^[A-Za-z0-9][A-Za-z0-9._@-]*$/.test(name)) return { success: false, error: `Invalid username "${name}".` };

    const resolved = await resolveUserApiBase(ctx);
    if ('error' in resolved) return { success: false, error: resolved.error };
    const base = resolved.base;

    const users = await searchUsers(ctx, base);
    const existing = users.find((u) => u.name === name && u.scope === 'system');

    const body: Record<string, unknown> = { name, scope: 'system' };
    if (typeof input.password === 'string' && input.password.length > 0) body['password'] = input.password;
    if (input.disabled !== undefined) body['disabled'] = input.disabled ? '1' : '0';
    if (typeof input.shell === 'string' && input.shell.trim()) body['shell'] = input.shell.trim();

    let result: OpnsenseApiResult<{ result?: string }>;
    try {
      if (existing) {
        result = await post(ctx.client, `${base}/set/${encodeURIComponent(existing.uuid)}`, { user: body });
      } else {
        result = await post(ctx.client, `${base}/add`, { user: body });
      }
    } catch (e) {
      return { success: false, error: `User API call failed: ${e instanceof Error ? e.message : String(e)}` };
    }
    if (!result.ok || result.data?.result !== 'saved') {
      const msg = typeof result.data === 'object' && result.data !== null && 'error' in (result.data as Record<string, unknown>)
        ? String((result.data as Record<string, unknown>)['error']) : `HTTP ${result.status}`;
      return { success: false, error: `Saving user "${name}" failed (${msg}) — the API key likely lacks write ACL for user management.` };
    }

    const after = (await searchUsers(ctx, base)).find((u) => u.name === name && u.scope === 'system');
    if (!after) return { success: false, error: `Verification failed — user "${name}" not present after save.` };
    return { success: true, applied: true, verified: true, details: existing ? { updated: name } : { created: name }, };
  },
};

// --- system.user.delete ------------------------------------------------------------------

const systemUserDelete: ActionDescriptor = {
  id: 'system.user.delete',
  label: 'Delete a local user',
  description:
    "Removes a local (scope=system) user by name. Idempotent — an unknown name is a no-op. Refuses to delete the only enabled admin account (that would lock you out). Requires write ACL on the API key.",
  module: 'System',
  riskLevel: 'write',
  deviceCount: 1,
  timeoutMs: 30_000,
  inputSchema: {
    name: { type: 'string', required: true, minLength: 2, maxLength: 64, description: 'Username to remove' },
  },
  async execute(ctx, input): Promise<ActionResult> {
    const name = String(input.name ?? '').trim();

    const resolved = await resolveUserApiBase(ctx);
    if ('error' in resolved) return { success: false, error: resolved.error };
    const base = resolved.base;

    const users = await searchUsers(ctx, base);
    const target = users.find((u) => u.name === name && u.scope === 'system');
    if (!target) return { success: true, applied: false, verified: true, details: { skipped: `no local user named "${name}"` } };

    // Lockout guard — never remove the last enabled admin.
    const otherAdmins = users.filter((u) => u.scope === 'system' && u.isAdmin && !u.disabled && u.name !== name);
    if (target.isAdmin && otherAdmins.length === 0) {
      return { success: false, error: `Refusing to delete "${name}" — it is the only enabled admin account. Create another admin first.` };
    }

    try {
      const result = await post<{ result?: string }>(ctx.client, `${base}/del/${encodeURIComponent(target.uuid)}`, {});
      if (!result.ok || result.data?.result !== 'deleted') {
        return { success: false, error: `Deleting user "${name}" failed (HTTP ${result.status}) — the API key likely lacks write ACL.` };
      }
    } catch (e) {
      return { success: false, error: `User delete call failed: ${e instanceof Error ? e.message : String(e)}` };
    }

    const after = (await searchUsers(ctx, base)).find((u) => u.name === name && u.scope === 'system');
    if (after) return { success: false, error: `Verification failed — user "${name}" still present.` };
    return { success: true, applied: true, verified: true, details: { deleted: name } };
  },
};

export const userActions: ActionDescriptor[] = [systemUsersRead, systemUserAdd, systemUserDelete];
