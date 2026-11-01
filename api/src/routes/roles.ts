import { Router, Request, Response } from 'express';
import { eq } from 'drizzle-orm';
import { db, pool } from '../db';
import * as schema from '../db/schema';
import { requireAuth, requirePermission } from '../auth/middleware';
import { ALL_PERMISSIONS } from '../auth/permissions';
import { parseDeviceScope, invalidateDeviceAccessCache } from '../deviceAccess';

const router = Router();

/** Public role shape. */
function serializeRole(row: typeof schema.roles.$inferSelect) {
  let permissions: string[] = [];
  try {
    permissions = JSON.parse(row.permissions);
  } catch {
    /* keep [] */
  }
  return {
    name: row.name,
    description: row.description ?? null,
    permissions: Array.isArray(permissions) ? permissions : [],
    deviceScope: parseDeviceScope(row.deviceScope),
    createdAt: row.createdAt,
  };
}

/** Validates a device-scope object ({siteIds?, tags?, deviceIds?} — arrays of non-empty strings). */
function validateDeviceScopeField(raw: unknown): { value?: Record<string, string[]>; error?: string } {
  if (raw === null) return { value: {} }; // explicit clear
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return { error: '"deviceScope" must be an object with optional siteIds/tags/deviceIds arrays' };
  }
  const out: Record<string, string[]> = {};
  for (const key of ['siteIds', 'tags', 'deviceIds'] as const) {
    if (!(key in raw)) continue;
    const arr = (raw as Record<string, unknown>)[key];
    if (!Array.isArray(arr) || arr.some((v) => typeof v !== 'string' || String(v).trim() === '')) {
      return { error: `"deviceScope.${key}" must be an array of non-empty strings` };
    }
    const cleaned = [...new Set((arr as string[]).map((s) => s.trim()))];
    if (cleaned.length > 0) out[key] = cleaned;
  }
  return { value: out };
}

/** Validates a role payload; returns values or an error message. */
function validateRolePayload(body: Record<string, unknown>, partial: boolean) {
  const values: { name?: string; description?: string | null; permissions?: string[]; deviceScope?: Record<string, string[]> } = {};

  if (body.name !== undefined || !partial) {
    if (typeof body.name !== 'string' || body.name.trim().length === 0) {
      return { error: '"name" is required and must be a non-empty string' };
    }
    values.name = body.name.trim();
  }

  if (body.description !== undefined) {
    if (body.description !== null && typeof body.description !== 'string') {
      return { error: '"description" must be a string or null' };
    }
    values.description = body.description === null ? null : String(body.description).trim() || null;
  }

  if (body.permissions !== undefined) {
    if (!Array.isArray(body.permissions) || body.permissions.some((p) => typeof p !== 'string')) {
      return { error: '"permissions" must be an array of permission ids' };
    }
    const cleaned = (body.permissions as string[]).map((p) => p.trim()).filter(Boolean);
    const unknown = cleaned.filter((p) => !ALL_PERMISSIONS.includes(p));
    if (unknown.length > 0) {
      return { error: `Unknown permission id(s): ${unknown.join(', ')}` };
    }
    values.permissions = [...new Set(cleaned)];
  }

  if (body.deviceScope !== undefined) {
    const ref = validateDeviceScopeField(body.deviceScope);
    if (ref.error) return { error: ref.error };
    values.deviceScope = ref.value!;
  }

  if (!values.name && values.description === undefined && !values.permissions && values.deviceScope === undefined) {
    return { error: 'Provide at least one of: name, description, permissions, deviceScope' };
  }
  return { values };
}

// GET /roles — list all roles (open to any authenticated user). Drives the
// role checkboxes on the Users page and the Roles management page.
router.get('/roles', requireAuth, async (_req: Request, res: Response) => {
  const rows = await db.query.roles.findMany({ orderBy: [schema.roles.name] });
  res.status(200).json(rows.map(serializeRole));
});

// POST /roles — create a role (requires users:write).
router.post('/roles', requireAuth, requirePermission('users:write'), async (req: Request, res: Response) => {
  const body = (req.body ?? {}) as Record<string, unknown>;
  const check = validateRolePayload(body, false);
  if ('error' in check) {
    res.status(400).json({ error: check.error });
    return;
  }

  const existing = await db.query.roles.findFirst({ where: eq(schema.roles.name, check.values.name!) });
  if (existing) {
    res.status(409).json({ error: `Role "${check.values.name}" already exists` });
    return;
  }

  await db.insert(schema.roles).values({
    name: check.values.name!,
    description: check.values.description ?? null,
    permissions: JSON.stringify(check.values.permissions ?? []),
    deviceScope: JSON.stringify(check.values.deviceScope ?? {}),
    createdAt: new Date().toISOString(),
  });

  const created = await db.query.roles.findFirst({ where: eq(schema.roles.name, check.values.name!) });
  res.status(201).json(serializeRole(created!));
});

// PATCH /roles/:name — update a role's description/permissions (requires users:write).
router.patch('/roles/:name', requireAuth, requirePermission('users:write'), async (req: Request, res: Response) => {
  const body = (req.body ?? {}) as Record<string, unknown>;
  const check = validateRolePayload(body, true);
  if ('error' in check) {
    res.status(400).json({ error: check.error });
    return;
  }

  const existing = await db.query.roles.findFirst({ where: eq(schema.roles.name, String(req.params.name ?? '')) });
  if (!existing) {
    res.status(404).json({ error: 'Role not found' });
    return;
  }

  await db.update(schema.roles).set({
    ...(check.values.description !== undefined ? { description: check.values.description } : {}),
    ...(check.values.permissions !== undefined
      ? { permissions: JSON.stringify(check.values.permissions) }
      : {}),
    ...(check.values.deviceScope !== undefined
      ? { deviceScope: JSON.stringify(check.values.deviceScope) }
      : {}),
  }).where(eq(schema.roles.name, String(req.params.name ?? '')));

  // Scope rules changed — drop the per-user allowed-id caches so members of
  // this role see the new scope immediately (not after the 5 s TTL).
  invalidateDeviceAccessCache();

  const updated = await db.query.roles.findFirst({ where: eq(schema.roles.name, String(req.params.name ?? '')) });
  res.status(200).json(serializeRole(updated!));
});

// DELETE /roles/:name — remove a role (requires users:write). The built-in
// `admin` role can never be deleted; other roles are refused while any user
// still carries them.
router.delete('/roles/:name', requireAuth, requirePermission('users:write'), async (req: Request, res: Response) => {
  const name = String(req.params.name ?? '');
  if (name === 'admin') {
    res.status(409).json({ error: 'The built-in admin role cannot be deleted.' });
    return;
  }

  const existing = await db.query.roles.findFirst({ where: eq(schema.roles.name, name) });
  if (!existing) {
    res.status(404).json({ error: 'Role not found' });
    return;
  }

  // Exact match on the JSON roles array (avoids false hits like "sub-admin").
  const usage = await pool.query('SELECT COUNT(*)::int AS n FROM users WHERE roles::jsonb @> $1', [
    JSON.stringify([name]),
  ]);
  const usedBy = Number(usage.rows[0]?.n ?? 0);
  if (usedBy > 0) {
    res.status(409).json({ error: `Role "${name}" is still assigned to ${usedBy} user(s). Remove it from them first.` });
    return;
  }

  await db.delete(schema.roles).where(eq(schema.roles.name, name));
  res.status(204).send();
});

/**
 * Computes a user's effective permission set: the union of their explicit
 * permissions and the permissions of every role they carry. Called when the
 * JWT is minted (routes/auth.ts) — unknown role names are ignored, so stale
 * role references never break login.
 */
export async function expandRolePermissions(roles: string[], explicit: string[]): Promise<string[]> {
  const effective = new Set(explicit);

  if (!Array.isArray(roles) || roles.length === 0) return [...effective];

  const rows = await db.query.roles.findMany({ where: (r, { inArray }) => inArray(r.name, roles) });
  for (const row of rows) {
    let perms: string[] = [];
    try {
      perms = JSON.parse(row.permissions);
    } catch {
      continue;
    }
    if (Array.isArray(perms)) {
      for (const p of perms) effective.add(p);
    }
  }
  return [...effective];
}

export default router;
