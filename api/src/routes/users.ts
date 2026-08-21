import { Router, Request, Response } from 'express';
import { eq } from 'drizzle-orm';
import { db, pool } from '../db';
import * as schema from '../db/schema';
import { requireAuth, requirePermission } from '../auth/middleware';
import { ALL_PERMISSIONS, PERMISSION_DESCRIPTIONS, KNOWN_ROLES } from '../auth/permissions';

const router = Router();

// GET /permissions — the canonical permission catalog (open to any
// authenticated user). Drives the role/permission checkboxes on the Users page.
router.get('/permissions', requireAuth, async (_req: Request, res: Response) => {
  res.status(200).json({
    permissions: ALL_PERMISSIONS.map((id) => ({ id, description: PERMISSION_DESCRIPTIONS[id] })),
    roles: KNOWN_ROLES,
  });
});

/** Public user shape — never exposes passwordHash or totpSecret. */
function serializeUser(row: typeof schema.users.$inferSelect) {
  let roles: string[] = [];
  let permissions: string[] = [];
  try {
    roles = JSON.parse(row.roles);
  } catch {
    /* keep [] */
  }
  try {
    permissions = JSON.parse(row.permissions);
  } catch {
    /* keep [] */
  }
  return {
    id: row.id,
    username: row.username,
    roles: Array.isArray(roles) ? roles : [],
    permissions: Array.isArray(permissions) ? permissions : [],
    createdAt: row.createdAt,
  };
}

/** Validates a `{ roles?, permissions? }` payload; returns values or an error. */
function validateUserUpdate(body: Record<string, unknown>) {
  const updates: { roles?: string[]; permissions?: string[] } = {};

  if (body.roles !== undefined) {
    if (!Array.isArray(body.roles) || body.roles.some((r) => typeof r !== 'string')) {
      return { error: '"roles" must be an array of strings' };
    }
    updates.roles = (body.roles as string[]).map((r) => r.trim()).filter(Boolean);
  }

  if (body.permissions !== undefined) {
    if (!Array.isArray(body.permissions) || body.permissions.some((p) => typeof p !== 'string')) {
      return { error: '"permissions" must be an array of strings' };
    }
    updates.permissions = (body.permissions as string[]).map((p) => p.trim()).filter(Boolean);
  }

  if (!updates.roles && !updates.permissions) {
    return { error: 'Provide at least one of: roles, permissions' };
  }
  return { values: updates };
}

// GET /users — list all users (requires users:read).
router.get('/users', requireAuth, requirePermission('users:read'), async (_req: Request, res: Response) => {
  const rows = await db.query.users.findMany({ orderBy: [schema.users.username] });
  res.status(200).json(rows.map(serializeUser));
});

// PATCH /users/:id — update roles/permissions (requires users:write).
router.patch('/users/:id', requireAuth, requirePermission('users:write'), async (req: Request, res: Response) => {
  const body = (req.body ?? {}) as Record<string, unknown>;
  const check = validateUserUpdate(body);
  if ('error' in check) {
    res.status(400).json({ error: check.error });
    return;
  }

  const existing = await db.query.users.findFirst({ where: eq(schema.users.id, req.params.id) });
  if (!existing) {
    res.status(404).json({ error: 'User not found' });
    return;
  }

  // Guard: never allow removing the admin role from the LAST admin.
  let currentRoles: string[] = [];
  try {
    currentRoles = JSON.parse(existing.roles);
  } catch {
    /* keep [] */
  }
  const losingAdmin =
    Array.isArray(currentRoles) &&
    currentRoles.includes('admin') &&
    check.values.roles !== undefined &&
    !check.values.roles.includes('admin');
  if (losingAdmin) {
    // Exact match on the JSON roles array (avoids false hits like "sub-admin").
    const adminCount = await pool.query(`SELECT COUNT(*)::int AS n FROM users WHERE roles::jsonb @> '["admin"]'`);
    const admins = Number(adminCount.rows[0]?.n ?? 0);
    if (admins <= 1) {
      res.status(409).json({ error: 'Cannot remove the last admin user. Promote another user to admin first.' });
      return;
    }
  }

  await db.update(schema.users).set({
    ...(check.values.roles !== undefined ? { roles: JSON.stringify(check.values.roles) } : {}),
    ...(check.values.permissions !== undefined
      ? { permissions: JSON.stringify(check.values.permissions) }
      : {}),
  }).where(eq(schema.users.id, req.params.id));

  const updated = await db.query.users.findFirst({ where: eq(schema.users.id, req.params.id) });
  if (!updated) {
    res.status(500).json({ error: 'Failed to retrieve updated user' });
    return;
  }
  res.status(200).json(serializeUser(updated));
});

// DELETE /users/:id — remove a user (requires users:write). Refuses self-delete
// and deleting the last admin.
router.delete('/users/:id', requireAuth, requirePermission('users:write'), async (req: Request, res: Response) => {
  const targetId = req.params.id;

  if (req.user?.sub && req.user.sub === targetId) {
    res.status(409).json({ error: 'You cannot delete your own account.' });
    return;
  }

  const existing = await db.query.users.findFirst({ where: eq(schema.users.id, targetId) });
  if (!existing) {
    res.status(404).json({ error: 'User not found' });
    return;
  }

  let roles: string[] = [];
  try {
    roles = JSON.parse(existing.roles);
  } catch {
    /* keep [] */
  }
  if (Array.isArray(roles) && roles.includes('admin')) {
    // Exact match on the JSON roles array (avoids false hits like "sub-admin").
    const adminCount = await pool.query(`SELECT COUNT(*)::int AS n FROM users WHERE roles::jsonb @> '["admin"]'`);
    const admins = Number(adminCount.rows[0]?.n ?? 0);
    if (admins <= 1) {
      res.status(409).json({ error: 'Cannot delete the last admin user. Promote another user to admin first.' });
      return;
    }
  }

  await db.delete(schema.users).where(eq(schema.users.id, targetId));
  res.status(204).send();
});

export default router;
