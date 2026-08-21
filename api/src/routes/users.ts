import { Router, Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import { v4 as uuidv4 } from 'uuid';
import { eq } from 'drizzle-orm';
import { db, pool } from '../db';
import * as schema from '../db/schema';
import { requireAuth, requirePermission } from '../auth/middleware';
import { generateSecret, buildOtpAuthUri } from '../auth/totp';
import { ALL_PERMISSIONS, PERMISSION_DESCRIPTIONS, KNOWN_ROLES, INITIAL_ADMIN_USERNAME } from '../auth/permissions';

const router = Router();

/** Minimum length for (re)set passwords. */
const MIN_PASSWORD_LENGTH = 8;

// GET /permissions — the canonical permission catalog + role definitions
// (open to any authenticated user). Drives the checkbox grids on the Users
// and Roles pages.
router.get('/permissions', requireAuth, async (_req: Request, res: Response) => {
  const roleRows = await db.query.roles.findMany({ orderBy: [schema.roles.name] });
  const roles = roleRows.map((row) => {
    let perms: string[] = [];
    try {
      perms = JSON.parse(row.permissions);
    } catch {
      /* keep [] */
    }
    return { name: row.name, description: row.description ?? null, permissions: Array.isArray(perms) ? perms : [] };
  });
  // Fallback so the UI still works if the roles table is somehow empty.
  if (roles.length === 0) {
    for (const name of KNOWN_ROLES) {
      roles.push({ name, description: null, permissions: [...ALL_PERMISSIONS] });
    }
  }

  res.status(200).json({
    permissions: ALL_PERMISSIONS.map((id) => ({ id, description: PERMISSION_DESCRIPTIONS[id] })),
    roles,
  });
});

/** Public user shape — never exposes passwordHash or totpSecret. */
export function serializeUser(row: typeof schema.users.$inferSelect) {
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
    // Whether a TOTP secret is enrolled (the secret itself never leaves the API).
    twoFactorEnabled: Boolean(row.totpSecret),
    createdAt: row.createdAt,
  };
}

/** Validates role/permission id arrays against the roles table + catalog. */
async function validateRoleAndPermissionIds(roles: string[], permissions: string[]) {
  const unknownPerms = permissions.filter((p) => !ALL_PERMISSIONS.includes(p));
  if (unknownPerms.length > 0) {
    return `Unknown permission id(s): ${unknownPerms.join(', ')}`;
  }
  if (roles.length > 0) {
    const rows = await db.query.roles.findMany();
    const known = new Set(rows.map((r) => r.name));
    const unknownRoles = roles.filter((r) => !known.has(r));
    if (unknownRoles.length > 0) {
      return `Unknown role(s): ${unknownRoles.join(', ')}`;
    }
  }
  return null;
}

/** TOTP enrollment payload returned to the UI for QR rendering. */
function enrollmentPayload(username: string, secret: string) {
  return { secret, otpauthUri: buildOtpAuthUri(username, secret) };
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

// POST /users — create a user (requires users:create). The new account is
// created with an initial password AND a fresh TOTP secret; the response
// carries the enrollment payload (secret + otpauth URI) so the UI can show a
// QR code for first-time authenticator-app setup.
router.post('/users', requireAuth, requirePermission('users:create'), async (req: Request, res: Response) => {
  const body = (req.body ?? {}) as Record<string, unknown>;

  if (typeof body.username !== 'string' || body.username.trim().length === 0) {
    res.status(400).json({ error: '"username" is required and must be a non-empty string' });
    return;
  }
  const username = body.username.trim();

  if (typeof body.password !== 'string' || body.password.length < MIN_PASSWORD_LENGTH) {
    res.status(400).json({ error: `"password" must be at least ${MIN_PASSWORD_LENGTH} characters` });
    return;
  }

  const roles = Array.isArray(body.roles) ? (body.roles as string[]).map((r) => String(r).trim()).filter(Boolean) : [];
  const permissions = Array.isArray(body.permissions)
    ? (body.permissions as string[]).map((p) => String(p).trim()).filter(Boolean)
    : [];

  const duplicate = await db.query.users.findFirst({ where: eq(schema.users.username, username) });
  if (duplicate) {
    res.status(409).json({ error: `Username "${username}" is already taken` });
    return;
  }

  const invalid = await validateRoleAndPermissionIds(roles, permissions);
  if (invalid) {
    res.status(400).json({ error: invalid });
    return;
  }

  const totpSecret = generateSecret();
  await db.insert(schema.users).values({
    id: uuidv4(),
    username,
    passwordHash: bcrypt.hashSync(body.password, 10),
    totpSecret,
    roles: JSON.stringify(roles),
    permissions: JSON.stringify(permissions),
    createdAt: new Date().toISOString(),
  });

  const created = await db.query.users.findFirst({ where: eq(schema.users.username, username) });
  res.status(201).json({ user: serializeUser(created!), enrollment: enrollmentPayload(username, totpSecret) });
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

  // Guard: the initial seeded admin can never be demoted (even if other admins exist).
  let currentRoles: string[] = [];
  try {
    currentRoles = JSON.parse(existing.roles);
  } catch {
    /* keep [] */
  }
  const isInitialAdmin = existing.username === INITIAL_ADMIN_USERNAME;
  if (isInitialAdmin && check.values.roles !== undefined && !check.values.roles.includes('admin')) {
    res.status(409).json({ error: `The initial admin user "${INITIAL_ADMIN_USERNAME}" cannot be demoted.` });
    return;
  }

  // Guard: never allow removing the admin role from the LAST admin.
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

  // Guard: the initial seeded admin can never be deleted (even if other admins exist).
  if (existing.username === INITIAL_ADMIN_USERNAME) {
    res.status(409).json({ error: `The initial admin user "${INITIAL_ADMIN_USERNAME}" cannot be deleted.` });
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

/**
 * Permission check for credential operations (password reset / TOTP) on a
 * target user. Self-operations need `users:self-credentials`; operating on
 * another user needs `users:manage-credentials`. Returns an error message or
 * null when access is granted.
 */
function checkCredentialAccess(req: Request, targetId: string): string | null {
  const perms = req.user?.permissions ?? [];
  if (req.user?.sub && req.user.sub === targetId) {
    return perms.includes('users:self-credentials') ? null : 'Missing required permission: users:self-credentials';
  }
  return perms.includes('users:manage-credentials')
    ? null
    : 'Missing required permission: users:manage-credentials';
}

// POST /users/:id/password — reset a user's password. Self (requires
// users:self-credentials) must prove the current password; resetting another
// user (requires users:manage-credentials) does not.
router.post('/users/:id/password', requireAuth, async (req: Request, res: Response) => {
  const denied = checkCredentialAccess(req, req.params.id);
  if (denied) {
    res.status(403).json({ error: denied });
    return;
  }

  const body = (req.body ?? {}) as Record<string, unknown>;
  if (typeof body.newPassword !== 'string' || body.newPassword.length < MIN_PASSWORD_LENGTH) {
    res.status(400).json({ error: `"newPassword" must be at least ${MIN_PASSWORD_LENGTH} characters` });
    return;
  }

  const existing = await db.query.users.findFirst({ where: eq(schema.users.id, req.params.id) });
  if (!existing) {
    res.status(404).json({ error: 'User not found' });
    return;
  }

  const isSelf = Boolean(req.user?.sub && req.user.sub === existing.id);
  if (isSelf) {
    if (typeof body.currentPassword !== 'string') {
      res.status(400).json({ error: '"currentPassword" is required when changing your own password' });
      return;
    }
    if (!bcrypt.compareSync(body.currentPassword, existing.passwordHash)) {
      res.status(401).json({ error: 'Current password is incorrect' });
      return;
    }
  }

  await db.update(schema.users)
    .set({ passwordHash: bcrypt.hashSync(body.newPassword, 10) })
    .where(eq(schema.users.id, existing.id));

  const updated = await db.query.users.findFirst({ where: eq(schema.users.id, existing.id) });
  res.status(200).json(serializeUser(updated!));
});

// POST /users/:id/totp/enroll — (re-)enroll TOTP for a user. Generates and
// persists a FRESH secret immediately; the response carries it plus an
// otpauth URI so the UI can render a QR code. Re-enrolling replaces any
// previous secret (old authenticator entries stop working).
router.post('/users/:id/totp/enroll', requireAuth, async (req: Request, res: Response) => {
  const denied = checkCredentialAccess(req, req.params.id);
  if (denied) {
    res.status(403).json({ error: denied });
    return;
  }

  const existing = await db.query.users.findFirst({ where: eq(schema.users.id, req.params.id) });
  if (!existing) {
    res.status(404).json({ error: 'User not found' });
    return;
  }

  const totpSecret = generateSecret();
  await db.update(schema.users)
    .set({ totpSecret })
    .where(eq(schema.users.id, existing.id));

  const updated = await db.query.users.findFirst({ where: eq(schema.users.id, existing.id) });
  res.status(200).json({ user: serializeUser(updated!), enrollment: enrollmentPayload(existing.username, totpSecret) });
});

// DELETE /users/:id/totp — disable TOTP for a user (clears the secret).
router.delete('/users/:id/totp', requireAuth, async (req: Request, res: Response) => {
  const denied = checkCredentialAccess(req, req.params.id);
  if (denied) {
    res.status(403).json({ error: denied });
    return;
  }

  const existing = await db.query.users.findFirst({ where: eq(schema.users.id, req.params.id) });
  if (!existing) {
    res.status(404).json({ error: 'User not found' });
    return;
  }

  await db.update(schema.users)
    .set({ totpSecret: null })
    .where(eq(schema.users.id, existing.id));
  res.status(204).send();
});

export default router;
