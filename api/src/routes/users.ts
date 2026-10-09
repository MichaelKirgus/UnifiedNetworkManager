import { Router, Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import { v4 as uuidv4 } from 'uuid';
import { and, eq } from 'drizzle-orm';
import { db, pool } from '../db';
import * as schema from '../db/schema';
import { requireAuth, requirePermission } from '../auth/middleware';
import { generateSecret, buildOtpAuthUri, verifyTotp } from '../auth/totp';
import { buildRegistrationOptions, verifyRegistration } from '../auth/webauthn';
import { ALL_PERMISSIONS, PERMISSION_DESCRIPTIONS, KNOWN_ROLES, INITIAL_ADMIN_USERNAME } from '../auth/permissions';
import { parseDeviceScope, invalidateDeviceAccessCache } from '../deviceAccess';
import { resolveCredentialPolicy, getGlobalPolicy, effectiveMinPasswordLength } from '../auth/credentialPolicy';

const router = Router();

/** Built-in floor for (re)set passwords when a policy leaves the minimum unset. */
const MIN_PASSWORD_LENGTH = 8;

/** The effective minimum length for a NEW user — only the global default applies. */
async function minLenForNewUser(): Promise<number> {
  try {
    return effectiveMinPasswordLength(await getGlobalPolicy());
  } catch {
    return MIN_PASSWORD_LENGTH;
  }
}

/** The effective minimum length for a TARGET user (per-user override merged onto global). */
async function minLenForUser(userId: string): Promise<number> {
  try {
    return effectiveMinPasswordLength(await resolveCredentialPolicy(userId));
  } catch {
    return MIN_PASSWORD_LENGTH;
  }
}

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
    return { name: row.name, description: row.description ?? null, permissions: Array.isArray(perms) ? perms : [], deviceScope: parseDeviceScope(row.deviceScope) };
  });
  // Fallback so the UI still works if the roles table is somehow empty.
  if (roles.length === 0) {
    for (const name of KNOWN_ROLES) {
      roles.push({ name, description: null, permissions: [...ALL_PERMISSIONS], deviceScope: {} });
    }
  }

  res.status(200).json({
    permissions: ALL_PERMISSIONS.map((id) => ({ id, description: PERMISSION_DESCRIPTIONS[id] })),
    roles,
  });
});

/** Public user shape — never exposes passwordHash or totpSecret. */
export async function serializeUser(row: typeof schema.users.$inferSelect) {
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

  // Number of enrolled passkeys (the credentials themselves are listed via
  // GET /users/:id/passkeys, gated by the same credential-access rules).
  let passkeyCount = 0;
  try {
    const countRow = await pool.query(
      `SELECT COUNT(*)::int AS n FROM webauthn_credentials WHERE "userId" = $1`,
      [row.id]
    );
    passkeyCount = Number(countRow.rows[0]?.n ?? 0);
  } catch {
    /* table missing pre-migration — treat as zero */
  }

  return {
    id: row.id,
    username: row.username,
    roles: Array.isArray(roles) ? roles : [],
    permissions: Array.isArray(permissions) ? permissions : [],
    // Whether ANY second factor is enrolled (TOTP secret or ≥1 passkey). The
    // secrets themselves never leave the API.
    twoFactorEnabled: Boolean(row.totpSecret) || passkeyCount > 0,
    totpEnabled: Boolean(row.totpSecret),
    passkeyCount,
    createdAt: row.createdAt,
    // Credential-policy state (see credentialPolicies): disabled accounts are
    // rejected at login and their live sessions terminate; lastLoginAt drives
    // the inactivity auto-disable sweep.
    disabled: Boolean(row.disabled),
    lastLoginAt: row.lastLoginAt ?? null,
    // First-run onboarding — NULL until the setup wizard is completed/skipped.
    onboardedAt: row.onboardedAt ?? null,
    // Device-level access control — the user's OWN scope rules (role scopes are
    // unioned on top server-side; see deviceAccess.ts).
    deviceScope: parseDeviceScope(row.deviceScope),
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
  const updates: { roles?: string[]; permissions?: string[]; deviceScope?: Record<string, string[]> } = {};

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

  if (body.deviceScope !== undefined) {
    const ref = validateDeviceScopeField(body.deviceScope);
    if (ref.error) return { error: ref.error };
    updates.deviceScope = ref.value!;
  }

  if (!updates.roles && !updates.permissions && updates.deviceScope === undefined) {
    return { error: 'Provide at least one of: roles, permissions, deviceScope' };
  }
  return { values: updates };
}

// GET /users — list all users (requires users:read).
router.get('/users', requireAuth, requirePermission('users:read'), async (_req: Request, res: Response) => {
  const rows = await db.query.users.findMany({ orderBy: [schema.users.username] });
  // serializeUser is async (passkey count query); run in parallel.
  const serialized = await Promise.all(rows.map((row) => serializeUser(row)));
  res.status(200).json(serialized);
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

  if (typeof body.password !== 'string') {
    res.status(400).json({ error: '"password" is required' });
    return;
  }
  const minLen = await minLenForNewUser();
  if (body.password.length < minLen) {
    res.status(400).json({ error: `"password" must be at least ${minLen} characters` });
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

  let deviceScope: Record<string, string[]> = {};
  if (body.deviceScope !== undefined) {
    const ref = validateDeviceScopeField(body.deviceScope);
    if (ref.error) {
      res.status(400).json({ error: ref.error });
      return;
    }
    deviceScope = ref.value!;
  }

  const totpSecret = generateSecret();
  await db.insert(schema.users).values({
    id: uuidv4(),
    username,
    passwordHash: bcrypt.hashSync(body.password, 10),
    totpSecret,
    roles: JSON.stringify(roles),
    permissions: JSON.stringify(permissions),
    deviceScope: JSON.stringify(deviceScope),
    createdAt: new Date().toISOString(),
    // A freshly created account has a fresh password — no forced rotation.
    passwordChangedAt: new Date().toISOString(),
  });

  const created = await db.query.users.findFirst({ where: eq(schema.users.username, username) });
  res.status(201).json({ user: await serializeUser(created!), enrollment: enrollmentPayload(username, totpSecret) });
});

// PATCH /users/:id — update roles/permissions (requires users:write).
router.patch('/users/:id', requireAuth, requirePermission('users:write'), async (req: Request, res: Response) => {
  const body = (req.body ?? {}) as Record<string, unknown>;
  const check = validateUserUpdate(body);
  if ('error' in check) {
    res.status(400).json({ error: check.error });
    return;
  }

  const existing = await db.query.users.findFirst({ where: eq(schema.users.id, String(req.params.id ?? '')) });
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
    ...(check.values.deviceScope !== undefined
      ? { deviceScope: JSON.stringify(check.values.deviceScope) }
      : {}),
  }).where(eq(schema.users.id, String(req.params.id ?? '')));

  // Scope rules changed — drop the per-user allowed-id caches so the new scope
  // applies immediately (not after the 5 s TTL).
  invalidateDeviceAccessCache();

  const updated = await db.query.users.findFirst({ where: eq(schema.users.id, String(req.params.id ?? '')) });
  if (!updated) {
    res.status(500).json({ error: 'Failed to retrieve updated user' });
    return;
  }
  res.status(200).json(await serializeUser(updated));
});

// DELETE /users/:id — remove a user (requires users:write). Refuses self-delete
// and deleting the last admin.
router.delete('/users/:id', requireAuth, requirePermission('users:write'), async (req: Request, res: Response) => {
  const targetId = String(req.params.id ?? '');
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
  invalidateDeviceAccessCache(); // drop the deleted user's cached scope entry
  res.status(204).send();
});

// PATCH /users/:id/status — enable/disable an account (requires users:write).
// Disabling is the manual counterpart to the inactivity auto-disable sweep: a
// disabled user is rejected at login and their live sessions terminate. The
// initial seeded admin can never be disabled (it would lock out the last
// guaranteed human path into the system).
router.patch('/users/:id/status', requireAuth, requirePermission('users:write'), async (req, res) => {
  const targetId = String(req.params.id ?? '');
  const body = (req.body ?? {}) as Record<string, unknown>;
  if (typeof body.disabled !== 'boolean') {
    res.status(400).json({ error: '"disabled" must be a boolean' });
    return;
  }

  const existing = await db.query.users.findFirst({ where: eq(schema.users.id, targetId) });
  if (!existing) {
    res.status(404).json({ error: 'User not found' });
    return;
  }
  if (body.disabled && existing.username === INITIAL_ADMIN_USERNAME) {
    res.status(409).json({ error: `The initial admin user "${INITIAL_ADMIN_USERNAME}" cannot be disabled.` });
    return;
  }

  await db.update(schema.users).set({ disabled: body.disabled }).where(eq(schema.users.id, targetId));
  const updated = await db.query.users.findFirst({ where: eq(schema.users.id, targetId) });
  res.status(200).json(await serializeUser(updated!));
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
  const denied = checkCredentialAccess(req, String(req.params.id ?? ''));
  if (denied) {
    res.status(403).json({ error: denied });
    return;
  }

  const body = (req.body ?? {}) as Record<string, unknown>;
  if (typeof body.newPassword !== 'string') {
    res.status(400).json({ error: '"newPassword" is required' });
    return;
  }

  const existing = await db.query.users.findFirst({ where: eq(schema.users.id, String(req.params.id ?? '')) });
  if (!existing) {
    res.status(404).json({ error: 'User not found' });
    return;
  }

  // Enforce the target user's effective minimum length (per-user override wins).
  const minLen = await minLenForUser(existing.id);
  if (body.newPassword.length < minLen) {
    res.status(400).json({ error: `"newPassword" must be at least ${minLen} characters` });
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
    .set({ passwordHash: bcrypt.hashSync(body.newPassword, 10), passwordChangedAt: new Date().toISOString() })
    .where(eq(schema.users.id, existing.id));

  const updated = await db.query.users.findFirst({ where: eq(schema.users.id, existing.id) });
  res.status(200).json(await serializeUser(updated!));
});

// POST /users/:id/totp/enroll — (re-)enroll TOTP for a user. Generates and
// persists a FRESH secret immediately; the response carries it plus an
// otpauth URI so the UI can render a QR code. Re-enrolling replaces any
// previous secret (old authenticator entries stop working).
router.post('/users/:id/totp/enroll', requireAuth, async (req: Request, res: Response) => {
  const denied = checkCredentialAccess(req, String(req.params.id ?? ''));
  if (denied) {
    res.status(403).json({ error: denied });
    return;
  }

  const existing = await db.query.users.findFirst({ where: eq(schema.users.id, String(req.params.id ?? '')) });
  if (!existing) {
    res.status(404).json({ error: 'User not found' });
    return;
  }

  const totpSecret = generateSecret();
  await db.update(schema.users)
    .set({ totpSecret })
    .where(eq(schema.users.id, existing.id));

  const updated = await db.query.users.findFirst({ where: eq(schema.users.id, existing.id) });
  res.status(200).json({ user: await serializeUser(updated!), enrollment: enrollmentPayload(existing.username, totpSecret) });
});

// POST /users/:id/totp/confirm — SELF-ONLY. Verifies a TOTP code against the
// caller's OWN enrolled secret and returns { valid }. Used by the first-run
// setup wizard to prove the initial admin actually scanned their freshly
// generated QR before we stamp onboarding complete (a half-done enrollment must
// not be skippable). No permission beyond being authenticated as that user —
// it never touches another account, so no users:* grant is needed.
router.post('/users/:id/totp/confirm', requireAuth, async (req: Request, res: Response) => {
  if (!req.user?.sub || req.user.sub !== String(req.params.id ?? '')) {
    res.status(403).json({ error: 'You can only confirm your own TOTP enrollment' });
    return;
  }

  const existing = await db.query.users.findFirst({ where: eq(schema.users.id, String(req.params.id ?? '')) });
  if (!existing || !existing.totpSecret) {
    res.status(409).json({ error: 'No TOTP secret is enrolled on this account' });
    return;
  }

  const code = typeof req.body?.code === 'string' ? req.body.code : '';
  res.status(200).json({ valid: verifyTotp(existing.totpSecret, code) });
});

// DELETE /users/:id/totp — disable TOTP for a user (clears the secret).
router.delete('/users/:id/totp', requireAuth, async (req: Request, res: Response) => {
  const denied = checkCredentialAccess(req, String(req.params.id ?? ''));
  if (denied) {
    res.status(403).json({ error: denied });
    return;
  }

  const existing = await db.query.users.findFirst({ where: eq(schema.users.id, String(req.params.id ?? '')) });
  if (!existing) {
    res.status(404).json({ error: 'User not found' });
    return;
  }

  await db.update(schema.users)
    .set({ totpSecret: null })
    .where(eq(schema.users.id, existing.id));
  res.status(204).send();
});

// --- Passkeys (WebAuthn) ----------------------------------------------------
//
// Multiple passkeys per user are allowed (one row per device). Enrollment is a
// two-step browser flow: the UI fetches registration options here, runs
// navigator.credentials.create(), and posts the response back for attestation
// verification. Gating mirrors TOTP: self needs users:self-credentials, acting
// on another user needs users:manage-credentials.

/** Serializes a credential row (no public key material — display metadata only). */
function serializeCredential(row: typeof schema.webauthnCredentials.$inferSelect) {
  let transports: string[] | null = null;
  try {
    const parsed = row.transports ? JSON.parse(row.transports) : null;
    if (Array.isArray(parsed)) transports = parsed.filter((t): t is string => typeof t === 'string');
  } catch {
    /* keep null */
  }
  return {
    id: row.id,
    credentialId: row.credentialId,
    label: row.label ?? null,
    transports,
    createdAt: row.createdAt,
  };
}

// GET /users/:id/passkeys — list a user's enrolled passkeys.
router.get('/users/:id/passkeys', requireAuth, async (req: Request, res: Response) => {
  const denied = checkCredentialAccess(req, String(req.params.id ?? ''));
  if (denied) {
    res.status(403).json({ error: denied });
    return;
  }

  try {
    const rows = await db.query.webauthnCredentials.findMany({
      where: eq(schema.webauthnCredentials.userId, String(req.params.id ?? '')),
      orderBy: [schema.webauthnCredentials.createdAt],
    });
    res.status(200).json(rows.map(serializeCredential));
  } catch (error) {
    console.error('Error listing passkeys:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /users/:id/passkeys — start passkey enrollment. Returns WebAuthn
// registration options for navigator.credentials.create(). Body: { label? }.
router.post('/users/:id/passkeys', requireAuth, async (req: Request, res: Response) => {
  const denied = checkCredentialAccess(req, String(req.params.id ?? ''));
  if (denied) {
    res.status(403).json({ error: denied });
    return;
  }

  const existing = await db.query.users.findFirst({ where: eq(schema.users.id, String(req.params.id ?? '')) });
  if (!existing) {
    res.status(404).json({ error: 'User not found' });
    return;
  }

  try {
    // Exclude already-enrolled credentials so the authenticator creates a NEW
    // one (multiple passkeys per user = multiple devices).
    const enrolled = await db.query.webauthnCredentials.findMany({
      where: eq(schema.webauthnCredentials.userId, existing.id),
    });
    const options = await buildRegistrationOptions({
      userId: existing.id,
      username: existing.username,
      excludeCredentials: enrolled.map((c) => c.credentialId),
    });

    res.status(200).json({
      options,
      // The challenge the UI must echo back on completion (attestation is
      // verified against it in POST /users/:id/passkeys/verify).
      nonce: String(options.challenge ?? ''),
    });
  } catch (error) {
    console.error('Error generating passkey registration options:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /users/:id/passkeys/verify — complete enrollment. Body:
// { nonce, response (PublicKeyCredentialCreationResponse), label? }. Verifies
// the attestation and stores the credential on success.
router.post('/users/:id/passkeys/verify', requireAuth, async (req: Request, res: Response) => {
  const denied = checkCredentialAccess(req, String(req.params.id ?? ''));
  if (denied) {
    res.status(403).json({ error: denied });
    return;
  }

  const existing = await db.query.users.findFirst({ where: eq(schema.users.id, String(req.params.id ?? '')) });
  if (!existing) {
    res.status(404).json({ error: 'User not found' });
    return;
  }

  const body = (req.body ?? {}) as Record<string, unknown>;
  if (typeof body.nonce !== 'string' || !body.nonce) {
    res.status(400).json({ error: '"nonce" is required' });
    return;
  }
  if (!body.response || typeof body.response !== 'object') {
    res.status(400).json({ error: '"response" (the PublicKeyCredentialCreationResponse) is required' });
    return;
  }

  try {
    const verified = await verifyRegistration({ expectedChallenge: body.nonce, response: body.response });
    if (!verified.verified || !verified.registrationInfo) {
      res.status(401).json({ error: 'Passkey attestation verification failed' });
      return;
    }

    // v13 shape: registrationInfo.credential = { id, publicKey (Uint8Array), counter }.
    const cred = verified.registrationInfo.credential;
    const credentialId = String(cred.id);

    // Duplicate credentialId (same authenticator re-registered) → 409.
    const dup = await db.query.webauthnCredentials.findFirst({
      where: eq(schema.webauthnCredentials.credentialId, credentialId),
    });
    if (dup) {
      res.status(409).json({ error: 'This passkey is already enrolled' });
      return;
    }

    const label = typeof body.label === 'string' && body.label.trim() ? body.label.trim().slice(0, 120) : null;
    await db.insert(schema.webauthnCredentials).values({
      id: uuidv4(),
      userId: existing.id,
      credentialId,
      // COSE public key as base64 (SimpleWebAuthn returns a Uint8Array).
      publicKey: Buffer.from(cred.publicKey).toString('base64'),
      counter: Number(cred.counter ?? 0),
      label,
      transports: null,
      createdAt: new Date().toISOString(),
    });

    const row = await db.query.webauthnCredentials.findFirst({
      where: eq(schema.webauthnCredentials.credentialId, credentialId),
    });
    res.status(201).json({ credential: serializeCredential(row!) });
  } catch (error) {
    console.error('Error verifying passkey registration:', error);
    const message = error instanceof Error ? error.message : 'Passkey attestation verification failed';
    res.status(401).json({ error: message });
  }
});

// DELETE /users/:id/passkeys/:credentialId — remove a passkey (self or admin).
router.delete('/users/:id/passkeys/:credentialId', requireAuth, async (req: Request, res: Response) => {
  const denied = checkCredentialAccess(req, String(req.params.id ?? ''));
  if (denied) {
    res.status(403).json({ error: denied });
    return;
  }

  try {
    // Scope by BOTH user and credential id — a credential can never be deleted
    // "through" another user's account.
    const result = await db.delete(schema.webauthnCredentials)
      .where(and(eq(schema.webauthnCredentials.userId, String(req.params.id ?? '')), eq(schema.webauthnCredentials.credentialId, String(req.params.credentialId ?? ''))))
      .returning({ id: schema.webauthnCredentials.id });

    if (!result || result.length === 0) {
      res.status(404).json({ error: 'Passkey not found' });
      return;
    }
    res.status(204).send();
  } catch (error) {
    console.error('Error deleting passkey:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;
