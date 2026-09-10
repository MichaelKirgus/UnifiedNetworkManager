import { Router } from 'express';
import bcrypt from 'bcryptjs';
import { eq } from 'drizzle-orm';
import { db, pool } from '../db';
import * as schema from '../db/schema';
import { signToken } from '../auth/jwt';
import { requireAuth } from '../auth/middleware';
import {
  login,
  verify2fa,
  revalidateChallenge,
  getFlow,
  getRedirectUrl,
  webauthnAssertionOptions,
  verifyWebauthn,
  resolveActiveProvider,
  BASIC_AUTH_PLUGIN_UUID,
} from '../auth/identityProvider';
import { expandRolePermissions } from './roles';
import { serializeUser } from './users';
import { getEffectiveSettingValue } from '../systemSettings';
import { resolveCredentialPolicy, effectiveSessionTtl, effectiveMinPasswordLength } from '../auth/credentialPolicy';

const router = Router();

/**
 * Mints the platform JWT from a verified identity assertion (shared by the
 * TOTP and WebAuthn completion paths). Effective permissions = explicit grants
 * + every permission of the user's roles, computed here so role changes take
 * effect at the next login. The token TTL is the global session timeout CAPPED
 * by any per-user `sessionTimeoutSeconds` override (a shorter lifetime for one
 * account), and a successful authentication stamps `lastLoginAt` — which drives
 * the inactivity auto-disable sweep.
 */
async function mintSession(identity: {
  userId: string;
  username: string;
  roles: string[];
  permissions: string[];
  amr: string[];
}) {
  const effectivePermissions = await expandRolePermissions(
    identity.roles,
    Array.isArray(identity.permissions) ? identity.permissions : []
  );

  const globalTtlSeconds = Number(await getEffectiveSettingValue('sessionTimeoutSeconds')) || 3600;
  let tokenTtlSeconds = globalTtlSeconds;
  try {
    const policy = await resolveCredentialPolicy(identity.userId);
    tokenTtlSeconds = effectiveSessionTtl(globalTtlSeconds, policy);
  } catch {
    // Policy lookup hiccup — fall back to the global TTL.
  }

  const accessToken = signToken(
    {
      sub: identity.userId,
      username: identity.username,
      roles: identity.roles,
      permissions: effectivePermissions,
      amr: identity.amr,
    },
    tokenTtlSeconds
  );

  // Stamp the last successful authentication (best-effort — a failure here must
  // not break sign-in; the sweep simply keeps the previous timestamp).
  try {
    await db.update(schema.users)
      .set({ lastLoginAt: new Date().toISOString() })
      .where(eq(schema.users.id, identity.userId));
  } catch (err) {
    console.error('[auth] failed to stamp lastLoginAt:', err);
  }

  return {
    accessToken,
    expiresIn: tokenTtlSeconds,
    username: identity.username,
    roles: identity.roles,
    permissions: effectivePermissions,
  };
}

/**
 * Returns the authenticated user's own profile (no users:read needed).
 * Powers the self-service "My Account" page. `effectivePermissions` is the
 * session's JWT claim (explicit grants + role-derived); `permissions` are the
 * explicit grants stored on the account.
 */
router.get('/auth/me', requireAuth, async (req, res) => {
  const row = await db.query.users.findFirst({ where: eq(schema.users.id, req.user!.sub) });
  if (!row) {
    res.status(401).json({ error: 'User no longer exists' });
    return;
  }
  res.status(200).json({ ...(await serializeUser(row)), effectivePermissions: req.user?.permissions ?? [] });
});

/** Coerce an unknown value into a clean string[] (drops non-strings, dedupes). */
function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  const seen = new Set<string>();
  for (const entry of value) {
    if (typeof entry === 'string' && entry.length > 0 && !seen.has(entry)) seen.add(entry);
  }
  return [...seen];
}

/** The caller's own UI preferences (nav order + hidden pages). No extra permission. */
router.get('/auth/me/preferences', requireAuth, async (req, res) => {
  const row = await db.query.userPreferences.findFirst({ where: eq(schema.userPreferences.userId, req.user!.sub) });
  let navOrder: string[] = [];
  let hiddenPages: string[] = [];
  if (row) {
    try { navOrder = asStringArray(JSON.parse(row.navOrder)); } catch { /* keep [] */ }
    try { hiddenPages = asStringArray(JSON.parse(row.hiddenPages)); } catch { /* keep [] */ }
  }
  res.status(200).json({ navOrder, hiddenPages });
});

/** Persist the caller's own UI preferences (upsert; missing row created on first save). */
router.put('/auth/me/preferences', requireAuth, async (req, res) => {
  const body = (req.body ?? {}) as Record<string, unknown>;
  // Omitted field = leave unchanged; present-but-invalid = treated as empty.
  const existing = await db.query.userPreferences.findFirst({ where: eq(schema.userPreferences.userId, req.user!.sub) });
  let navOrder: string[];
  let hiddenPages: string[];
  if (body.navOrder === undefined) {
    try { navOrder = existing ? asStringArray(JSON.parse(existing.navOrder)) : []; } catch { navOrder = []; }
  } else {
    navOrder = asStringArray(body.navOrder);
  }
  if (body.hiddenPages === undefined) {
    try { hiddenPages = existing ? asStringArray(JSON.parse(existing.hiddenPages)) : []; } catch { hiddenPages = []; }
  } else {
    hiddenPages = asStringArray(body.hiddenPages);
  }
  const now = new Date().toISOString();
  await db.insert(schema.userPreferences)
    .values({ userId: req.user!.sub, navOrder: JSON.stringify(navOrder), hiddenPages: JSON.stringify(hiddenPages), updatedAt: now })
    .onConflictDoUpdate({ target: [schema.userPreferences.userId], set: { navOrder: JSON.stringify(navOrder), hiddenPages: JSON.stringify(hiddenPages), updatedAt: now } });
  res.status(200).json({ navOrder, hiddenPages });
});

/**
 * Reports the authentication flow of the active identity provider so the
 * webapp can adapt its login UI (e.g. password + TOTP vs. an OAuth2 redirect).
 * Public endpoint — no credentials are involved.
 */
router.get('/auth/flow', async (_req, res) => {
  try {
    const flow = await getFlow();
    // Passkey (WebAuthn) step-2 is supported by the built-in basic-auth
    // provider (the only `password`-flow provider). External IdPs (OAuth2/
    // SAML/LDAP) do not use it.
    let supportsPasskey = false;
    try {
      const provider = await resolveActiveProvider();
      supportsPasskey = flow === 'password' && provider.id === BASIC_AUTH_PLUGIN_UUID;
    } catch {
      // Provider resolution failed — the login itself will fail too, so just
      // report no passkey support.
    }
    res.status(200).json({ flow, supportsPasskey });
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Unable to determine auth flow' });
  }
});

/**
 * Returns the URL to redirect the user to in order to start an external
 * authentication flow (OAuth2 / SAML / LDAP web login). The webapp calls this
 * for non-`password` flows and then navigates the browser to the returned URL.
 * Responds 501 when the active provider does not support redirect-based login.
 */
router.get('/auth/redirect', async (_req, res) => {
  try {
    const redirectUrl = await getRedirectUrl();
    res.status(200).json({ redirectUrl });
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Unable to determine redirect URL' });
  }
});

/**
 * Authentication routes.
 *
 * The API is a pure identity broker: it does NOT verify credentials itself.
 * It delegates to the active identity provider plugin (selected via
 * `AUTH_PLUGIN_ID`, falling back to the built-in basic-auth plugin) and mints
 * the platform JWT from the provider's verified identity assertion.
 *
 * The public contract is unchanged:
 *   POST /auth/login      -> { challengeToken, twoFactorRequired }
 *   POST /auth/2fa/verify -> { accessToken, expiresIn, roles, permissions }
 */
router.post('/auth/login', async (req, res) => {
  const { username, password } = req.body ?? {};

  try {
    const result = await login(username ?? '', password ?? '');
    res.status(200).json({
      challengeToken: result.challengeToken,
      twoFactorRequired: result.twoFactorRequired,
      // The webapp keeps this across the 2FA step and forces a password change
      // right after sign-in completes when true.
      passwordExpired: Boolean(result.passwordExpired),
    });
  } catch (err) {
    const e = err as { status?: number; message?: string; code?: string };
    // Distinct codes so the webapp can point to the right remedy instead of a
    // generic failure.
    if (e.message === 'no_2fa_enrolled') {
      res.status(403).json({ error: 'No enrolled second factor satisfies the credential policy', code: 'no_2fa_enrolled' });
      return;
    }
    if (e.code === 'user_disabled') {
      res.status(403).json({ error: 'Account is disabled — contact an administrator', code: 'user_disabled' });
      return;
    }
    if (e.code === 'no_interactive_login') {
      res.status(403).json({
        error: 'This account is service-only and cannot sign in to the web UI. Use its API token instead.',
        code: 'no_interactive_login',
      });
      return;
    }
    res.status(e.status ?? 500).json({ error: e.message ?? 'Authentication failed' });
  }
});

router.post('/auth/2fa/verify', async (req, res) => {
  const { challengeToken, totpCode } = req.body ?? {};

  try {
    const identity = await verify2fa(challengeToken ?? '', totpCode ?? '');
    res.status(200).json(await mintSession(identity));
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Authentication failed' });
  }
});

/**
 * WebAuthn step 2a: fetch assertion options for a pending challenge. The API
 * generates the nonce + options (it owns the RP identity); the provider binds
 * the nonce to its in-memory challenge entry. The webapp then calls
 * navigator.credentials.get() with `options` and posts the result back to
 * /auth/webauthn/verify together with `nonce`.
 */
router.get('/auth/webauthn/assertion-options', async (req, res) => {
  const challengeToken = typeof req.query.challengeToken === 'string' ? req.query.challengeToken : '';

  try {
    const result = await webauthnAssertionOptions(challengeToken);
    res.status(200).json(result);
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Unable to fetch passkey options' });
  }
});

/**
 * WebAuthn step 2b: verify the assertion and mint the session JWT (same shape
 * as /auth/2fa/verify; amr carries ['pwd','webauthn']).
 */
router.post('/auth/webauthn/verify', async (req, res) => {
  const { challengeToken, response, nonce } = req.body ?? {};

  try {
    const identity = await verifyWebauthn(
      typeof challengeToken === 'string' ? challengeToken : '',
      response,
      typeof nonce === 'string' ? nonce : ''
    );
    res.status(200).json(await mintSession(identity));
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Passkey verification failed' });
  }
});

// --- In-session 2FA re-validation ------------------------------------------
// A session whose 2FA `amr` has expired (or a user with no 2FA amr) is rejected
// by require2FA-gated endpoints (plan create/execute). Rather than forcing a
// full re-login, the webapp can re-prove TOTP/passkey HERE to mint a fresh JWT.
// The password is NOT re-checked — the caller's identity is already established
// by their current JWT; only the second factor is re-asserted (per policy).

/** Counts enrolled passkeys for a user (0 when the table predates migration). */
async function countPasskeys(userId: string): Promise<number> {
  try {
    const r = await pool.query(`SELECT COUNT(*)::int AS n FROM webauthn_credentials WHERE "userId" = $1`, [userId]);
    return Number(r.rows[0]?.n ?? 0);
  } catch {
    return 0;
  }
}

// POST /auth/revalidate/challenge — start a revalidation for the CALLER. Returns
// a challenge token + whether passkey step-2 is available (so the UI can offer it).
router.post('/auth/revalidate/challenge', requireAuth, async (req, res) => {
  const userId = req.user?.sub ?? '';
  try {
    const row = await db.query.users.findFirst({ where: eq(schema.users.id, userId) });
    if (!row) {
      res.status(401).json({ error: 'User no longer exists' });
      return;
    }
    const result = await revalidateChallenge(userId);
    // Passkey is offered only when the active provider supports it AND the user
    // has at least one enrolled passkey (TOTP-only users get the code field).
    let supportsPasskey = false;
    try {
      const provider = await resolveActiveProvider();
      if (provider.id === BASIC_AUTH_PLUGIN_UUID) supportsPasskey = (await countPasskeys(userId)) > 0;
    } catch {
      // Provider resolution failed — just report no passkey support.
    }
    res.status(200).json({ challengeToken: result.challengeToken, twoFactorRequired: true, supportsPasskey, userId });
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Unable to start revalidation' });
  }
});

// POST /auth/revalidate/totp — complete a revalidation with a TOTP code. Mints a
// fresh JWT (amr carries the verified second factor) exactly like login step-2.
router.post('/auth/revalidate/totp', requireAuth, async (req, res) => {
  const { challengeToken, totpCode } = req.body ?? {};
  try {
    const identity = await verify2fa(typeof challengeToken === 'string' ? challengeToken : '', typeof totpCode === 'string' ? totpCode : '');
    res.status(200).json(await mintSession(identity));
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Revalidation failed' });
  }
});

// GET /auth/revalidate/webauthn/options — passkey assertion options for a pending
// revalidation challenge. Restricted to the CALLER (userId must match) so one
// user cannot drive another's passkey prompt.
router.get('/auth/revalidate/webauthn/options', requireAuth, async (req, res) => {
  const challengeToken = typeof req.query.challengeToken === 'string' ? req.query.challengeToken : '';
  const userId = typeof req.query.userId === 'string' ? req.query.userId : '';
  if (!userId || userId !== req.user?.sub) {
    res.status(403).json({ error: 'Can only fetch passkey options for your own account' });
    return;
  }
  try {
    const result = await webauthnAssertionOptions(challengeToken);
    res.status(200).json(result);
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Unable to fetch passkey options' });
  }
});

// POST /auth/revalidate/webauthn/verify — complete a revalidation with a passkey
// assertion. Mints a fresh JWT (amr carries ['webauthn']) like login step-2b.
router.post('/auth/revalidate/webauthn/verify', requireAuth, async (req, res) => {
  const { challengeToken, response, nonce } = req.body ?? {};
  try {
    const identity = await verifyWebauthn(
      typeof challengeToken === 'string' ? challengeToken : '',
      response,
      typeof nonce === 'string' ? nonce : ''
    );
    res.status(200).json(await mintSession(identity));
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Passkey revalidation failed' });
  }
});

// POST /auth/me/password — the CALLER rotates their own password. Used by the
// forced-change flow when a login reports `passwordExpired` (and available to
// any user with users:self-credentials). The current password must be proven,
// and the new one must satisfy the caller's effective minimum length policy.
router.post('/auth/me/password', requireAuth, async (req, res) => {
  const body = (req.body ?? {}) as Record<string, unknown>;
  if (typeof body.currentPassword !== 'string' || typeof body.newPassword !== 'string') {
    res.status(400).json({ error: '"currentPassword" and "newPassword" are required' });
    return;
  }

  const existing = await db.query.users.findFirst({ where: eq(schema.users.id, req.user!.sub) });
  if (!existing) {
    res.status(401).json({ error: 'User no longer exists' });
    return;
  }
  if (existing.disabled) {
    res.status(403).json({ error: 'Account is disabled — contact an administrator', code: 'user_disabled' });
    return;
  }

  const policy = await resolveCredentialPolicy(existing.id);
  const minLen = effectiveMinPasswordLength(policy);
  if (body.newPassword.length < minLen) {
    res.status(400).json({ error: `"newPassword" must be at least ${minLen} characters` });
    return;
  }

  try {
    const ok = await bcrypt.compare(body.currentPassword, existing.passwordHash);
    if (!ok) {
      res.status(401).json({ error: 'Current password is incorrect' });
      return;
    }
  } catch (err) {
    console.error('[auth] current-password check failed:', err);
    res.status(500).json({ error: 'Internal server error' });
    return;
  }

  await db.update(schema.users)
    .set({ passwordHash: bcrypt.hashSync(body.newPassword, 10), passwordChangedAt: new Date().toISOString() })
    .where(eq(schema.users.id, existing.id));

  const updated = await db.query.users.findFirst({ where: eq(schema.users.id, existing.id) });
  res.status(200).json(await serializeUser(updated!));
});

export default router;
