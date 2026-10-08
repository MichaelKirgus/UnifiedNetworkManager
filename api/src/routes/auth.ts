import { Request, Response as ExpressResponse, Router } from 'express';
import bcrypt from 'bcryptjs';
import { eq } from 'drizzle-orm';
import { v4 as uuidv4 } from 'uuid';
import { db, pool } from '../db';
import * as schema from '../db/schema';
import { signToken } from '../auth/jwt';
import { requireAuth } from '../auth/middleware';
import { allowedDeviceIds } from '../deviceAccess';
import {
  login,
  verify2fa,
  completeLogin,
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
import { INITIAL_ADMIN_USERNAME } from '../auth/permissions';

const router = Router();

/** The second factors currently enrolled on a user (totp and/or webauthn). */
async function enrolledSecondFactorMethods(user: typeof schema.users.$inferSelect): Promise<string[]> {
  const methods: string[] = [];
  if (user.totpSecret) methods.push('totp');
  try {
    const countRow = await pool.query(
      `SELECT COUNT(*)::int AS n FROM webauthn_credentials WHERE "userId" = $1`,
      [user.id]
    );
    if (Number(countRow.rows[0]?.n ?? 0) > 0) methods.push('webauthn');
  } catch {
    /* table missing pre-migration — treat as none */
  }
  return methods;
}

/**
 * Upserts the initial admin's per-user credential-policy override so login step
 * 2 requires exactly the second factors they enrolled during onboarding. Called
 * from /auth/onboarding/complete (first completion only). `gateAmrs` mirrors
 * `requiredMethods` so require2FA-gated endpoints accept the same AMRs. When no
 * factor is enrolled we keep the override at requiredMethods [] — but that state
 * cannot occur in practice, because onboarding completion requires enrolling one.
 */
async function upsertInitialAdminPolicy(userId: string, methods: string[]): Promise<void> {
  const now = new Date().toISOString();
  const existing = await db.query.credentialPolicies.findFirst({ where: eq(schema.credentialPolicies.userId, userId) });
  if (existing) {
    await db.update(schema.credentialPolicies)
      .set({ requiredMethods: JSON.stringify(methods), gateAmrs: JSON.stringify(methods), updatedAt: now })
      .where(eq(schema.credentialPolicies.id, existing.id));
  } else {
    await db.insert(schema.credentialPolicies).values({
      id: uuidv4(),
      userId,
      requiredMethods: JSON.stringify(methods),
      gateAmrs: JSON.stringify(methods),
      updatedAt: now,
    });
  }
}

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

  // Device-level access state for the webapp (restricted-view badge + pickers):
  // unrestricted = devices:all permission OR no scope rules configured.
  let deviceAccessUnrestricted = true;
  try {
    deviceAccessUnrestricted = (await allowedDeviceIds(req)) === null;
  } catch {
    /* keep the optimistic default — enforcement is server-side anyway */
  }

  // Instance display name (global setting) — the webapp renders it in the
  // window title for every authenticated page.
  let instanceName = 'UnifiedNetworkManager';
  try {
    const v = await getEffectiveSettingValue('instanceName');
    if (typeof v === 'string' && v.trim() !== '') instanceName = v;
  } catch {
    /* keep the default — a settings hiccup must not break /auth/me */
  }

  res.status(200).json({
    ...(await serializeUser(row)),
    effectivePermissions: req.user?.permissions ?? [],
    deviceAccessUnrestricted,
    instanceName,
  });
});

/**
 * Returns the caller's session expiry + warning lead time. The expiry is
 * computed SERVER-SIDE from the JWT's issued-at plus the user's EFFECTIVE
 * session TTL (global setting capped by any per-user `sessionTimeoutSeconds`
 * override) — so it matches exactly what requireAuth enforces, and a shorter
 * global timeout set after login is reflected here too. The webapp renders
 * this as a top-bar countdown chip and an amber warning banner once the
 * remaining time drops below `warnSeconds`.
 */
router.get('/auth/session', requireAuth, async (req, res) => {
  const payload = req.user!;
  const iat = typeof payload.iat === 'number' ? payload.iat : null;
  if (iat === null) {
    res.status(401).json({ error: 'Session has no issued-at claim', code: 'session_expired' });
    return;
  }

  const globalTtl = Number(await getEffectiveSettingValue('sessionTimeoutSeconds')) || 3600;
  let ttlSeconds = globalTtl;
  try {
    const policy = await resolveCredentialPolicy(payload.sub);
    ttlSeconds = effectiveSessionTtl(globalTtl, policy);
  } catch {
    // Policy lookup hiccup — fall back to the global TTL (requireAuth does the same).
  }

  const warnSeconds = Number(await getEffectiveSettingValue('sessionWarnSeconds')) || 0;

  // Whether the "Extend" button may be offered at all: the policy kill switch
  // AND an enrolled second factor (extension always requires re-proving one).
  let extensionAllowed = false;
  try {
    const policy = await resolveCredentialPolicy(payload.sub);
    if (policy.allowSessionExtension !== false) extensionAllowed = await hasEnrolledSecondFactor(payload.sub);
  } catch {
    /* keep false — the extend endpoints re-check everything anyway */
  }

  res.status(200).json({
    expiresAt: Math.floor(iat * 1000 + ttlSeconds * 1000),
    ttlSeconds,
    warnSeconds,
    extensionAllowed,
  });
});

// --- Session extension (2FA-gated) ------------------------------------------
// Extending a session mints a fresh JWT for the same identity. It is NEVER
// allowed without re-proving a second factor — an unauthenticated refresh would
// let anyone holding a stolen token keep minting new ones forever. The flow
// mirrors /auth/revalidate/*: start a challenge, complete it with TOTP or a
// passkey, and only then mint the extended token (amr carries the verified
// second factor). Two hard gates apply BEFORE any of that:
//   1. The user's effective credential policy `allowSessionExtension` must be
//      true — an admin can deny extension entirely (security hardening), in
//      which case sessions simply end at their expiry.
//   2. The user must have a second factor enrolled (TOTP secret or ≥1 passkey)
//      that satisfies the policy's `requiredMethods` — a password-only account
//      can never extend, even if extension is allowed.

/** True when the caller has an enrolled second factor satisfying their policy's requiredMethods. */
async function hasEnrolledSecondFactor(userId: string): Promise<boolean> {
  const row = await db.query.users.findFirst({ where: eq(schema.users.id, userId) });
  if (!row) return false;
  const policy = await resolveCredentialPolicy(userId);
  if (policy.requiredMethods.length === 0) return true; // no 2FA required — any enrolled factor counts
  const hasTotp = Boolean(row.totpSecret);
  let passkeyCount = 0;
  try {
    const r = await pool.query(`SELECT COUNT(*)::int AS n FROM webauthn_credentials WHERE "userId" = $1`, [userId]);
    passkeyCount = Number(r.rows[0]?.n ?? 0);
  } catch {
    /* table missing pre-migration — treat as zero */
  }
  return (
    (policy.requiredMethods.includes('totp') && hasTotp) ||
    (policy.requiredMethods.includes('webauthn') && passkeyCount > 0)
  );
}

/** Shared gate for the extension endpoints: policy kill switch + enrolled factor. */
async function assertExtensionAllowed(userId: string, res: ExpressResponse): Promise<boolean> {
  const policy = await resolveCredentialPolicy(userId);
  if (policy.allowSessionExtension === false) {
    res.status(403).json({ error: 'Session extension is disabled for this account by its credential policy', code: 'extension_disabled' });
    return false;
  }
  if (!(await hasEnrolledSecondFactor(userId))) {
    res.status(403).json({ error: 'Extending a session requires an enrolled second factor (TOTP or passkey)', code: 'no_2fa_enrolled' });
    return false;
  }
  return true;
}

// POST /auth/session/extend/challenge — start a session-extension revalidation.
router.post('/auth/session/extend/challenge', requireAuth, async (req, res) => {
  const userId = req.user?.sub ?? '';
  if ((req.user?.amr ?? []).includes('token')) {
    res.status(403).json({ error: 'API tokens cannot be extended' });
    return;
  }
  try {
    if (!(await assertExtensionAllowed(userId, res))) return;
    const result = await revalidateChallenge(userId);
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
    res.status(e.status ?? 500).json({ error: e.message ?? 'Unable to start session extension' });
  }
});

// POST /auth/session/extend/totp — complete the extension with a TOTP code.
router.post('/auth/session/extend/totp', requireAuth, async (req, res) => {
  const userId = req.user?.sub ?? '';
  if ((req.user?.amr ?? []).includes('token')) {
    res.status(403).json({ error: 'API tokens cannot be extended' });
    return;
  }
  try {
    if (!(await assertExtensionAllowed(userId, res))) return;
    const identity = await verify2fa(typeof req.body?.challengeToken === 'string' ? req.body.challengeToken : '', typeof req.body?.totpCode === 'string' ? req.body.totpCode : '');
    // The revalidation only mints a token when the second factor actually
    // verified (amr carries totp/webauthn, never bare pwd) — enforce that here.
    if (!(identity.amr ?? []).some((a) => a === 'totp' || a === 'webauthn')) {
      res.status(403).json({ error: 'Session extension requires a verified second factor', code: 'no_2fa_enrolled' });
      return;
    }
    const globalTtlSeconds = Number(await getEffectiveSettingValue('sessionTimeoutSeconds')) || 3600;
    const tokenTtlSeconds = effectiveSessionTtl(globalTtlSeconds, await resolveCredentialPolicy(userId));
    res.status(200).json({ accessToken: signToken({ sub: identity.userId, username: identity.username, roles: identity.roles, permissions: identity.permissions, amr: identity.amr }, tokenTtlSeconds), expiresIn: tokenTtlSeconds });
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Session extension failed' });
  }
});

// GET /auth/session/extend/webauthn/options — passkey assertion options for a pending extension challenge.
router.get('/auth/session/extend/webauthn/options', requireAuth, async (req, res) => {
  const userId = req.user?.sub ?? '';
  if ((req.user?.amr ?? []).includes('token')) {
    res.status(403).json({ error: 'API tokens cannot be extended' });
    return;
  }
  try {
    if (!(await assertExtensionAllowed(userId, res))) return;
    const challengeToken = typeof req.query.challengeToken === 'string' ? req.query.challengeToken : '';
    const queryUserId = typeof req.query.userId === 'string' ? req.query.userId : '';
    if (!queryUserId || queryUserId !== userId) {
      res.status(403).json({ error: 'Can only fetch passkey options for your own account' });
      return;
    }
    const result = await webauthnAssertionOptions(challengeToken);
    res.status(200).json(result);
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Unable to fetch passkey options' });
  }
});

// POST /auth/session/extend/webauthn/verify — complete the extension with a passkey assertion.
router.post('/auth/session/extend/webauthn/verify', requireAuth, async (req, res) => {
  const userId = req.user?.sub ?? '';
  if ((req.user?.amr ?? []).includes('token')) {
    res.status(403).json({ error: 'API tokens cannot be extended' });
    return;
  }
  try {
    if (!(await assertExtensionAllowed(userId, res))) return;
    const identity = await verifyWebauthn(typeof req.body?.challengeToken === 'string' ? req.body.challengeToken : '', req.body?.response ?? {}, typeof req.body?.nonce === 'string' ? req.body.nonce : '');
    if (!(identity.amr ?? []).some((a) => a === 'totp' || a === 'webauthn')) {
      res.status(403).json({ error: 'Session extension requires a verified second factor', code: 'no_2fa_enrolled' });
      return;
    }
    const globalTtlSeconds = Number(await getEffectiveSettingValue('sessionTimeoutSeconds')) || 3600;
    const tokenTtlSeconds = effectiveSessionTtl(globalTtlSeconds, await resolveCredentialPolicy(userId));
    res.status(200).json({ accessToken: signToken({ sub: identity.userId, username: identity.username, roles: identity.roles, permissions: identity.permissions, amr: identity.amr }, tokenTtlSeconds), expiresIn: tokenTtlSeconds });
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Passkey session extension failed' });
  }
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

/** The caller's own UI preferences (nav order + hidden pages + date/time display). No extra permission. */
router.get('/auth/me/preferences', requireAuth, async (req, res) => {
  const row = await db.query.userPreferences.findFirst({ where: eq(schema.userPreferences.userId, req.user!.sub) });
  let navOrder: string[] = [];
  let hiddenPages: string[] = [];
  if (row) {
    try { navOrder = asStringArray(JSON.parse(row.navOrder)); } catch { /* keep [] */ }
    try { hiddenPages = asStringArray(JSON.parse(row.hiddenPages)); } catch { /* keep [] */ }
  }
  res.status(200).json({
    navOrder,
    hiddenPages,
    // NULL/absent timezone = follow the browser's local zone.
    timezone: row?.timezone ?? null,
    dateFormat: row?.dateFormat && DATE_FORMAT_PRESETS.has(row.dateFormat) ? row.dateFormat : 'locale',
    showTzSuffix: Boolean(row?.showTzSuffix),
  });
});

/** Date/time format presets accepted by PUT /auth/me/preferences. */
const DATE_FORMAT_PRESETS = new Set(['locale', 'iso', 'us', 'eu']);

/** Validate a timezone value: null/'browser' = follow the browser; anything else must be a real IANA zone (or "UTC"). */
function normalizeTimezone(raw: unknown): { value?: string | null; error?: string } {
  if (raw === null || raw === undefined || raw === '' || raw === 'browser') return { value: null };
  if (typeof raw !== 'string' || raw.length > 64) return { error: '"timezone" must be a string IANA timezone identifier, "browser", or null' };
  try {
    // Intl throws RangeError for unknown zone names — the canonical validation.
    new Intl.DateTimeFormat('en-US', { timeZone: raw });
    return { value: raw };
  } catch {
    return { error: `Unknown timezone "${raw}"` };
  }
}

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

  // Date/time display preferences — same omit-to-keep semantics.
  let timezone: string | null;
  if (body.timezone === undefined) {
    timezone = existing?.timezone ?? null;
  } else {
    const tz = normalizeTimezone(body.timezone);
    if (tz.error) { res.status(400).json({ error: tz.error }); return; }
    timezone = tz.value ?? null;
  }
  let dateFormat: string;
  if (body.dateFormat === undefined) {
    dateFormat = existing?.dateFormat && DATE_FORMAT_PRESETS.has(existing.dateFormat) ? existing.dateFormat : 'locale';
  } else {
    dateFormat = typeof body.dateFormat === 'string' && DATE_FORMAT_PRESETS.has(body.dateFormat) ? body.dateFormat : 'locale';
  }
  let showTzSuffix: boolean;
  if (body.showTzSuffix === undefined) {
    showTzSuffix = Boolean(existing?.showTzSuffix);
  } else {
    showTzSuffix = Boolean(body.showTzSuffix);
  }

  const now = new Date().toISOString();
  await db.insert(schema.userPreferences)
    .values({ userId: req.user!.sub, navOrder: JSON.stringify(navOrder), hiddenPages: JSON.stringify(hiddenPages), timezone, dateFormat, showTzSuffix, updatedAt: now })
    .onConflictDoUpdate({ target: [schema.userPreferences.userId], set: { navOrder: JSON.stringify(navOrder), hiddenPages: JSON.stringify(hiddenPages), timezone, dateFormat, showTzSuffix, updatedAt: now } });
  res.status(200).json({ navOrder, hiddenPages, timezone, dateFormat, showTzSuffix });
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
    // Instance display name (global setting) — lets the login page show it in
    // the window title before any credentials are entered.
    let instanceName = 'UnifiedNetworkManager';
    try {
      const v = await getEffectiveSettingValue('instanceName');
      if (typeof v === 'string' && v.trim() !== '') instanceName = v;
    } catch {
      /* keep the default */
    }
    res.status(200).json({ flow, supportsPasskey, instanceName });
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
 * Password-only completion for a challenge whose policy requires NO second
 * factor (today: the initial admin before onboarding — see /auth/login's
 * `twoFactorRequired: false`). The provider re-checks the LIVE credential
 * policy and answers 403 `two_factor_required` when one is now required, so
 * this can never mint a session for an account that should have used TOTP or a
 * passkey. Mints the same session shape as /auth/2fa/verify (amr: ['pwd']).
 */
router.post('/auth/login/complete', async (req, res) => {
  const challengeToken = typeof req.body?.challengeToken === 'string' ? req.body.challengeToken : '';

  try {
    const identity = await completeLogin(challengeToken);
    res.status(200).json(await mintSession(identity));
  } catch (err) {
    const e = err as { status?: number; message?: string };
    if (e.message === 'two_factor_required') {
      res.status(403).json({ error: 'A second factor is required for this account', code: 'two_factor_required' });
      return;
    }
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

// POST /auth/onboarding/complete — the CALLER marks their first-run setup
// wizard as done. Idempotent; stamps users.onboardedAt so the webapp never
// redirects them to /onboarding again. Self-only by design — there is no admin
// override because re-running the wizard for someone else would be meaningless
// (it edits their own password/2FA + instance settings).
//
// For the INITIAL ADMIN this also RE-ENABLES 2FA: first sign-in was allowed to
// be password-only (a per-user policy override with requiredMethods [] is seeded
// alongside the account), so on completion we point that override at whatever
// second factor they actually enrolled (totp and/or webauthn). From their next
// login onward a matching second factor is mandatory again. Non-admin callers
// are unaffected — they never had such an override.
router.post('/auth/onboarding/complete', requireAuth, async (req, res) => {
  const userId = req.user!.sub;

  // First completion wins — re-calls keep the original timestamp AND do not
  // rewrite the credential policy (the enrolled set is fixed at first finish).
  const existing = await db.query.users.findFirst({ where: eq(schema.users.id, userId) });
  if (!existing) {
    res.status(401).json({ error: 'User no longer exists' });
    return;
  }
  if (!existing.onboardedAt) {
    try {
      await db.update(schema.users)
        .set({ onboardedAt: new Date().toISOString() })
        .where(eq(schema.users.id, userId));

      // Re-arm the initial admin's 2FA requirement from their live enrollment.
      if (existing.username === INITIAL_ADMIN_USERNAME) {
        const methods = await enrolledSecondFactorMethods(existing);
        await upsertInitialAdminPolicy(userId, methods);
      }
    } catch (err) {
      console.error('[auth] onboarding complete failed:', err);
      res.status(500).json({ error: 'Internal server error' });
      return;
    }
  }

  const row = await db.query.users.findFirst({ where: eq(schema.users.id, userId) });
  if (!row) {
    res.status(401).json({ error: 'User no longer exists' });
    return;
  }
  res.status(200).json(await serializeUser(row));
});

export default router;
