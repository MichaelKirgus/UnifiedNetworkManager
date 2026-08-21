import { Router } from 'express';
import { eq } from 'drizzle-orm';
import { db } from '../db';
import * as schema from '../db/schema';
import { signToken } from '../auth/jwt';
import { requireAuth } from '../auth/middleware';
import { login, verify2fa, getFlow, getRedirectUrl } from '../auth/identityProvider';
import { expandRolePermissions } from './roles';
import { serializeUser } from './users';

const router = Router();

const TOKEN_TTL_SECONDS = 3600;

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
  res.status(200).json({ ...serializeUser(row), effectivePermissions: req.user?.permissions ?? [] });
});

/**
 * Reports the authentication flow of the active identity provider so the
 * webapp can adapt its login UI (e.g. password + TOTP vs. an OAuth2 redirect).
 * Public endpoint — no credentials are involved.
 */
router.get('/auth/flow', async (_req, res) => {
  try {
    const flow = await getFlow();
    res.status(200).json({ flow });
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
    });
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Authentication failed' });
  }
});

router.post('/auth/2fa/verify', async (req, res) => {
  const { challengeToken, totpCode } = req.body ?? {};

  try {
    const identity = await verify2fa(challengeToken ?? '', totpCode ?? '');

    // Effective permissions = explicit grants + every permission of the user's
    // roles (roles are bundles; enforcement stays on this flat claim). Role
    // changes therefore take effect at the next login.
    const effectivePermissions = await expandRolePermissions(
      identity.roles,
      Array.isArray(identity.permissions) ? identity.permissions : []
    );

    const accessToken = signToken(
      {
        sub: identity.userId,
        username: identity.username,
        roles: identity.roles,
        permissions: effectivePermissions,
        amr: identity.amr,
      },
      TOKEN_TTL_SECONDS
    );

    res.status(200).json({
      accessToken,
      expiresIn: TOKEN_TTL_SECONDS,
      username: identity.username,
      roles: identity.roles,
      permissions: effectivePermissions,
    });
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Authentication failed' });
  }
});

export default router;
