import { NextFunction, Request, Response } from 'express';
import { eq } from 'drizzle-orm';
import { verifyToken, AccessTokenPayload } from './jwt';
import { resolveApiTokenPayload } from './apiTokens';
import { resolveCredentialPolicy, effectiveSessionTtl } from './credentialPolicy';
import { getEffectiveSettingValue } from '../systemSettings';
import { allowedDeviceIds, isUnrestricted } from '../deviceAccess';
import { db } from '../db';
import * as schema from '../db/schema';

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      user?: AccessTokenPayload;
    }
  }
}

/**
 * Validates the bearer token on the Authorization header and attaches the
 * decoded payload to `req.user`. Responds 401 when missing/invalid/expired.
 *
 * Accepts TWO credential kinds:
 *   1. Short-lived JWTs minted by /auth/login (may carry a TOTP `amr` claim).
 *   2. Long-lived API tokens (`unm_…`) for agents/scripts — resolved against
 *      the api_tokens table; their permission set is re-intersected with the
 *      user's CURRENT effective permissions on every request, and they can
 *      never satisfy a 2FA requirement (no TOTP claim).
 *
 * Beyond signature/expiry checks this also enforces credential-policy state
 * LIVE (short-cached): a DISABLED user is rejected outright (`user_disabled`),
 * and a JWT session whose age exceeds the user's effective session timeout —
 * the global setting capped by any per-user `sessionTimeoutSeconds` override —
 * is treated as expired. API tokens are exempt from both: they carry their own
 * expiry and must not be cut short by an interactive-session policy.
 */

const AUTH_POLICY_CACHE_TTL_MS = 5_000;
interface AuthPolicyEntry {
  disabled: boolean;
  /** Effective session TTL in seconds (global capped by the per-user override). */
  ttlSeconds: number;
  cachedAt: number;
}
const authPolicyCache = new Map<string, AuthPolicyEntry>();

/** Resolves a user's live policy state (disabled flag + effective session TTL), short-cached. */
async function resolveAuthState(userId: string): Promise<AuthPolicyEntry> {
  const now = Date.now();
  let entry = authPolicyCache.get(userId);
  if (!entry || now - entry.cachedAt > AUTH_POLICY_CACHE_TTL_MS) {
    const [policy, userRow] = await Promise.all([
      resolveCredentialPolicy(userId),
      db.query.users.findFirst({ where: (u, { eq }) => eq(u.id, userId) }),
    ]);
    const globalTtl = Number(await getEffectiveSettingValue('sessionTimeoutSeconds')) || 3600;
    entry = { disabled: Boolean(userRow?.disabled), ttlSeconds: effectiveSessionTtl(globalTtl, policy), cachedAt: now };
    authPolicyCache.set(userId, entry);
  }
  return entry;
}

export async function requireAuth(req: Request, res: Response, next: NextFunction): Promise<void> {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Authentication required' });
    return;
  }

  const token = header.slice('Bearer '.length).trim();
  let payload: AccessTokenPayload | null = null;
  try {
    payload = verifyToken<AccessTokenPayload>(token);
  } catch {
    // Not a valid JWT — fall through to the API-token lookup.
  }

  if (payload) {
    req.user = payload;
    const state = await resolveAuthState(payload.sub).catch(() => null);
    if (!state) {
      res.status(503).json({ error: 'Unable to verify account status' });
      return;
    }
    if (state.disabled) {
      res.status(401).json({ error: 'Account is disabled', code: 'user_disabled' });
      return;
    }
    // Enforce the per-user session cap against the JWT's issued-at time. The
    // static `exp` claim cannot be shortened after minting, so we compare age
    // to the effective TTL instead (a shorter global setting also applies).
    const iat = typeof payload.iat === 'number' ? payload.iat : null;
    if (iat !== null && Date.now() / 1000 - iat > state.ttlSeconds) {
      res.status(401).json({ error: 'Session expired', code: 'session_expired' });
      return;
    }
    next();
    return;
  }

  const tokenPayload = await resolveApiTokenPayload(token).catch(() => null);
  if (tokenPayload) {
    req.user = tokenPayload as unknown as AccessTokenPayload;
    next();
    return;
  }
  res.status(401).json({ error: 'Invalid or expired token' });
}

/**
 * Factory for middleware that ensures the authenticated user carries a given
 * permission string (e.g. `devices:write`).
 */
export function requirePermission(permission: string) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const permissions = req.user?.permissions ?? [];
    if (!permissions.includes(permission)) {
      res.status(403).json({ error: `Missing required permission: ${permission}` });
      return;
    }
    next();
  };
}

/**
 * Device-level access gate for routes parameterized by `:id`. Callers
 * carrying the `devices:all` permission pass through untouched; everyone else
 * is checked against their effective device scope (own rules ∪ role rules,
 * resolved live with a short in-memory cache — see deviceAccess.ts). Out-of-
 * scope devices answer 404 "Device not found" rather than 403 so the existence
 * of a device is never leaked to callers who cannot see it. Must run AFTER
 * requireAuth (it reads req.user) and BEFORE any handler that touches the DB.
 */
export async function requireDeviceAccess(req: Request, res: Response, next: NextFunction): Promise<void> {
  // Express 5 types params as string | string[] — coerce (all routes here use single-segment params).
  const deviceId = String(req.params.deviceId ?? '');
  if (!deviceId || isUnrestricted(req)) {
    next();
    return;
  }

  try {
    const allowed = await allowedDeviceIds(req);
    if (allowed !== null && !allowed.has(deviceId)) {
      res.status(404).json({ error: 'Device not found' });
      return;
    }
    next();
  } catch (err) {
    // Fail closed — a scope-resolution hiccup must never open the device.
    console.error('[auth] requireDeviceAccess failed:', err);
    res.status(503).json({ error: 'Unable to verify device access' });
  }
}

/**
 * Ensures the session satisfies the user's credential-policy gate. The policy
 * is resolved LIVE (per request, short-cached) so an admin changing which AMRs
 * satisfy the gate takes effect immediately for existing sessions — no waiting
 * out the 1h JWT TTL. A session passes when its `amr` claim intersects the
 * user's effective `gateAmrs`. Long-lived API tokens (amr ['token']) can never
 * pass, same as before. Used for privileged endpoints marked
 * `x-2fa-required: true` in the OpenAPI spec (e.g. config job submission).
 */

const GATE_POLICY_CACHE_TTL_MS = 5_000;
const gatePolicyCache = new Map<string, { gateAmrs: string[]; cachedAt: number }>();

export async function require2FA(req: Request, res: Response, next: NextFunction): Promise<void> {
  const amr = req.user?.amr ?? [];
  if (amr.length === 0) {
    res.status(401).json({ error: '2FA-completed session required' });
    return;
  }

  try {
    const now = Date.now();
    let entry = gatePolicyCache.get(req.user!.sub);
    if (!entry || now - entry.cachedAt > GATE_POLICY_CACHE_TTL_MS) {
      const policy = await resolveCredentialPolicy(req.user!.sub);
      entry = { gateAmrs: [...policy.gateAmrs], cachedAt: now };
      gatePolicyCache.set(req.user!.sub, entry);
    }

    if (!amr.some((a) => entry!.gateAmrs.includes(a))) {
      res.status(401).json({ error: '2FA-completed session required' });
      return;
    }
  } catch (err) {
    // Fail closed on policy-lookup errors — privileged endpoints must not be
    // opened by an infrastructure hiccup.
    console.error('[auth] require2FA policy lookup failed:', err);
    res.status(503).json({ error: 'Unable to evaluate 2FA requirement' });
    return;
  }

  next();
}
