import { NextFunction, Request, Response } from 'express';
import { verifyToken, AccessTokenPayload } from './jwt';
import { resolveApiTokenPayload } from './apiTokens';

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
 */
export async function requireAuth(req: Request, res: Response, next: NextFunction): Promise<void> {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Authentication required' });
    return;
  }

  const token = header.slice('Bearer '.length).trim();
  try {
    const payload = verifyToken(token);
    req.user = payload;
    next();
    return;
  } catch {
    // Not a valid JWT — fall through to the API-token lookup.
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
 * Ensures the JWT was issued after a completed 2FA challenge, i.e. its `amr`
 * claim includes `totp`. Used for privileged endpoints marked
 * `x-2fa-required: true` in the OpenAPI spec (e.g. config job submission).
 */
export function require2FA(req: Request, res: Response, next: NextFunction): void {
  const amr = req.user?.amr ?? [];
  if (!amr.includes('totp')) {
    res.status(401).json({ error: '2FA-completed session required' });
    return;
  }
  next();
}
