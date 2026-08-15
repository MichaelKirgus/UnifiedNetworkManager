import { NextFunction, Request, Response } from 'express';
import { verifyToken, AccessTokenPayload } from './jwt';

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
 */
export function requireAuth(req: Request, res: Response, next: NextFunction): void {
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
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
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
