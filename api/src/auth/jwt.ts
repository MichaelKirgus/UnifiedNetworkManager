import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET ?? 'dev-secret';

export interface AccessTokenPayload {
  sub: string;
  username: string;
  roles: string[];
  permissions: string[];
  amr?: string[];
  [key: string]: unknown;
}

export interface ChallengeTokenPayload {
  sub: string;
  purpose: 'challenge';
  [key: string]: unknown;
}

/**
 * Signs a JWT with the given payload. Defaults to a 1 hour expiry.
 */
export function signToken(payload: Record<string, unknown>, expiresIn: string | number = '1h'): string {
  return jwt.sign(payload, JWT_SECRET, { expiresIn } as jwt.SignOptions);
}

/**
 * Verifies a JWT and returns its decoded payload, or throws if invalid/expired.
 */
export function verifyToken<T extends object = AccessTokenPayload>(token: string): T {
  return jwt.verify(token, JWT_SECRET) as T;
}
