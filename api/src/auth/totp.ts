import { authenticator } from 'otplib';

/**
 * Verifies a 6-digit TOTP code against the given base32 secret.
 */
export function verifyTotp(secret: string, code: string): boolean {
  try {
    return authenticator.verify({ token: code, secret });
  } catch {
    return false;
  }
}

/**
 * Generates a new base32 TOTP secret for enrolling a user's authenticator app.
 */
export function generateSecret(): string {
  return authenticator.generateSecret();
}

/**
 * Builds an otpauth:// URI suitable for rendering as a QR code during enrollment.
 */
export function buildOtpAuthUri(username: string, secret: string, issuer = 'UnifiedNetworkManager'): string {
  return authenticator.keyuri(username, issuer, secret);
}
