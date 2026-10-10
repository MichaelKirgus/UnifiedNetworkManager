// otplib@13 dropped the `authenticator` instance in favor of a functional API
// (verifySync/generateSecret/generateURI). verifySync returns { valid } — not a boolean.
import { generateSecret as otpGenerateSecret, generateURI, verifySync } from 'otplib';

/**
 * Verifies a 6-digit TOTP code against the given base32 secret.
 */
export function verifyTotp(secret: string, code: string): boolean {
  try {
    return verifySync({ token: code, secret }).valid;
  } catch (err) {
    // Log the real reason (e.g. SecretTooShortError for a legacy/corrupt stored
    // secret) — but never the secret or the attempted code themselves.
    console.error('[basic-auth] TOTP verification error:', err instanceof Error ? err.message : String(err));
    return false;
  }
}

/**
 * Generates a new base32 TOTP secret for enrolling a user's authenticator app.
 */
export function generateSecret(): string {
  return otpGenerateSecret();
}

/**
 * Builds an otpauth:// URI suitable for rendering as a QR code during enrollment.
 */
export function buildOtpAuthUri(username: string, secret: string, issuer = 'UnifiedNetworkManager'): string {
  return generateURI({ strategy: 'totp', issuer, label: username, secret });
}
