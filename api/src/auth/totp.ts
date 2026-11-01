// otplib@13 dropped the `authenticator` instance in favor of a functional API
// (verifySync/generateSecret/generateURI). verifySync returns { valid } — not a boolean.
import { generateSecret as otpGenerateSecret, generateURI, verifySync } from 'otplib';

/**
 * TOTP helpers used by the API for user provisioning (admin seeding).
 *
 * Note: TOTP *verification* during login is performed by the active identity
 * provider plugin (e.g. the basic-auth plugin), not here. The API only needs
 * to generate a secret and build the enrollment URI when it seeds users.
 */

/**
 * Generates a new base32 TOTP secret for enrolling a user's authenticator app.
 */
export function generateSecret(): string {
  return otpGenerateSecret();
}

/**
 * Builds an otpauth:// URI suitable for rendering a QR code during enrollment.
 */
export function buildOtpAuthUri(username: string, secret: string, issuer = 'UnifiedNetworkManager'): string {
  return generateURI({ strategy: 'totp', issuer, label: username, secret });
}
/**
 * Verifies a 6-digit TOTP code against a base32 secret (±1 time step). Used by
 * the onboarding flow to CONFIRM that the initial admin actually scanned their
 * freshly-enrolled secret before we stamp onboarding complete — so a half-done
 * enrollment can't be skipped past. Login-time verification still happens in the
 * identity provider plugin; this is only for the self-service confirm step.
 */
export function verifyTotp(secret: string, code: string): boolean {
  try {
    return verifySync({ token: (code ?? '').trim(), secret }).valid;
  } catch (err) {
    // Log the real reason (e.g. SecretTooShortError for a legacy/corrupt stored
    // secret) — but never the secret or the attempted code themselves.
    console.error('[auth] TOTP verification error:', err instanceof Error ? err.message : String(err));
    return false;
  }
}