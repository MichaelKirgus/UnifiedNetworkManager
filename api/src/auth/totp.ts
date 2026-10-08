import { authenticator } from 'otplib';

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
  return authenticator.generateSecret();
}

/**
 * Builds an otpauth:// URI suitable for rendering as a QR code during enrollment.
 */
export function buildOtpAuthUri(username: string, secret: string, issuer = 'UnifiedNetworkManager'): string {
  return authenticator.keyuri(username, issuer, secret);
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
    return authenticator.verify({ token: (code ?? '').trim(), secret });
  } catch {
    return false;
  }
}