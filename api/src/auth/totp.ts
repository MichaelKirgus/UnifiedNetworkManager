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
