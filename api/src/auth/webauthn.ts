import { randomBytes } from 'node:crypto';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';

/**
 * WebAuthn (passkey) configuration + option generation.
 *
 * The API OWNS the relying-party identity and generates all WebAuthn options;
 * the basic-auth plugin performs assertion verification during login (it owns
 * the challenge store). Registration attestation is verified HERE, in the API,
 * when a passkey is enrolled via POST /users/:id/passkeys.
 *
 * Environment:
 *   WEBAUTHN_RP_ID    — relying party id (default "localhost"; set to your
 *                        domain in production, e.g. "unm.example.com")
 *   WEBAUTHN_ORIGIN   — webapp origin(s), comma-separated list allowed by the
 *                        browser (default "http://localhost:8080"). Production
 *                        MUST use https origins.
 */

export interface WebauthnConfig {
  rpId: string;
  rpName: string;
  origins: string[];
}

let cachedConfig: WebauthnConfig | null = null;

/** Resolves the RP config from env (cached after first read). */
export function getWebauthnConfig(): WebauthnConfig {
  if (!cachedConfig) {
    const rpId = process.env.WEBAUTHN_RP_ID?.trim() || 'localhost';
    const origins = (process.env.WEBAUTHN_ORIGIN ?? 'http://localhost:8080')
      .split(',')
      .map((o) => o.trim())
      .filter(Boolean);
    cachedConfig = { rpId, rpName: 'UnifiedNetworkManager', origins };
  }
  return cachedConfig;
}

/** Fresh random challenge (base64url), used as the WebAuthn nonce. */
export function generateWebauthnNonce(): string {
  return Buffer.from(randomBytes(32)).toString('base64url');
}

/**
 * Builds authentication options for a login assertion. `allowCredentials` is
 * the user's enrolled credential ids (empty = discoverable, any of their
 * passkeys may be used). `nonceOverride` pins the challenge to an externally
 * generated nonce (the API generates it so the provider can bind it to its
 * in-memory challenge entry for replay protection).
 */
export async function buildAuthenticationOptions(params: {
  userId: string;
  username: string;
  allowCredentials?: string[];
  nonceOverride?: string;
}) {
  const cfg = getWebauthnConfig();
  return await generateAuthenticationOptions({
    challenge: params.nonceOverride ?? generateWebauthnNonce(),
    rpID: cfg.rpId,
    // userVerification 'discouraged' — this is a 2FA step on top of the
    // password; we don't want to force a PIN/biometric prompt that some
    // platform authenticators would add friction for. Presence is still
    // required by WebAuthn itself.
    userVerification: 'discouraged',
    timeout: 60_000,
    allowCredentials: (params.allowCredentials ?? []).map((credentialId) => ({ id: credentialId })),
  });
}

/**
 * Builds registration options for enrolling a new passkey. `excludeCredentials`
 * are the user's already-enrolled ids so the authenticator won't re-register
 * one of them.
 */
export async function buildRegistrationOptions(params: {
  userId: string;
  username: string;
  excludeCredentials?: string[];
}) {
  const cfg = getWebauthnConfig();
  return await generateRegistrationOptions({
    rpID: cfg.rpId,
    rpName: cfg.rpName,
    userName: params.username,
    userDisplayName: params.username,
    userID: Buffer.from(params.userId),
    challenge: generateWebauthnNonce(),
    timeout: 120_000,
    attestationType: 'none',
    authenticatorSelection: {
      residentKey: 'preferred',
      requireResidentKey: false,
      userVerification: 'discouraged',
    },
    excludeCredentials: (params.excludeCredentials ?? []).map((credentialId) => ({ id: credentialId })),
  });
}

/**
 * Verifies a registration attestation response and returns the stored form of
 * the new credential. Throws on invalid/failed verification (SimpleWebAuthn
 * raises with a descriptive message).
 */
export async function verifyRegistration(params: {
  expectedChallenge: string;
  response: unknown; // PublicKeyCredentialCreationResponse from the browser
}) {
  const cfg = getWebauthnConfig();
  return await verifyRegistrationResponse({
    response: params.response as never,
    expectedChallenge: params.expectedChallenge,
    expectedOrigin: cfg.origins,
    expectedRPID: cfg.rpId,
    requireUserPresence: true,
    // UV is discouraged in the options (2FA context) — don't hard-require it.
    requireUserVerification: false,
  });
}
