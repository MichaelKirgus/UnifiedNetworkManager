import { verifyAuthenticationResponse } from '@simplewebauthn/server';
import type { WebauthnCredentialRecord } from './apiClient';

/**
 * WebAuthn assertion verification for the basic-auth identity provider.
 *
 * The API generates the authentication options (it owns the RP identity and
 * the nonce bound to the challenge entry); this module verifies the browser's
 * response against one of the user's enrolled credentials:
 *   - expectedChallenge = the nonce stored on the challenge entry (replay protection)
 *   - expectedOrigin / expectedRPID from env (same values as the API uses for
 *     option generation — compose passes WEBAUTHN_ORIGIN/WEBAUTHN_RP_ID to both)
 *   - credential = { id, publicKey (base64→bytes), counter } from the DB row
 */

let cachedConfig: { rpId: string; origins: string[] } | null = null;

function getConfig(): { rpId: string; origins: string[] } {
  if (!cachedConfig) {
    const rpId = process.env.WEBAUTHN_RP_ID?.trim() || 'localhost';
    const origins = (process.env.WEBAUTHN_ORIGIN ?? 'http://localhost:5173')
      .split(',')
      .map((o) => o.trim())
      .filter(Boolean);
    cachedConfig = { rpId, origins };
  }
  return cachedConfig;
}

export interface VerifiedAssertion {
  /** The DB id of the credential that satisfied the assertion (for counter bump). */
  credentialDbId: string;
  /** New signature counter to persist. */
  newCounter: number;
  userVerified: boolean;
}

/**
 * Verifies a login assertion against ONE enrolled credential. Throws on any
 * verification failure (SimpleWebAuthn raises with descriptive messages).
 */
export async function verifyAssertion(params: {
  response: unknown; // PublicKeyCredentialAuthenticationResponse from the browser
  expectedChallenge: string; // the nonce bound to the challenge entry
  credential: WebauthnCredentialRecord;
}): Promise<VerifiedAssertion> {
  const cfg = getConfig();

  const verified = await verifyAuthenticationResponse({
    response: params.response as never,
    expectedChallenge: params.expectedChallenge,
    expectedOrigin: cfg.origins,
    expectedRPID: cfg.rpId,
    credential: {
      id: params.credential.credentialId,
      publicKey: Buffer.from(params.credential.publicKey, 'base64'),
      counter: params.credential.counter,
    },
    // UV is discouraged in the options (2FA step on top of the password) —
    // don't hard-require it; user presence is still enforced by WebAuthn.
    requireUserVerification: false,
  });

  if (!verified.authenticationInfo || !verified.authenticationInfo.newCounter) {
    throw new Error('Assertion verification did not produce a counter');
  }

  return {
    credentialDbId: params.credential.id,
    newCounter: verified.authenticationInfo.newCounter,
    userVerified: Boolean(verified.authenticationInfo.userVerified),
  };
}
