import {
  PluginOptionDescriptor,
  createPluginLogger,
  createPluginServer,
  readSettings,
  requirePluginKey,
  resolvePluginIdentity,
} from '@unm/plugin-sdk';
import bcrypt from 'bcryptjs';
import { v4 as uuidv4 } from 'uuid';
import { verifyTotp } from './totp';
import { getUserByUsername, getUserById, getWebauthnCredentials, updateWebauthnCredentialCounter } from './apiClient';
import { verifyAssertion } from './webauthn';

export const PLUGIN_UUID = '00000000-0000-4000-8000-000000000001';
export const PLUGIN_NAME = 'Basic Auth (Local Users + TOTP)';

/**
 * Multi-instance support: set `PLUGIN_INSTANCE_ID` (e.g. "site-a") to run several
 * instances of the same plugin type — each advertises a distinct identity
 * (`<uuid>:<instanceId>`) so the API registers them as separate plugins.
 * `PLUGIN_DISPLAY_NAME` optionally overrides the advertised name; without it,
 * the instance id is appended. Unset = single-instance behavior.
 * (Convention implemented in @unm/plugin-sdk's resolvePluginIdentity.)
 */
const identity = resolvePluginIdentity({
  uuid: PLUGIN_UUID,
  name: PLUGIN_NAME,
  version: '0.1.0',
  vendors: ['unm'],
  capabilities: ['identityProvider'],
  authType: 'token',
});

const CHALLENGE_TTL_MS = 5 * 60 * 1000;

/**
 * Configurable options. This plugin is called by the API's auth broker (not the
 * telemetry loop), but the settings header still flows through — so `logToApi`
 * works here exactly like in device-facing plugins.
 */
const PLUGIN_OPTIONS: PluginOptionDescriptor[] = [
  {
    key: 'logToApi',
    label: 'Send logs to UNM',
    type: 'boolean' as const,
    default: true,
    description:
      'Ship structured log entries (failed login/2FA attempts, API errors) to the UNM API for the Logs view. Disable to keep logging container-local only.',
  },
];

// Pre-wired app (cors + json + /healthz + /discover, mDNS on listen) comes from
// @unm/plugin-sdk — this file only registers its own routes.
const server = createPluginServer({
  identity,
  logTag: 'basic-auth-plugin',
  discovery: {
    // The `identityProvider` capability marks this plugin as an identity provider;
    // `flow` tells the webapp which UI to render.
    identityProvider: { flow: 'password' },
    options: PLUGIN_OPTIONS,
  },
});
const app = server.app;

// Structured logs shipped to the API (see docs/PLUGIN-DEVELOPMENT.md, Logging).
// Emission is gated per call by the `logToApi` option via setEnabled() — it
// flows through the settings loop, so it works globally and per-device.
const logger = createPluginLogger(identity);

// --- Challenge token store (in-memory, 5-minute TTL) -----------------------
interface ChallengeEntry {
  userId: string;
  expiresAt: number;
  // WebAuthn nonce bound to this challenge (set when assertion options are
  // requested). The verify endpoint rejects any response whose challenge does
  // not match — replay protection across the two-step flow.
  webauthnNonce?: string;
}
const challenges = new Map<string, ChallengeEntry>();

function purgeExpiredChallenges(): void {
  const now = Date.now();
  for (const [token, entry] of challenges.entries()) {
    if (entry.expiresAt <= now) {
      challenges.delete(token);
    }
  }
}

/**
 * Step 1: verify credentials. On success, issues a single-use challenge token
 * (2FA pending). The API broker forwards this to the webapp.
 *
 * Credential policy enforcement: the API resolves the user's effective policy
 * and passes `policy.requiredMethods` (which enrolled 2nd factors satisfy step
 * 2; empty = no 2FA required). When non-empty but NONE of the allowed methods
 * is enrolled, login fails with the distinct `no_2fa_enrolled` error so the UI
 * can point to enrollment.
 */
app.post('/auth/login', requirePluginKey, async (req, res) => {
  const { username, password, policy } = req.body ?? {};
  logger.setEnabled(readSettings(req, PLUGIN_OPTIONS).logToApi === true);

  let user;
  try {
    user = await getUserByUsername(typeof username === 'string' ? username : '');
    if (!user || !bcrypt.compareSync(typeof password === 'string' ? password : '', user.passwordHash)) {
      // Security-relevant: failed credential check (bounded by the API's auth rate limiter).
      logger.warn(`Login attempt with invalid credentials for "${typeof username === 'string' ? username : '?'}"`, { context: { username } });
      res.status(401).json({ error: 'Invalid username or password' });
      return;
    }
  } catch (err) {
    logger.error(`User lookup failed during login for "${typeof username === 'string' ? username : '?'}": ${(err as Error).message}`, { context: { username } });
    res.status(502).json({ error: 'Identity backend unavailable' });
    return;
  }

  // Policy check (best-effort — a lookup failure must not lock everyone out).
  const requiredMethods = Array.isArray(policy?.requiredMethods) ? policy.requiredMethods : [];
  if (requiredMethods.length > 0) {
    try {
      const hasTotp = Boolean(user.totpSecret);
      let passkeyCount = 0;
      if (!hasTotp || !requiredMethods.includes('totp')) {
        // Only fetch credentials when they could satisfy the policy.
        if (requiredMethods.includes('webauthn')) {
          const creds = await getWebauthnCredentials(user.id);
          passkeyCount = creds.length;
        }
      }
      const satisfies =
        (requiredMethods.includes('totp') && hasTotp) ||
        (requiredMethods.includes('webauthn') && passkeyCount > 0);
      if (!satisfies) {
        logger.warn(`Login blocked for "${user.username}": no enrolled second factor satisfies the credential policy`, { context: { username: user.username, requiredMethods } });
        res.status(401).json({ error: 'no_2fa_enrolled' });
        return;
      }
    } catch (err) {
      logger.error(`Credential policy check failed during login for "${user.username}": ${(err as Error).message}`);
      // Fail open on the 2FA-enrollment check — step 2 still requires a valid
      // TOTP code or passkey assertion, so no security is lost.
    }
  }

  purgeExpiredChallenges();
  const challengeToken = uuidv4();
  challenges.set(challengeToken, { userId: user.id, expiresAt: Date.now() + CHALLENGE_TTL_MS });

  res.status(200).json({ challengeToken, twoFactorRequired: true });
});

/**
 * Re-validation challenge: issue a 2FA challenge for an ALREADY-authenticated
 * user WITHOUT re-checking the password. The API calls this from its
 * /auth/revalidate/challenge route — it has already verified the caller's JWT,
 * so it passes the caller's own userId (the plugin trusts the shared
 * x-plugin-api-key + that id). Lets a session whose 2FA `amr` expired re-prove
 * TOTP/passkey to mint a fresh token without a full re-login.
 */
app.post('/auth/revalidate/challenge', requirePluginKey, async (req, res) => {
  const { userId } = req.body ?? {};
  logger.setEnabled(readSettings(req, PLUGIN_OPTIONS).logToApi === true);

  if (typeof userId !== 'string' || !userId) {
    res.status(400).json({ error: 'userId is required' });
    return;
  }
  let user;
  try {
    user = await getUserById(userId);
  } catch (err) {
    logger.error(`User lookup failed during revalidation challenge for "${userId}": ${(err as Error).message}`);
    res.status(502).json({ error: 'Identity backend unavailable' });
    return;
  }
  if (!user) {
    res.status(401).json({ error: 'Unknown user' });
    return;
  }

  purgeExpiredChallenges();
  const challengeToken = uuidv4();
  challenges.set(challengeToken, { userId: user.id, expiresAt: Date.now() + CHALLENGE_TTL_MS });
  res.status(200).json({ challengeToken, twoFactorRequired: true });
});

/**
 * Step 2: verify the TOTP code for the challenge and return the verified
 * identity assertion. The API broker mints the platform JWT from this.
 */
app.post('/auth/2fa/verify', requirePluginKey, async (req, res) => {
  const { challengeToken, code } = req.body ?? {};
  logger.setEnabled(readSettings(req, PLUGIN_OPTIONS).logToApi === true);

  purgeExpiredChallenges();
  const entry = typeof challengeToken === 'string' ? challenges.get(challengeToken) : undefined;
  if (!entry) {
    // Security-relevant: unknown/expired challenge (possible replay or stale UI).
    logger.warn('2FA verification with an invalid or expired challenge token');
    res.status(401).json({ error: 'Invalid or expired 2FA challenge/token' });
    return;
  }

  let user;
  try {
    user = await getUserById(entry.userId);
  } catch (err) {
    logger.error(`User lookup failed during 2FA verification: ${(err as Error).message}`);
    res.status(502).json({ error: 'Identity backend unavailable' });
    return;
  }
  if (!user) {
    res.status(401).json({ error: 'Invalid or expired 2FA challenge/token' });
    return;
  }

  let totpVerified = false;
  if (user.totpSecret) {
    const valid = verifyTotp(user.totpSecret, typeof code === 'string' ? code : '');
    if (!valid) {
      res.status(401).json({ error: 'Invalid or expired 2FA challenge/token' });
      return;
    }
    totpVerified = true;
  }
  // If no TOTP secret is enrolled, allow completion in dev mode but do NOT
  // claim `totp` in `amr` — this keeps `require2FA`-gated endpoints locked.

  challenges.delete(challengeToken);

  const roles = JSON.parse(user.roles) as string[];
  const permissions = JSON.parse(user.permissions) as string[];

  res.status(200).json({
    identity: {
      userId: user.id,
      username: user.username,
      roles,
      permissions,
      amr: totpVerified ? ['totp'] : ['pwd'],
    },
  });
});

/**
 * Step 2 (passkey variant, part a): bind the WebAuthn nonce to a pending
 * challenge. Called by the API broker AFTER it generated the assertion options
 * (the nonce doubles as the WebAuthn challenge). Returns the user's enrolled
 * credential ids so the browser prompt is restricted to this account.
 */
app.post('/auth/webauthn/assertion-options', requirePluginKey, async (req, res) => {
  const { challengeToken, nonce } = req.body ?? {};
  logger.setEnabled(readSettings(req, PLUGIN_OPTIONS).logToApi === true);

  purgeExpiredChallenges();
  const entry = typeof challengeToken === 'string' ? challenges.get(challengeToken) : undefined;
  if (!entry || typeof nonce !== 'string' || !nonce) {
    res.status(401).json({ error: 'Invalid or expired 2FA challenge/token' });
    return;
  }

  entry.webauthnNonce = nonce;

  let credentialIds: string[] = [];
  try {
    const creds = await getWebauthnCredentials(entry.userId);
    credentialIds = creds.map((c) => c.credentialId);
  } catch (err) {
    logger.error(`Passkey lookup failed during assertion-options for challenge: ${(err as Error).message}`);
    res.status(502).json({ error: 'Identity backend unavailable' });
    return;
  }

  let user;
  try {
    user = await getUserById(entry.userId);
  } catch (err) {
    logger.error(`User lookup failed during assertion-options: ${(err as Error).message}`);
    res.status(502).json({ error: 'Identity backend unavailable' });
    return;
  }
  if (!user) {
    challenges.delete(challengeToken);
    res.status(401).json({ error: 'Invalid or expired 2FA challenge/token' });
    return;
  }

  res.status(200).json({ userId: user.id, username: user.username, credentialIds });
});

/**
 * Step 2 (passkey variant, part b): verify the WebAuthn assertion for a
 * pending challenge and return the verified identity. The nonce must match the
 * one bound in part a; the response is checked against every enrolled
 * credential of the user (first valid one wins). On success the signature
 * counter is bumped and the challenge consumed.
 */
app.post('/auth/webauthn/verify', requirePluginKey, async (req, res) => {
  const { challengeToken, response, nonce } = req.body ?? {};
  logger.setEnabled(readSettings(req, PLUGIN_OPTIONS).logToApi === true);

  purgeExpiredChallenges();
  const entry = typeof challengeToken === 'string' ? challenges.get(challengeToken) : undefined;
  if (!entry || !entry.webauthnNonce || entry.webauthnNonce !== nonce) {
    // Unknown/expired challenge OR nonce mismatch (replay attempt).
    logger.warn('WebAuthn verification with an invalid, expired or replayed challenge/nonce');
    res.status(401).json({ error: 'Invalid or expired 2FA challenge/token' });
    return;
  }

  let user;
  try {
    user = await getUserById(entry.userId);
  } catch (err) {
    logger.error(`User lookup failed during WebAuthn verification: ${(err as Error).message}`);
    res.status(502).json({ error: 'Identity backend unavailable' });
    return;
  }
  if (!user) {
    challenges.delete(challengeToken);
    res.status(401).json({ error: 'Invalid or expired 2FA challenge/token' });
    return;
  }

  let credentials;
  try {
    credentials = await getWebauthnCredentials(user.id);
  } catch (err) {
    logger.error(`Passkey lookup failed during WebAuthn verification: ${(err as Error).message}`);
    res.status(502).json({ error: 'Identity backend unavailable' });
    return;
  }

  if (response === undefined || response === null) {
    challenges.delete(challengeToken);
    res.status(401).json({ error: 'Passkey verification failed' });
    return;
  }

  // Try each enrolled credential (multiple passkeys = multiple devices).
  let verified: { credentialDbId: string; newCounter: number } | null = null;
  for (const cred of credentials) {
    try {
      const result = await verifyAssertion({ response, expectedChallenge: entry.webauthnNonce, credential: cred });
      verified = { credentialDbId: result.credentialDbId, newCounter: result.newCounter };
      break;
    } catch {
      // Not this credential — try the next one.
    }
  }

  if (!verified) {
    logger.warn(`WebAuthn assertion rejected for "${user.username}" (no enrolled credential matched)`);
    challenges.delete(challengeToken);
    res.status(401).json({ error: 'Passkey verification failed' });
    return;
  }

  // Bump the counter (best-effort — a failure here must not block login).
  try {
    await updateWebauthnCredentialCounter(verified.credentialDbId, verified.newCounter);
  } catch (err) {
    logger.error(`Failed to bump passkey counter after successful assertion: ${(err as Error).message}`);
  }

  challenges.delete(challengeToken);

  const roles = JSON.parse(user.roles) as string[];
  const permissions = JSON.parse(user.permissions) as string[];

  res.status(200).json({
    identity: {
      userId: user.id,
      username: user.username,
      roles,
      permissions,
      amr: ['pwd', 'webauthn'],
    },
  });
});

// listen() binds the conventional plugin port (4080 by default) and starts
// mDNS advertising — both handled by @unm/plugin-sdk.
server.listen().catch((err) => {
  console.error('[basic-auth-plugin] fatal startup error:', err);
  process.exit(1);
});
