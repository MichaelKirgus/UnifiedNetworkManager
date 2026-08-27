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
import { getUserByUsername, getUserById } from './apiClient';

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
 */
app.post('/auth/login', requirePluginKey, async (req, res) => {
  const { username, password } = req.body ?? {};
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

// listen() binds the conventional plugin port (4080 by default) and starts
// mDNS advertising — both handled by @unm/plugin-sdk.
server.listen().catch((err) => {
  console.error('[basic-auth-plugin] fatal startup error:', err);
  process.exit(1);
});
