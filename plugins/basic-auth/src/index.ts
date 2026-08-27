import { createPluginServer, requirePluginKey, resolvePluginIdentity } from '@unm/plugin-sdk';
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

// Pre-wired app (cors + json + /healthz + /discover, mDNS on listen) comes from
// @unm/plugin-sdk — this file only registers its own routes.
const server = createPluginServer({
  identity,
  logTag: 'basic-auth-plugin',
  discovery: {
    // The `identityProvider` capability marks this plugin as an identity provider;
    // `flow` tells the webapp which UI to render.
    identityProvider: { flow: 'password' },
  },
});
const app = server.app;

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

  const user = await getUserByUsername(typeof username === 'string' ? username : '');
  if (!user || !bcrypt.compareSync(typeof password === 'string' ? password : '', user.passwordHash)) {
    res.status(401).json({ error: 'Invalid username or password' });
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

  purgeExpiredChallenges();
  const entry = typeof challengeToken === 'string' ? challenges.get(challengeToken) : undefined;
  if (!entry) {
    res.status(401).json({ error: 'Invalid or expired 2FA challenge/token' });
    return;
  }

  const user = await getUserById(entry.userId);
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
