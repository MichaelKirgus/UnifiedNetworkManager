import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import { v4 as uuidv4 } from 'uuid';
import { Bonjour } from 'bonjour-service';
import { verifyTotp } from './totp';
import { getUserByUsername, getUserById } from './apiClient';

export const PLUGIN_UUID = '00000000-0000-4000-8000-000000000001';
export const PLUGIN_NAME = 'Basic Auth (Local Users + TOTP)';
export const PLUGIN_VERSION = '0.1.0';
export const PLUGIN_VENDORS = ['unm'];
export const PLUGIN_CAPABILITIES = ['identityProvider'];
export const PLUGIN_AUTH_TYPE = 'token';

const PORT = Number(process.env.PORT ?? 4002);
const ADVERTISED_ENDPOINT = process.env.ADVERTISED_ENDPOINT ?? `http://localhost:${PORT}`;
const CHALLENGE_TTL_MS = 5 * 60 * 1000;

const app = express();
app.use(cors());
app.use(express.json());

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
 * Authenticates the calling UnifiedNetworkManager API using the shared
 * `x-plugin-api-key` (the same convention the API uses for its internal
 * plugin-facing routes). When `PLUGIN_API_KEY` is unset (dev), the check is
 * skipped to match the API's own behavior.
 */
function requirePluginKey(req: express.Request, res: express.Response, next: express.NextFunction): void {
  const expected = process.env.PLUGIN_API_KEY;
  const provided = req.headers['x-plugin-api-key'];
  if (expected && provided !== expected) {
    res.status(403).json({ error: 'Forbidden: Invalid plugin API key' });
    return;
  }
  next();
}

app.get('/healthz', (_req, res) => {
  res.status(200).json({ status: 'ok' });
});

/**
 * Plugin identity endpoint. The UnifiedNetworkManager API polls this (as a
 * fallback to mDNS discovery) to discover and upsert this plugin. The
 * `identityProvider` capability is what marks this plugin as an identity
 * provider; `flow` tells the webapp which UI to render.
 */
app.get('/discover', (_req, res) => {
  res.status(200).json({
    uuid: PLUGIN_UUID,
    name: PLUGIN_NAME,
    version: PLUGIN_VERSION,
    vendors: PLUGIN_VENDORS,
    capabilities: PLUGIN_CAPABILITIES,
    endpoint: ADVERTISED_ENDPOINT,
    authType: PLUGIN_AUTH_TYPE,
    identityProvider: { flow: 'password' },
  });
});

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

/**
 * Advertises this plugin over mDNS/DNS-SD so the API can discover it
 * automatically (service type `_unm-plugin._tcp`). Best-effort; the API also
 * polls known plugin endpoints as a fallback.
 */
function startMdnsAdvertising(): void {
  try {
    const bonjour = new Bonjour();
    bonjour.publish({
      name: PLUGIN_NAME,
      type: 'unm-plugin',
      port: PORT,
      txt: {
        uuid: PLUGIN_UUID,
        name: PLUGIN_NAME,
        version: PLUGIN_VERSION,
        vendors: PLUGIN_VENDORS.join(','),
        capabilities: PLUGIN_CAPABILITIES.join(','),
        endpoint: ADVERTISED_ENDPOINT,
        authType: PLUGIN_AUTH_TYPE,
      },
    });
    // eslint-disable-next-line no-console
    console.log(`[basic-auth-plugin] advertising via mDNS as "${PLUGIN_NAME}" (${PLUGIN_UUID})`);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.warn('[basic-auth-plugin] mDNS advertising unavailable:', (err as Error).message);
  }
}

async function start(): Promise<void> {
  app.listen(PORT, () => {
    // eslint-disable-next-line no-console
    console.log(`[basic-auth-plugin] listening on port ${PORT}`);
    startMdnsAdvertising();
  });
}

start().catch((err) => {
  // eslint-disable-next-line no-console
  console.error('[basic-auth-plugin] fatal startup error:', err);
  process.exit(1);
});
