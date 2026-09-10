import axios from 'axios';
import { eq } from 'drizzle-orm';
import { db } from '../db';
import * as schema from '../db/schema';
import { buildAuthenticationOptions, generateWebauthnNonce } from './webauthn';
import { resolveCredentialPolicy, isPasswordExpired } from './credentialPolicy';
import { expandRolePermissions } from '../routes/roles';

/**
 * Identity provider broker.
 *
 * The API no longer verifies credentials itself. It delegates to an identity
 * provider plugin (any plugin advertising the `identityProvider` capability)
 * and mints the platform JWT from the provider's verified identity assertion.
 *
 * Provider selection:
 *   - `AUTH_PLUGIN_ID` env var names the active provider (its plugin UUID).
 *   - If unset, or the named provider is unknown/offline, we fall back to the
 *     reserved basic-auth plugin (local users + TOTP).
 */

/** Reserved UUID for the built-in basic-auth identity provider plugin. */
export const BASIC_AUTH_PLUGIN_UUID = '00000000-0000-4000-8000-000000000001';

const PROVIDER_TIMEOUT_MS = 5000;
const PROVIDER_CACHE_TTL_MS = 5000;
const ONLINE_WINDOW_MS = 5 * 60 * 1000;

/** Verified identity returned by an identity provider after authentication. */
export interface IdentityAssertion {
  userId: string;
  username: string;
  displayName?: string;
  roles: string[];
  permissions: string[];
  amr: string[];
  externalId?: string;
}

export interface LoginResult {
  challengeToken: string;
  twoFactorRequired: boolean;
  /** True when the user's password has exceeded its max age — the webapp must
   *  force a password change right after sign-in completes. */
  passwordExpired?: boolean;
}

interface ProviderRecord {
  id: string;
  endpoint: string;
  capabilities: string[];
  lastSeenAt: string | null;
}

interface CachedProvider {
  record: ProviderRecord;
  cachedAt: number;
}

let cachedProvider: CachedProvider | null = null;

function parseCapabilities(raw: string | null | undefined): string[] {
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function isOnline(record: ProviderRecord, now: number): boolean {
  if (!record.lastSeenAt) return false;
  const last = Date.parse(record.lastSeenAt);
  if (Number.isNaN(last)) return false;
  return now - last <= ONLINE_WINDOW_MS;
}

function toRecord(row: typeof schema.plugins.$inferSelect): ProviderRecord {
  return {
    id: row.id,
    endpoint: row.endpoint,
    capabilities: parseCapabilities(row.capabilities),
    lastSeenAt: row.lastSeenAt,
  };
}

async function findProviderById(id: string): Promise<ProviderRecord | null> {
  const row = await db.query.plugins.findFirst({
    where: (plugins, { eq }) => eq(plugins.id, id),
  });
  return row ? toRecord(row) : null;
}

async function findFirstIdentityProvider(): Promise<ProviderRecord | null> {
  const rows = await db.query.plugins.findMany();
  const providers = rows
    .map(toRecord)
    .filter((p) => p.capabilities.includes('identityProvider'));
  if (providers.length === 0) return null;
  providers.sort((a, b) => (b.lastSeenAt ?? '').localeCompare(a.lastSeenAt ?? ''));
  return providers[0];
}

/**
 * Resolves the active identity provider. Honors `AUTH_PLUGIN_ID`; falls back
 * to the reserved basic-auth plugin (or the first registered identity
 * provider) when the named one is missing or offline.
 */
export async function resolveActiveProvider(): Promise<ProviderRecord> {
  const now = Date.now();
  if (cachedProvider && now - cachedProvider.cachedAt < PROVIDER_CACHE_TTL_MS) {
    return cachedProvider.record;
  }

  const configuredId = process.env.AUTH_PLUGIN_ID?.trim();
  let record: ProviderRecord | null = null;

  if (configuredId) {
    record = await findProviderById(configuredId);
    if (record && !isOnline(record, now)) {
      // eslint-disable-next-line no-console
      console.warn(`[identity] configured provider ${configuredId} is offline; falling back to basic-auth`);
      record = null;
    }
  }

  if (!record) {
    record = await findProviderById(BASIC_AUTH_PLUGIN_UUID);
  }
  if (!record) {
    record = await findFirstIdentityProvider();
  }

  if (!record) {
    throw Object.assign(
      new Error(
        'No identity provider available. Start the basic-auth plugin or set AUTH_PLUGIN_ID to a registered identity provider.'
      ),
      { status: 503 }
    );
  }

  cachedProvider = { record, cachedAt: now };
  return record;
}

/**
 * Calls an identity provider endpoint, authenticating with the shared
 * `x-plugin-api-key` (the same convention the API uses for its internal
 * plugin-facing routes).
 */
async function callProvider<T>(
  provider: ProviderRecord,
  path: string,
  body: Record<string, unknown>
): Promise<T> {
  const base = provider.endpoint.replace(/\/+$/, '');
  const apiKey = process.env.PLUGIN_API_KEY;

  try {
    const res = await axios.post<T>(`${base}${path}`, body, {
      timeout: PROVIDER_TIMEOUT_MS,
      headers: apiKey ? { 'x-plugin-api-key': apiKey } : undefined,
    });
    return res.data;
  } catch (err) {
    const e = err as {
      response?: { status?: number; data?: { error?: string } };
      message?: string;
    };
    const status = e.response?.status ?? 502;
    const message = e.response?.data?.error ?? `Identity provider unavailable (${e.message ?? 'error'})`;
    throw Object.assign(new Error(message), { status });
  }
}

/**
 * Step 1: verify credentials. Returns a challenge token (2FA pending).
 *
 * The user's effective credential policy is resolved HERE and forwarded to the
 * provider, which enforces it: if `requiredMethods` is non-empty but none of
 * the allowed methods is enrolled, login fails with `no_2fa_enrolled`.
 */
export async function login(username: string, password: string): Promise<LoginResult> {
  const provider = await resolveActiveProvider();

  // Resolve the user's policy up-front (best-effort — an unknown username just
  // gets the global default; the provider will reject the credentials anyway).
  let requiredMethods: string[] | undefined;
  let passwordExpired = false;
  try {
    const row = await db.query.users.findFirst({ where: eq(schema.users.username, username) });
    if (row) {
      // A disabled account is rejected BEFORE the provider even sees the
      // credentials — distinct code so the UI can say "contact an admin".
      if (row.disabled) {
        throw Object.assign(new Error('Account is disabled'), { status: 403, code: 'user_disabled' });
      }
      // Service-only lockdown: a user WITHOUT `auth:interactive-login` in their
      // effective set (explicit grants + roles) may not sign into the web UI.
      // The check runs before credential verification so the distinct error code
      // reaches the client; long-lived API tokens are never affected by this.
      let explicitPerms: string[] = [];
      try {
        explicitPerms = JSON.parse(row.permissions);
      } catch {
        /* keep [] */
      }
      let roleNames: string[] = [];
      try {
        roleNames = JSON.parse(row.roles);
      } catch {
        /* keep [] */
      }
      const effectivePerms = await expandRolePermissions(roleNames, Array.isArray(explicitPerms) ? explicitPerms : []);
      if (!effectivePerms.includes('auth:interactive-login')) {
        throw Object.assign(new Error('Interactive web-UI login is not allowed for this account'), {
          status: 403,
          code: 'no_interactive_login',
        });
      }
      const policy = await resolveCredentialPolicy(row.id);
      requiredMethods = [...policy.requiredMethods];
      passwordExpired = isPasswordExpired(policy, row.passwordChangedAt ?? null);
    }
  } catch (err) {
    // Deliberate policy rejections must propagate to the client verbatim.
    const code = (err as { code?: string })?.code;
    if (code === 'user_disabled' || code === 'no_interactive_login') throw err;
    // DB hiccup — let the provider decide with its own defaults.
  }

  const data = await callProvider<{
    twoFactorRequired?: boolean;
    challengeToken?: string;
  }>(provider, '/auth/login', { username, password, policy: { requiredMethods } });

  if (!data.challengeToken) {
    throw Object.assign(new Error('Identity provider did not return a challenge token'), { status: 502 });
  }

  return { challengeToken: data.challengeToken, twoFactorRequired: data.twoFactorRequired ?? true, passwordExpired };
}

/**
 * Re-validation challenge for an ALREADY-authenticated user — issues a 2FA
 * challenge WITHOUT re-checking the password. The caller (the API's
 * /auth/revalidate/challenge route) has already verified the JWT, so it passes
 * the caller's own userId; the provider trusts that id (shared plugin key).
 * Lets a session whose 2FA `amr` expired re-prove TOTP/passkey to mint a fresh
 * token without a full re-login. The completion steps reuse verify2fa /
 * webauthnAssertionOptions / verifyWebauthn unchanged.
 */
export async function revalidateChallenge(userId: string): Promise<LoginResult> {
  const provider = await resolveActiveProvider();

  const data = await callProvider<{
    twoFactorRequired?: boolean;
    challengeToken?: string;
  }>(provider, '/auth/revalidate/challenge', { userId });

  if (!data.challengeToken) {
    throw Object.assign(new Error('Identity provider did not return a revalidation challenge token'), { status: 502 });
  }

  return { challengeToken: data.challengeToken, twoFactorRequired: data.twoFactorRequired ?? true };
}

/**
 * Step 2: complete authentication (e.g. TOTP) and return the verified identity.
 */
export async function verify2fa(challengeToken: string, code: string): Promise<IdentityAssertion> {
  const provider = await resolveActiveProvider();
  const data = await callProvider<{ identity?: IdentityAssertion }>(provider, '/auth/2fa/verify', {
    challengeToken,
    code,
  });

  if (!data.identity) {
    throw Object.assign(new Error('Identity provider did not return a verified identity'), { status: 502 });
  }

  return data.identity;
}

/**
 * Step 2 (passkey variant): fetch WebAuthn assertion options for a pending
 * challenge. The API generates the nonce + options (it owns the RP identity);
 * the provider binds the nonce to its in-memory challenge entry so the later
 * verify call can reject replays/mismatches.
 */
export async function webauthnAssertionOptions(challengeToken: string): Promise<{
  // PublicKeyCredentialRequestOptionsJSON from @simplewebauthn/server.
  options: unknown;
  nonce: string;
}> {
  const provider = await resolveActiveProvider();

  // Generate the nonce FIRST so it can be both bound to the challenge entry
  // (replay protection) and used as the WebAuthn challenge.
  const nonce = generateWebauthnNonce();

  // Ask the provider to validate the challenge and bind our nonce to it. It
  // returns the user's enrolled credential ids so we can restrict the browser
  // prompt to this account's passkeys (allowCredentials).
  const data = await callProvider<{
    userId?: string;
    username?: string;
    credentialIds?: string[];
  }>(provider, '/auth/webauthn/assertion-options', { challengeToken, nonce });

  if (!data.userId || !data.username) {
    throw Object.assign(new Error('Identity provider did not accept the challenge token'), { status: 502 });
  }

  const options = await buildAuthenticationOptions({
    userId: data.userId,
    username: data.username,
    allowCredentials: Array.isArray(data.credentialIds) ? data.credentialIds : [],
    nonceOverride: nonce,
  });

  return { options, nonce };
}

/**
 * Step 2 (passkey variant): verify a WebAuthn assertion for a pending
 * challenge and return the verified identity. The provider checks the stored
 * nonce, the credential policy, and the signature/counter; it bumps the
 * counter through an internal API route.
 */
export async function verifyWebauthn(
  challengeToken: string,
  response: unknown,
  nonce: string
): Promise<IdentityAssertion> {
  const provider = await resolveActiveProvider();
  const data = await callProvider<{ identity?: IdentityAssertion }>(provider, '/auth/webauthn/verify', {
    challengeToken,
    response,
    nonce,
  });

  if (!data.identity) {
    throw Object.assign(new Error('Identity provider did not return a verified identity'), { status: 502 });
  }

  return data.identity;
}

/**
 * Returns the authentication `flow` of the active identity provider
 * (e.g. `password`, `oauth2`, `ldap`, `saml`). The webapp uses this to adapt
 * its login UI before the user enters any credentials.
 *
 * The flow is declared by the provider in its `GET /discover` response under
 * `identityProvider.flow`. Defaults to `password` when the provider does not
 * declare one.
 */
export async function getFlow(): Promise<string> {
  const provider = await resolveActiveProvider();
  const base = provider.endpoint.replace(/\/+$/, '');

  try {
    const res = await axios.get<{ identityProvider?: { flow?: string } }>(`${base}/discover`, {
      timeout: PROVIDER_TIMEOUT_MS,
    });
    const flow = res.data?.identityProvider?.flow;
    return typeof flow === 'string' && flow.length > 0 ? flow : 'password';
  } catch {
    // Discovery is best-effort; fall back to the common password flow.
    return 'password';
  }
}

/**
 * Returns the URL the webapp should redirect the user to in order to start an
 * external authentication flow (OAuth2 / SAML / LDAP web login). The provider
 * declares it in its `GET /discover` response under
 * `identityProvider.redirectUrl`.
 *
 * Throws a 501 when the active provider does not expose a redirect URL (e.g.
 * the basic-auth password provider), so the webapp can fall back to its
 * password form.
 */
export async function getRedirectUrl(): Promise<string> {
  const provider = await resolveActiveProvider();
  const base = provider.endpoint.replace(/\/+$/, '');

  try {
    const res = await axios.get<{ identityProvider?: { redirectUrl?: string } }>(
      `${base}/discover`,
      { timeout: PROVIDER_TIMEOUT_MS }
    );
    const url = res.data?.identityProvider?.redirectUrl;
    if (typeof url === 'string' && url.length > 0) {
      return url;
    }
  } catch {
    // fall through to the 501 below
  }

  throw Object.assign(
    new Error('The active identity provider does not support redirect-based login'),
    { status: 501 }
  );
}
