import type { SecretField, SecretType } from '@unm/plugin-sdk';
import { pluginAxios } from './utils/pluginHttp';
import { eq } from 'drizzle-orm';
import { db } from './db';
import * as schema from './db/schema';

/**
 * Secrets provider broker.
 *
 * The API no longer encrypts/decrypts or manages secrets itself. It delegates
 * to secrets provider plugins (any plugin advertising the `secretsProvider`
 * capability). Each provider owns its own crypto (MASTER_KEY) and declares the
 * secret types it serves (field schemas) via its `/discover` endpoint. The API
 * keeps the `secrets` table (single source of truth) and exposes it to
 * providers via the internal `/plugin/secrets/*` routes.
 *
 * Multi-provider:
 *   - Each secret row records the `type` and the `providerId` that created it,
 *     so decryption is always routed back to the provider that owns the key.
 *   - `SECRETS_PLUGIN_ID` names the *default* provider used for new secrets
 *     when the caller doesn't specify one.
 *   - `listSecretProviders()` exposes all registered providers + their types.
 */

/** Reserved UUID for the built-in secrets provider plugin. */
export const SECRETS_PROVIDER_UUID = '00000000-0000-4000-8000-000000000002';

const PROVIDER_TIMEOUT_MS = 5000;
const PROVIDER_CACHE_TTL_MS = 5000;
const ONLINE_WINDOW_MS = 5 * 60 * 1000;

// The secret field/type contract lives in @unm/plugin-sdk — re-exported so API
// modules keep their existing imports.
export type { SecretField, SecretType };

/** A registered secrets provider + the secret types it serves. */
export interface SecretProviderInfo {
  id: string;
  name: string;
  version: string;
  endpoint: string;
  online: boolean;
  secretTypes: SecretType[];
}

/** A decrypted secret: its type + the decrypted field values. */
export interface DecryptedSecret {
  type: string;
  fields: Record<string, string>;
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

let cachedDefaultProvider: CachedProvider | null = null;

/** Per-provider cache of the secret types declared in /discover. */
const secretTypesCache = new Map<string, { types: SecretType[]; cachedAt: number }>();

// --- Decrypted-secret cache (poll-path decoupling) ---------------------------
// The telemetry worker fetches every assignment's decrypted secret on EVERY
// poll cycle — at 200 devices that is ~400 round-trips to the secrets provider
// per beat. Secrets rarely change, so we cache decrypted values briefly:
//   - cuts secrets-provider load by orders of magnitude at scale;
//   - if the provider plugin dies mid-cycle, in-flight polls keep working from
//     cache instead of flipping the whole fleet to 'unknown'.
// Invalidated on regenerate/delete (see routes/secrets.ts) so rotation is
// visible within one beat. TTL is env-tunable for large fleets.
const SECRET_CACHE_TTL_MS = Math.max(0, Number(process.env.SECRET_CACHE_TTL_MS ?? 60_000));
const secretCache = new Map<string, { value: DecryptedSecret; cachedAt: number }>();

/** Drops one (or all) cached decrypted secrets — call after rotation/deletion. */
export function invalidateSecretCache(secretId?: string): void {
  if (secretId === undefined) {
    secretCache.clear();
    return;
  }
  secretCache.delete(secretId);
}

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

async function findFirstSecretsProvider(): Promise<ProviderRecord | null> {
  const rows = await db.query.plugins.findMany();
  const providers = rows
    .map(toRecord)
    .filter((p) => p.capabilities.includes('secretsProvider'));
  if (providers.length === 0) return null;
  providers.sort((a, b) => (b.lastSeenAt ?? '').localeCompare(a.lastSeenAt ?? ''));
  return providers[0];
}

/**
 * Resolves a secrets provider. Honors an explicit `providerId`; otherwise
 * honors `SECRETS_PLUGIN_ID`; falls back to the reserved secrets-provider
 * plugin (or the first registered provider) when the named one is missing or
 * offline.
 */
export async function resolveSecretsProvider(providerId?: string): Promise<ProviderRecord> {
  const now = Date.now();
  const explicit = providerId?.trim();

  if (explicit) {
    const record = await findProviderById(explicit);
    if (record && record.capabilities.includes('secretsProvider')) {
      return record;
    }
    throw Object.assign(new Error(`Unknown secrets provider: ${explicit}`), { status: 400 });
  }

  if (cachedDefaultProvider && now - cachedDefaultProvider.cachedAt < PROVIDER_CACHE_TTL_MS) {
    return cachedDefaultProvider.record;
  }

  const configuredId = process.env.SECRETS_PLUGIN_ID?.trim();
  let record: ProviderRecord | null = null;

  if (configuredId) {
    record = await findProviderById(configuredId);
    if (record && !isOnline(record, now)) {
      // eslint-disable-next-line no-console
      console.warn('[secrets] configured provider is offline; falling back to secrets-provider');
      record = null;
    }
  }

  if (!record) {
    record = await findProviderById(SECRETS_PROVIDER_UUID);
  }
  if (!record) {
    record = await findFirstSecretsProvider();
  }

  if (!record) {
    throw Object.assign(
      new Error(
        'No secrets provider available. Start the secrets-provider plugin or set SECRETS_PLUGIN_ID to a registered provider.'
      ),
      { status: 503 }
    );
  }

  cachedDefaultProvider = { record, cachedAt: now };
  return record;
}

/**
 * Calls a secrets provider endpoint, authenticating with the shared
 * `x-plugin-api-key`.
 */
async function callProvider<T>(
  provider: ProviderRecord,
  path: string,
  method: 'GET' | 'POST' | 'PATCH' | 'DELETE',
  body?: Record<string, unknown>
): Promise<T> {
  const apiKey = process.env.PLUGIN_API_KEY;
  const headers = apiKey ? { 'x-plugin-api-key': apiKey } : undefined;
  // mTLS (Stage 1): pluginAxios picks the transport for this provider.
  const http = pluginAxios(provider.endpoint);

  try {
    if (method === 'GET') {
      const res = await http.get<T>(path, { timeout: PROVIDER_TIMEOUT_MS, headers });
      return res.data;
    }
    if (method === 'PATCH') {
      const res = await http.patch<T>(path, body, { timeout: PROVIDER_TIMEOUT_MS, headers });
      return res.data;
    }
    if (method === 'DELETE') {
      const res = await http.delete<T>(path, { timeout: PROVIDER_TIMEOUT_MS, headers });
      return res.data;
    }
    const res = await http.post<T>(path, body, { timeout: PROVIDER_TIMEOUT_MS, headers });
    return res.data;
  } catch (err) {
    const e = err as {
      response?: { status?: number; data?: { error?: string } };
      message?: string;
    };
    const status = e.response?.status ?? 502;
    const message = e.response?.data?.error ?? `Secrets provider unavailable (${e.message ?? 'error'})`;
    throw Object.assign(new Error(message), { status });
  }
}

/**
 * Fetches the secret types a provider serves (from its `/discover` endpoint),
 * cached briefly.
 */
export async function getProviderSecretTypes(provider: ProviderRecord): Promise<SecretType[]> {
  const now = Date.now();
  const cached = secretTypesCache.get(provider.id);
  if (cached && now - cached.cachedAt < PROVIDER_CACHE_TTL_MS) {
    return cached.types;
  }
  try {
    const apiKey = process.env.PLUGIN_API_KEY;
    const headers = apiKey ? { 'x-plugin-api-key': apiKey } : undefined;
    const res = await pluginAxios(provider.endpoint).get<{ secretsProvider?: { secretTypes?: SecretType[] } }>(
      '/discover',
      { timeout: PROVIDER_TIMEOUT_MS, headers }
    );
    const types = res.data.secretsProvider?.secretTypes ?? [];
    secretTypesCache.set(provider.id, { types, cachedAt: now });
    return types;
  } catch {
    return [];
  }
}

/**
 * Lists all registered secrets providers + the secret types each serves.
 */
export async function listSecretProviders(): Promise<SecretProviderInfo[]> {
  const rows = await db.query.plugins.findMany();
  const now = Date.now();
  const providers = rows
    .map(toRecord)
    .filter((p) => p.capabilities.includes('secretsProvider'));
  const infos = await Promise.all(
    providers.map(async (p) => {
      const row = rows.find((r) => r.id === p.id);
      return {
        id: p.id,
        name: row?.name ?? p.id,
        version: row?.version ?? '',
        endpoint: p.endpoint,
        online: isOnline(p, now),
        secretTypes: await getProviderSecretTypes(p),
      };
    })
  );
  infos.sort((a, b) => Number(b.online) - Number(a.online) || a.name.localeCompare(b.name));
  return infos;
}

/**
 * Creates a secret via the given (or default) provider. The provider encrypts
 * the fields and stores the ciphertext tagged with the secret type + provider
 * id; the API returns the new id + createdAt.
 */
export async function createSecret(input: {
  type: string;
  providerId?: string;
  fields: Record<string, string>;
  label?: string;
  expiresAt?: string;
  userId: string;
  /** Interactive-session usage flags (see schema.secrets). Default false. */
  interactiveLoginAllowed?: boolean;
  fileAccessAllowed?: boolean;
}): Promise<{ id: string; createdAt: string }> {
  const provider = await resolveSecretsProvider(input.providerId);
  return callProvider(provider, '/secrets', 'POST', {
    type: input.type,
    fields: input.fields,
    label: input.label,
    expiresAt: input.expiresAt,
    userId: input.userId,
    interactiveLoginAllowed: input.interactiveLoginAllowed ?? false,
    fileAccessAllowed: input.fileAccessAllowed ?? false,
  });
}

/**
 * Lists secret metadata (no decrypted values).
 */
export async function listSecrets(): Promise<unknown[]> {
  const provider = await resolveSecretsProvider();
  return callProvider<unknown[]>(provider, '/secrets', 'GET');
}

/**
 * Looks up the provider that owns a secret (from the row's providerId),
 * falling back to the default provider.
 */
async function providerForSecret(secretId: string): Promise<ProviderRecord> {
  const row = await db.query.secrets.findFirst({
    where: (secrets, { eq }) => eq(secrets.id, secretId),
  });
  if (row?.providerId) {
    const provider = await findProviderById(row.providerId);
    if (provider) return provider;
  }
  return resolveSecretsProvider();
}

/**
 * Retrieves a decrypted secret by id, routed to the provider that created it.
 * Results are cached for SECRET_CACHE_TTL_MS (see above) — the poll path calls
 * this once per assignment per beat and most assignments share few secrets.
 */
export async function getSecret(id: string): Promise<DecryptedSecret> {
  if (SECRET_CACHE_TTL_MS > 0) {
    const hit = secretCache.get(id);
    if (hit && Date.now() - hit.cachedAt < SECRET_CACHE_TTL_MS) return hit.value;
  }
  const provider = await providerForSecret(id);
  const value = await callProvider<DecryptedSecret>(provider, `/secrets/${encodeURIComponent(id)}`, 'GET');
  if (SECRET_CACHE_TTL_MS > 0) {
    secretCache.set(id, { value, cachedAt: Date.now() });
  }
  return value;
}

/**
 * Like getSecret but NEVER consults or fills the cache — for paths where a
 * stale credential must not be tolerated (config application, plan steps).
 */
export async function getSecretFresh(id: string): Promise<DecryptedSecret> {
  const provider = await providerForSecret(id);
  return callProvider<DecryptedSecret>(provider, `/secrets/${encodeURIComponent(id)}`, 'GET');
}

/**
 * Deletes a secret by id, routed to the provider that created it.
 */
export async function deleteSecret(id: string): Promise<void> {
  const provider = await providerForSecret(id);
  await callProvider(provider, `/secrets/${encodeURIComponent(id)}`, 'DELETE');
}

/**
 * Asks a provider to GENERATE a new secret of a generatable type (the provider
 * creates the key material itself). Returns the new id + createdAt. The API is
 * a pure broker — it never sees or stores the plaintext material.
 */
/** Response of a generate call. `publicFields` = non-secret generated material
 *  the provider echoes back for display (e.g. an ssh-ed25519 public key line);
 *  secret fields never leave the provider. */
export interface GeneratedSecret {
  id: string;
  createdAt: string;
  type?: string;
  publicFields?: Record<string, string>;
}

export async function generateSecret(input: {
  type: string;
  providerId?: string;
  fields?: Record<string, unknown>;
  label?: string;
  expiresAt?: string;
  userId: string;
}): Promise<GeneratedSecret> {
  const provider = await resolveSecretsProvider(input.providerId);
  return callProvider(provider, '/generate', 'POST', {
    type: input.type,
    fields: input.fields ?? {},
    label: input.label,
    expiresAt: input.expiresAt,
    userId: input.userId,
  });
}

/**
 * Asks the owning provider to REGENERATE a secret's key material in place (same
 * id preserved). Used for rotation and by plan provisioning when a referenced
 * secret must be re-rolled.
 */
export async function regenerateSecret(id: string): Promise<{ id: string; type?: string }> {
  const provider = await providerForSecret(id);
  return callProvider(provider, '/regenerate', 'POST', { id });
}

/**
 * Retrieves a secret's decrypted fields for editing (routed to the owning
 * provider). Unlike getSecret this is NOT cached — an edit form must always
 * show current values.
 */
export async function getSecretFields(id: string): Promise<DecryptedSecret> {
  const provider = await providerForSecret(id);
  return callProvider<DecryptedSecret>(provider, `/secrets/${encodeURIComponent(id)}`, 'GET');
}

/**
 * Updates a secret's fields IN PLACE (same id preserved, so assignments and
 * plans referencing it keep working). Works for ALL secret types — the owning
 * provider re-encrypts the new field values. `label`/`expiresAt` are optional
 * metadata updates applied alongside.
 */
export async function updateSecret(
  id: string,
  input: {
    fields?: Record<string, unknown>;
    label?: string | null;
    expiresAt?: string | null;
    /** Interactive-session usage flags — omitted = leave unchanged. */
    interactiveLoginAllowed?: boolean;
    fileAccessAllowed?: boolean;
  }
): Promise<{ id: string }> {
  const provider = await providerForSecret(id);
  // POST /update (id in body) — same convention as the provider's /regenerate.
  return callProvider(provider, '/update', 'POST', {
    id,
    fields: input.fields ?? {},
    ...(input.label !== undefined ? { label: input.label } : {}),
    ...(input.expiresAt !== undefined ? { expiresAt: input.expiresAt } : {}),
    ...(input.interactiveLoginAllowed !== undefined ? { interactiveLoginAllowed: input.interactiveLoginAllowed } : {}),
    ...(input.fileAccessAllowed !== undefined ? { fileAccessAllowed: input.fileAccessAllowed } : {}),
  });
}

/** The secret types a device plugin accepts for its PRIMARY credential. */
export interface RequiredSecretTypes {
  /** Legacy single type (first of `types`) — kept so older consumers keep working. */
  requiredSecretType: string | null;
  /** All acceptable primary secret types (e.g. ['usernamePassword', 'sshKeyPair']).
   *  Empty when the plugin declares none or is unreachable. */
  requiredSecretTypes: string[];
}

/**
 * Reads the secret type(s) a device plugin requires for its PRIMARY credential
 * (from its `/discover` `requiredSecretType` / `requiredSecretTypes`). Returns
 * empty when undeclared or the plugin is unreachable.
 */
export async function getRequiredSecretTypes(pluginId: string): Promise<RequiredSecretTypes> {
  const row = await db.query.plugins.findFirst({
    where: (plugins, { eq }) => eq(plugins.id, pluginId),
  });
  if (!row) return { requiredSecretType: null, requiredSecretTypes: [] };
  const provider = toRecord(row);
  try {
    const apiKey = process.env.PLUGIN_API_KEY;
    const headers = apiKey ? { 'x-plugin-api-key': apiKey } : undefined;
    const res = await pluginAxios(provider.endpoint).get<{ requiredSecretType?: string; requiredSecretTypes?: string[] }>('/discover', {
      timeout: PROVIDER_TIMEOUT_MS,
      headers,
    });
    const types: string[] = [];
    if (Array.isArray(res.data.requiredSecretTypes)) {
      for (const t of res.data.requiredSecretTypes) {
        if (typeof t === 'string' && t.trim() !== '' && !types.includes(t.trim())) types.push(t.trim());
      }
    }
    const single = typeof res.data.requiredSecretType === 'string' ? res.data.requiredSecretType.trim() : '';
    if (single && !types.includes(single)) types.unshift(single);
    return { requiredSecretType: types[0] ?? null, requiredSecretTypes: types };
  } catch {
    return { requiredSecretType: null, requiredSecretTypes: [] };
  }
}
