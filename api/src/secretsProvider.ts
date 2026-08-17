import axios from 'axios';
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

/** A secret field as declared by a provider's secret type schema. */
export interface SecretField {
  name: string;
  label: string;
  input: 'text' | 'password' | 'select';
  secret?: boolean;
  required?: boolean;
  options?: string[];
}

/** A secret type (e.g. `apiKey`, `usernamePassword`) with its field schema. */
export interface SecretType {
  type: string;
  label: string;
  fields: SecretField[];
}

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
      console.warn(`[secrets] configured provider ${configuredId} is offline; falling back to secrets-provider`);
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
  method: 'GET' | 'POST' | 'DELETE',
  body?: Record<string, unknown>
): Promise<T> {
  const base = provider.endpoint.replace(/\/+$/, '');
  const apiKey = process.env.PLUGIN_API_KEY;
  const headers = apiKey ? { 'x-plugin-api-key': apiKey } : undefined;

  try {
    if (method === 'GET') {
      const res = await axios.get<T>(`${base}${path}`, { timeout: PROVIDER_TIMEOUT_MS, headers });
      return res.data;
    }
    if (method === 'DELETE') {
      const res = await axios.delete<T>(`${base}${path}`, { timeout: PROVIDER_TIMEOUT_MS, headers });
      return res.data;
    }
    const res = await axios.post<T>(`${base}${path}`, body, { timeout: PROVIDER_TIMEOUT_MS, headers });
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
    const base = provider.endpoint.replace(/\/+$/, '');
    const apiKey = process.env.PLUGIN_API_KEY;
    const headers = apiKey ? { 'x-plugin-api-key': apiKey } : undefined;
    const res = await axios.get<{ secretsProvider?: { secretTypes?: SecretType[] } }>(
      `${base}/discover`,
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
}): Promise<{ id: string; createdAt: string }> {
  const provider = await resolveSecretsProvider(input.providerId);
  return callProvider(provider, '/secrets', 'POST', {
    type: input.type,
    fields: input.fields,
    label: input.label,
    expiresAt: input.expiresAt,
    userId: input.userId,
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
 */
export async function getSecret(id: string): Promise<DecryptedSecret> {
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
 * Reads the secret type a device plugin requires (from its `/discover`
 * `requiredSecretType`), if declared. Returns `null` when undeclared or the
 * plugin is unreachable.
 */
export async function getRequiredSecretType(pluginId: string): Promise<string | null> {
  const row = await db.query.plugins.findFirst({
    where: (plugins, { eq }) => eq(plugins.id, pluginId),
  });
  if (!row) return null;
  const provider = toRecord(row);
  try {
    const base = provider.endpoint.replace(/\/+$/, '');
    const apiKey = process.env.PLUGIN_API_KEY;
    const headers = apiKey ? { 'x-plugin-api-key': apiKey } : undefined;
    const res = await axios.get<{ requiredSecretType?: string }>(`${base}/discover`, {
      timeout: PROVIDER_TIMEOUT_MS,
      headers,
    });
    return res.data.requiredSecretType ?? null;
  } catch {
    return null;
  }
}
