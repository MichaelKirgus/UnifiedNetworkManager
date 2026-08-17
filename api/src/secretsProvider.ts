import axios from 'axios';
import { eq } from 'drizzle-orm';
import { db } from './db';
import * as schema from './db/schema';

/**
 * Secrets provider broker.
 *
 * The API no longer encrypts/decrypts or manages secrets itself. It delegates
 * to a secrets provider plugin (any plugin advertising the `secretsProvider`
 * capability). The plugin owns the crypto (MASTER_KEY) and the management
 * logic; the API keeps the `secrets` table and exposes it to the plugin via
 * the internal `/plugin/secrets/*` routes.
 *
 * Provider selection:
 *   - `SECRETS_PLUGIN_ID` env var names the active provider (its plugin UUID).
 *   - If unset, or the named provider is unknown/offline, we fall back to the
 *     reserved secrets-provider plugin.
 */

/** Reserved UUID for the built-in secrets provider plugin. */
export const SECRETS_PROVIDER_UUID = '00000000-0000-4000-8000-000000000002';

const PROVIDER_TIMEOUT_MS = 5000;
const PROVIDER_CACHE_TTL_MS = 5000;
const ONLINE_WINDOW_MS = 5 * 60 * 1000;

/** A decrypted device secret as returned by the provider. */
export interface DecryptedSecret {
  apiKey: string;
  apiSecret: string;
  label?: string;
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
 * Resolves the active secrets provider. Honors `SECRETS_PLUGIN_ID`; falls back
 * to the reserved secrets-provider plugin (or the first registered provider)
 * when the named one is missing or offline.
 */
export async function resolveActiveSecretsProvider(): Promise<ProviderRecord> {
  const now = Date.now();
  if (cachedProvider && now - cachedProvider.cachedAt < PROVIDER_CACHE_TTL_MS) {
    return cachedProvider.record;
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

  cachedProvider = { record, cachedAt: now };
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
 * Creates a secret. The provider encrypts the payload and stores the
 * ciphertext; the API returns the new id + createdAt.
 */
export async function createSecret(input: {
  apiKey: string;
  apiSecret: string;
  label?: string;
  expiresAt?: string;
  userId: string;
}): Promise<{ id: string; createdAt: string }> {
  const provider = await resolveActiveSecretsProvider();
  return callProvider(provider, '/secrets', 'POST', {
    apiKey: input.apiKey,
    apiSecret: input.apiSecret,
    label: input.label,
    expiresAt: input.expiresAt,
    userId: input.userId,
  });
}

/**
 * Lists secret metadata (no decrypted values).
 */
export async function listSecrets(): Promise<unknown[]> {
  const provider = await resolveActiveSecretsProvider();
  return callProvider<unknown[]>(provider, '/secrets', 'GET');
}

/**
 * Retrieves a decrypted secret by id.
 */
export async function getSecret(id: string): Promise<DecryptedSecret> {
  const provider = await resolveActiveSecretsProvider();
  return callProvider<DecryptedSecret>(provider, `/secrets/${encodeURIComponent(id)}`, 'GET');
}

/**
 * Deletes a secret by id.
 */
export async function deleteSecret(id: string): Promise<void> {
  const provider = await resolveActiveSecretsProvider();
  await callProvider(provider, `/secrets/${encodeURIComponent(id)}`, 'DELETE');
}
