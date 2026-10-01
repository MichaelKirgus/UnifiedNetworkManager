import type { Readable } from 'stream';
import { AxiosInstance } from 'axios';
import { pluginAxios } from './utils/pluginHttp';
import { eq } from 'drizzle-orm';
import { db } from './db';
import * as schema from './db/schema';
import { getEffectiveSettingValue } from './systemSettings';

/**
 * File-repo broker.
 *
 * The API owns ALL file-repo metadata in Postgres (`repo_files` + `repo_file_uses`)
 * and delegates the BYTES to a file-repo plugin (any plugin advertising the
 * `fileRepo` capability). This mirrors the secretsProvider broker: the provider
 * is resolved from the plugins table, called over HTTP with the shared
 * x-plugin-api-key, and never owns a database.
 *
 * Multi-instance / multi-segment: each file-repo instance (PLUGIN_INSTANCE_ID)
 * registers as its own plugin with its own volume. `FILE_REPO_PLUGIN_ID` names
 * the DEFAULT provider for new uploads; an explicit providerId (per row or per
 * request header) always wins. Rows whose bytes live in a specific repo are
 * routed back to THAT repo by their stored providerId — so files can sit in
 * different network segments while UNM treats them as one repository.
 *
 * Legacy fallback: rows with `providerId = NULL` keep reading from the api-local
 * volume (FILE_REPO_PATH) via fileRepo.ts's local helpers, and new uploads fall
 * back to local storage when no provider is online — so a missing plugin never
 * breaks the Files page.
 */

/** Reserved UUID for the built-in local-filesystem file-repo plugin. */
export const FILE_REPO_PLUGIN_UUID = '00000000-0000-4000-8000-000000000011';

const PROVIDER_TIMEOUT_MS = 5_000; // control-plane calls (health, delete)
const ONLINE_WINDOW_MS = 5 * 60 * 1000;

interface ProviderRecord {
  id: string;
  name: string;
  endpoint: string;
  capabilities: string[];
  lastSeenAt: string | null;
}

let cachedDefaultProvider: { record: ProviderRecord | null; cachedAt: number } | null = null;

function parseCapabilities(raw: string | null | undefined): string[] {
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as unknown[]).filter((c): c is string => typeof c === 'string') : [];
  } catch {
    return [];
  }
}

function toRecord(row: typeof schema.plugins.$inferSelect): ProviderRecord {
  return {
    id: row.id,
    name: row.name,
    endpoint: row.endpoint,
    capabilities: parseCapabilities(row.capabilities),
    lastSeenAt: row.lastSeenAt,
  };
}

function isOnline(record: ProviderRecord, now: number): boolean {
  if (!record.lastSeenAt) return false;
  const last = Date.parse(record.lastSeenAt);
  if (Number.isNaN(last)) return false;
  return now - last <= ONLINE_WINDOW_MS;
}

async function findProviderById(id: string): Promise<ProviderRecord | null> {
  const row = await db.query.plugins.findFirst({ where: (plugins, { eq }) => eq(plugins.id, id) });
  if (!row || !parseCapabilities(row.capabilities).includes('fileRepo')) return null;
  return toRecord(row);
}

async function findFirstFileRepoProvider(): Promise<ProviderRecord | null> {
  const rows = await db.query.plugins.findMany();
  const providers = rows.map(toRecord).filter((p) => p.capabilities.includes('fileRepo'));
  if (providers.length === 0) return null;
  providers.sort((a, b) => (b.lastSeenAt ?? '').localeCompare(a.lastSeenAt ?? ''));
  return providers[0];
}

/**
 * Resolves a file-repo provider. Honors an explicit `providerId`; otherwise the
 * `FILE_REPO_PLUGIN_ID` env; falls back to the reserved built-in plugin, then any
 * registered provider. Returns NULL (not an error) when nothing is available —
 * callers fall back to local storage for uploads / legacy reads.
 */
export async function resolveFileRepoProvider(providerId?: string | null): Promise<ProviderRecord | null> {
  const now = Date.now();

  if (providerId && providerId.trim()) {
    // Explicit — no fallback, may be offline (the caller decides what that means).
    return await findProviderById(providerId.trim());
  }

  if (cachedDefaultProvider && now - cachedDefaultProvider.cachedAt < PROVIDER_TIMEOUT_MS) {
    return cachedDefaultProvider.record;
  }

  // The "default file repository" is a system setting (Settings page → Files):
  // stored override ⊕ FILE_REPO_PLUGIN_ID env baseline. Empty = auto-resolve.
  const configuredId = String((await getEffectiveSettingValue('fileRepoDefaultProviderId')) ?? '').trim();
  let record: ProviderRecord | null = null;

  if (configuredId) {
    record = await findProviderById(configuredId);
    if (record && !isOnline(record, now)) {
      // eslint-disable-next-line no-console
      console.warn(`[file-repo] configured provider ${configuredId} is offline`);
      record = null;
    }
  }

  if (!record) {
    record = await findProviderById(FILE_REPO_PLUGIN_UUID);
    if (record && !isOnline(record, now)) {
      // eslint-disable-next-line no-console
      console.warn(`[file-repo] built-in provider ${FILE_REPO_PLUGIN_UUID} is offline`);
      record = null;
    }
  }

  if (!record) {
    const any = await findFirstFileRepoProvider();
    record = any && isOnline(any, now) ? any : null;
  }

  cachedDefaultProvider = { record, cachedAt: now }; // null is cached too (briefly)
  return record;
}

/** Lists all registered file-repo providers + online state (webapp repo picker). */
export async function listFileRepoProviders(): Promise<Array<{ id: string; name: string; endpoint: string; online: boolean }>> {
  const rows = await db.query.plugins.findMany();
  const now = Date.now();
  return rows
    .map(toRecord)
    .filter((p) => p.capabilities.includes('fileRepo'))
    .sort((a, b) => Number(isOnline(b, now)) - Number(isOnline(a, now)) || a.name.localeCompare(b.name))
    .map((p) => ({ id: p.id, name: p.name, endpoint: p.endpoint, online: isOnline(p, now) }));
}

/**
 * The effective default provider for NEW uploads (what the Files page should
 * preselect): the resolved default when one is online, else null (= auto — no
 * repo available / local fallback). Mirrors resolveFileRepoProvider() exactly.
 */
export async function defaultFileRepoProviderId(): Promise<string | null> {
  const record = await resolveFileRepoProvider();
  return record ? record.id : null;
}

/** One axios instance per provider (control-plane timeout; streams override it). */
const httpCache = new Map<string, AxiosInstance>();
function providerHttp(provider: ProviderRecord): AxiosInstance {
  let h = httpCache.get(provider.id);
  if (!h) {
    const apiKey = process.env.PLUGIN_API_KEY;
    // mTLS (Stage 1): pluginAxios picks the transport for this provider.
    h = pluginAxios(provider.endpoint, {
      timeout: PROVIDER_TIMEOUT_MS,
      headers: apiKey ? { 'x-plugin-api-key': apiKey } : undefined,
      maxContentLength: Infinity, // multi-GB ISOs — never buffer/limit
      maxBodyLength: Infinity,
    });
    httpCache.set(provider.id, h);
  }
  return h;
}

function providerError(e: unknown, what: string): Error {
  const err = e as { response?: { status?: number; data?: { error?: string } }; message?: string };
  const status = err.response?.status ?? 502;
  const message = err.response?.data?.error ?? `${what} unavailable (${err.message ?? 'error'})`;
  return Object.assign(new Error(message), { status });
}

/**
 * Streams a readable into the provider's content-addressed store. Returns the
 * content identity `{ sha256, sizeBytes }` computed BY THE PROVIDER (the API does
 * not hash uploads itself). No timeout — multi-GB transfers are bounded by the
 * caller's request lifetime.
 */
export async function storeBlobViaProvider(
  provider: ProviderRecord,
  source: Readable
): Promise<{ sha256: string; sizeBytes: number }> {
  try {
    const res = await providerHttp(provider).put<{ sha256: string; sizeBytes: number }>(
      '/store',
      source,
      { timeout: 0, headers: { 'content-type': 'application/octet-stream' } }
    );
    return { sha256: res.data.sha256, sizeBytes: Number(res.data.sizeBytes ?? 0) };
  } catch (e) {
    throw providerError(e, `File-repo ${provider.name}`);
  }
}

/**
 * Opens a stored blob for streaming by its sha256 key. Returns null when the
 * provider answers 404 (bytes missing from that volume). Mid-stream failures
 * surface on the returned stream's 'error' event, like local reads.
 */
export async function openBlobFromProvider(
  provider: ProviderRecord,
  sha256: string
): Promise<Readable | null> {
  try {
    const res = await providerHttp(provider).get<Readable>(`/store/${encodeURIComponent(sha256)}`, {
      responseType: 'stream',
      timeout: 0, // no idle limit — a slow consumer (backpressure) must not abort the stream
    });
    return res.data;
  } catch (e) {
    const err = e as { response?: { status?: number } };
    if (err.response?.status === 404) return null; // bytes gone — same semantics as a missing local file
    throw providerError(e, `File-repo ${provider.name}`);
  }
}

/** Deletes a stored blob. Tolerates 404 (already gone). */
export async function deleteBlobViaProvider(provider: ProviderRecord, sha256: string): Promise<void> {
  try {
    await providerHttp(provider).delete(`/store/${encodeURIComponent(sha256)}`);
  } catch (e) {
    const err = e as { response?: { status?: number } };
    if (err.response?.status === 404) return; // idempotent — already gone
    throw providerError(e, `File-repo ${provider.name}`);
  }
}
