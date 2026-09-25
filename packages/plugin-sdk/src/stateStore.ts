/**
 * @unm/plugin-sdk — generic plugin state store (backed by the UNM database).
 *
 * Plugins that need to remember something ACROSS polls and container restarts —
 * file-integrity baselines keyed by host+path, last-seen counters, TOFU
 * fingerprints — use this instead of owning a database connection or a local
 * volume. The API owns the storage (table `plugin_state`); plugins read/write
 * through the internal `/plugin/state/*` routes with the shared x-plugin-api-key.
 *
 * Contract:
 *  - Natural key = (namespace, key). `namespace` groups one feature's state
 *    ("file-integrity"); `key` is the plugin-chosen stable identity within it
 *    ("<host>|/etc/passwd"). The pluginId is implicit — every call is scoped to
 *    THIS plugin instance.
 *  - `value` is an opaque JSON blob owned entirely by the plugin; the API never
 *    interprets it. Keep blobs small (the API caps one at 64 KB).
 *  - Every operation is BEST-EFFORT and NEVER throws: a missing PLUGIN_API_KEY,
 *    an unreachable API or a malformed response degrades to "no state" (empty
 *    list / no-op put) so the calling feature keeps working — e.g. file-integrity
 *    simply re-baselines on the next poll when it cannot reach the store.
 */

import { createApiClient } from './apiClient';
import type { PluginIdentity } from './identity';

export interface PluginStateEntry {
  /** Feature group (e.g. "file-integrity"). Part of the natural key. */
  namespace: string;
  /** Stable identity within the namespace (e.g. "<host>|/etc/passwd"). Part of the key. */
  key: string;
  /** Opaque JSON-serializable blob owned by the plugin. */
  value?: unknown;
  /** Optional device scope — set so DELETE /devices cascades the row. */
  deviceId?: string | null;
}

export interface PluginStateRow {
  namespace: string;
  key: string;
  value: unknown;
  deviceId: string | null;
  updatedAt: string;
}

/** The state-store surface a plugin needs — all best-effort, none throw. */
export interface PluginStateStore {
  /** List this plugin's rows (optionally filtered). Returns key → value for the
   *  given namespace, or ALL rows when no namespace is passed. */
  list(namespace?: string): Promise<Record<string, unknown>>;
  /** One row's value, or undefined when absent / store unreachable. */
  get(namespace: string, key: string): Promise<unknown>;
  /** Upsert a batch of entries (one round-trip). Resolves with the count stored. */
  put(entries: PluginStateEntry[]): Promise<number>;
  /** Delete rows in one namespace — exactly `keys` when given, else all of it. */
  delete(namespace: string, keys?: string[]): Promise<void>;
}

export interface PluginStateStoreOptions {
  /** Per-request timeout (default 4000 ms). */
  timeoutMs?: number;
}

/**
 * Creates a state store bound to this plugin instance. Only the EFFECTIVE uuid
 * matters (`<uuid>:<instanceId>` when instanced) — pass either the full
 * `PluginIdentity` from /discover or just `{ effectiveUuid }`. Multi-instance
 * plugins keep separate state because their effective ids differ.
 */
export function createPluginStateStore(
  identity: Pick<PluginIdentity, 'effectiveUuid'> | PluginIdentity,
  opts: PluginStateStoreOptions = {},
): PluginStateStore {
  const client = createApiClient({ timeoutMs: opts.timeoutMs ?? 4_000 });
  const pluginId = identity.effectiveUuid;

  // No API key configured → the store is a silent no-op (dev mode without an API).
  if (!process.env.PLUGIN_API_KEY) {
    return {
      list: async () => ({}),
      get: async () => undefined,
      put: async () => 0,
      delete: async () => undefined,
    };
  }

  const base = `/plugin/state/${encodeURIComponent(pluginId)}`;

  const list = async (namespace?: string): Promise<Record<string, unknown>> => {
    try {
      const qs = namespace ? `?namespace=${encodeURIComponent(namespace)}` : '';
      const res = await client.get(`${base}${qs}`);
      const rows: PluginStateRow[] = Array.isArray(res.data?.rows) ? (res.data.rows as PluginStateRow[]) : [];
      const out: Record<string, unknown> = {};
      for (const r of rows) {
        if (!namespace || r.namespace === namespace) out[r.key] = r.value;
      }
      return out;
    } catch {
      return {}; // unreachable / malformed — degrade to "no state"
    }
  };

  const get = async (namespace: string, key: string): Promise<unknown> => {
    const all = await list(namespace);
    return Object.prototype.hasOwnProperty.call(all, key) ? all[key] : undefined;
  };

  const put = async (entries: PluginStateEntry[]): Promise<number> => {
    if (entries.length === 0) return 0;
    try {
      const res = await client.put('/plugin/state', { pluginId, entries });
      return typeof res.data?.upserted === 'number' ? res.data.upserted : 0;
    } catch {
      return 0; // unreachable — the feature re-baselines next poll
    }
  };

  const remove = async (namespace: string, keys?: string[]): Promise<void> => {
    try {
      await client.delete(`${base}?namespace=${encodeURIComponent(namespace)}`, { data: keys ? { keys } : undefined });
    } catch {
      /* best-effort — stale rows age out via the API's own retention if needed */
    }
  };

  return { list, get, put, delete: remove };
}
