import { AxiosInstance } from 'axios';
import { get, post, OpnsenseApiResult } from './http';

/**
 * Edition detection + Business Edition (OPNBE) sync API.
 *
 * Community Edition and Business Edition share the same core modules; BE adds
 * the `opncentral/sync` controller — a true central-sync surface used by
 * OPNcentral: listClasses (config sections + per-section md5 → drift detection),
 * readConfig/<path> (dump one config path), reconfigure (merge new config, auto-
 * restart affected services) and service listing/restart.
 *
 * The plugin probes `listClasses` once per appliance to decide which edition is
 * running (200 = BE, 403/404 = CE) and caches the result + class list so the
 * API's frequent polls never re-probe. An explicit `editionOverride` option
 * (`auto|ce|be`) exists for appliances where probing is blocked by ACLs.
 */

export type OpnsenseEdition = 'ce' | 'be';

/** One synchronizable config section as reported by BE listClasses. */
export interface SyncClass {
  id: string;
  description?: string;
  help?: string;
  /** Config path, e.g. `OPNsense.Firewall.Alias`. */
  section?: string;
  /** Services restarted when this class changes, e.g. ["pf"]. */
  services?: string[];
  /** md5 of the current config for this section — equal across hosts = in sync. */
  md5?: string;
}

interface EditionCacheEntry {
  edition: OpnsenseEdition;
  classes: SyncClass[];
  checkedAt: number;
}

const EDITION_TTL_MS = 15 * 60 * 1000; // matches the inventory cache cadence
const editionCache = new Map<string, EditionCacheEntry>();

/** Clears a host's cached edition (e.g. after a failed BE call that may indicate an upgrade). */
export function invalidateEditionCache(host: string): void {
  editionCache.delete(host);
}

/**
 * Resolves the edition for a host. `override` comes from the plugin's
 * `editionOverride` option; anything other than 'ce'/'be' (or undefined) means
 * auto-detect via probe + cache.
 */
export async function resolveEdition(
  client: AxiosInstance,
  host: string,
  override?: string
): Promise<{ edition: OpnsenseEdition; classes: SyncClass[] }> {
  if (override === 'ce' || override === 'be') {
    const cached = editionCache.get(host);
    return { edition: override, classes: cached?.classes ?? [] };
  }

  const cached = editionCache.get(host);
  if (cached && Date.now() - cached.checkedAt < EDITION_TTL_MS) {
    return { edition: cached.edition, classes: cached.classes };
  }

  let edition: OpnsenseEdition = 'ce';
  let classes: SyncClass[] = [];
  try {
    const res = await get<{ classes?: unknown }>(client, '/api/opncentral/sync/listClasses');
    if (res.ok && res.data && Array.isArray(res.data.classes)) {
      edition = 'be';
      classes = res.data.classes as SyncClass[];
    }
  } catch {
    /* probe failed — treat as CE */
  }

  editionCache.set(host, { edition, classes, checkedAt: Date.now() });
  return { edition, classes };
}

// --- BE sync client (opncentral/sync) ---------------------------------------------

/** GET /api/opncentral/sync/listClasses — all synchronizable sections + md5s. */
export function listSyncClasses(client: AxiosInstance): Promise<OpnsenseApiResult<{ classes?: SyncClass[] }>> {
  return get(client, '/api/opncentral/sync/listClasses');
}

/** GET /api/opncentral/sync/metrics — sync metrics for the host. */
export function getSyncMetrics(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return get(client, '/api/opncentral/sync/metrics');
}

/** GET /api/opncentral/sync/readConfig/$path — dump one config path (e.g. OPNsense.Firewall.Alias). */
export function readConfigPath(client: AxiosInstance, path: string): Promise<OpnsenseApiResult> {
  return get(client, `/api/opncentral/sync/readConfig/${encodeURIComponent(path)}`);
}

/** POST /api/opncentral/sync/reconfigure — merge new config data; auto-restarts affected services. */
export function reconfigureSync(client: AxiosInstance, payload: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return post(client, '/api/opncentral/sync/reconfigure', { payload });
}

/** GET /api/opncentral/sync/listServices — active services + status. */
export function listSyncServices(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return get(client, '/api/opncentral/sync/listServices');
}

/** POST /api/opncentral/sync/restartService — restart the given service names. */
export function restartSyncServices(client: AxiosInstance, services: string[]): Promise<OpnsenseApiResult> {
  return post(client, '/api/opncentral/sync/restartService', { services });
}
