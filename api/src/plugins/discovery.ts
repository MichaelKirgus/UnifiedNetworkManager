import axios from 'axios';
import { Bonjour } from 'bonjour-service';
import { eq } from 'drizzle-orm';
import { db } from '../db';
import * as schema from '../db/schema';
import type { PluginOptionDescriptor } from '../types/pluginOptions';
import type { DeviceModelEntry } from '../types/deviceModels';
import { CredentialSlotDescriptor, normalizeCredentialSlots } from '../types/credentialSlots';
import { getEffectiveSettingValue } from '../systemSettings';

/**
 * Self-describing identity that every plugin MUST expose, either via its
 * `/discover` endpoint (HTTP polling) or via mDNS TXT records (DNS-SD).
 * The `uuid` is the single source of truth that identifies a plugin and is
 * used as the primary key in the `plugins` table.
 */
export interface PluginIdentity {
  uuid: string;
  name: string;
  version: string;
  vendors: string[];
  capabilities: string[];
  endpoint: string;
  authType: string;
  /** Metric descriptors declared by the plugin (drives webapp visualization). */
  metrics?: unknown[];
  /** Option descriptors declared by the plugin (drives the settings form + API-side persistence/validation). */
  options?: PluginOptionDescriptor[];
  /** Action catalog declared by the plugin (drives plan creation in the webapp). */
  actions?: unknown[];
  /** Icon path relative to the plugin root (e.g. "/icons/lancom.svg"); proxied via GET /plugins/:id/icon. */
  iconUrl?: string | null;
  /** Supported device model catalog (drives Model/Firmware dropdowns in the webapp). Absent = no catalog. */
  deviceModels?: DeviceModelEntry[];
  /** Additional named credential slots beyond the primary secret (see types/credentialSlots.ts). */
  credentialSlots?: CredentialSlotDescriptor[];
}

/**
 * Defensively normalizes a raw `deviceModels` array from /discover: keeps only
 * entries with non-empty string vendor + model, coerces iconPath/firmwareVersions
 * to the expected shapes, and drops malformed items instead of failing discovery.
 */
function normalizeDeviceModels(raw: unknown): DeviceModelEntry[] | undefined {
  if (!Array.isArray(raw)) return undefined;
  const out: DeviceModelEntry[] = [];
  for (const item of raw) {
    if (!item || typeof item !== 'object') continue;
    const e = item as Record<string, unknown>;
    if (typeof e.vendor !== 'string' || e.vendor.trim() === '') continue;
    if (typeof e.model !== 'string' || e.model.trim() === '') continue;
    const entry: DeviceModelEntry = { vendor: e.vendor.trim(), model: e.model.trim() };
    if (typeof e.iconPath === 'string' && e.iconPath.trim() !== '') entry.iconPath = e.iconPath.trim();
    // Suggested topology layer for this model — passed through as-is when a
    // non-empty string. Deliberately NOT validated against the network_layers
    // table here: layers may be added later, and resolution is lazy at
    // topology-build time (an unknown id simply falls back to the heuristic).
    if (typeof e.defaultLayerId === 'string' && e.defaultLayerId.trim() !== '') entry.defaultLayerId = e.defaultLayerId.trim();
    if (Array.isArray(e.firmwareVersions)) {
      const versions = e.firmwareVersions.filter((v): v is string => typeof v === 'string' && v.trim() !== '').map((v) => v.trim());
      if (versions.length > 0) entry.firmwareVersions = versions;
    }
    out.push(entry);
  }
  return out.length > 0 ? out : undefined;
}

/** Normalizes a raw icon path: must be a relative path (no scheme, no ".."). */
function normalizeIconPath(raw: unknown): string | null {
  if (typeof raw !== 'string' || raw.trim() === '') return null;
  const p = raw.trim();
  if (/^[a-z][a-z0-9+.-]*:/i.test(p)) return null; // scheme like http: — reject
  if (p.includes('..')) return null; // path traversal — reject
  return p.startsWith('/') ? p : `/${p}`;
}

export interface DiscoveryOptions {
  /** Optional list of plugin HTTP endpoints to poll as a fallback when mDNS is not reachable (e.g. Docker bridge networks). */
  pollEndpoints?: string[];
  /** Poll interval in milliseconds. Defaults to 60_000. */
  pollIntervalMs?: number;
  /** How long a plugin stays "registered" after its last successful discovery, in ms. Defaults to 5 minutes. */
  staleAfterMs?: number;
}

const DISCOVERY_SERVICE_TYPE = 'unm-plugin';
const DISCOVERY_POLL_TIMEOUT_MS = 3000;

/**
 * Standard scheduling options injected into EVERY plugin's option descriptors.
 * They drive the window-based telemetry dispatcher (workers/telemetry.ts):
 *   pollIntervalMs    — how often /monitoring is called for this plugin (ms);
 *   inventoryWindowMs — how often the slow/static collection runs (ms).
 * Injected API-side so no plugin code is needed; a plugin that declares its
 * own option with the same key wins (dedup below). No `default` on purpose:
 * unset = inherit the system setting, and effectiveValues only carries keys
 * with an explicit default or a stored override.
 */
const STANDARD_SCHEDULING_OPTIONS: PluginOptionDescriptor[] = [
  {
    key: 'pollIntervalMs',
    label: 'Poll interval (ms)',
    type: 'integer',
    min: 5_000,
    max: 3_600_000,
    description:
      'How often this plugin polls /monitoring for live metrics. Leave unset to inherit the system default (Workers page).',
  },
  {
    key: 'inventoryWindowMs',
    label: 'Inventory refresh window (ms)',
    type: 'integer',
    min: 30_000,
    max: 12 * 60 * 60_000,
    description:
      'How often the slow/static inventory collection runs (networks, hosts, routes, …). Leave unset to inherit the system default.',
  },
];

/** Merges the standard scheduling options into a plugin's declared options —
 * a plugin-declared option with the same key always wins. */
function withStandardOptions(options: PluginOptionDescriptor[] | undefined): PluginOptionDescriptor[] {
  const out = [...(options ?? [])];
  for (const std of STANDARD_SCHEDULING_OPTIONS) {
    if (!out.some((o) => o.key === std.key)) out.push(std);
  }
  return out;
}

function parseTxt(txt: Record<string, string> | undefined): Partial<PluginIdentity> {
  const raw = txt ?? {};
  const list = (v: string | undefined): string[] =>
    v ? v.split(',').map((s) => s.trim()).filter(Boolean) : [];

  return {
    uuid: raw.uuid,
    name: raw.name,
    version: raw.version,
    vendors: list(raw.vendors),
    capabilities: list(raw.capabilities),
    endpoint: raw.endpoint,
    authType: raw.authType,
  };
}

async function fetchIdentity(endpoint: string): Promise<PluginIdentity | null> {
  try {
    const url = `${endpoint.replace(/\/+$/, '')}/discover`;
    const res = await axios.get<PluginIdentity>(url, { timeout: DISCOVERY_POLL_TIMEOUT_MS });
    const data = res.data;
    if (!data || typeof data.uuid !== 'string' || data.uuid.length === 0) {
      // eslint-disable-next-line no-console
      console.warn(`[discovery] plugin at ${endpoint} did not return a uuid`);
      return null;
    }
    return {
      uuid: data.uuid,
      name: data.name ?? data.uuid,
      version: data.version ?? 'unknown',
      vendors: Array.isArray(data.vendors) ? data.vendors : [],
      capabilities: Array.isArray(data.capabilities) ? data.capabilities : [],
      endpoint: data.endpoint ?? endpoint,
      authType: data.authType ?? 'none',
      metrics: Array.isArray(data.metrics) ? data.metrics : undefined,
      // Standard scheduling options are injected for every plugin so the
      // Workers/Plugins settings UIs can tune per-plugin poll windows.
      options: withStandardOptions(Array.isArray(data.options) ? (data.options as PluginOptionDescriptor[]) : undefined),
      actions: Array.isArray(data.actions) ? data.actions : undefined,
      iconUrl: normalizeIconPath(data.iconUrl),
      deviceModels: normalizeDeviceModels(data.deviceModels),
      credentialSlots: normalizeCredentialSlots(data.credentialSlots),
    };
  } catch (err) {
    // eslint-disable-next-line no-console
    console.warn(`[discovery] failed to fetch identity from ${endpoint}:`, (err as Error).message);
    return null;
  }
}

async function upsertPlugin(identity: PluginIdentity): Promise<void> {
  const now = new Date().toISOString();
  const existing = await db.query.plugins.findFirst({
    where: (plugins, { eq }) => eq(plugins.id, identity.uuid),
  });

  // Only overwrite the stored descriptors when this discovery source actually
  // carries them (the mDNS TXT path does not), so a metrics-less upsert never
  // wipes descriptors set by the HTTP polling path. Same guard for options.
  const hasMetrics = Array.isArray(identity.metrics) && identity.metrics.length > 0;
  const metricDescriptors = hasMetrics ? JSON.stringify(identity.metrics) : null;
  const hasOptions = Array.isArray(identity.options) && identity.options.length > 0;
  const optionDescriptors = hasOptions ? JSON.stringify(identity.options) : null;
  // Same guard: only overwrite the stored catalog when this discovery source
  // actually carries one, so a catalog-less upsert never wipes it.
  const hasActions = Array.isArray(identity.actions) && identity.actions.length > 0;
  const actionDescriptors = hasActions ? JSON.stringify(identity.actions) : null;
  // Icon + device model catalog: same guard — the mDNS TXT path carries neither,
  // so a TXT upsert must never wipe values set by the HTTP polling path.
  const iconUrl = identity.iconUrl ?? null;
  const hasIcon = iconUrl !== null;
  const hasModels = Array.isArray(identity.deviceModels) && identity.deviceModels.length > 0;
  const deviceModelsJson = hasModels ? JSON.stringify(identity.deviceModels) : null;
  // Credential slots: same guard — the mDNS TXT path carries none, so a TXT
  // upsert must never wipe slot descriptors set by the HTTP polling path.
  const hasSlots = Array.isArray(identity.credentialSlots) && identity.credentialSlots.length > 0;
  const credentialSlotsJson = hasSlots ? JSON.stringify(identity.credentialSlots) : null;

  if (existing) {
    await db
      .update(schema.plugins)
      .set({
        name: identity.name,
        version: identity.version,
        vendors: JSON.stringify(identity.vendors),
        capabilities: JSON.stringify(identity.capabilities),
        endpoint: identity.endpoint,
        authType: identity.authType,
        ...(hasMetrics ? { metricDescriptors } : {}),
        ...(hasOptions ? { optionDescriptors } : {}),
        ...(hasActions ? { actionDescriptors } : {}),
        ...(hasIcon ? { iconUrl } : {}),
        ...(hasModels ? { deviceModels: deviceModelsJson } : {}),
        ...(hasSlots ? { credentialSlots: credentialSlotsJson } : {}),
        lastSeenAt: now,
      })
      .where(eq(schema.plugins.id, identity.uuid));
  } else {
    await db.insert(schema.plugins).values({
      id: identity.uuid,
      name: identity.name,
      version: identity.version,
      vendors: JSON.stringify(identity.vendors),
      capabilities: JSON.stringify(identity.capabilities),
      endpoint: identity.endpoint,
      authType: identity.authType,
      metricDescriptors,
      optionDescriptors,
      actionDescriptors,
      iconUrl,
      deviceModels: deviceModelsJson,
      credentialSlots: credentialSlotsJson,
      createdAt: now,
      lastSeenAt: now,
    });
  }

  // eslint-disable-next-line no-console
  console.log(`[discovery] upserted plugin "${identity.name}" (${identity.uuid})`);
}

async function pollEndpoints(endpoints: string[]): Promise<void> {
  for (const endpoint of endpoints) {
    const identity = await fetchIdentity(endpoint);
    if (identity) {
      await upsertPlugin(identity);
    }
  }
}

/**
 * Starts plugin discovery. Two complementary mechanisms are used:
 *
 * 1. mDNS/DNS-SD browsing: plugins advertise themselves as `_unm-plugin._tcp`
 *    services. The API browses for them and upserts each one.
 * 2. HTTP polling fallback: mDNS multicast is often isolated on Docker bridge
 *    networks, so any plugin endpoints configured via `pollEndpoints` are
 *    also polled on an interval.
 *
 * Returns a cleanup function that stops both mechanisms.
 */
export function startPluginDiscovery(options: DiscoveryOptions = {}): () => void {
  const fallbackIntervalMs = options.pollIntervalMs ?? 60_000;
  const pollEndpointsList = options.pollEndpoints ?? [];

  let bonjour: Bonjour | null = null;
  let browser: ReturnType<Bonjour['find']> | null = null;
  let pollTimer: ReturnType<typeof setTimeout> | null = null;
  let stopped = false;

  // mDNS browsing
  try {
    bonjour = new Bonjour();
    browser = bonjour.find({ type: DISCOVERY_SERVICE_TYPE }, (service) => {
      const identity: PluginIdentity = {
        uuid: service.txt?.uuid ?? service.name,
        name: service.txt?.name ?? service.name,
        version: service.txt?.version ?? 'unknown',
        vendors: parseTxt(service.txt).vendors ?? [],
        capabilities: parseTxt(service.txt).capabilities ?? [],
        endpoint: service.txt?.endpoint ?? `http://${service.host}:${service.port}`,
        authType: service.txt?.authType ?? 'none',
      };
      void upsertPlugin(identity);
    });
    // eslint-disable-next-line no-console
    console.log('[discovery] browsing mDNS for plugins...');
  } catch (err) {
    // eslint-disable-next-line no-console
    console.warn('[discovery] mDNS browsing unavailable, using polling only:', (err as Error).message);
  }

  // HTTP polling fallback. The interval is re-read from Settings on every cycle
  // (self-rescheduling timer), so changing the discovery poll interval takes
  // effect without a restart.
  if (pollEndpointsList.length > 0) {
    const scheduleNext = () => {
      if (stopped) return;
      void getEffectiveSettingValue('discoveryPollIntervalMs')
        .then((v) => Number(v) || fallbackIntervalMs)
        .catch(() => fallbackIntervalMs)
        .then((ms) => {
          pollTimer = setTimeout(async () => {
            await pollEndpoints(pollEndpointsList);
            scheduleNext();
          }, ms);
        });
    };
    void pollEndpoints(pollEndpointsList); // initial pass
    scheduleNext();
  }

  return () => {
    stopped = true;
    if (browser) browser.stop();
    if (bonjour) bonjour.destroy();
    if (pollTimer) clearTimeout(pollTimer);
  };
}