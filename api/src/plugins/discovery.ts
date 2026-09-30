import axios from 'axios';
import { Bonjour } from 'bonjour-service';
import { eq } from 'drizzle-orm';
import { db } from '../db';
import * as schema from '../db/schema';
import type { PluginOptionDescriptor } from '../types/pluginOptions';
import type { DeviceModelEntry } from '../types/deviceModels';
import type {
  DeviceSupport,
  DeviceSupportProfile,
  SupportCapabilityGrant,
  SupportCondition,
  SupportIntentGrant,
} from '../types/deviceSupport';
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
  /** Quick actions for the Devices page "Device Actions" column (see types/quickActions.ts). */
  quickActions?: unknown[];
  /** Icon path relative to the plugin root (e.g. "/icons/lancom.svg"); proxied via GET /plugins/:id/icon. */
  iconUrl?: string | null;
  /** Supported device model catalog (drives Model/Firmware dropdowns in the webapp). Absent = no catalog. */
  deviceModels?: DeviceModelEntry[];
  /** Additional named credential slots beyond the primary secret (see types/credentialSlots.ts). */
  credentialSlots?: CredentialSlotDescriptor[];
  /** Device support metadata — license/help/docs + supported-device matrix (see types/deviceSupport.ts). */
  deviceSupport?: DeviceSupport;
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

/** Keeps only safe relative paths (no scheme, no traversal) — for doc/license file refs. */
function safeAssetPath(raw: unknown): string | undefined {
  if (typeof raw !== 'string' || raw.trim() === '') return undefined;
  const p = raw.trim();
  if (/^[a-z][a-z0-9+.-]*:/i.test(p) || p.startsWith('//') || p.includes('..')) return undefined;
  return p.startsWith('/') ? p.slice(1) : p;
}

function strArray(raw: unknown): string[] | undefined {
  if (!Array.isArray(raw)) return undefined;
  const out = raw.filter((v): v is string => typeof v === 'string' && v.trim() !== '').map((v) => (v as string).trim());
  return out.length > 0 ? out : undefined;
}

function strOrNull(raw: unknown): string | undefined {
  if (typeof raw !== 'string' || raw.trim() === '') return undefined;
  return raw.trim();
}

/** Normalizes one gating condition object, dropping empty fields. */
function normalizeCondition(raw: unknown): SupportCondition | undefined {
  if (!raw || typeof raw !== 'object') return undefined;
  const c = raw as Record<string, unknown>;
  const out: SupportCondition = {};
  const feats = strArray(c.requiresFeatures);
  const slots = strArray(c.requiredSlots);
  const minFw = strOrNull(c.minFirmware);
  const maxFw = strOrNull(c.maxFirmware);
  if (feats) out.requiresFeatures = feats;
  if (slots) out.requiredSlots = slots;
  if (minFw) out.minFirmware = minFw;
  if (maxFw) out.maxFirmware = maxFw;
  return Object.keys(out).length > 0 ? out : undefined;
}

/** Normalizes a capability grant ({ name, label?, conditions? }). */
function normalizeCapabilityGrant(raw: unknown): SupportCapabilityGrant | undefined {
  if (!raw || typeof raw !== 'object') return undefined;
  const g = raw as Record<string, unknown>;
  const id = strOrNull(g.name);
  if (!id) return undefined;
  const out: SupportCapabilityGrant = { name: id };
  const label = strOrNull(g.label);
  if (label) out.label = label;
  const cond = normalizeCondition(g.conditions);
  if (cond) out.conditions = cond;
  return out;
}

/** Normalizes an intent grant ({ actionId, label?, conditions? }). */
function normalizeIntentGrant(raw: unknown): SupportIntentGrant | undefined {
  if (!raw || typeof raw !== 'object') return undefined;
  const g = raw as Record<string, unknown>;
  const id = strOrNull(g.actionId);
  if (!id) return undefined;
  const out: SupportIntentGrant = { actionId: id };
  const label = strOrNull(g.label);
  if (label) out.label = label;
  const cond = normalizeCondition(g.conditions);
  if (cond) out.conditions = cond;
  return out;
}

/**
 * Defensively normalizes a raw `deviceSupport` object from /discover: keeps
 * only well-formed fields, drops malformed profile/grant entries instead of
 * failing discovery. The API persists the normalized document verbatim —
 * evaluation against a device happens at read time (types/deviceSupport.ts).
 */
function normalizeDeviceSupport(raw: unknown): DeviceSupport | undefined {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return undefined;
  const d = raw as Record<string, unknown>;
  const out: DeviceSupport = {};

  // License — { name (required), url?, file? }.
  const lic = d.license;
  if (lic && typeof lic === 'object') {
    const l = lic as Record<string, unknown>;
    const name = strOrNull(l.name);
    if (name) {
      out.license = { name };
      const url = strOrNull(l.url);
      if (url) out.license.url = url;
      const file = safeAssetPath(l.file);
      if (file) out.license.file = file;
    }
  }

  const helpUrl = strOrNull(d.helpUrl);
  if (helpUrl) out.helpUrl = helpUrl;
  const docPath = safeAssetPath(d.docPath);
  if (docPath) out.docPath = docPath;

  // Default capabilities — grants effective on every device of this plugin.
  if (Array.isArray(d.defaultCapabilities)) {
    const caps = d.defaultCapabilities.map(normalizeCapabilityGrant).filter((g): g is SupportCapabilityGrant => !!g);
    if (caps.length > 0) out.defaultCapabilities = caps;
  }

  // Profiles — the support matrix; first match wins at evaluation time.
  const profiles: DeviceSupportProfile[] = [];
  if (Array.isArray(d.profiles)) {
    for (const p of d.profiles) {
      if (!p || typeof p !== 'object') continue;
      const pr = p as Record<string, unknown>;
      const entry: DeviceSupportProfile = { capabilities: [] };
      const vendor = strOrNull(pr.vendor);
      if (vendor) entry.vendor = vendor;
      const model = strOrNull(pr.model);
      if (model) entry.model = model;
      const minFw = strOrNull(pr.minFirmware);
      if (minFw) entry.minFirmware = minFw;
      const maxFw = strOrNull(pr.maxFirmware);
      if (maxFw) entry.maxFirmware = maxFw;
      const caps = Array.isArray(pr.capabilities)
        ? pr.capabilities.map(normalizeCapabilityGrant).filter((g): g is SupportCapabilityGrant => !!g)
        : [];
      if (caps.length === 0 && !vendor && !model) continue; // a profile must grant something or match something
      entry.capabilities = caps;
      const intents = Array.isArray(pr.intents)
        ? pr.intents.map(normalizeIntentGrant).filter((g): g is SupportIntentGrant => !!g)
        : [];
      if (intents.length > 0) entry.intents = intents;
      profiles.push(entry);
    }
  }
  if (profiles.length > 0) out.profiles = profiles;

  // A document with nothing useful in it is treated as absent.
  const hasContent = !!out.license || !!out.helpUrl || !!out.docPath || (out.defaultCapabilities?.length ?? 0) > 0 || profiles.length > 0;
  return hasContent ? out : undefined;
}

/** Normalizes a raw icon path: must be a relative path (no scheme, no ".."). */
function normalizeIconPath(raw: unknown): string | null {
  if (typeof raw !== 'string' || raw.trim() === '') return null;
  const p = raw.trim();
  if (/^[a-z][a-z0-9+.-]*:/i.test(p)) return null; // scheme like http: — reject
  if (p.includes('..')) return null; // path traversal — reject
  return p.startsWith('/') ? p : `/${p}`;
}

/**
 * Defensively normalizes a raw `quickActions` array from /discover: keeps only
 * entries with a non-empty string id + label and a known kind, coerces the
 * optional url.path to a string, and drops malformed items instead of failing
 * discovery. The API persists the list verbatim — validation against the plugin's
 * own catalog (kind 'action' → actionId must exist) happens at render time in the
 * webapp, not here.
 */
function normalizeQuickActions(raw: unknown): unknown[] | undefined {
  if (!Array.isArray(raw)) return undefined;
  const out: unknown[] = [];
  for (const item of raw) {
    if (!item || typeof item !== 'object') continue;
    const e = item as Record<string, unknown>;
    if (typeof e.id !== 'string' || e.id.trim() === '') continue;
    if (typeof e.label !== 'string' || e.label.trim() === '') continue;
    if (e.kind !== 'url' && e.kind !== 'shell' && e.kind !== 'files' && e.kind !== 'action') continue;
    const entry: Record<string, unknown> = { id: e.id.trim(), label: e.label.trim(), kind: e.kind };
    if (typeof e.description === 'string' && e.description.trim() !== '') entry.description = e.description.trim();
    // Plugin-provided icon path — kept verbatim; the API icon proxy re-validates
    // it (scheme/traversal) when the webapp actually requests the image.
    if (typeof e.iconPath === 'string' && e.iconPath.trim() !== '') entry.iconPath = e.iconPath.trim();
    if (e.kind === 'url') {
      const urlObj = (e.url && typeof e.url === 'object' ? e.url : {}) as Record<string, unknown>;
      const path = typeof urlObj.path === 'string' ? urlObj.path.trim() : '';
      entry.url = path !== '' ? { path } : {};
    }
    if (e.kind === 'action') {
      if (typeof e.actionId !== 'string' || e.actionId.trim() === '') continue; // unusable without a target
      entry.actionId = e.actionId.trim();
      if (e.prefill && typeof e.prefill === 'object' && !Array.isArray(e.prefill)) entry.prefill = e.prefill;
    }
    out.push(entry);
  }
  return out.length > 0 ? out : undefined;
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
      quickActions: normalizeQuickActions(data.quickActions),
      iconUrl: normalizeIconPath(data.iconUrl),
      deviceModels: normalizeDeviceModels(data.deviceModels),
      credentialSlots: normalizeCredentialSlots(data.credentialSlots),
      deviceSupport: normalizeDeviceSupport(data.deviceSupport),
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
  // Quick actions: same guard — an empty/absent list must not wipe stored ones
  // (the mDNS TXT path carries none).
  const hasQuickActions = Array.isArray(identity.quickActions) && identity.quickActions.length > 0;
  const quickActionsJson = hasQuickActions ? JSON.stringify(identity.quickActions) : null;
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
  // Device support metadata: same guard — only overwrite when this discovery
  // source actually carries a document (the mDNS TXT path does not).
  const deviceSupportJson = identity.deviceSupport ? JSON.stringify(identity.deviceSupport) : null;

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
        ...(hasQuickActions ? { quickActions: quickActionsJson } : {}),
        ...(hasIcon ? { iconUrl } : {}),
        ...(hasModels ? { deviceModels: deviceModelsJson } : {}),
        ...(hasSlots ? { credentialSlots: credentialSlotsJson } : {}),
        ...(deviceSupportJson !== null ? { deviceSupport: deviceSupportJson } : {}),
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
      quickActions: quickActionsJson,
      iconUrl,
      deviceModels: deviceModelsJson,
      credentialSlots: credentialSlotsJson,
      deviceSupport: deviceSupportJson,
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