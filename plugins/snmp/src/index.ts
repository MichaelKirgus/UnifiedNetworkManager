import express from 'express';
import cors from 'cors';
import { Bonjour } from 'bonjour-service';
import {
  SnmpCredentials,
  SystemInfo,
  WifiAccessPoint,
  WifiClient,
  WalkOptions,
  getInventory,
  walkCounters,
  computeRates,
} from './snmpClient';
import { buildDescriptors, DISCOVER_METRICS, INVENTORY_INTERVAL_MS, MetricDescriptor } from './metrics';

export const PLUGIN_UUID = '00000000-0000-4000-8000-000000000003';
export const PLUGIN_NAME = 'SNMP Plugin';

/**
 * Multi-instance support: set `PLUGIN_INSTANCE_ID` (e.g. "site-a") to run several
 * instances of the same plugin type — each advertises a distinct identity
 * (`<uuid>:<instanceId>`) so the API registers them as separate plugins.
 * `PLUGIN_DISPLAY_NAME` optionally overrides the advertised name; without it,
 * the instance id is appended: "SNMP Plugin (site-a)". Unset = single-instance behavior.
 */
const INSTANCE_ID = process.env.PLUGIN_INSTANCE_ID?.trim() ?? '';
export const EFFECTIVE_UUID = INSTANCE_ID ? `${PLUGIN_UUID}:${INSTANCE_ID}` : PLUGIN_UUID;
export const DISPLAY_NAME =
  process.env.PLUGIN_DISPLAY_NAME?.trim() || (INSTANCE_ID ? `${PLUGIN_NAME} (${INSTANCE_ID})` : PLUGIN_NAME);
// 0.3.0 — WiFi (802.11) collection: IEEE 802.11 MIB walks for access-point
// and client facts, gated by the boolean `collectWifi` option (default on).
export const PLUGIN_VERSION = '0.3.0';
export const PLUGIN_VENDORS = ['generic'];
export const PLUGIN_CAPABILITIES = ['monitoring', 'inventory'];
export const PLUGIN_AUTH_TYPE = 'none';

const PORT = Number(process.env.PORT ?? 4005);
const ADVERTISED_ENDPOINT = process.env.ADVERTISED_ENDPOINT ?? `http://localhost:${PORT}`;

type Health = 'ok' | 'warning' | 'critical' | 'unknown';

/**
 * Configurable options. Declared in /discover so the API persists user-set
 * values and injects them back via the `x-unm-settings` header on every call —
 * this plugin never stores settings itself (see readSettings()).
 */
const PLUGIN_OPTIONS = [
  {
    key: 'timeoutMs',
    label: 'SNMP timeout (ms)',
    type: 'integer' as const,
    default: 5000,
    min: 1000,
    max: 30000,
    description: 'Per-request SNMP timeout. Kept well under the API\'s 10s poll budget.',
  },
  {
    key: 'retries',
    label: 'SNMP retries',
    type: 'integer' as const,
    default: 2,
    min: 0,
    max: 10,
    description: 'How many times snmpwalk retries a request before giving up.',
  },
  {
    key: 'mibDir',
    label: 'MIB directory (container path)',
    type: 'string' as const,
    maxLength: 512,
    description:
      'Container-internal directory holding extra MIB files. Defaults to the MIB_DIR env var (the mounted ./plugins/snmp/mibs volume at /app/mibs). Standard MIBs ship with net-snmp and are always available.',
  },
  {
    key: 'inventoryTtlMs',
    label: 'Inventory refresh interval (ms)',
    type: 'integer' as const,
    default: INVENTORY_INTERVAL_MS,
    min: 60_000,
    max: 86_400_000,
    description:
      'How often the slow-changing inventory walks (system group + interface table) are re-run. Live throughput counters still refresh every poll cycle.',
  },
  {
    key: 'collectWifi',
    label: 'Collect WiFi data (802.11 MIBs)',
    type: 'boolean' as const,
    default: true,
    description:
      'Walk IEEE 802.11 MIB tables for access-point and client info (SSID, BSSID, channel, security + connected client MACs). Refreshes with the inventory interval. Turn off per-device when a dedicated WiFi plugin covers the device.',
  },
];

const app = express();
app.use(cors());
app.use(express.json());

app.get('/healthz', (_req, res) => {
  res.status(200).json({ status: 'ok' });
});

app.get('/discover', (_req, res) => {
  res.status(200).json({
    uuid: EFFECTIVE_UUID,
    name: DISPLAY_NAME,
    version: PLUGIN_VERSION,
    vendors: PLUGIN_VENDORS,
    capabilities: PLUGIN_CAPABILITIES,
    endpoint: ADVERTISED_ENDPOINT,
    authType: PLUGIN_AUTH_TYPE,
    // Credentials come from the existing 'snmp' secret type (version + community for v1/v2c, USM fields for v3).
    requiredSecretType: 'snmp',
    metrics: DISCOVER_METRICS,
    options: PLUGIN_OPTIONS,
  });
});

/**
 * Reads the effective settings the API injects on every call (defaults ⊕ user
 * overrides) from the `x-unm-settings` JSON header, merged over this plugin's
 * declared defaults so a missing header still yields sane values.
 */
function readSettings(req: { headers?: Record<string, unknown> }): Record<string, unknown> {
  const defaults: Record<string, unknown> = {};
  for (const opt of PLUGIN_OPTIONS) if (opt.default !== undefined) defaults[opt.key] = opt.default;

  const raw = req.headers?.['x-unm-settings'];
  if (typeof raw !== 'string' || raw.trim() === '') return defaults;
  try {
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === 'object') return { ...defaults, ...(parsed as Record<string, unknown>) };
  } catch {
    // Malformed header: fall back to defaults rather than failing the call.
  }
  return defaults;
}

function clampInt(value: unknown, min: number, max: number, fallback: number): number {
  const n = typeof value === 'number' && Number.isInteger(value) ? value : fallback;
  return Math.min(max, Math.max(min, n));
}

/** Extracts a bare host (no scheme/port/brackets) from a management address. */
function hostFromAddress(address: string): string {
  const trimmed = (address ?? '').trim();
  if (!trimmed) return '';
  try {
    const u = new URL(trimmed.includes('://') ? trimmed : `http://${trimmed}`);
    return u.hostname.replace(/^\[|\]$/g, ''); // strip IPv6 literal brackets
  } catch {
    return trimmed.split('/')[0].split(':')[0];
  }
}

/** Resolves walk options from effective settings. */
function resolveOptions(settings: Record<string, unknown>): WalkOptions {
  // mibDir precedence: plugin option (per-device/global) > MIB_DIR env var
  // (set in docker-compose to the mounted ./plugins/snmp/mibs volume).
  const settingMib = typeof settings.mibDir === 'string' && settings.mibDir.trim() ? settings.mibDir.trim() : '';
  return {
    timeoutMs: clampInt(settings.timeoutMs, 1_000, 30_000, 5_000),
    retries: clampInt(settings.retries, 0, 10, 2),
    mibDir: settingMib || (process.env.MIB_DIR ? process.env.MIB_DIR : undefined),
    inventoryTtlMs: clampInt(settings.inventoryTtlMs, 60_000, 86_400_000, INVENTORY_INTERVAL_MS),
    // WiFi collection is ON by default — only an explicit false disables it.
    collectWifi: settings.collectWifi !== false,
  };
}

/** Reads a trimmed string field from the decrypted secret fields. */
function strField(fields: Record<string, unknown>, key: string): string {
  const v = fields[key];
  return typeof v === 'string' ? v.trim() : '';
}

const V3_SECURITY_LEVELS = ['noAuthNoPriv', 'authNoPriv', 'authPriv'] as const;
const V3_AUTH_PROTOCOLS = ['MD5', 'SHA'] as const;
const V3_PRIV_PROTOCOLS = ['DES', 'AES'] as const;

/**
 * Builds + validates SNMP credentials from a flat field map. Shared by all
 * credential sources so the rules are identical everywhere:
 *   - /monitoring  → fields come from the decrypted `snmp` secret (API body)
 *   - POST /inventory → same JSON body contract as /monitoring (v3-capable)
 *   - GET  /inventory → query params, v1/v2c only (community strings are fine
 *                       in URLs; USM passwords must not be — see the routes)
 *
 * Per-version required set: v1/v2c need a community string; v3 needs a USM
 * username + security level, with auth/priv protocol+password pairs added per
 * security level. Error messages are source-neutral (no "secret"/"query param"
 * wording) since the same builder serves both paths.
 */
function buildSnmpCredentials(fields: Record<string, unknown>): { creds?: SnmpCredentials; error?: string } {
  const versionRaw = strField(fields, 'version') || 'v2c';
  if (versionRaw !== 'v1' && versionRaw !== 'v2c' && versionRaw !== 'v3') {
    return { error: `SNMP version "${versionRaw}" is not supported — this plugin supports v1, v2c and v3.` };
  }

  // v1/v2c — community string based.
  if (versionRaw === 'v1' || versionRaw === 'v2c') {
    const community = strField(fields, 'community');
    if (!community) return { error: `No SNMP community configured for ${versionRaw} devices.` };
    return { creds: { version: versionRaw, community } };
  }

  // v3 (USM) — username + security level; auth/priv pairs per level.
  const username = strField(fields, 'username');
  if (!username) return { error: 'SNMPv3 requires a USM username.' };

  const securityLevel = strField(fields, 'securityLevel') || 'noAuthNoPriv';
  if (!(V3_SECURITY_LEVELS as readonly string[]).includes(securityLevel)) {
    return { error: `SNMPv3 security level "${securityLevel}" is invalid — use noAuthNoPriv, authNoPriv or authPriv.` };
  }

  const creds: SnmpCredentials = { version: 'v3', username, securityLevel: securityLevel as SnmpCredentials['securityLevel'] };

  if (securityLevel !== 'noAuthNoPriv') {
    const authProtocol = strField(fields, 'authProtocol');
    const authPassword = strField(fields, 'authPassword');
    if (!authProtocol || !authPassword) {
      return { error: `SNMPv3 security level "${securityLevel}" requires an auth protocol and auth password.` };
    }
    if (!(V3_AUTH_PROTOCOLS as readonly string[]).includes(authProtocol)) {
      return { error: `SNMPv3 auth protocol "${authProtocol}" is invalid — use MD5 or SHA.` };
    }
    creds.authProtocol = authProtocol as 'MD5' | 'SHA';
    creds.authPassword = authPassword;
  }

  if (securityLevel === 'authPriv') {
    const privProtocol = strField(fields, 'privProtocol');
    const privPassword = strField(fields, 'privPassword');
    if (!privProtocol || !privPassword) {
      return { error: 'SNMPv3 security level "authPriv" requires a privacy protocol and privacy password.' };
    }
    if (!(V3_PRIV_PROTOCOLS as readonly string[]).includes(privProtocol)) {
      return { error: `SNMPv3 privacy protocol "${privProtocol}" is invalid — use DES or AES.` };
    }
    creds.privProtocol = privProtocol as 'DES' | 'AES';
    creds.privPassword = privPassword;
  }

  return { creds };
}

/** Extracts SNMP credentials from the monitoring body (decrypted by the API). */
function resolveCredentials(body: Record<string, unknown>): { creds?: SnmpCredentials; error?: string } {
  const credentials = (body.credentials ?? {}) as Record<string, unknown>;
  return buildSnmpCredentials(credentials);
}

/** Builds the per-interface rate map keyed by unique display name. */
function buildInterfaceRateMap(
  interfaces: Array<{ ifIndex: string; name: string }>,
  ratesByIndex: Record<string, { rx: number | null; tx: number | null }>
): { map: Record<string, { rx: number | null; tx: number | null }>; names: string[] } {
  const seen = new Set<string>();
  const map: Record<string, { rx: number | null; tx: number | null }> = {};
  const names: string[] = [];

  for (const iface of interfaces) {
    let key = iface.name || `if${iface.ifIndex}`;
    while (seen.has(key)) key += '…'; // defensive — duplicate display names
    seen.add(key);
    map[key] = ratesByIndex[iface.ifIndex] ?? { rx: null, tx: null };
    names.push(key);
  }

  return { map, names };
}

app.post('/monitoring', async (req, res) => {
  const body = req.body ?? {};
  const deviceId = typeof body.deviceId === 'string' ? body.deviceId : null;
  const managementAddress = typeof body.managementAddress === 'string' ? body.managementAddress : '';

  const settings = readSettings(req);
  const opts = resolveOptions(settings);
  const host = hostFromAddress(managementAddress);

  const fail = (health: Health, error: string) => {
    res.status(200).json({
      deviceId,
      collectedAt: new Date().toISOString(),
      health,
      metrics: { 'system.error': error },
      metricDescriptors: [
        ...buildDescriptors([], opts.inventoryTtlMs),
        { key: 'system.error', label: 'Error', type: 'string' as const, visualization: 'text' as const, group: 'System' },
      ],
      error,
    });
  };

  if (!host) return fail('critical', 'No target address — set the device management address.');

  const { creds, error } = resolveCredentials(body);
  if (error || !creds) return fail('critical', error ?? 'Missing SNMP credentials.');

  try {
    // Slow path: system group + interface table, TTL-cached per host.
    const inventory = await getInventory(host, creds, opts);
    const snapshot = inventory.snapshot;

    if (!snapshot) {
      return fail('critical', inventory.error ?? 'SNMP collection failed — no data available.');
    }

    // Fast path: counter-only walk every cycle for fresh rates.
    let counters = await walkCounters(host, creds, opts, snapshot.useHc);
    if (!counters) {
      // Counter walk failed this cycle — fall back to the cached table's
      // counters so we still emit *something* (rates will be stale/skipped).
      counters = snapshot.counters;
    }

    const ratesByIndex = computeRates(host, counters);
    const { map: interfaceMap, names } = buildInterfaceRateMap(snapshot.interfaces, ratesByIndex);

    // Aggregated throughput (bits/s): sum of all non-null rx + tx.
    let total: number | null = null;
    for (const r of Object.values(interfaceMap)) {
      if (r.rx !== null || r.tx !== null) {
        total = (total ?? 0) + (r.rx ?? 0) + (r.tx ?? 0);
      }
    }

    const metrics: Record<string, unknown> = {};
    const sys = snapshot.system;
    if (sys) {
      metrics['system.description'] = sys.description || null;
      metrics['system.objectId'] = sys.objectId || null;
      metrics['system.name'] = sys.name || null;
      metrics['system.location'] = sys.location || null;
      metrics['system.contact'] = sys.contact || null;
      metrics['system.uptime'] = sys.uptimeSeconds; // seconds — format:'duration' renders "1d 2h …"
    }

    metrics.interfaces = interfaceMap; // { <name>: { rx, tx } } bits/s (null until 2nd sample)
    metrics['throughput.total'] = total;

    // Inventory: per-interface attributes for later use.
    metrics['inventory.interfaces'] = snapshot.interfaces.map((i) => ({
      name: i.name || `if${Number(i.ifIndex)}`,
      type: i.type,
      speed: i.speedBps !== null ? `${(i.speedBps / 1_000_000).toFixed(0)} Mbit` : '—',
      mac: i.mac || '—',
      status: i.status,
    }));

    // WiFi (IEEE 802.11 MIBs): emitted only when collection is enabled AND the
    // device actually exposed WLAN data — absence on non-AP devices is normal
    // and must not degrade health or add descriptors.
    const wifi = snapshot.wifi;
    if (wifi && (wifi.accessPoints.length > 0 || wifi.clients.length > 0)) {
      metrics['wifi.accessPoints'] = wifi.accessPoints.map((ap) => ({
        ssid: ap.ssid || '—',
        bssid: ap.bssid || '—',
        channel: ap.channel !== null ? String(ap.channel) : '—',
        security: ap.security || '—',
      }));
      metrics['wifi.clients'] = wifi.clients.map((c) => ({
        mac: c.mac,
        ssid: c.ssid || '—',
        rate: c.rateMbps !== null ? `${c.rateMbps} Mbit` : '—',
      }));
    }

    // Health: partial data (or a failed counter walk) degrades to warning.
    let health: Health = 'ok';
    const warnings: string[] = [];
    if (!sys) warnings.push('system group unavailable');
    if (snapshot.interfaces.length === 0) warnings.push('no interfaces reported');
    if (inventory.error) warnings.push(inventory.error);
    if (warnings.length > 0) {
      health = 'warning';
      metrics['system.error'] = warnings.join('; ');
    }

    const hasWifi = !!wifi && (wifi.accessPoints.length > 0 || wifi.clients.length > 0);
    const descriptors: MetricDescriptor[] = buildDescriptors(names, opts.inventoryTtlMs, hasWifi);
    if (metrics['system.error']) {
      descriptors.push({ key: 'system.error', label: 'Error', type: 'string', visualization: 'text', group: 'System' });
    }

    res.status(200).json({
      deviceId,
      collectedAt: new Date().toISOString(),
      health,
      metrics,
      metricDescriptors: descriptors,
      // Echo back the effective settings — proof of the API→plugin loop.
      activeSettings: {
        timeoutMs: opts.timeoutMs,
        retries: opts.retries,
        mibDir: opts.mibDir ?? null,
        inventoryTtlMs: opts.inventoryTtlMs,
        collectWifi: opts.collectWifi !== false,
      },
    });
  } catch (err) {
    return fail('critical', (err as Error).message);
  }
});

/** Shared inventory response shape + the walk/serialize core. */
interface InventoryResponse {
  capability: 'inventory';
  collectedAt: string;
  system: SystemInfo | null;
  interfaces: Array<{
    name: string;
    ifIndex: number;
    type: string;
    speedBps: number | null;
    mac: string;
    status: string;
  }>;
  /** WiFi facts when collectWifi is enabled (null = no 802.11 data on device). */
  wifi?: {
    accessPoints: WifiAccessPoint[];
    clients: WifiClient[];
    source: 'ieee802dot11-2' | 'legacy';
  } | null;
  error?: string;
}

function inventoryError(message: string): InventoryResponse {
  return { capability: 'inventory', collectedAt: new Date().toISOString(), system: null, interfaces: [], error: message };
}

async function runInventory(host: string, creds: SnmpCredentials, opts: WalkOptions): Promise<InventoryResponse> {
  try {
    const inventory = await getInventory(host, creds, opts);
    return {
      capability: 'inventory',
      collectedAt: new Date().toISOString(),
      system: inventory.snapshot?.system ?? null,
      interfaces: (inventory.snapshot?.interfaces ?? []).map((i) => ({
        name: i.name || `if${Number(i.ifIndex)}`,
        ifIndex: Number(i.ifIndex),
        type: i.type,
        speedBps: i.speedBps,
        mac: i.mac,
        status: i.status,
      })),
      // WiFi rides the same TTL-cached snapshot — no extra walks here.
      ...(inventory.snapshot?.wifi !== undefined ? { wifi: inventory.snapshot.wifi } : {}),
      ...(inventory.error ? { error: inventory.error } : {}),
    };
  } catch (err) {
    return inventoryError((err as Error).message);
  }
}

/**
 * Dedicated inventory endpoint (opnsense parity): full system + interface
 * facts on demand, usable by external/programmatic consumers without a device
 * assignment. Two routes share the same core:
 *
 *   GET  /inventory?managementAddress=…&community=…[&version=v1|v2c]
 *        Convenience form for community-based credentials — low-sensitivity
 *        shared strings that are acceptable in URLs (and shell history).
 *
 *   POST /inventory  { managementAddress, credentials: { version, … } }
 *        Same body contract as /monitoring. REQUIRED for SNMPv3: USM auth/priv
 *        passwords must not travel in query strings (URLs end up in caller
 *        history, proxy/firewall logs, and any future access logging).
 */
app.get('/inventory', async (req, res) => {
  const q = req.query ?? {};
  const host = typeof q.managementAddress === 'string' ? hostFromAddress(q.managementAddress) : '';

  if (!host) {
    return res.status(200).json(inventoryError('Provide managementAddress as a query param.'));
  }

  // v3 via GET is rejected: USM passwords must not appear in URLs.
  const versionRaw = typeof q.version === 'string' && q.version.trim() ? q.version.trim() : 'v2c';
  if (versionRaw === 'v3') {
    return res.status(200).json(
      inventoryError('SNMPv3 is not supported via GET query params — POST /inventory with a JSON body: { managementAddress, credentials: { version: "v3", username, securityLevel, … } }.')
    );
  }

  const { creds, error } = buildSnmpCredentials(q);
  if (error || !creds) {
    return res.status(200).json(inventoryError(error ?? 'Missing SNMP credentials.'));
  }

  res.status(200).json(await runInventory(host, creds, resolveOptions(readSettings(req))));
});

app.post('/inventory', async (req, res) => {
  const body = req.body ?? {};
  const managementAddress = typeof body.managementAddress === 'string' ? body.managementAddress : '';
  const host = hostFromAddress(managementAddress);

  if (!host) {
    return res.status(200).json(inventoryError('Provide managementAddress in the JSON body.'));
  }

  // Same credential contract as /monitoring: decrypted `snmp` secret fields.
  const credentials = (body.credentials ?? {}) as Record<string, unknown>;
  const { creds, error } = buildSnmpCredentials(credentials);
  if (error || !creds) {
    return res.status(200).json(inventoryError(error ?? 'Missing SNMP credentials.'));
  }

  res.status(200).json(await runInventory(host, creds, resolveOptions(readSettings(req))));
});

/**
 * Advertises this plugin over mDNS/DNS-SD so the UnifiedNetworkManager API can
 * discover it automatically. Best-effort — the API also polls known endpoints.
 */
function startMdnsAdvertising(): void {
  try {
    const bonjour = new Bonjour();
    bonjour.publish({
      name: DISPLAY_NAME,
      type: 'unm-plugin',
      port: PORT,
      txt: {
        uuid: EFFECTIVE_UUID,
        name: DISPLAY_NAME,
        version: PLUGIN_VERSION,
        vendors: PLUGIN_VENDORS.join(','),
        capabilities: PLUGIN_CAPABILITIES.join(','),
        endpoint: ADVERTISED_ENDPOINT,
        authType: PLUGIN_AUTH_TYPE,
      },
    });
    // eslint-disable-next-line no-console
    console.log(`[snmp-plugin] advertising via mDNS as "${DISPLAY_NAME}" (${EFFECTIVE_UUID})`);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.warn('[snmp-plugin] mDNS advertising unavailable, falling back to polling discovery only:', (err as Error).message);
  }
}

app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`[snmp-plugin] listening on port ${PORT}`);
  startMdnsAdvertising();
});
