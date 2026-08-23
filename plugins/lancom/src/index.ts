import express from 'express';
import cors from 'cors';
import { Bonjour } from 'bonjour-service';
import { SnmpCredentials, buildSnmpCredentials } from '@unm/snmp-client';
import { LcosOptions, getLcosInventory, walkLcosCounters } from './lcosClient';
import { buildDescriptors, DISCOVER_METRICS, INVENTORY_INTERVAL_MS, MetricDescriptor } from './metrics';

export const PLUGIN_UUID = '00000000-0000-4000-8000-000000000004';
export const PLUGIN_NAME = 'LANCOM LX-Series Plugin';

/**
 * Multi-instance support: set `PLUGIN_INSTANCE_ID` (e.g. "site-a") to run several
 * instances of the same plugin type — each advertises a distinct identity
 * (`<uuid>:<instanceId>`) so the API registers them as separate plugins.
 */
const INSTANCE_ID = process.env.PLUGIN_INSTANCE_ID?.trim() ?? '';
export const EFFECTIVE_UUID = INSTANCE_ID ? `${PLUGIN_UUID}:${INSTANCE_ID}` : PLUGIN_UUID;
export const DISPLAY_NAME =
  process.env.PLUGIN_DISPLAY_NAME?.trim() || (INSTANCE_ID ? `${PLUGIN_NAME} (${INSTANCE_ID})` : PLUGIN_NAME);

// 0.1.0 — initial release: LCOS-LX-MIB monitoring (system, radios, SSIDs,
// per-client stations, LAN ports) + inventory propagation for the Networks/
// Hosts pages. Read-only by design — the vendor MIB exposes no writable
// objects; actions require a separate transport (future phase).
export const PLUGIN_VERSION = '0.1.0';
export const PLUGIN_VENDORS = ['lancom'];
export const PLUGIN_CAPABILITIES = ['monitoring', 'inventory'];
export const PLUGIN_AUTH_TYPE = 'none';

const PORT = Number(process.env.PORT ?? 4006);
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
    min: 1_000,
    max: 30_000,
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
      'Container-internal directory holding extra MIB files. Defaults to the MIB_DIR env var (the mounted ./plugins/lancom/mibs volume at /app/mibs). Parsing uses numeric OIDs — MIBs are for debugging only.',
  },
  {
    key: 'inventoryTtlMs',
    label: 'Inventory refresh interval (ms)',
    type: 'integer' as const,
    default: INVENTORY_INTERVAL_MS,
    min: 60_000,
    max: 86_400_000,
    description:
      'How often the slow-changing LCOS status walk (radios, SSIDs, clients, LAN) is re-run. Live byte counters and station event deltas still refresh every poll cycle.',
  },
  {
    key: 'maxClientRows',
    label: 'Max client/neighbor rows',
    type: 'integer' as const,
    default: 100,
    min: 10,
    max: 2_000,
    description:
      'Caps the per-client station table and RF neighbor scan payloads. Higher values increase walk size on busy APs.',
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
function resolveOptions(settings: Record<string, unknown>): LcosOptions {
  const settingMib = typeof settings.mibDir === 'string' && settings.mibDir.trim() ? settings.mibDir.trim() : '';
  return {
    timeoutMs: clampInt(settings.timeoutMs, 1_000, 30_000, 5_000),
    retries: clampInt(settings.retries, 0, 10, 2),
    mibDir: settingMib || (process.env.MIB_DIR ? process.env.MIB_DIR : undefined),
    inventoryTtlMs: clampInt(settings.inventoryTtlMs, 60_000, 86_400_000, INVENTORY_INTERVAL_MS),
    maxClientRows: clampInt(settings.maxClientRows, 10, 2_000, 100),
  };
}

/** Extracts SNMP credentials from the monitoring body (decrypted by the API). */
function resolveCredentials(body: Record<string, unknown>): { creds?: SnmpCredentials; error?: string } {
  const credentials = (body.credentials ?? {}) as Record<string, unknown>;
  return buildSnmpCredentials(credentials);
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
        ...buildDescriptors(opts.inventoryTtlMs),
        { key: 'system.error', label: 'Error', type: 'string' as const, visualization: 'text' as const, group: 'System' },
      ],
      error,
    });
  };

  if (!host) return fail('critical', 'No target address — set the device management address.');

  const { creds, error } = resolveCredentials(body);
  if (error || !creds) return fail('critical', error ?? 'Missing SNMP credentials.');

  try {
    // Slow path: targeted parallel LCOS walks (only the subtrees we use),
    // TTL-cached per host with a quality gate against partial-failure data.
    const inventory = await getLcosInventory(host, creds, opts);
    const snapshot = inventory.snapshot;

    if (!snapshot) {
      // No LCOS tree at all — this device is not a LANCOM LX AP (or SNMP is
      // misconfigured). 'unknown' rather than 'critical': the plugin may simply
      // be assigned to the wrong device type.
      return fail('unknown', inventory.error ?? 'No LCOS-LX MIB data on this device.');
    }

    // Fast path: counter-only walks every cycle for fresh rates + event deltas.
    const fast = await walkLcosCounters(host, creds, opts);

    const metrics: Record<string, unknown> = {};
    const sys = snapshot.system;
    metrics['system.name'] = sys.name || null;
    metrics['system.swVersion'] = sys.swVersion || null;
    metrics['system.serialNumber'] = sys.serialNumber || null;
    metrics['system.uptime'] = sys.uptimeSeconds; // seconds — format:'duration' renders "1d 2h …"
    metrics['system.cpuLoad'] = sys.cpuLoadPct;
    if (sys.memoryTotalKb !== null && sys.memoryFreeKb !== null) {
      const usedPct = Math.round(((sys.memoryTotalKb - sys.memoryFreeKb) / sys.memoryTotalKb) * 100);
      metrics['system.memoryUsedPct'] = Math.max(0, Math.min(100, usedPct));
    } else {
      metrics['system.memoryUsedPct'] = null;
    }
    metrics['system.bootcount'] = sys.bootcount;

    // Management mode: CAPWAP-managed APs have their config owned by the WLC —
    // surface this prominently so users don't expect local changes to stick.
    const mgmt = snapshot.management;
    metrics['management.mode'] = mgmt.capwapState || 'standalone';
    metrics['management.controller'] = mgmt.controller || null;
    metrics['management.lmcStatus'] = mgmt.lmcStatus || null;

    // --- WiFi (only when the device actually exposes WLAN data) -----------
    const hasWifi = snapshot.radios.length > 0 || snapshot.ssids.length > 0 || snapshot.clients.length > 0;
    if (hasWifi) {
      metrics['wifi.radios'] = snapshot.radios.map((r) => ({
        band: r.band || '—',
        channel: r.channel !== null ? String(r.channel) : '—',
        mode: r.mode || '—',
        txPowerDbm: r.txPowerDbm !== null ? `${r.txPowerDbm} dBm` : '—',
        noiseFloorDbm: r.noiseFloorDbm !== null ? `${r.noiseFloorDbm} dBm` : '—',
        modemLoadPct: r.modemLoadPct !== null ? `${r.modemLoadPct}%` : '—',
        stations: r.stations ?? '—',
        temperatureC: r.temperatureC !== null ? `${r.temperatureC} °C` : '—',
      }));

      metrics['wifi.ssids'] = snapshot.ssids.map((s) => ({
        ssid: s.ssid || s.name,
        bssid: s.bssid || '—',
        band: s.band || '—',
        vlanId: s.vlanId !== null ? String(s.vlanId) : '—',
        encryption: s.encryption || '—',
        maxStations: s.maxStations ?? '—',
        pskFailures: `${s.pskFailures} (${s.pskWrongPassphrase} wrong pw)`,
      }));

      metrics['wifi.clients'] = snapshot.clients.map((c) => ({
        mac: c.mac,
        hostname: c.hostname || c.username || '—',
        ssid: c.ssid || '—',
        band: c.band || '—',
        signalDbm: c.signalDbm !== null ? `${c.signalDbm} dBm` : '—',
        txRateMbps: c.txRateMbps !== null ? `${c.txRateMbps}` : '—',
        rxRateMbps: c.rxRateMbps !== null ? `${c.rxRateMbps}` : '—',
        vlanId: c.vlanId !== null ? String(c.vlanId) : '—',
        mode: c.mode || '—',
      }));

      if (snapshot.channelUtilization.length > 0) {
        metrics['wifi.channelUtilization'] = snapshot.channelUtilization.map((c) => ({
          channel: String(c.channel),
          utilizationPct: c.utilizationPct !== null ? `${c.utilizationPct}%` : '—',
          overload: c.overload ? 'yes' : 'no',
        }));
      }

      // Station lifecycle events since the last poll (trap-counter deltas).
      if (fast && Object.keys(fast.wifiEvents).length > 0) {
        metrics['wifi.events'] = Object.entries(fast.wifiEvents).map(([event, count]) => ({ event, count }));
      }

      // Radio throughput rates (bits/s) from the fast-path byte counters.
      if (fast && Object.keys(fast.radioRates).length > 0) {
        metrics['wifi.rates'] = fast.radioRates; // { <ifc>: { rx, tx } } — MAP form table
      }

      // RF environment: neighbor APs seen by the scan engine (slow path).
      if (snapshot.neighbors.length > 0) {
        metrics['wifi.neighbors'] = snapshot.neighbors.map((n) => ({
          bssid: n.bssid,
          ssid: n.ssid || '—',
          channel: n.channel !== null ? String(n.channel) : '—',
          band: n.band || '—',
          signalDbm: n.signalDbm !== null ? `${n.signalDbm} dBm` : '—',
        }));
      }

      // WDS/mesh links to other LANCOM APs (slow path).
      if (snapshot.wdsLinks.length > 0) {
        metrics['wifi.wdsLinks'] = snapshot.wdsLinks.map((l) => ({
          name: l.name,
          remoteMac: l.remoteMac,
          connected: l.connected === null ? '—' : l.connected ? 'up' : 'down',
          signalDbm: l.signalDbm !== null ? `${l.signalDbm} dBm` : '—',
        }));
      }
    }

    // --- LAN ----------------------------------------------------------------
    metrics['lan.ports'] = snapshot.ports.map((p) => ({
      name: p.name,
      linkUp: p.linkUp === null ? '—' : p.linkUp ? 'up' : 'down',
      speedLabel: p.speedLabel || '—',
      mac: p.mac || '—',
    }));

    if (fast && Object.keys(fast.portRates).length > 0) {
      metrics['lan.rates'] = fast.portRates; // { <port>: { rx, tx, crcPerSec } } — MAP form table
    }

    // --- Inventory propagation (consumed by the API's ingestInventory) -----
    // networks[]: IP rows + interface rows without IPs (MAC from LAN ports).
    const portMac = new Map(snapshot.ports.map((p) => [p.name, p.mac]));
    const ipIfnames = new Set(snapshot.ips.map((i) => i.ifname));
    const networks: Array<Record<string, unknown>> = snapshot.ips.map((ip) => ({
      name: ip.ifname,
      ip: ip.address,
      // Canonical values are 'v4'/'v6' (what the OPNsense plugin emits); the API
      // also tolerates 'ipv4'/'ipv6', but stay consistent with the other plugins.
      version: ip.version === '4' ? 'v4' : 'v6',
      status: null,
    }));
    for (const p of snapshot.ports) {
      if (!ipIfnames.has(p.name)) {
        networks.push({ name: p.name, ip: '', mac: p.mac || null, status: p.linkUp ? 'up' : 'down' });
      } else if (portMac.get(p.name)) {
        // Attach the port MAC to its IP row for topology detection.
        const row = networks.find((n) => n.name === p.name && n.ip === snapshot.ips.find((i) => i.ifname === p.name)?.address);
        if (row) row.mac = portMac.get(p.name);
      }
    }
    // WLAN SSID rows — one per LOGICAL network. The same SSID on the same VLAN
    // can be broadcast by several radios (e.g. 5 GHz + 6 GHz); those are ONE
    // network, so merge them here (per-radio details stay in wifi.ssids).
    const ssidSeen = new Set<string>();
    for (const s of snapshot.ssids) {
      const name = s.ssid || s.name;
      if (!name) continue;
      const vlanId = s.vlanId ?? null;
      const key = `${name}|${vlanId}`;
      if (ssidSeen.has(key)) continue;
      ssidSeen.add(key);
      networks.push({ name, ip: '', vlanId, status: 'up' });
    }
    // Safety net for the API's upsert key (name, ip): never emit two rows with
    // that key in one snapshot — Postgres would reject the whole batch.
    const emittedNetKeys = new Set<string>();
    metrics['networks'] = networks.filter((n) => {
      const k = `${n.name}|${n.ip}`;
      if (emittedNetKeys.has(k)) return false;
      emittedNetKeys.add(k);
      return true;
    });

    // wlanClients[] → hosts table with source 'wlan' (API-side ingestion).
    const wlanClients = snapshot.clients
      .filter((c) => c.ip4 !== '' || c.ip6 !== '')
      .map((c) => ({
        mac: c.mac,
        ip: c.ip4 || c.ip6,
        hostname: c.hostname || c.username || null,
        intf: c.ifc || null,
      }));
    if (wlanClients.length > 0) metrics['wlanClients'] = wlanClients;

    // --- Health -------------------------------------------------------------
    let health: Health = 'ok';
    const warnings: string[] = [];
    if (!sys.name && !sys.swVersion) warnings.push('system scalars unavailable');
    if (snapshot.radios.length === 0 && snapshot.ports.length === 0) warnings.push('no radios or LAN ports reported');
    if (inventory.error) warnings.push(inventory.error);
    if (warnings.length > 0) {
      health = 'warning';
      metrics['system.error'] = warnings.join('; ');
    }

    const descriptors: MetricDescriptor[] = buildDescriptors(opts.inventoryTtlMs, hasWifi);
    // Runtime rows for the MAP-form rate tables.
    if (fast && Object.keys(fast.radioRates).length > 0) {
      const d = descriptors.find((x) => x.key === 'wifi.rates');
      if (d) d.rows = Object.keys(fast.radioRates);
    }
    if (fast && Object.keys(fast.portRates).length > 0) {
      const d = descriptors.find((x) => x.key === 'lan.rates');
      if (d) d.rows = Object.keys(fast.portRates);
    }
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
        maxClientRows: opts.maxClientRows,
      },
    });
  } catch (err) {
    return fail('critical', (err as Error).message);
  }
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
    console.log(`[lancom-plugin] advertising via mDNS as "${DISPLAY_NAME}" (${EFFECTIVE_UUID})`);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.warn('[lancom-plugin] mDNS advertising unavailable, falling back to polling discovery only:', (err as Error).message);
  }
}

app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`[lancom-plugin] listening on port ${PORT}`);
  startMdnsAdvertising();
});
