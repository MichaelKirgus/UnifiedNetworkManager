import path from 'path';
import {
  Health,
  MetricDescriptor,
  PluginOptionDescriptor,
  clampInt,
  createPluginLogger,
  createPluginServer,
  createTerminalPool,
  errorDescriptor,
  hostFromAddress,
  INVENTORY_INTERVAL_MS,
  makeConsoleUpgrade,
  modelFirmwareDescriptors,
  readSettings,
  resolvePluginIdentity,
  resolveSshCredentials,
  TtlCache,
  collectDeviceCertificates,
  parseProbeTarget,
  CertificateRow,
} from '@unm/plugin-sdk';
import { SnmpCredentials, buildSnmpCredentials } from '@unm/snmp-client';
import { LcosOptions, getLcosInventory, walkLcosCounters } from './lcosClient';
import { buildDescriptors, DISCOVER_METRICS } from './metrics';
import { DEVICE_MODELS } from './deviceModels';

export const PLUGIN_UUID = '00000000-0000-4000-8000-000000000004';
export const PLUGIN_NAME = 'LANCOM LX-Series Plugin';

/**
 * Multi-instance support: set `PLUGIN_INSTANCE_ID` (e.g. "site-a") to run several
 * instances of the same plugin type — each advertises a distinct identity
 * (`<uuid>:<instanceId>`) so the API registers them as separate plugins.
 * (Convention implemented in @unm/plugin-sdk's resolvePluginIdentity.)
 */
const identity = resolvePluginIdentity({
  uuid: PLUGIN_UUID,
  name: PLUGIN_NAME,
  // 0.1.0 — initial release: LCOS-LX-MIB monitoring (system, radios, SSIDs,
  // per-client stations, LAN ports) + inventory propagation for the Networks/
  // Hosts pages. Read-only by design — the vendor MIB exposes no writable
  // objects; actions require a separate transport (future phase).
  version: '0.1.0',
  vendors: ['lancom'],
  // monitoring + inventory over the LCOS-LX MIB, plus an interactive SSH console
  // ('sshConsole') — LX access points expose a CLI shell over SSH (port 22).
  capabilities: ['monitoring', 'inventory', 'sshConsole'],
});

/**
 * Configurable options. Declared in /discover so the API persists user-set
 * values and injects them back via the `x-unm-settings` header on every call —
 * this plugin never stores settings itself (see readSettings()).
 */
const PLUGIN_OPTIONS: PluginOptionDescriptor[] = [
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
    description: 'How many times an SNMP request is retried before giving up.',
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
  {
    key: 'logToApi',
    label: 'Send logs to UNM',
    type: 'boolean' as const,
    default: true,
    description:
      'Ship structured log entries (SNMP walk failures) to the UNM API for the device Logs view. Disable to keep logging container-local only.',
  },
];

// --- Certificates (capability: cross-device Certificates page) -----------------
// Certificate rows are probed on a slower cadence than the inventory walk — they
// change rarely and each probe opens fresh TLS/SSH connections to the device.
const CERT_TTL_MS = 10 * 60_000;
const certCache = new TtlCache<CertificateRow[]>({ isFresh: (v) => Array.isArray(v) });

// --- Interactive SSH console (capability 'sshConsole') -------------------------
// LX access points expose a CLI over SSH (port 22). The webapp's DeviceDetail page
// renders a generic "Shell" button for any plugin advertising 'sshConsole'; the API
// proxies the browser's xterm.js to our /console WebSocket, which opens a PTY on the
// bound `ssh` credential slot. LX's PRIMARY secret is SNMP (a community string cannot
// log into a shell), so an explicit ssh slot MUST be bound — hence slotOnly. Unlike
// LCOS routers, LX only supports username/password SSH login (no public keys).
const termPool = createTerminalPool();
process.on('SIGTERM', () => termPool.closeAll());
process.on('SIGINT', () => termPool.closeAll());

const consoleUpgrade = makeConsoleUpgrade({
  expectedApiKey: () => process.env.PLUGIN_API_KEY ?? null,
  path: '/console',
  onOpen: async (hello) => {
    const host = hostFromAddress(hello.managementAddress);
    if (!host) throw new Error('Missing management address');
    // Only the bound ssh slot counts — the primary SNMP secret must NOT be reused.
    const creds = resolveSshCredentials(hello.credentials as Record<string, unknown> | undefined, { slotOnly: true });
    if (!creds) {
      throw new Error('No SSH credential bound — bind a usernamePassword secret to the assignment\'s "ssh" slot (LX does not support public keys).');
    }
    const conn = await termPool.get(host, 22, creds, {
      onHostKey: (fp) => console.warn(`[lancom-lx-plugin] observed host key for ${host}:22 → ${fp} (pin it in the device's SSH settings to enforce strict verification)`),
    });
    return conn.openShell(creds); // a plain LX login shell, like PuTTY
  },
});

// Pre-wired app: cors + json + /healthz + /discover (+ static icons, mDNS on
// listen) come from @unm/plugin-sdk — this file only registers its own routes.
const server = createPluginServer({
  identity,
  logTag: 'lancom-lx-plugin',
  // Interactive SSH console (capability 'sshConsole') — WS upgrades for /console.
  wsUpgrade: consoleUpgrade,
  // Static icon assets (plugin + per-model icons), advertised in /discover and
  // fetched by the API's icon proxy. dist/src/../../icons = <plugin root>/icons.
  iconsDir: path.join(__dirname, '../../icons'),
  discovery: {
    // Credentials come from the existing 'snmp' secret type (version + community for v1/v2c, USM fields for v3).
    requiredSecretType: 'snmp',
    // Optional SSH login for the interactive web console. LX only supports
    // username/password over SSH — no public keys.
    credentialSlots: [
      { name: 'ssh', secretType: 'usernamePassword', required: false, description: 'SSH login (port 22) for the interactive web console — username/password only' },
    ],
    metrics: DISCOVER_METRICS,
    options: PLUGIN_OPTIONS,
    // Icon + supported device model catalog — drives the webapp's Model/Firmware
    // dropdowns and the icon shown on the Devices pages. The user's selection is
    // forwarded to /monitoring (model/firmwareVersion) for future per-model logic.
    iconUrl: '/icons/lancom-lx.svg',
    deviceModels: DEVICE_MODELS,
  },
});
const app = server.app;

// Structured logs shipped to the API (see docs/PLUGIN-DEVELOPMENT.md, Logging).
// Emission is gated per call by the `logToApi` option via setEnabled() — it
// flows through the settings loop, so it works globally and per-device.
const logger = createPluginLogger(identity);

/** Resolves walk options from effective settings. */
function resolveOptions(settings: Record<string, unknown>): LcosOptions {
  return {
    timeoutMs: clampInt(settings.timeoutMs, 1_000, 30_000, 5_000),
    retries: clampInt(settings.retries, 0, 10, 2),
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

  // User-selected hardware model / firmware version (forwarded by the API from
  // the device row). Surfaced as System metrics so the selection is visible in
  // the webapp's monitoring view; available for future per-model data gathering.
  const selectedModel = typeof body.model === 'string' && body.model ? body.model : null;
  const selectedFirmware = typeof body.firmwareVersion === 'string' && body.firmwareVersion ? body.firmwareVersion : null;

  const settings = readSettings(req, PLUGIN_OPTIONS);
  logger.setEnabled(settings.logToApi === true);
  const opts = resolveOptions(settings);
  const host = hostFromAddress(managementAddress);

  // Window-based scheduling: the API sends collectInventory=false on metrics-only
  // polls. The slow walk stays TTL-cached (cheap between windows) and system
  // scalars keep flowing; only the cross-device inventory keys are omitted so
  // the response stays small until the next inventory-due poll.
  const emitInventory = body.collectInventory !== false;

  const fail = (health: Health, error: string) => {
    res.status(200).json({
      deviceId,
      collectedAt: new Date().toISOString(),
      health,
      metrics: { 'system.error': error },
      // hasWifi=false — a failed probe carries no WLAN data, so don't advertise
      // the WiFi groups (their summary cells would render empty).
      metricDescriptors: [
        ...buildDescriptors(opts.inventoryTtlMs, false),
        errorDescriptor(),
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
    const inventory = await getLcosInventory(host, creds, opts, {
      log: (level, message, context) => logger.warn(message, { deviceId, context }),
    });
    const snapshot = inventory.snapshot;

    if (!snapshot) {
      // No LCOS tree at all — this device is not a LANCOM LX AP (or SNMP is
      // misconfigured). 'unknown' rather than 'critical': the plugin may simply
      // be assigned to the wrong device type.
      logger.warn(`No usable LCOS-LX data from ${host}: ${inventory.error ?? 'no LCOS-LX MIB tree'}`, { deviceId, context: { host } });
      return fail('unknown', inventory.error ?? 'No LCOS-LX MIB data on this device.');
    }

    if (inventory.error) {
      // Partial walk failure — the snapshot is usable but some subtrees are empty.
      logger.warn(`Partial LCOS-LX data from ${host}: ${inventory.error}`, { deviceId, context: { host } });
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
    // User-selected hardware model / firmware (from the device form) — shown in
    // the System group so the selection is visible next to the live data.
    if (selectedModel) metrics['system.model'] = selectedModel;
    if (selectedFirmware) metrics['system.firmwareVersion'] = selectedFirmware;

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

      // Scalar summaries for the device overview table (summary: true) — one
      // channel + airtime-utilization metric PER BAND, derived from the radio
      // and channel-utilization tables above. The utilization table is indexed
      // by plain channel number with no band column (verified against the
      // LC-LX-6500 MIB), so bands are inferred: 1–14 = 2.4 GHz, 36–165 =
      // 5 GHz, >165 = 6 GHz. The agent currently only reports 2.4/5 GHz rows —
      // the 6 GHz metrics stay null until it starts reporting them.
      const radioChannelOf = (bandRe: RegExp): string | null => {
        const r = snapshot.radios.find((x) => bandRe.test(x.band || '') && x.channel !== null);
        return r ? String(r.channel) : null;
      };
      metrics['wifi.channel2g'] = radioChannelOf(/^2\.4/);
      metrics['wifi.channel5g'] = radioChannelOf(/^5 /);
      metrics['wifi.channel6g'] = radioChannelOf(/^6 /);
      const worstUtilInBand = (pred: (ch: number) => boolean): number | null => {
        const vals = snapshot.channelUtilization.filter((c) => pred(c.channel)).map((c) => c.utilizationPct ?? -1);
        if (!vals.length) return null;
        const worst = Math.max(...vals);
        return worst >= 0 ? worst : null;
      };
      metrics['wifi.utilization2g'] = worstUtilInBand((ch) => ch >= 1 && ch <= 14);
      metrics['wifi.utilization5g'] = worstUtilInBand((ch) => ch >= 36 && ch <= 165);
      metrics['wifi.utilization6g'] = worstUtilInBand((ch) => ch > 165);

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
    if (emitInventory) {
      metrics['networks'] = networks.filter((n) => {
        const k = `${n.name}|${n.ip}`;
        if (emittedNetKeys.has(k)) return false;
        emittedNetKeys.add(k);
        return true;
      });
    }

    // wlanClients[] → hosts table with source 'wlan' (API-side ingestion).
    // ALL associated stations are emitted — IP-less ones included — because the
    // cross-device WiFi page counts connected clients per SSID. Host ingestion
    // skips rows without an address, so the Hosts page is unaffected.
    const wlanClients = snapshot.clients.map((c) => ({
      mac: c.mac,
      ip: c.ip4 || c.ip6,
      hostname: c.hostname || c.username || null,
      intf: c.ifc || null,
      ssid: c.ssid || null,
    }));
    if (emitInventory && wlanClients.length > 0) metrics['wlanClients'] = wlanClients;

    // wifiNetworks[] / wifiAirtime[] → cross-device WiFi page. One row per
    // SSID×band (per radio); the channel is joined from the radio table via the
    // SSID's ifc, and airtime comes from the per-channel utilization table.
    const BAND_SHORT: Record<string, string> = { '2.4 GHz': '2.4', '5 GHz': '5', '6 GHz': '6' };
    const wifiNetworks: Array<Record<string, unknown>> = [];
    const emittedWifiKeys = new Set<string>();
    for (const s of snapshot.ssids) {
      const name = s.ssid || s.name;
      if (!name) continue;
      const band = BAND_SHORT[s.band] ?? '';
      const key = `${name}|${band}`;
      if (emittedWifiKeys.has(key)) continue;
      emittedWifiKeys.add(key);
      const radio = snapshot.radios.find((r) => r.ifc === s.ifc);
      wifiNetworks.push({
        name,
        band,
        channel: radio?.channel ?? null,
        ifc: s.ifc || null,
        bssid: s.bssid || null,
        encryption: s.encryption || null,
        vlanId: s.vlanId,
      });
    }
    if (emitInventory && wifiNetworks.length > 0) metrics['wifiNetworks'] = wifiNetworks;

    const wifiAirtime = snapshot.channelUtilization
      .filter((c) => Number.isFinite(c.channel))
      .map((c) => ({ channel: c.channel, utilizationPct: c.utilizationPct }));
    if (emitInventory && wifiAirtime.length > 0) metrics['wifiAirtime'] = wifiAirtime;

    // wifiRadios[] → per-radio RF context for the WiFi page spectrum view
    // (noise-floor line + bandwidth). One row per radio.
    const mhzOf = (label: string): number | null => {
      const m = /(\d+)/.exec(label || '');
      return m ? Number(m[1]) : null;
    };
    const wifiRadios = snapshot.radios.map((r) => ({
      ifc: r.ifc || null,
      band: BAND_SHORT[r.band] ?? '',
      channel: r.channel,
      bandwidthMhz: mhzOf(r.bandwidth),
      noiseFloorDbm: r.noiseFloorDbm,
    }));
    if (emitInventory && wifiRadios.length > 0) metrics['wifiRadios'] = wifiRadios;

    // wifiNeighbors[] → neighbor scan results for the WiFi page's scanner list.
    // Same data as the `wifi.neighbors` device metric above, but in inventory
    // form so the API can persist it cross-device.
    const wifiNeighbors = snapshot.neighbors.map((n) => ({
      bssid: n.bssid,
      ssid: n.ssid || null,
      band: BAND_SHORT[n.band] ?? '',
      channel: n.channel,
      signalDbm: n.signalDbm,
    }));
    if (emitInventory && wifiNeighbors.length > 0) metrics['wifiNeighbors'] = wifiNeighbors;

    // --- Certificates (normalized for the cross-device Certificates page) ----
    // Management HTTPS cert + SSH host key on port 22. Both probes are
    // credential-free and best-effort; a failure simply contributes no row.
    if (emitInventory) {
      const cachedCerts = certCache.get(host, CERT_TTL_MS) ?? null;
      let certRows: CertificateRow[] | null = cachedCerts;
      if (!certRows) {
        // LX APs default to an HTTPS management UI — probe TLS on 443 (no row is
        // contributed when the box is HTTP-only) plus the SSH host key on port 22.
        const target = parseProbeTarget(managementAddress, 443);
        certRows = target
          ? await collectDeviceCertificates({
              host: target.host,
              httpsPort: target.port,
              servername: target.host,
              sshEnabled: true,
              timeoutMs: 5_000,
            })
          : [];
        certCache.set(host, certRows);
      }
      if (certRows.length > 0) metrics['certificates'] = certRows;
    }

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
      descriptors.push(errorDescriptor());
    }
    // Descriptors for the user-selected model/firmware metrics (only when set).
    descriptors.push(...modelFirmwareDescriptors(selectedModel, selectedFirmware));

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
        inventoryTtlMs: opts.inventoryTtlMs,
        maxClientRows: opts.maxClientRows,
        // User-selected hardware model / firmware version (forwarded by the API).
        // Available for future per-model data gathering; echoed here as well.
        model: selectedModel,
        firmwareVersion: selectedFirmware,
      },
    });
  } catch (err) {
    logger.error(`Monitoring poll for ${host} failed: ${(err as Error).message}`, { deviceId, context: { host } });
    return fail('critical', (err as Error).message);
  }
});

// listen() binds the conventional plugin port (4080 by default) and starts
// mDNS advertising — both handled by @unm/plugin-sdk.
server.listen().catch((err) => {
  console.error('[lancom-lx-plugin] fatal startup error:', err);
  process.exit(1);
});
