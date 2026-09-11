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
import { getAction, listCatalog, listModules } from './actions/registry';
import { ActionContext, StepCredentials, validateInput } from './actions/types';
import { buildPlan, PlanningError, PlanRequest } from './plan';

export const PLUGIN_UUID = '00000000-0000-4000-8000-000000000006';
export const PLUGIN_NAME = 'LANCOM LCOS Plugin';

/**
 * Multi-instance support: set `PLUGIN_INSTANCE_ID` (e.g. "site-a") to run several
 * instances of the same plugin type — each advertises a distinct identity
 * (`<uuid>:<instanceId>`) so the API registers them as separate plugins.
 * (Convention implemented in @unm/plugin-sdk's resolvePluginIdentity.)
 */
const identity = resolvePluginIdentity({
  uuid: PLUGIN_UUID,
  name: PLUGIN_NAME,
  // 0.1.0 — initial release: unified LCOS-MIB monitoring (system, LAN/WAN throughput,
  // VPN, temperature) + inventory propagation for the Networks/Hosts pages, plus
  // config/planning over SNMP SET and web-UI config backup via a credential slot.
  version: '0.1.0',
  vendors: ['lancom'],
  // All four capabilities: monitoring (SNMP walks), inventory (networks/hosts),
  // configuration (SNMP SET actions) + planning (multi-device fan-out). Plus an
  // interactive SSH console ('sshConsole') — LCOS exposes a full CLI over SSH.
  capabilities: ['monitoring', 'configuration', 'inventory', 'planning', 'sshConsole'],
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
      'How often the slow-changing LCOS status walk (LAN/WAN config, VPN, temperature) is re-run. Live byte counters still refresh every poll cycle.',
  },
  {
    key: 'webTransport',
    label: 'Web-UI transport',
    type: 'string' as const,
    default: 'auto',
    pattern: '^(auto|http|https)$',
    description:
      "How to reach the router's web UI for backup/restore. auto = HTTPS with self-signed certificates accepted, falling back to HTTP (default). https = force TLS. http = plaintext.",
  },
  {
    key: 'backupPath',
    label: 'Config backup endpoint path',
    type: 'string' as const,
    maxLength: 512,
    description:
      "The web-UI URL path that returns the running configuration (e.g. \"/config/backup\"). Configurable while the exact LCOS endpoint is being probed on real hardware; leave empty to disable backup actions.",
  },
  {
    key: 'logToApi',
    label: 'Send logs to UNM',
    type: 'boolean' as const,
    default: true,
    description:
      'Ship structured log entries (SNMP walk failures, config/plan errors) to the UNM API for the device Logs view. Disable to keep logging container-local only.',
  },
];

// --- Certificates (capability: cross-device Certificates page) -----------------
// Certificate rows are probed on a slower cadence than the inventory walk — they
// change rarely and each probe opens fresh TLS/SSH connections to the device.
const CERT_TTL_MS = 10 * 60_000;
const certCache = new TtlCache<CertificateRow[]>({ isFresh: (v) => Array.isArray(v) });

// --- Interactive SSH console (capability 'sshConsole') -------------------------
// LCOS exposes a full interactive CLI over SSH (port 22). The webapp's DeviceDetail
// page renders a generic "Shell" button for any plugin advertising 'sshConsole'; the
// API proxies the browser's xterm.js to our /console WebSocket, which opens a PTY on
// the bound `ssh` credential slot. LCOS's PRIMARY secret is SNMP (a community string
// cannot log into a shell), so an explicit ssh slot MUST be bound — hence slotOnly.
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
      throw new Error('No SSH credential bound — bind a usernamePassword or sshKeyPair secret to the assignment\'s "ssh" slot.');
    }
    const conn = await termPool.get(host, 22, creds, {
      onHostKey: (fp) => console.warn(`[lancom-lcos-plugin] observed host key for ${host}:22 → ${fp} (pin it in the device's SSH settings to enforce strict verification)`),
    });
    return conn.openShell(creds); // a plain LCOS login shell, like PuTTY
  },
});

// Pre-wired app: cors + json (32mb — plan-step inputs can carry a substituted
// ${steps[N].result.details.backupBase64} token) + /healthz + /discover (+ static
// icons, mDNS on listen) come from @unm/plugin-sdk — this file only registers
// its own routes.
const server = createPluginServer({
  identity,
  logTag: 'lancom-lcos-plugin',
  // Interactive SSH console (capability 'sshConsole') — WS upgrades for /console.
  wsUpgrade: consoleUpgrade,
  jsonLimit: '32mb',
  // Static icon assets, advertised in /discover and fetched by the API's icon proxy.
  iconsDir: path.join(__dirname, '../../icons'),
  discovery: {
    // Primary credential = the existing 'snmp' secret type (community for v1/v2c, USM fields for v3).
    requiredSecretType: 'snmp',
    // Additional named credential slot: a separate web-UI login used ONLY by the
    // backup/restore actions. This is exactly what the plugin credential-slot
    // system was designed for — one device, two distinct credentials (SNMP primary + web UI).
    credentialSlots: [
      { name: 'web', secretType: 'usernamePassword', required: false, description: 'Web-UI login for config backup/restore' },
      {
        name: 'ssh',
        secretTypes: ['usernamePassword', 'sshKeyPair'],
        required: false,
        description:
          "Optional SSH access (port 22) for the interactive web console — a full LCOS CLI shell, like PuTTY. The primary SNMP credential cannot log into a shell, so bind a usernamePassword or sshKeyPair secret here to enable the Shell button on the device page.",
      },
    ],
    metrics: DISCOVER_METRICS,
    options: PLUGIN_OPTIONS,
    // The full action catalog (single-device actions) + module grouping. One registry
    // serves /discover, /plan and /config — see src/actions/registry.ts.
    actions: listCatalog(),
    modules: listModules(),
    iconUrl: '/icons/lancom-lcos.svg',
    deviceModels: DEVICE_MODELS,
  },
});
const app = server.app;

// Structured logs shipped to the API (see docs/PLUGIN-DEVELOPMENT.md, Logging).
// Emission is gated per call by the `logToApi` option via setEnabled() — it
// flows through the settings loop, so it works globally and per-device.
const logger = createPluginLogger(identity);

/** Resolves SNMP walk options from effective settings. */
function resolveOptions(settings: Record<string, unknown>): LcosOptions {
  return {
    timeoutMs: clampInt(settings.timeoutMs, 1_000, 30_000, 5_000),
    retries: clampInt(settings.retries, 0, 10, 2),
    inventoryTtlMs: clampInt(settings.inventoryTtlMs, 60_000, 86_400_000, INVENTORY_INTERVAL_MS),
  };
}

/** Reads the web-UI transport preference from settings. */
function webTransportOf(settings: Record<string, unknown>): 'auto' | 'http' | 'https' {
  const v = typeof settings.webTransport === 'string' ? settings.webTransport : 'auto';
  return v === 'http' || v === 'https' ? v : 'auto';
}

/** Reads the configured backup endpoint path (empty when unset). */
function backupPathOf(settings: Record<string, unknown>): string {
  const v = typeof settings.backupPath === 'string' ? settings.backupPath.trim() : '';
  return v;
}

/** Extracts SNMP credentials from a body/query field map (decrypted by the API). */
function resolveCredentials(fields: Record<string, unknown>): { creds?: SnmpCredentials; error?: string } {
  return buildSnmpCredentials(fields);
}

app.post('/monitoring', async (req, res) => {
  const body = req.body ?? {};
  const deviceId = typeof body.deviceId === 'string' ? body.deviceId : null;
  const managementAddress = typeof body.managementAddress === 'string' ? body.managementAddress : '';

  // User-selected hardware model / firmware version (forwarded by the API from
  // the device row). Surfaced as System metrics so the selection is visible in
  // the webapp's monitoring view.
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
      // hasWifi=false — a failed probe carries no WLAN data.
      metricDescriptors: [
        ...buildDescriptors(opts.inventoryTtlMs, false),
        errorDescriptor(),
      ],
      error,
    });
  };

  if (!host) return fail('critical', 'No target address — set the device management address.');

  const { creds, error } = resolveCredentials((body.credentials ?? {}) as Record<string, unknown>);
  if (error || !creds) return fail('critical', error ?? 'Missing SNMP credentials.');

  try {
    // Slow path: targeted parallel LCOS walks (only the subtrees we use),
    // TTL-cached per host with a quality gate against partial-failure data.
    const inventory = await getLcosInventory(host, creds, opts, {
      log: (level, message, context) => logger.warn(message, { deviceId, context }),
    });
    const snapshot = inventory.snapshot;

    if (!snapshot) {
      // No LCOS tree at all — this device is not a Lancom LCOS router (or SNMP
      // is misconfigured). 'unknown' rather than 'critical': the plugin may simply
      // be assigned to the wrong device type.
      logger.warn(`No usable LCOS data from ${host}: ${inventory.error ?? 'no LCOS MIB tree'}`, { deviceId, context: { host } });
      return fail('unknown', inventory.error ?? 'No LCOS MIB data on this device.');
    }

    if (inventory.error) {
      // Partial walk failure — the snapshot is usable but some subtrees are empty.
      logger.warn(`Partial LCOS data from ${host}: ${inventory.error}`, { deviceId, context: { host } });
    }

    // Fast path: counter-only walks every cycle for fresh LAN/WAN rates.
    const fast = await walkLcosCounters(host, creds, opts);

    const metrics: Record<string, unknown> = {};
    const sys = snapshot.system;
    metrics['system.name'] = sys.name || null;
    metrics['system.swVersion'] = sys.swVersion || null;
    metrics['system.modelNumber'] = sys.modelNumber || null;
    metrics['system.serialNumber'] = sys.serialNumber || null;
    metrics['system.cpuType'] = sys.cpuType || null;
    metrics['system.uptime'] = sys.uptimeText || null; // DisplayString as reported
    metrics['system.cpuLoad'] = sys.cpuLoadPct;
    if (sys.memoryTotalKb !== null && sys.memoryFreeKb !== null && sys.memoryTotalKb > 0) {
      const usedPct = Math.round(((sys.memoryTotalKb - sys.memoryFreeKb) / sys.memoryTotalKb) * 100);
      metrics['system.memoryUsedPct'] = Math.max(0, Math.min(100, usedPct));
    } else {
      metrics['system.memoryUsedPct'] = null;
    }
    // User-selected hardware model / firmware (from the device form).
    if (selectedModel) metrics['system.model'] = selectedModel;
    if (selectedFirmware) metrics['system.firmwareVersion'] = selectedFirmware;

    // --- LAN ----------------------------------------------------------------
    metrics['lan.ports'] = snapshot.lanPorts.map((p) => ({
      name: p.name,
      linkUp: p.linkUp === null ? '—' : p.linkUp ? 'up' : 'down',
      connectorLabel: p.connectorLabel || '—',
      mac: p.mac || '—',
    }));
    if (Object.keys(fast.lanRates).length > 0) {
      metrics['lan.rates'] = fast.lanRates; // { <port>: { rx, tx } } — MAP form table
    }

    // --- WAN ----------------------------------------------------------------
    metrics['wan.ips'] = snapshot.wanIps.map((w) => ({
      peer: w.peer,
      typeLabel: w.typeLabel || '—',
      address: w.address || '—',
      netmask: w.netmask || '—',
      gateway: w.gateway || '—',
    }));
    if (Object.keys(fast.wanRates).length > 0) {
      metrics['wan.rates'] = fast.wanRates; // { <ifc>: { rx, tx } } — MAP form table
      // Headline aggregate for the device overview table (summary: true).
      let totalRx = 0;
      let totalTx = 0;
      for (const r of Object.values(fast.wanRates)) {
        if (r.rx !== null) totalRx += r.rx;
        if (r.tx !== null) totalTx += r.tx;
      }
      metrics['wan.throughputTotal'] = totalRx + totalTx; // bits/s, both directions
    }

    // --- VPN ----------------------------------------------------------------
    if (snapshot.vpnConnections.length > 0) {
      metrics['vpn.connections'] = snapshot.vpnConnections.map((v) => ({
        peer: v.peer,
        physConn: v.physConn || '—',
        ikeType: v.ikeType || '—',
        cryptAlg: v.cryptAlg || '—',
        stateLabel: v.stateLabel || '—',
        modeLabel: v.modeLabel || '—',
        connTimeSeconds: v.connTimeSeconds !== null ? `${v.connTimeSeconds}s` : '—',
      }));
    }

    // --- Tunnels (normalized for the cross-device Tunnels page) --------------
    // IPsec connections from the VPN table + PPPoE WAN links. The LCOS MIB has
    // no WireGuard/OpenVPN/GRE subtrees, so those types never appear here.
    const tunnelRows: Record<string, unknown>[] = [];
    for (const v of snapshot.vpnConnections) {
      const up = /connected|bundled/i.test(v.stateLabel);
      tunnelRows.push({
        name: v.physConn || v.peer,
        type: 'ipsec',
        peerAddress: v.peer === v.physConn ? '' : v.peer, // peer == physConn → no separate remote known
        localAddress: '',
        status: up ? 'up' : /disconnect/i.test(v.stateLabel) ? 'down' : 'enabled',
        uptimeSeconds: v.connTimeSeconds,
        extra: { ikeType: v.ikeType || null, cryptAlg: v.cryptAlg || null, mode: v.modeLabel || null },
      });
    }
    for (const w of snapshot.wanIps) {
      if (!/ppp/i.test(w.typeLabel)) continue; // PPPoE WAN links only
      const rate = fast.wanRates[w.peer];
      tunnelRows.push({
        name: w.peer,
        type: 'pppoe',
        peerAddress: '', // the ISP side is not exposed via SNMP
        localAddress: w.address || '',
        status: w.address ? 'up' : 'down',
        interfaceName: w.peer,
        // wanRates are bits/s; the tunnels contract stores bytes/s.
        ...(rate?.rx !== null && rate?.rx !== undefined ? { rxRate: rate.rx / 8 } : {}),
        ...(rate?.tx !== null && rate?.tx !== undefined ? { txRate: rate.tx / 8 } : {}),
      });
    }
    if (emitInventory && tunnelRows.length > 0) metrics['tunnels'] = tunnelRows;

    // --- Certificates (normalized for the cross-device Certificates page) ----
    // Management HTTPS cert (only when the web UI actually speaks TLS — an 'http'
    // transport has no certificate to read) + SSH host key on port 22. Both probes
    // are credential-free and best-effort; a failure simply contributes no row.
    if (emitInventory) {
      const cachedCerts = certCache.get(host, CERT_TTL_MS) ?? null;
      let certRows: CertificateRow[] | null = cachedCerts;
      if (!certRows) {
        const target = parseProbeTarget(managementAddress, 443);
        certRows =
          target && webTransportOf(settings) !== 'http'
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

    // --- Routes (normalized for the cross-device Routes page) ----------------
    // The active routing table carries static AND dynamically-learned routes in
    // one walk — the per-row Type enum is already mapped to a protocol by the
    // client. IPv4 only (the MIB has no v6 route table).
    if (emitInventory && snapshot.routes.length > 0) {
      metrics['routes'] = snapshot.routes.map((r) => ({
        destination: r.destination,
        gateway: r.gateway,
        protocol: r.protocol,
        distance: r.distance,
        metric: r.metric, // set by the ipCidrRouteTable fallback only
        status: 'active', // the active table only lists installed routes
        extra: { rtgTag: r.rtgTag, peer: r.peer || null, rawType: r.rawTypeLabel || null },
      }));
    }

    // --- WiFi (built-in radios only — most routers report nothing) ----------
    const hasWifi = snapshot.radios.length > 0 || snapshot.ssids.length > 0 || snapshot.clients.length > 0;
    if (hasWifi) {
      metrics['wifi.radios'] = snapshot.radios.map((r) => ({
        ifc: r.ifc,
        bandLabel: r.bandLabel || '—',
        channel: r.channel !== null ? String(r.channel) : '—',
        noiseFloorDbm: r.noiseFloorDbm !== null ? `${r.noiseFloorDbm} dBm` : '—',
        modemLoadPct: r.modemLoadPct !== null ? `${r.modemLoadPct}%` : '—',
        txPower: r.txPower || '—',
        utilizationPct: r.utilizationPct !== null ? `${r.utilizationPct}%` : '—',
      }));
      metrics['wifi.ssids'] = snapshot.ssids.map((s) => ({
        ifc: s.ifc,
        name: s.name || '—',
        operating: s.operating === null ? '—' : s.operating ? 'on' : 'off',
        bssid: s.bssid || '—',
        stations: s.stations ?? '—',
        vlanId: s.vlanId !== null ? String(s.vlanId) : '—',
      }));
      metrics['wifi.clients'] = snapshot.clients.map((c) => ({
        mac: c.mac,
        hostname: c.hostname || '—',
        ifc: c.ifc || '—',
        ip4: c.ip4 || '—',
        signalDbm: c.signalDbm !== null ? `${c.signalDbm} dBm` : '—',
        txRateMbps: c.txRateMbps !== null ? String(c.txRateMbps) : '—',
        rxRateMbps: c.rxRateMbps !== null ? String(c.rxRateMbps) : '—',
        vlanId: c.vlanId !== null ? String(c.vlanId) : '—',
      }));

      // wifiNetworks[] / wifiAirtime[] → cross-device WiFi page. Band and
      // channel are joined from the radio table (this MIB indexes the network
      // table by radio only); airtime is per-radio — there is no per-channel
      // utilization table in LCOS.
      const BAND_SHORT: Record<string, string> = { '2.4 GHz': '2.4', '5 GHz': '5' };
      const wifiNetworks: Array<Record<string, unknown>> = [];
      for (const s of snapshot.ssids) {
        const name = s.name || '';
        if (!name) continue;
        const radio = snapshot.radios.find((r) => r.ifc === s.ifc);
        wifiNetworks.push({
          name,
          band: BAND_SHORT[radio?.bandLabel ?? ''] ?? '',
          channel: radio?.channel ?? null,
          ifc: s.ifc || null,
          bssid: s.bssid || null,
          vlanId: s.vlanId,
        });
      }
      if (emitInventory && wifiNetworks.length > 0) metrics['wifiNetworks'] = wifiNetworks;

      const wifiAirtime = snapshot.radios
        .filter((r) => r.channel !== null && Number.isFinite(r.channel))
        .map((r) => ({ channel: r.channel, utilizationPct: r.utilizationPct }));
      if (emitInventory && wifiAirtime.length > 0) metrics['wifiAirtime'] = wifiAirtime;

      // wifiRadios[] → per-radio RF context for the WiFi page spectrum view
      // (noise-floor line + bandwidth). One row per radio.
      const wifiRadios = snapshot.radios.map((r) => ({
        ifc: r.ifc || null,
        band: BAND_SHORT[r.bandLabel] ?? '',
        channel: r.channel,
        bandwidthMhz: r.bandwidthMhz,
        noiseFloorDbm: r.noiseFloorDbm,
      }));
      if (emitInventory && wifiRadios.length > 0) metrics['wifiRadios'] = wifiRadios;
    }

    // --- Temperature --------------------------------------------------------
    if (snapshot.temperatureExtremes.length > 0) {
      metrics['temperature.extremes'] = snapshot.temperatureExtremes.map((t) => ({
        sensor: t.sensor,
        kind: t.kind,
        valueTenthsC: t.valueTenthsC !== null ? `${(t.valueTenthsC / 10).toFixed(1)} °C` : '—',
      }));
    }

    // --- Inventory propagation (consumed by the API's ingestInventory) -----
    // networks[]: configured IP rows (+ MAC attached where a LAN port matches).
    const portMac = new Map(snapshot.lanPorts.map((p) => [p.name, p.mac]));
    const networks: Array<Record<string, unknown>> = snapshot.networks.map((n) => {
      const row: Record<string, unknown> = { name: n.name, ip: n.ip || '', prefix: n.prefix, version: 'v4', status: null };
      if (n.vlanId !== null) row['vlanId'] = n.vlanId;
      // Attach the port MAC to its IP row for topology detection.
      const mac = n.ifcLabel ? portMac.get(n.ifcLabel) : undefined;
      if (mac) row['mac'] = mac;
      return row;
    });
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

    // arp[] → hosts table with source 'arp'.
    const arpRows = snapshot.arp
      .filter((a) => a.mac !== '' && a.ip !== '')
      .map((a) => ({ mac: a.mac, ip: a.ip, intf: a.portLabel || null }));
    if (emitInventory && arpRows.length > 0) metrics['arp'] = arpRows;

    // dhcpLeases[] → hosts table with source 'dhcp' (expiry as ISO timestamp).
    const nowMs = Date.now();
    const leaseRows = snapshot.dhcpLeases
      .filter((d) => d.mac !== '' && d.ip !== '')
      .map((d) => ({
        mac: d.mac,
        ip: d.ip,
        hostname: d.hostname || null,
        intf: d.networkName || null,
        expiry: d.expirySeconds !== null ? new Date(nowMs + d.expirySeconds * 1000).toISOString() : null,
      }));
    if (emitInventory && leaseRows.length > 0) metrics['dhcpLeases'] = leaseRows;

    // wlanClients[] → hosts table with source 'wlan' + WiFi page client counts.
    // ALL associated stations are emitted — IP-less ones included; host
    // ingestion skips rows without an address. The SSID is joined via the
    // station's radio (the network table is indexed by radio in this MIB).
    const ssidByIfc = new Map(snapshot.ssids.filter((s) => s.name !== '').map((s) => [s.ifc, s.name]));
    const wlanClients = snapshot.clients.map((c) => ({
      mac: c.mac,
      ip: c.ip4 || c.ip6,
      hostname: c.hostname || null,
      intf: c.ifc || null,
      ssid: (c.ifc ? ssidByIfc.get(c.ifc) : undefined) ?? null,
    }));
    if (emitInventory && wlanClients.length > 0) metrics['wlanClients'] = wlanClients;

    // --- Health -------------------------------------------------------------
    let health: Health = 'ok';
    const warnings: string[] = [];
    if (!sys.name && !sys.swVersion) warnings.push('system scalars unavailable');
    if (snapshot.lanPorts.length === 0 && snapshot.wanIps.length === 0) warnings.push('no LAN ports or WAN interfaces reported');
    if (inventory.error) warnings.push(inventory.error);
    if (warnings.length > 0) {
      health = 'warning';
      metrics['system.error'] = warnings.join('; ');
    }

    const descriptors: MetricDescriptor[] = buildDescriptors(opts.inventoryTtlMs, hasWifi);
    // Runtime rows for the MAP-form rate tables.
    if (Object.keys(fast.lanRates).length > 0) {
      const d = descriptors.find((x) => x.key === 'lan.rates');
      if (d) d.rows = Object.keys(fast.lanRates);
    }
    if (Object.keys(fast.wanRates).length > 0) {
      const d = descriptors.find((x) => x.key === 'wan.rates');
      if (d) d.rows = Object.keys(fast.wanRates);
    }
    // Normalized tunnel rows (IPsec + PPPoE) — also ingested by the API into
    // the cross-device `tunnels` table; rendered here as a per-device table.
    if (Array.isArray(metrics['tunnels']) && (metrics['tunnels'] as unknown[]).length > 0) {
      descriptors.push({
        key: 'tunnels',
        label: 'Tunnels',
        type: 'string',
        visualization: 'table',
        group: 'VPN',
        columns: ['name', 'type', 'peerAddress', 'localAddress', 'status'],
        intervalMs: opts.inventoryTtlMs,
      });
    }
    // Normalized route rows — also ingested by the API into the cross-device
    // `routes` table; rendered here as a per-device table.
    if (Array.isArray(metrics['routes']) && (metrics['routes'] as unknown[]).length > 0) {
      descriptors.push({
        key: 'routes',
        label: 'Routes',
        type: 'string',
        visualization: 'table',
        group: 'Routing',
        columns: ['destination', 'gateway', 'protocol', 'distance', 'status'],
        intervalMs: opts.inventoryTtlMs,
      });
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
        webTransport: webTransportOf(settings),
        backupPath: backupPathOf(settings) || null,
        // User-selected hardware model / firmware version (forwarded by the API).
        model: selectedModel,
        firmwareVersion: selectedFirmware,
      },
    });
  } catch (err) {
    logger.error(`Monitoring poll for ${host} failed: ${(err as Error).message}`, { deviceId, context: { host } });
    return fail('critical', (err as Error).message);
  }
});

/** Builds the ActionContext for a /config call. */
async function buildActionContext(args: {
  host: string;
  address: string;
  deviceId?: string;
  credentials: StepCredentials;
  settings: Record<string, unknown>;
}): Promise<ActionContext> {
  const opts = resolveOptions(args.settings);
  return {
    host: args.host,
    address: args.address,
    deviceId: args.deviceId,
    credentials: args.credentials,
    opts,
    webTransport: webTransportOf(args.settings),
    backupPath: backupPathOf(args.settings),
  };
}

/**
 * Executes ONE action step against one router. This is the unit of work the
 * API's config-job worker dispatches — either a single-device job (legacy shape:
 * `{action, payload}`) or one step of a multi-device plan (registry shape:
 * `{actionId, input, credentials}`). The plugin owns ALL logic: it validates
 * the input against the action's schema and runs the executor. The API only
 * propagates — it never interprets payloads.
 */
app.post('/config', async (req, res) => {
  const body = req.body ?? {};
  const { deviceId, managementAddress } = body;
  // Registry shape preferred; legacy `{action, payload}` maps onto it.
  const actionId: string | undefined = typeof body.actionId === 'string' ? body.actionId : (typeof body.action === 'string' ? body.action : undefined);
  const input: Record<string, unknown> =
    body.input && typeof body.input === 'object'
      ? (body.input as Record<string, unknown>)
      : body.payload && typeof body.payload === 'object'
        ? (body.payload as Record<string, unknown>)
        : {};

  const settings = readSettings(req, PLUGIN_OPTIONS);  logger.setEnabled(settings.logToApi === true);
  if (!actionId) {
    res.status(400).json({ success: false, result: { error: 'Missing actionId (or legacy "action")' } });
    return;
  }
  if (typeof managementAddress !== 'string' || !managementAddress) {
    res.status(400).json({ success: false, result: { error: 'Missing managementAddress' } });
    return;
  }

  const action = getAction(actionId);
  if (!action) {
    res.status(400).json({ success: false, result: { error: `Unknown action "${actionId}"` } });
    return;
  }

  // Credentials: the assignment's decrypted fields are the base (the primary
  // SNMP secret); bound slots arrive under `credentials.slots.<name>`.
  const credsFields = (body.credentials && typeof body.credentials === 'object' ? body.credentials : {}) as Record<string, unknown>;
  const { creds, error } = resolveCredentials(credsFields);
  if (error || !creds) {
    res.status(200).json({ success: false, result: { error: error ?? 'Missing SNMP credentials.' } });
    return;
  }
  const stepCredentials: StepCredentials = {
    snmp: creds,
    ...(typeof credsFields.slots === 'object' && credsFields.slots !== null ? { slots: credsFields.slots as Record<string, Record<string, string>> } : {}),
    ...credsFields,
  };

  try {
    const ctx = await buildActionContext({
      host: hostFromAddress(managementAddress),
      address: managementAddress,
      deviceId: typeof deviceId === 'string' ? deviceId : undefined,
      credentials: stepCredentials,
      settings,
    });

    // Validate input against the action's declared schema — the plugin is the
    // authority on what it accepts; the API only checks that the id exists.
    const issues = validateInput(action.inputSchema, input);
    if (issues.length > 0) {
      res.status(200).json({
        success: false,
        result: { error: `Invalid input for ${actionId}: ${issues.map((i) => `${i.path}: ${i.message}`).join('; ')}` },
      });
      return;
    }

    const result = await action.execute(ctx, input);
    if (!result.success) {
      logger.warn(`Config action ${actionId} reported failure for ${managementAddress}: ${typeof result.error === 'string' ? result.error : JSON.stringify(result)}`, { deviceId: typeof deviceId === 'string' ? deviceId : null, context: { host: managementAddress, actionId } });
    }
    res.status(200).json({ success: result.success, result: { ...result } });
  } catch (err) {
    logger.error(`Config action ${actionId} failed for ${managementAddress}: ${(err as Error).message}`, { deviceId: typeof deviceId === 'string' ? deviceId : null, context: { host: managementAddress, actionId } });
    res.status(200).json({ success: false, result: { error: (err as Error).message } });
  }
});

/**
 * Plans a multi-device intent (or fans out a single action across a batch).
 * The plugin does ALL the planning — dependency ordering and the auto-prepended
 * best-effort config backup per dirty device. It never generates key material:
 * LCOS v1 needs no provisioned secrets at all.
 *
 * Body: { intent: { actionId, inputs }, devices: [{ deviceId, managementAddress, credentials }] }
 */
app.post('/plan', async (req, res) => {
  const body = req.body ?? {};

  const planReq: PlanRequest = {
    intent: {
      actionId: typeof body.intent?.actionId === 'string' ? body.intent.actionId : '',
      inputs: (body.intent?.inputs && typeof body.intent.inputs === 'object' ? body.intent.inputs : {}) as Record<string, unknown>,
    },
    devices: Array.isArray(body.devices)
      ? (body.devices as PlanRequest['devices']).map((d) => ({
          deviceId: String(d.deviceId),
          managementAddress: String(d.managementAddress ?? ''),
          credentials: (d.credentials && typeof d.credentials === 'object' ? d.credentials : {}) as Record<string, unknown>,
        }))
      : [],
  };

  try {
    const plan = buildPlan(planReq);
    res.status(200).json({ plan });
  } catch (err) {
    if (err instanceof PlanningError) {
      res.status(400).json({ error: err.message });
      return;
    }
    res.status(500).json({ error: (err as Error).message });
  }
});

// listen() binds the conventional plugin port (4080 by default) and starts
// mDNS advertising — both handled by @unm/plugin-sdk.
server.listen().catch((err) => {
  console.error('[lancom-lcos-plugin] fatal startup error:', err);
  process.exit(1);
});
