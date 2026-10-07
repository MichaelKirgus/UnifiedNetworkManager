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
  isTransientTransportError,
  quickActionHandler,
  buildWebUiUrl,
  modelFirmwareDescriptors,
  readSettings,
  resolvePluginIdentity,
  resolveSshCredentials,
  createSftpPool,
  TtlCache,
  createPinningGuard,
  dynamicSshHostVerifier,
  collectDeviceCertificates,
  parseProbeTarget,
  resolveHttpsPort,
  resolveHttpPort,
  resolveSshPort,
  buildDeviceTimeInfo,
  parseLooseDeviceDatetime,
  splitCidr,
  warnOnce,
  catalogFirmwareRow,
  CertificateRow,
  type QuickAction,
} from '@unm/plugin-sdk';
import { LANCOM_LCOS_DEVICE_SUPPORT } from './deviceSupport';
import { SnmpCredentials, buildSnmpCredentials } from '@unm/snmp-client';

// The LCOS `lcsStatusTimeCurrentTime` DisplayString is normalized by the shared
// SDK parser (parseLooseDeviceDatetime): it handles "YYYY-MM-DD HH:MM:SS", the
// dotted European "DD.MM.YYYY HH:MM:SS" variant, and the US-style
// "MM/DD/YYYY HH:MM:SS" that some firmware reports (observed live:
// "09/13/2026 23:06:22"). Unparseable → null so the caller omits the metric.
import { LcosOptions, getLcosInventory, walkLcosCounters } from './lcosClient';
import { deriveSecurityChecks } from './security';
import { buildDescriptors, DISCOVER_METRICS } from './metrics';
import { DEVICE_MODELS } from './deviceModels';
import { getAction, listCatalog, listModules } from './actions/registry';
import { ActionContext, StepCredentials, validateInput } from './actions/types';
import { buildPlan, PlanningError, PlanRequest } from './plan';
import { PREFLIGHT_RESOLVERS } from './actions/preflight';

/** Every firmware line known across the LCOS catalog — the Updates page compares
 * a device's live swVersion against this set (always in sync with /discover). */
const KNOWN_LCOS_LINES = Array.from(new Set(DEVICE_MODELS.flatMap((m) => m.firmwareVersions ?? [])));

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
  // 0.2.0 — Updates page support (capability 'updates'): firmware `updates[]` row
  // from the live swVersion vs the static LCOS release catalog (available-without-
  // apply — LANCOM MIBs are read-only, OS updates go through the web UI).
  // 0.3.0 — SSH/SFTP config management: backup/restore over the LCOS virtual
  // `/config` SFTP file (the same LCF document as `readconfig`) + interactive-CLI
  // actions (`set <path> <value>` with read-back verification) for device name,
  // timezone and WLAN SSID settings. The web-UI backup path is kept only as a
  // legacy fallback — the LCOS web UI locks out repeated failed POSTs.
  // 0.4.0 — WiFi parity round 1 (lancom-lx feature set): read actions over the
  // status MIBs (wlan.networks.read, wlan.radios.read) + write actions for radio
  // channel/power via single-cell LCF replacement over SFTP /config (the WLAN
  // setup tree is SNMP-read-only — NoAccess on SET). The former wlan.ssid.state.set
  // was removed: per-SSID operating state is runtime-only, not expressible in the
  // config document. SSID name changes remain unsupported — broadcast names are
  // stored nowhere in the LCF (verified exhaustively), only in the status MIB.
  version: '0.4.0',
  vendors: ['lancom'],
  // All four capabilities: monitoring (SNMP walks), inventory (networks/hosts),
  // configuration (SNMP SET actions) + planning (multi-device fan-out). Plus an
  // interactive SSH console ('sshConsole') — LCOS exposes a full CLI over SSH.
  // securityChecks: IPsec crypto strength derived from the already-collected
  // snapshot (no extra SNMP walks).
  capabilities: ['monitoring', 'configuration', 'inventory', 'planning', 'sshConsole', 'updates', 'quickActions', 'securityChecks'],
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
    enumOptions: ['auto', 'http', 'https'],
    description:
      "How to reach the router's web UI for backup/restore. auto = HTTPS with self-signed certificates accepted, falling back to HTTP (default). https = force TLS. http = plaintext.",
  },
  {
    key: 'httpsPort',
    label: 'HTTPS port',
    type: 'integer' as const,
    default: 443,
    min: 1,
    max: 65535,
    description:
      "TCP port of the router's HTTPS management UI. Used when the management address carries no explicit port (an explicit https://host:<port> always wins). Also the port certificate pinning verifies against.",
  },
  {
    key: 'httpPort',
    label: 'HTTP port',
    type: 'integer' as const,
    default: 80,
    min: 1,
    max: 65535,
    description: "TCP port of the router's plain-HTTP management UI (used when webTransport is http or auto falls back to it).",
  },
  {
    key: 'sshPort',
    label: 'SSH port',
    type: 'integer' as const,
    default: 22,
    min: 1,
    max: 65535,
    description:
      "TCP port of the router's SSH daemon. Used for the interactive web console and host-key pinning when the management address carries no explicit port.",
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
  {
    key: 'securityChecksEnabled',
    label: 'Security checks',
    type: 'boolean' as const,
    default: true,
    description:
      'Run per-device security checks (IPsec crypto strength — IKEv1, DES/3DES, MD5/SHA-1). Findings appear in the cross-device Security page.',
  },
];

// --- Certificates (capability: cross-device Certificates page) -----------------
// Certificate rows are probed on a slower cadence than the inventory walk — they
// change rarely and each probe opens fresh TLS/SSH connections to the device.
const CERT_TTL_MS = 10 * 60_000;
const certCache = new TtlCache<CertificateRow[]>({ isFresh: (v) => Array.isArray(v) });

// Certificate pinning — one process-wide guard for every credential-bearing
// entry point. Strict mode + a known fingerprint MISMATCH throws before any
// credentials are transmitted; unknown endpoints are TOFU-accepted and land in
// UNM's inventory via the `certificates` metric below.
const assertPinned = createPinningGuard();

// --- Interactive SSH console (capability 'sshConsole') -------------------------
// LCOS exposes a full interactive CLI over SSH (port 22). The webapp's DeviceDetail
// page renders a generic "Shell" button for any plugin advertising 'sshConsole'; the
// API proxies the browser's xterm.js to our /console WebSocket, which opens a PTY on
// the bound `ssh` credential slot. LCOS's PRIMARY secret is SNMP (a community string
// cannot log into a shell), so an explicit ssh slot MUST be bound — hence slotOnly.
const termPool = createTerminalPool();

// SFTP pool for the config backup/restore actions — LCOS exposes the running
// configuration as a virtual `/config` file over SFTP (read AND write), which is
// the same LCF document `readconfig` prints. One pooled session per host; the
// pool keys by host|port|username so credential rotation never leaks into it.
const sftpPool = createSftpPool();

process.on('SIGTERM', () => { termPool.closeAll(); sftpPool.closeAll(); });
process.on('SIGINT', () => { termPool.closeAll(); sftpPool.closeAll(); });

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
    // Configured SSH port (plugin option `sshPort`, default 22) — delivered by
    // the API in the console hello frame so a per-device override is honored.
    const sshPort = resolveSshPort(hello.settings?.['sshPort']);
    const conn = await termPool.get(host, sshPort, creds, {
      // UNM certificate pinning — resolves the freshest trusted fingerprint at
      // handshake time (pooled sessions outlive single requests). A mismatch
      // rejects the handshake BEFORE any auth message is sent.
      hostKeyVerifier: dynamicSshHostVerifier(host, sshPort),
      onHostKey: (fp) => console.warn(`[lancom-lcos-plugin] observed host key for ${host}:${sshPort} → ${fp} (pin it in the device's SSH settings to enforce strict verification)`),
    });
    return conn.openShell(creds); // a plain LCOS login shell, like PuTTY
  },
});

/** Quick actions propagated to the Devices page "Device Actions" column. */
const QUICK_ACTIONS: QuickAction[] = [
  {
    id: 'webui',
    label: 'Web UI',
    description: "Open the router's management web interface in a new tab",
    iconPath: '/icons/lancom-lcos.svg',
    kind: 'url',
    url: {},
  },
  {
    id: 'shell',
    label: 'Shell',
    description: 'Interactive LCOS CLI shell over SSH (requires a bound SSH credential)',
    iconPath: '/icons/lancom-lcos.svg',
    kind: 'shell',
  },
];

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
  // Static doc/license assets served at /assets/* (proxied by the API's
  // GET /plugins/:id/asset) — referenced from discovery.deviceSupport.
  assetsDir: path.join(__dirname, '../..'),
  discovery: {
    // Primary credential = the existing 'snmp' secret type (community for v1/v2c, USM fields for v3).
    requiredSecretType: 'snmp',
    // Additional named credential slots: SSH (config backup/restore over the
    // virtual /config SFTP file + CLI actions + interactive console) and a legacy
    // web-UI login (kept for the old HTTP backup fallback). One device, several
    // distinct credentials — exactly what the plugin slot system is designed for.
    credentialSlots: [
      {
        name: 'ssh',
        secretTypes: ['usernamePassword', 'sshKeyPair'],
        required: false,
        description:
          "SSH access (port 22) used by config backup/restore (the LCOS virtual /config SFTP file), the CLI setting actions and the interactive web console. The primary SNMP credential cannot log into a shell — bind a usernamePassword or sshKeyPair secret here to enable these features.",
      },
      { name: 'web', secretType: 'usernamePassword', required: false, description: 'Legacy web-UI login (HTTP backup fallback only)' },
    ],
    metrics: DISCOVER_METRICS,
    options: PLUGIN_OPTIONS,
    // The full action catalog (single-device actions) + module grouping. One registry
    // serves /discover, /plan and /config — see src/actions/registry.ts.
    actions: listCatalog(),
    modules: listModules(),
    // Quick actions for the Devices page "Device Actions" column. The web-UI URL
    // is resolved by THIS plugin (scheme follows webTransport, port = httpsPort);
    // shell reuses the existing console dialog.
    quickActions: QUICK_ACTIONS,
    iconUrl: '/icons/lancom-lcos.svg',
    deviceModels: DEVICE_MODELS,
    // License/help/docs metadata for UNM's Plugins page (see ./deviceSupport.ts).
    deviceSupport: LANCOM_LCOS_DEVICE_SUPPORT,
  },
});
const app = server.app;

// POST /quick-action — resolve a kind:'url' quick action into the management web-UI
// URL. The plugin owns all URL knowledge; no credentials are transmitted.
app.post('/quick-action', quickActionHandler(async (body, req) => {
  const settings = readSettings(req, PLUGIN_OPTIONS);
  const qa = QUICK_ACTIONS.find((q) => q.id === body.actionId && q.kind === 'url');
  if (!qa) throw new Error(`Unknown url quick action: ${body.actionId}`);
  return {
    url: buildWebUiUrl(body.managementAddress, {
      webUiPort: resolveHttpsPort(settings.httpsPort),
      scheme: typeof settings.webTransport === 'string' && settings.webTransport === 'http' ? 'http' : 'https',
    }, qa.url?.path),
  };
}, 'lancom-lcos-plugin'));

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

/** Extracts the configured endpoint ports from injected settings (defaults 443/80). */
function portsOf(settings: Record<string, unknown>): { httpsPort?: number; httpPort?: number } {
  const hp = resolveHttpsPort(settings.httpsPort);
  const tp = resolveHttpPort(settings.httpPort);
  return { httpsPort: hp !== 443 ? hp : undefined, httpPort: tp !== 80 ? tp : undefined };
}

/** Extracts the configured SSH port from injected settings (default 22). */
function sshPortOf(settings: Record<string, unknown>): number {
  return resolveSshPort(settings.sshPort);
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
    // Certificate pinning — verify the router's TLS cert against UNM's
    // inventory BEFORE any credentials are transmitted (throws on mismatch).
    await assertPinned(req, managementAddress, webTransportOf(settings), portsOf(settings));

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
    // Updates page: firmware row from the live swVersion (e.g. "10.94.0327RU4 /
    // 16.07.2026") vs the newest known LCOS line — major.minor comparison, so
    // build suffixes + dates never matter. Available-without-apply.
    if (sys.swVersion) {
      // Release notes: LANCOM's FTP release-notes folder for the target line
      // (RN_LCOS-<line>-*.pdf).
      const fwRow = catalogFirmwareRow(sys.swVersion, KNOWN_LCOS_LINES, {
        releaseNotesUrl: (target) => `https://ftp.lancom.de/Documentation/Release-Notes/LCOS/${String(target).replace(/\./g, '')}/`,
      });
      if (fwRow) metrics['updates'] = [fwRow];
    }
    metrics['system.modelNumber'] = sys.modelNumber || null;
    metrics['system.serialNumber'] = sys.serialNumber || null;
    metrics['system.cpuType'] = sys.cpuType || null;
    metrics['system.uptime'] = sys.uptimeText || null; // DisplayString as reported
    // Device clock (Time page): lcsStatusTimeCurrentTime + the timezone enum → a
    // fixed UTC offset, so buildDeviceTimeInfo resolves an absolute instant and
    // drift IS computable for LCOS routers (unlike zone-less SNMP devices).
    let lcosClockEmitted = false;
    if (sys.systemDate) {
      const parsed = parseLooseDeviceDatetime(sys.systemDate);
      if (parsed) { metrics['system.deviceTime'] = buildDeviceTimeInfo(parsed.localIso, null, sys.timezoneMinutes ?? undefined) ?? { localIso: parsed.localIso }; lcosClockEmitted = true; }
    }
    // One-shot diagnostic (stdout-visible, once per host): when no clock blob is
    // emitted, log the raw SNMP value so a missing OID / empty DisplayString
    // surfaces. warnOnce is NOT the SDK logger — that one ships to the API.
    if (!lcosClockEmitted) {
      warnOnce('lancom-lcos-plugin', host, `deviceTime: no usable clock from ${host} — systemDate=${JSON.stringify(sys.systemDate)} timezoneMinutes=${sys.timezoneMinutes}`);
    }
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

    // Security checks (IPsec crypto strength) — pure derivation from the
    // snapshot, throttled internally to a ~15-min cadence. Best-effort: a
    // failure omits the key entirely (absent = no wipe).
    if (settings.securityChecksEnabled !== false) {
      try {
        metrics['securityChecks'] = deriveSecurityChecks(host, snapshot);
      } catch {
        /* best-effort — a failed check must never sink the poll */
      }
    }

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
        const p = portsOf(settings);
        const target = parseProbeTarget(managementAddress, p.httpsPort ?? 443);
        certRows =
          target && webTransportOf(settings) !== 'http'
            ? await collectDeviceCertificates({
                host: target.host,
                httpsPort: target.port,
                servername: target.host,
                sshEnabled: true,
                sshPort: sshPortOf(settings),
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
    // Dual-stack: LCOS keeps v6 in a separate tree, so the v4 NET_LIST walk
    // above never sees it. The Status/IPv6 Prefix table is the only v6 source
    // with real prefix lengths (the Addresses table has none) — emit one row
    // per advertised/delegated prefix as ip=<network address>, version='v6'.
    for (const p of snapshot.ipv6Prefixes) {
      const split = splitCidr(p.cidr);
      if (!split) continue;
      networks.push({ name: p.name, ip: split.net, prefix: split.prefix, version: 'v6', status: null });
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
  deviceName?: string;
  credentials: StepCredentials;
  settings: Record<string, unknown>;
}): Promise<ActionContext> {
  const opts = resolveOptions(args.settings);
  return {
    host: args.host,
    address: args.address,
    deviceId: args.deviceId,
    deviceName: args.deviceName,
    credentials: args.credentials,
    opts,
    webTransport: webTransportOf(args.settings),
    backupPath: backupPathOf(args.settings),
    httpsPort: resolveHttpsPort(args.settings.httpsPort),
    httpPort: resolveHttpPort(args.settings.httpPort),
    sftpPool,
    terminalPool: termPool,
    sshPort: resolveSshPort(args.settings.sshPort),
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
    // Certificate pinning — a config action transmits real credentials (web-UI
    // Basic auth over HTTPS); refuse the connection when the router's key
    // differs from UNM's inventory.
    await assertPinned(req, managementAddress, webTransportOf(settings), portsOf(settings));

    const ctx = await buildActionContext({
      host: hostFromAddress(managementAddress),
      address: managementAddress,
      deviceId: typeof deviceId === 'string' ? deviceId : undefined,
      deviceName: typeof body.deviceName === 'string' && body.deviceName !== '' ? body.deviceName : undefined,
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
    // Transport-level failures (router down / not ready yet) are transient — the
    // plan executor re-dispatches them per the plan's retry policy. Web-UI/SNMP
    // protocol errors already come back as ok:false results and stay hard.
    const retryable = isTransientTransportError(err);
    res.status(200).json({ success: false, result: { error: (err as Error).message, ...(retryable ? { retryable: true } : {}) } });
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
    // Per-device input overrides (rollout wizard's confirmed preflight values).
    deviceInputs: body.deviceInputs && typeof body.deviceInputs === 'object'
      ? (body.deviceInputs as PlanRequest['deviceInputs'])
      : undefined,
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

/**
 * POST /preflight — resolve best-guess per-device values for a canonical fleet
 * intent BEFORE planning (the "smart" half of the rollout wizard). Body:
 * { intentActionId, inputs?, device: { deviceId, managementAddress, credentials } }
 * READ-ONLY by contract: resolvers probe live state (SNMP walks, CLI `dir -a`)
 * and return suggestions; they never write. The webapp shows the values with
 * confidence + notes and lets the user override them before plan creation.
 */
app.post('/preflight', async (req, res) => {
  const body = req.body ?? {};
  const intentActionId: string | undefined = typeof body.intentActionId === 'string' ? body.intentActionId : undefined;
  const inputs: Record<string, unknown> =
    body.inputs && typeof body.inputs === 'object' ? (body.inputs as Record<string, unknown>) : {};
  const dev = body.device ?? {};
  const managementAddress: string | undefined = typeof dev.managementAddress === 'string' ? dev.managementAddress : undefined;

  if (!intentActionId || !managementAddress) {
    res.status(400).json({ error: 'intentActionId and device.managementAddress are required' });
    return;
  }
  const resolver = PREFLIGHT_RESOLVERS[intentActionId];
  if (!resolver) {
    res.status(400).json({ error: `No preflight resolver for intent "${intentActionId}"` });
    return;
  }

  // Same credential assembly as /config — the primary secret fields plus bound
  // slots under credentials.slots.<name> (SSH is needed for CLI-based reads).
  const credsFields = (dev.credentials && typeof dev.credentials === 'object' ? dev.credentials : {}) as Record<string, unknown>;
  const { creds, error } = resolveCredentials(credsFields);
  if (error || !creds) {
    res.status(200).json({ result: { deviceId: String(dev.deviceId ?? ''), values: [], degraded: true, error: error ?? 'Missing SNMP credentials.' } });
    return;
  }
  const stepCredentials: StepCredentials = {
    snmp: creds,
    ...(typeof credsFields.slots === 'object' && credsFields.slots !== null ? { slots: credsFields.slots as Record<string, Record<string, string>> } : {}),
    ...credsFields,
  };

  const settings = readSettings(req, PLUGIN_OPTIONS);
  try {
    const ctx = await buildActionContext({
      host: hostFromAddress(managementAddress),
      address: managementAddress,
      deviceId: typeof dev.deviceId === 'string' ? dev.deviceId : undefined,
      credentials: stepCredentials,
      settings,
    });
    const result = await resolver(ctx, inputs);
    res.status(200).json({ result });
  } catch (err) {
    // Preflight is advisory — a probe failure degrades the suggestion, it must
    // never block planning. The UI shows the device as degraded.
    res.status(200).json({ result: { deviceId: String(dev.deviceId ?? ''), values: [], degraded: true, error: (err as Error).message } });
  }
});

// listen() binds the conventional plugin port (4080 by default) and starts
// mDNS advertising — both handled by @unm/plugin-sdk.
server.listen().catch((err) => {
  console.error('[lancom-lcos-plugin] fatal startup error:', err);
  process.exit(1);
});
