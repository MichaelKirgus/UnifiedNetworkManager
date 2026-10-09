import path from 'path';
import {
  Health,
  MetricDescriptor,
  PluginOptionDescriptor,
  StateRequestBody,
  clampInt,
  createPluginLogger,
  createPluginServer,
  errorDescriptor,
  hostFromAddress,
  INVENTORY_INTERVAL_MS,
  modelFirmwareDescriptors,
  isTransientTransportError,
  quickActionHandler,
  buildWebUiUrl,
  readSettings,
  resolvePluginIdentity,
  stateHandler,
  TtlCache,
  createPinningGuard,
  collectDeviceCertificates,
  parseProbeTarget,
  resolveHttpsPort,
  resolveHttpPort,
  resolveSshPort,
  buildDeviceTimeInfo,
  catalogFirmwareRow,
  CertificateRow,
  type QuickAction,
} from '@unm/plugin-sdk';
import { LANCOM_SX_DEVICE_SUPPORT } from './deviceSupport';
import { SnmpCredentials, buildSnmpCredentials } from '@unm/snmp-client';

/**
 * Normalizes a LANCOM-SX `systemDate` DisplayString to a naive ISO-8601 wall clock.
 * Handles "YYYY-MM-DD HH:MM:SS" (and the dotted "DD.MM.YYYY HH:MM:SS" variant some
 * firmware prints). Returns null when unparseable so the caller omits the metric.
 */
function lancomDateToIso(raw: string): string | null {
  const s = raw.trim();
  if (!s) return null;
  let m = s.match(/^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})(?::(\d{2}))?/);
  if (m) return `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6] ?? '00'}`;
  m = s.match(/^(\d{2})\.(\d{2})\.(\d{4})\s+(\d{2}):(\d{2})(?::(\d{2}))?/);
  if (m) return `${m[3]}-${m[2]}-${m[1]}T${m[4]}:${m[5]}:${m[6] ?? '00'}`;
  return null;
}
import { SxOptions, getSxInventory, walkSxCounters } from './sxClient';
import { buildDescriptors, DISCOVER_METRICS } from './metrics';
import { DEVICE_MODELS } from './deviceModels';

/** Every firmware line known across the LCOS-SX catalog — the Updates page
 * compares a device's live swVersion against this set (always in sync with
 * /discover). */
const KNOWN_SX_LINES = Array.from(new Set(DEVICE_MODELS.flatMap((m) => m.firmwareVersions ?? [])));

import { getAction, listCatalog, listModules } from './actions/registry';
import { ActionContext, StepCredentials, validateInput } from './actions/types';
import { buildPlan, PlanningError, PlanRequest } from './plan';
import { buildSxState } from './state';

export const PLUGIN_UUID = '00000000-0000-4000-8000-000000000007';
export const PLUGIN_NAME = 'LANCOM SX-Series Plugin';

/**
 * Multi-instance support: set `PLUGIN_INSTANCE_ID` (e.g. "site-a") to run several
 * instances of the same plugin type — each advertises a distinct identity
 * (`<uuid>:<instanceId>`) so the API registers them as separate plugins.
 * (Convention implemented in @unm/plugin-sdk's resolvePluginIdentity.)
 */
const identity = resolvePluginIdentity({
  uuid: PLUGIN_UUID,
  name: PLUGIN_NAME,
  // 0.1.0 — initial release: LCOS-SX switch monitoring (system/PSU/fans/temp,
  // ports + throughput, PoE, LAG/LACP) for BOTH firmware lines (unified 4.x tree
  // and legacy GS-2310 3.x tree, auto-detected), network/host inventory
  // propagation, plus config/planning actions over SNMP SET.
  // 0.2.0 — Updates page support (capability 'updates'): firmware `updates[]`
  // row from the live swVersion vs the static LCOS-SX release catalog
  // (available-without-apply — LANCOM MIBs are read-only, OS updates go through
  // the web UI).
  version: '0.2.0',
  vendors: ['lancom'],
  // All four capabilities + deviceState (dynamic Config-page state document):
  // monitoring (SNMP walks), inventory (networks/hosts/ports), configuration
  // (SNMP SET actions) + planning (multi-device fan-out).
  capabilities: ['monitoring', 'configuration', 'inventory', 'planning', 'deviceState', 'updates', 'quickActions'],
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
    key: 'snmpPort',
    label: 'SNMP port',
    type: 'integer' as const,
    default: 161,
    min: 1,
    max: 65_535,
    description:
      "UDP port of the switch's SNMP agent (default 161). Override only if the agent listens elsewhere — e.g. a test harness.",
  },
  {
    key: 'inventoryTtlMs',
    label: 'Inventory refresh interval (ms)',
    type: 'integer' as const,
    default: INVENTORY_INTERVAL_MS,
    min: 60_000,
    max: 86_400_000,
    description:
      'How often the slow-changing LCOS-SX status walk (ports, VLANs, PoE, LAG, neighbor cache) is re-run. Live byte counters still refresh every poll cycle.',
  },
  {
    key: 'enrichHostPorts',
    label: 'Enrich host rows with learned-on port (Q-BRIDGE FDB)',
    type: 'boolean' as const,
    default: false,
    description:
      'Walks the Q-BRIDGE forwarding database to attach a port number to each ARP/NDP host row. OFF by default — on a switch with a populated MAC table this walk takes ~15-20 s and can exceed the API poll budget.',
  },
  {
    key: 'logToApi',
    label: 'Send logs to UNM',
    type: 'boolean' as const,
    default: true,
    description:
      'Ship structured log entries (SNMP walk failures, config/plan errors) to the UNM API for the device Logs view. Disable to keep logging container-local only.',
  },  {
    key: 'httpsPort',
    label: 'HTTPS port',
    type: 'integer' as const,
    default: 443,
    min: 1,
    max: 65535,
    description:
      "TCP port of the switch's HTTPS management UI. Used when the management address carries no explicit port (an explicit https://host:<port> always wins). Also the port certificate pinning verifies against.",
  },
  {
    key: 'httpPort',
    label: 'HTTP port',
    type: 'integer' as const,
    default: 80,
    min: 1,
    max: 65535,
    description: "TCP port of the switch's plain-HTTP management UI (used when auto falls back to it).",
  },
  {
    key: 'sshPort',
    label: 'SSH port',
    type: 'integer' as const,
    default: 22,
    min: 1,
    max: 65535,
    description:
      "TCP port of the switch's SSH daemon. Used for the host-key inventory probe when the management address carries no explicit port.",
  },];

/** Quick actions propagated to the Devices page "Device Actions" column. */
const QUICK_ACTIONS: QuickAction[] = [
  {
    id: 'webui',
    label: 'Web UI',
    description: "Open the switch's management web interface in a new tab",
    iconPath: '/icons/lancom-sx.svg',
    kind: 'url',
    url: {},
  },
];

// Pre-wired app: cors + json (32mb for base64 config payloads) + /healthz +
// /discover (+ static icons, mDNS on listen) come from @unm/plugin-sdk — this
// file only registers its own routes.
const server = createPluginServer({
  identity,
  logTag: 'lancom-sx',
  jsonLimit: '32mb',
  // Static icon assets, advertised in /discover and fetched by the API's icon proxy.
  iconsDir: path.join(__dirname, '../../icons'),
  // Static doc/license assets served at /assets/* (proxied by the API's
  // GET /plugins/:id/asset) — referenced from discovery.deviceSupport.
  assetsDir: path.join(__dirname, '../..'),
  discovery: {
    // Primary credential = the existing 'snmp' secret type (community for v1/v2c, USM fields for v3).
    requiredSecretType: 'snmp',
    metrics: DISCOVER_METRICS,
    options: PLUGIN_OPTIONS,
    // The full action catalog (single-device actions) + module grouping. One registry
    // serves /discover, /plan and /config — see src/actions/registry.ts.
    actions: listCatalog(),
    modules: listModules(),
    // Quick action for the Devices page "Device Actions" column — the web-UI URL
    // is resolved by THIS plugin (port = the configured httpsPort option).
    quickActions: QUICK_ACTIONS,
    iconUrl: '/icons/lancom-sx.svg',
    deviceModels: DEVICE_MODELS,
    // License/help/docs metadata for UNM's Plugins page (see ./deviceSupport.ts).
    deviceSupport: LANCOM_SX_DEVICE_SUPPORT,
  },
});
const app = server.app;

// POST /quick-action — resolve a kind:'url' quick action into the management web-UI
// URL. The plugin owns all URL knowledge; no credentials are transmitted.
app.post('/quick-action', quickActionHandler(async (body, req) => {
  const settings = readSettings(req, PLUGIN_OPTIONS);
  const qa = QUICK_ACTIONS.find((q) => q.id === body.actionId && q.kind === 'url');
  if (!qa) throw new Error(`Unknown url quick action: ${body.actionId}`);
  return { url: buildWebUiUrl(body.managementAddress, { webUiPort: resolveHttpsPort(settings.httpsPort), scheme: 'https' }, qa.url?.path) };
}, 'lancom-sx-plugin'));

// Structured logs shipped to the API (see docs/PLUGIN-DEVELOPMENT.md, Logging).
// Emission is gated per call by the `logToApi` option via setEnabled() — it
// flows through the settings loop, so it works globally and per-device.
const logger = createPluginLogger(identity);

// --- Certificates (capability: cross-device Certificates page) -----------------
// Certificate rows are probed on a slower cadence than the inventory walk — they
// change rarely and each probe opens fresh TLS/SSH connections to the device.
const CERT_TTL_MS = 10 * 60_000;
const certCache = new TtlCache<CertificateRow[]>({ isFresh: (v) => Array.isArray(v) });

// Certificate pinning — one process-wide guard for every credential-bearing
// entry point. Strict mode + a known fingerprint MISMATCH throws before any
// credentials are transmitted; unknown endpoints are TOFU-accepted and land in
// UNM's inventory via the `certificates` metric.
const assertPinned = createPinningGuard();

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

/** Resolves SNMP walk options from effective settings. */
function resolveOptions(settings: Record<string, unknown>): SxOptions {
  return {
    timeoutMs: clampInt(settings.timeoutMs, 1_000, 30_000, 5_000),
    retries: clampInt(settings.retries, 0, 10, 2),
    port: clampInt(settings.snmpPort, 1, 65_535, 161),
    inventoryTtlMs: clampInt(settings.inventoryTtlMs, 60_000, 86_400_000, INVENTORY_INTERVAL_MS),
    enrichHostPorts: settings.enrichHostPorts === true,
  };
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
      // sx4 descriptors — the superset; a failed probe carries no data anyway.
      metricDescriptors: [
        ...buildDescriptors(opts.inventoryTtlMs, 'sx4'),
        errorDescriptor(),
      ],
      error,
    });
  };

  if (!host) return fail('critical', 'No target address — set the device management address.');

  const { creds, error } = resolveCredentials((body.credentials ?? {}) as Record<string, unknown>);
  if (error || !creds) return fail('critical', error ?? 'Missing SNMP credentials.');

  try {
    // Certificate pinning — verify the switch's TLS cert against UNM's
    // inventory BEFORE any credentials are transmitted (throws on mismatch).
    await assertPinned(req, managementAddress, 'auto', portsOf(settings));

    // Slow path: targeted parallel LCOS-SX walks (only the subtrees we use),
    // TTL-cached per host with a quality gate against partial-failure data.
    const inventory = await getSxInventory(host, creds, opts, {
      log: (level, message, context) => logger.warn(message, { deviceId, context }),
    });
    const snapshot = inventory.snapshot;

    if (!snapshot) {
      // No LCOS-SX tree at all — this device is not a Lancom SX switch (or SNMP
      // is misconfigured). 'unknown' rather than 'critical': the plugin may simply
      // be assigned to the wrong device type.
      logger.warn(`No usable LCOS-SX data from ${host}: ${inventory.error ?? 'no LCOS-SX MIB tree'}`, { deviceId, context: { host } });
      return fail('unknown', inventory.error ?? 'No LCOS-SX MIB data on this device.');
    }

    if (inventory.error) {
      // Partial walk failure — the snapshot is usable but some subtrees are empty.
      logger.warn(`Partial LCOS-SX data from ${host}: ${inventory.error}`, { deviceId, context: { host } });
    }

    // Fast path: counter-only walk every cycle for fresh port rates.
    const fast = await walkSxCounters(host, creds, opts, snapshot.variant);

    const metrics: Record<string, unknown> = {};
    const sys = snapshot.system;
    metrics['system.name'] = sys.name || null;
    metrics['system.modelNumber'] = sys.model || null;
    metrics['system.swVersion'] = sys.firmwareVersion || null;
    // Updates page: firmware row from the live swVersion (e.g. "v3.34.0326" or
    // "4.30.xxxx") vs the newest known LCOS-SX line — major.minor comparison,
    // so the leading "v" + build suffix never matter. Available-without-apply.
    if (sys.firmwareVersion) {
      // Release notes: LANCOM's FTP release-notes folder for the target line
      // (RN_LCOS-SX-<line>-*.pdf).
      const fwRow = catalogFirmwareRow(sys.firmwareVersion, KNOWN_SX_LINES, {
        releaseNotesUrl: (target) => `https://ftp.lancom.de/Documentation/Release-Notes/LCOS%20SX/${String(target).replace(/\./g, '')}/`,
      });
      if (fwRow) metrics['updates'] = [fwRow];
    }
    metrics['system.serialNumber'] = sys.serialNumber || null;
    metrics['system.hostMac'] = sys.hostMac || null;
    metrics['system.uptime'] = sys.uptimeText || null; // DisplayString as reported
    // Device clock (Time page): the switch's wall clock from lcsSystemInfoSystemDate.
    // LANCOM-SX exposes no IANA zone over SNMP, so we emit localIso only — the Time
    // page shows the local time and marks drift "not computable" rather than guessing.
    if (sys.systemDate) {
      const iso = lancomDateToIso(sys.systemDate);
      if (iso) {
        // No IANA zone over SNMP → emit the local wall clock so the Time page can
        // display it; drift is "not computable" without a resolvable instant.
        metrics['system.deviceTime'] = buildDeviceTimeInfo(iso, null) ?? { localIso: iso };
      }
    }
    metrics['system.cpuLoad'] = sys.cpuLoadPct;
    if (sys.memoryTotalMb !== null && sys.memoryFreeMb !== null && sys.memoryTotalMb > 0) {
      const usedPct = Math.round(((sys.memoryTotalMb - sys.memoryFreeMb) / sys.memoryTotalMb) * 100);
      metrics['system.memoryUsedPct'] = Math.max(0, Math.min(100, usedPct));
    } else {
      metrics['system.memoryUsedPct'] = null;
    }
    // User-selected hardware model / firmware (from the device form).
    if (selectedModel) metrics['system.model'] = selectedModel;
    if (selectedFirmware) metrics['system.firmwareVersion'] = selectedFirmware;

    // --- Hardware -----------------------------------------------------------
    metrics['hardware.psuA'] = sys.psuAStatus || null;
    metrics['hardware.psuB'] = sys.psuBStatus || null;
    metrics['hardware.fanSpeed'] = sys.fanSpeedText || null;
    for (let i = 0; i < 3; i++) {
      const t = sys.temperatureC[i];
      if (t !== null) metrics[`hardware.temperature${i + 1}`] = t;
    }

    // --- Ports ---------------------------------------------------------------
    metrics['ports.table'] = snapshot.ports.map((p) => ({
      name: p.label,
      linkUp: p.linkUp === null ? '—' : p.linkUp ? 'up' : 'down',
      speedStatus: p.speedStatus || (p.media && p.media !== '' ? `${p.speedStatus} (${p.media})` : '') || '—',
      vlanModeLabel: p.vlanModeLabel || '—',
      pvid: p.pvid !== null ? String(p.pvid) : '—',
      allowedVlans: p.allowedVlans || '—',
    }));
    if (Object.keys(fast).length > 0) {
      metrics['ports.rates'] = fast; // { P<n>: { rx, tx } } — MAP form table
    }

    // --- PoE (4.x only) --------------------------------------------------------
    const hasPoe = snapshot.poePorts.length > 0 || snapshot.poeTotals !== null;
    if (hasPoe) {
      metrics['poe.ports'] = snapshot.poePorts.map((e) => ({
        port: `P${e.port}`,
        pdClass: e.pdClass || '—',
        powerRequestedWatts: e.powerRequestedWatts !== null ? `${e.powerRequestedWatts} W` : '—',
        powerAllocatedWatts: e.powerAllocatedWatts !== null ? `${e.powerAllocatedWatts} W` : '—',
        powerUsedWatts: e.powerUsedWatts !== null ? `${e.powerUsedWatts} W` : '—',
        priorityLabel: e.priorityLabel || '—',
        portStatusLabel: e.portStatusLabel || '—',
      }));
      if (snapshot.poeTotals?.usedWatts !== null && snapshot.poeTotals?.usedWatts !== undefined) {
        metrics['poe.totalUsedWatts'] = snapshot.poeTotals.usedWatts; // summary gauge
      }
    }

    // --- LAG / LACP (4.x only) ---------------------------------------------------
    if (snapshot.lags.length > 0) {
      metrics['lag.members'] = snapshot.lags.map((l) => ({
        port: `P${l.port}`,
        lacpLabel: l.lacpLabel || '—',
        key: l.key || '—',
        aggrId: l.aggrId || '—',
        partnerSystemId: l.partnerSystemId || '—',
        partnerPort: l.partnerPort || '—',
      }));
    }

    // --- Inventory propagation (consumed by the API's ingestInventory) -----
    // networks[]: configured IP rows from SVIs (4.x) / management address (3.x).
    const emittedNetKeys = new Set<string>();
    if (emitInventory) {
      metrics['networks'] = snapshot.networks.filter((n) => {
        if (!n.ip) return false;
        const k = `${n.name}|${n.ip}`; // safety net for the API's upsert key (name, ip)
        if (emittedNetKeys.has(k)) return false;
        emittedNetKeys.add(k);
        return true;
      }).map((n) => {
        const row: Record<string, unknown> = { name: n.name, ip: n.ip, prefix: n.prefix, version: n.version, status: null };
        if (n.vlanId !== null) row['vlanId'] = n.vlanId;
        return row;
      });
    }

    // arp[] / ndp[] → hosts table with source 'arp'/'ndp', split by IP family.
    const arpRows = snapshot.neighbors
      .filter((n) => n.version === 'v4' && n.mac !== '' && n.ip !== '')
      .map((n) => ({ mac: n.mac, ip: n.ip, intf: n.port !== null ? `P${n.port}` : null }));
    if (emitInventory && arpRows.length > 0) metrics['arp'] = arpRows;

    const ndpRows = snapshot.neighbors
      .filter((n) => n.version === 'v6' && n.mac !== '' && n.ip !== '')
      .map((n) => ({ mac: n.mac, ip: n.ip, intf: n.port !== null ? `P${n.port}` : null }));
    if (emitInventory && ndpRows.length > 0) metrics['ndp'] = ndpRows;

    // NOTE: no dhcpLeases[] — the LCOS-SX MIB's DHCP binding table is commented
    // out in both firmware lines, so per-lease data is not available via SNMP.

    // routes[] → cross-device Routes page (4.x only; 3.x switches emit nothing).
    if (emitInventory && snapshot.routes.length > 0) {
      metrics['routes'] = snapshot.routes.map((r) => ({
        destination: r.destination,
        gateway: r.gateway,
        protocol: r.protocol,
        distance: r.distance,
        status: 'active', // the live status table only lists active entries
      }));
    }

    // ports[] → device_ports table (per-device Config page + cross-device views).
    // One row per switch port with its live link state; MACs learned on the port
    // ride in extra.macs when FDB enrichment is enabled.
    if (emitInventory) {
      metrics['ports'] = snapshot.ports.map((p) => {
        const macs = snapshot.neighbors.filter((n) => n.port === p.port && n.mac !== '').map((n) => n.mac);
        return {
          name: `P${p.port}`,
          status: p.linkUp === null ? 'unknown' : p.linkUp ? 'up' : 'down',
          speed: p.speedStatus || (p.media && p.media !== '' ? `${p.speedStatus} (${p.media})` : '') || null,
          vlanId: p.pvid,
          extra: macs.length > 0 ? { macs } : {},
        };
      });
    }

    // --- Certificates (normalized for the cross-device Certificates page) ----
    // Management HTTPS cert + SSH host key on port 22. Both probes are
    // credential-free and best-effort; a failure simply contributes no row.
    if (emitInventory) {
      const cachedCerts = certCache.get(host, CERT_TTL_MS) ?? null;
      let certRows: CertificateRow[] | null = cachedCerts;
      if (!certRows) {
        // SX switches default to an HTTPS management UI — probe TLS on the
        // configured port (default 443) plus the SSH host key on its port.
        const p = portsOf(settings);
        const target = parseProbeTarget(managementAddress, p.httpsPort ?? 443);
        certRows = target
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

    // --- Health -------------------------------------------------------------
    let health: Health = 'ok';
    const warnings: string[] = [];
    if (!sys.name && !sys.firmwareVersion) warnings.push('system scalars unavailable');
    if (snapshot.ports.length === 0) warnings.push('no ports reported');
    if (inventory.error) warnings.push(inventory.error);
    // SNMPv1 has no GetBulk — every table row costs one PDU, so port-table
    // walks on a legacy switch take ~20s and blow the poll budget. Point the
    // user at v2c/v3 instead of letting them stare at an empty Ports group.
    if (warnings.length > 0 && creds.version === 'v1') {
      warnings.push('SNMPv1 lacks GetBulk — table walks are very slow; use SNMPv2c or v3 for this device');
    }
    if (warnings.length > 0) {
      health = 'warning';
      metrics['system.error'] = warnings.join('; ');
    }

    const descriptors: MetricDescriptor[] = buildDescriptors(opts.inventoryTtlMs, snapshot.variant);
    // Runtime rows for the MAP-form rate table.
    if (Object.keys(fast).length > 0) {
      const d = descriptors.find((x) => x.key === 'ports.rates');
      if (d) d.rows = Object.keys(fast);
    }
    if (metrics['system.error']) {
      descriptors.push(errorDescriptor());
    }
    // Routes table descriptor — only when the snapshot actually carries rows.
    if (Array.isArray(metrics['routes']) && (metrics['routes'] as unknown[]).length > 0) {
      descriptors.push({ key: 'routes', label: 'Routes', type: 'string', visualization: 'table', group: 'Inventory', columns: ['destination', 'gateway', 'protocol', 'distance'], intervalMs: opts.inventoryTtlMs });
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
function buildActionContext(args: {
  host: string;
  address: string;
  deviceId?: string;
  credentials: StepCredentials;
  settings: Record<string, unknown>;
}): ActionContext {
  const opts = resolveOptions(args.settings);
  return {
    host: args.host,
    address: args.address,
    deviceId: args.deviceId,
    credentials: args.credentials,
    opts,
  };
}

/**
 * Executes ONE action step against one switch. This is the unit of work the
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
    // Certificate pinning — a config action transmits real credentials;
    // refuse the connection when the switch's key differs from UNM's inventory.
    await assertPinned(req, managementAddress, 'auto', portsOf(settings));

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
    // Transport-level failures (switch down / not ready yet) are transient — the
    // plan executor re-dispatches them per the plan's retry policy. Web-UI/SNMP
    // protocol errors already come back as ok:false results and stay hard.
    const retryable = isTransientTransportError(err);
    res.status(200).json({ success: false, result: { error: (err as Error).message, ...(retryable ? { retryable: true } : {}) } });
  }
});

/**
 * Plans a multi-device intent (or fans out a single action across a batch).
 * The plugin does ALL the planning — dependency ordering. It never generates
 * key material: SX v1 needs no provisioned secrets at all, and there is no
 * auto-prepended backup step (no web-UI slot in v1).
 *
 * Body: { intent: { actionId, inputs }, devices: [{ deviceId, managementAddress, credentials }] }
 */
app.post('/plan', async (req, res) => {
  const body = req.body ?? {};
  const settings = readSettings(req, PLUGIN_OPTIONS);
  logger.setEnabled(settings.logToApi === true);

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
      logger.error(`Planning ${planReq.intent.actionId} failed: ${err.message}`, { context: { actionId: planReq.intent.actionId, deviceCount: planReq.devices.length } });
      res.status(400).json({ error: err.message });
      return;
    }
    logger.error(`Planning ${planReq.intent.actionId} failed unexpectedly: ${(err as Error).message}`, { context: { actionId: planReq.intent.actionId, deviceCount: planReq.devices.length } });
    res.status(500).json({ error: (err as Error).message });
  }
});

/**
 * GET /state — the dynamic device-state document for the UNM Config page.
 * Reuses the TTL-cached slow-path inventory walk (same cache as /monitoring),
 * so a state fetch is cheap right after a poll and bounded otherwise. The
 * stateHandler wrapper guarantees an Express-4-safe JSON error envelope.
 */
app.post(
  '/state',
  stateHandler(async (body, req) => {
    const settings = readSettings(req, PLUGIN_OPTIONS);
    logger.setEnabled(settings.logToApi === true);
    const opts = resolveOptions(settings);
    const host = hostFromAddress(body.managementAddress);
    if (!host) throw new Error('No target address — set the device management address.');

    // Certificate pinning — /state reads live data with credentials; verify first.
    await assertPinned(req, body.managementAddress, 'auto', portsOf(settings));

    const { creds, error } = resolveCredentials((body.credentials ?? {}) as Record<string, unknown>);
    if (error || !creds) throw new Error(error ?? 'Missing SNMP credentials.');

    const inventory = await getSxInventory(host, creds, opts, {
      log: (level, message, context) => logger.warn(message, { deviceId: body.deviceId, context }),
    });
    if (!inventory.snapshot) {
      throw new Error(inventory.error ?? 'No LCOS-SX MIB data on this device.');
    }
    return buildSxState(inventory.snapshot);
  }, 'lancom-sx')
);

// listen() binds the conventional plugin port (4080 by default) and starts
// mDNS advertising — both handled by @unm/plugin-sdk.
server.listen().catch((err) => {
  console.error('[lancom-sx] fatal startup error:', err);
  process.exit(1);
});
