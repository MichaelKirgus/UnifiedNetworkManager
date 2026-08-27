import path from 'path';
import {
  Health,
  MetricDescriptor,
  PluginOptionDescriptor,
  clampInt,
  createPluginServer,
  errorDescriptor,
  hostFromAddress,
  INVENTORY_INTERVAL_MS,
  modelFirmwareDescriptors,
  readSettings,
  resolvePluginIdentity,
} from '@unm/plugin-sdk';
import { SnmpCredentials, buildSnmpCredentials } from '@unm/snmp-client';
import { SxOptions, getSxInventory, walkSxCounters } from './sxClient';
import { buildDescriptors, DISCOVER_METRICS } from './metrics';
import { DEVICE_MODELS } from './deviceModels';
import { getAction, listCatalog, listModules } from './actions/registry';
import { ActionContext, StepCredentials, validateInput } from './actions/types';
import { buildPlan, PlanningError, PlanRequest } from './plan';

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
  version: '0.1.0',
  vendors: ['lancom'],
  // All four capabilities: monitoring (SNMP walks), inventory (networks/hosts),
  // configuration (SNMP SET actions) + planning (multi-device fan-out).
  capabilities: ['monitoring', 'configuration', 'inventory', 'planning'],
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
    description: 'How many times snmpwalk/snmpset retries a request before giving up.',
  },
  {
    key: 'mibDir',
    label: 'MIB directory (container path)',
    type: 'string' as const,
    maxLength: 512,
    description:
      'Container-internal directory holding extra MIB files. Defaults to the MIB_DIR env var (the mounted ./plugins/lancom-sx/mibs volume at /app/mibs). Parsing uses numeric OIDs — MIBs are for debugging only.',
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
  discovery: {
    // Primary credential = the existing 'snmp' secret type (community for v1/v2c, USM fields for v3).
    requiredSecretType: 'snmp',
    metrics: DISCOVER_METRICS,
    options: PLUGIN_OPTIONS,
    // The full action catalog (single-device actions) + module grouping. One registry
    // serves /discover, /plan and /config — see src/actions/registry.ts.
    actions: listCatalog(),
    modules: listModules(),
    iconUrl: '/icons/lancom-sx.svg',
    deviceModels: DEVICE_MODELS,
  },
});
const app = server.app;

/** Resolves SNMP walk options from effective settings. */
function resolveOptions(settings: Record<string, unknown>): SxOptions {
  const settingMib = typeof settings.mibDir === 'string' && settings.mibDir.trim() ? settings.mibDir.trim() : '';
  return {
    timeoutMs: clampInt(settings.timeoutMs, 1_000, 30_000, 5_000),
    retries: clampInt(settings.retries, 0, 10, 2),
    mibDir: settingMib || (process.env.MIB_DIR ? process.env.MIB_DIR : undefined),
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
  const opts = resolveOptions(settings);
  const host = hostFromAddress(managementAddress);

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
    // Slow path: targeted parallel LCOS-SX walks (only the subtrees we use),
    // TTL-cached per host with a quality gate against partial-failure data.
    const inventory = await getSxInventory(host, creds, opts);
    const snapshot = inventory.snapshot;

    if (!snapshot) {
      // No LCOS-SX tree at all — this device is not a Lancom SX switch (or SNMP
      // is misconfigured). 'unknown' rather than 'critical': the plugin may simply
      // be assigned to the wrong device type.
      return fail('unknown', inventory.error ?? 'No LCOS-SX MIB data on this device.');
    }

    // Fast path: counter-only walk every cycle for fresh port rates.
    const fast = await walkSxCounters(host, creds, opts, snapshot.variant);

    const metrics: Record<string, unknown> = {};
    const sys = snapshot.system;
    metrics['system.name'] = sys.name || null;
    metrics['system.modelNumber'] = sys.model || null;
    metrics['system.swVersion'] = sys.firmwareVersion || null;
    metrics['system.serialNumber'] = sys.serialNumber || null;
    metrics['system.hostMac'] = sys.hostMac || null;
    metrics['system.uptime'] = sys.uptimeText || null; // DisplayString as reported
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

    // arp[] / ndp[] → hosts table with source 'arp'/'ndp', split by IP family.
    const arpRows = snapshot.neighbors
      .filter((n) => n.version === 'v4' && n.mac !== '' && n.ip !== '')
      .map((n) => ({ mac: n.mac, ip: n.ip, intf: n.port !== null ? `P${n.port}` : null }));
    if (arpRows.length > 0) metrics['arp'] = arpRows;

    const ndpRows = snapshot.neighbors
      .filter((n) => n.version === 'v6' && n.mac !== '' && n.ip !== '')
      .map((n) => ({ mac: n.mac, ip: n.ip, intf: n.port !== null ? `P${n.port}` : null }));
    if (ndpRows.length > 0) metrics['ndp'] = ndpRows;

    // NOTE: no dhcpLeases[] — the LCOS-SX MIB's DHCP binding table is commented
    // out in both firmware lines, so per-lease data is not available via SNMP.

    // routes[] → cross-device Routes page (4.x only; 3.x switches emit nothing).
    if (snapshot.routes.length > 0) {
      metrics['routes'] = snapshot.routes.map((r) => ({
        destination: r.destination,
        gateway: r.gateway,
        protocol: r.protocol,
        distance: r.distance,
        status: 'active', // the live status table only lists active entries
      }));
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
        mibDir: opts.mibDir ?? null,
        inventoryTtlMs: opts.inventoryTtlMs,
        // User-selected hardware model / firmware version (forwarded by the API).
        model: selectedModel,
        firmwareVersion: selectedFirmware,
      },
    });
  } catch (err) {
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

  const settings = readSettings(req, PLUGIN_OPTIONS);

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
    res.status(200).json({ success: result.success, result: { ...result } });
  } catch (err) {
    res.status(200).json({ success: false, result: { error: (err as Error).message } });
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
  console.error('[lancom-sx] fatal startup error:', err);
  process.exit(1);
});
