/**
 * The SwOS action registry — single source of truth for everything this plugin
 * can do. Serves three entry points (same contract as the OPNsense plugin):
 *  - /discover → listCatalog() (the catalog the API persists + validates)
 *  - /plan     → buildPlan() fans out single-device actions per device
 *  - /config   → getAction(step.actionId).execute(ctx, input) runs one step
 *
 * Write semantics follow the reference project's proven pattern: GET current
 * state → mutate in memory → POST ONLY writable fields (per-port settings as
 * COMPLETE arrays; PoE arrays truncated to the PoE-capable port count). All
 * changes are applied and persisted immediately by the switch.
 */

import { buildPostArray, buildPostData, encodeHexString, encodeIpLe, encodePortMask } from '../swosClient';
import { getField, hasField } from '../platform';
import { ActionContext, ActionDescriptor, InputSchema, RiskLevel, validateInput } from './types';

// --- Small helpers --------------------------------------------------------------------

function str(input: Record<string, unknown>, key: string): string | undefined {
  const v = input[key];
  return typeof v === 'string' && v.length > 0 ? v : undefined;
}

function num(input: Record<string, unknown>, key: string): number | undefined {
  const v = input[key];
  return typeof v === 'number' && Number.isFinite(v) ? Math.floor(v) : undefined;
}

/** Resolves a 1-based port against the switch's actual port count. */
async function resolvePort(ctx: ActionContext, port: number): Promise<number> {
  const max = await ctx.platform.portCount();
  if (!Number.isInteger(port) || port < 1 || (max > 0 && port > max)) {
    throw new Error(`Invalid port ${port} — this switch has ${max || 'an unknown number of'} ports`);
  }
  return port;
}

/** Re-POSTs a parsed object body, dropping fields that were absent in the GET. */
function postObject(ctx: ActionContext, endpoint: string, data: Record<string, unknown>): Promise<string> {
  const fields: Record<string, number | string | (number | string)[]> = {};
  for (const [k, v] of Object.entries(data)) {
    if (v === undefined || v === null) continue;
    if (Array.isArray(v)) fields[k] = v as (number | string)[];
    else if (typeof v === 'number' || typeof v === 'string') fields[k] = v;
  }
  return ctx.client.post(endpoint, buildPostData(fields));
}

/**
 * POSTs only the WRITABLE subset of a parsed body — the protocol requires that
 * read-only fields (status, statistics, calculated values) are never sent back.
 * `writableKeys` names the logical fields allowed on this endpoint.
 */
function postWritable(ctx: ActionContext, endpoint: string, data: Record<string, unknown>, writableKeys: readonly (keyof import('../platform').FieldMap)[]): Promise<string> {
  const map = ctx.platform.map;
  const fields: Record<string, number | string | (number | string)[]> = {};
  for (const key of writableKeys) {
    if (!hasField(map, key)) continue;
    const id = map[key];
    const v = data[id as string];
    if (v === undefined || v === null) continue;
    if (Array.isArray(v)) fields[id as string] = v as (number | string)[];
    else if (typeof v === 'number' || typeof v === 'string') fields[id as string] = v;
  }
  return ctx.client.post(endpoint, buildPostData(fields));
}

/** Writable sys.b fields (identity + management access). Everything else on the page is read-only. */
const SYS_WRITABLE_KEYS = ['systemIdentity', 'systemAddressAcquisition', 'systemStaticIp', 'systemAllowFromIp', 'systemAllowFromBits', 'systemAllowFromPorts', 'systemAllowFromVlan'] as const;

// --- Read actions -----------------------------------------------------------------------

const systemInfoAction: ActionDescriptor = {
  id: 'swos.system.info',
  label: 'Read system information',
  description: 'Fetches identity, model, firmware version, MAC/serial, uptime and management settings from sys.b.',
  module: 'System',
  riskLevel: 'read',
  deviceCount: 1,
  inputSchema: {},
  async execute(ctx) {
    const map = ctx.platform.map;
    const sys = (await ctx.client.get('sys.b')) as Record<string, unknown>;
    return {
      success: true,
      details: {
        identity: decodeHex(getField(sys, map, 'systemIdentity')),
        model: decodeHex(getField(sys, map, 'systemModel')),
        firmwareVersion: decodeHex(getField(sys, map, 'systemVersion')),
        macAddress: String(getField(sys, map, 'systemMac') ?? ''),
        serialNumber: decodeHex(getField(sys, map, 'systemSerial')),
        uptimeSeconds: typeof getField(sys, map, 'systemUptime') === 'number' ? (getField(sys, map, 'systemUptime') as number) : null,
        currentIp: String(getField(sys, map, 'systemCurrentIp') ?? ''),
      },
    };
  },
};

const backupDownloadAction: ActionDescriptor = {
  id: 'swos.backup.download',
  label: 'Download configuration backup (.swb)',
  description:
    'Downloads the switch\'s complete binary configuration backup (proprietary .swb format). The file is returned base64-encoded in details — use it as a rollback point before risky changes or to clone a config. Read-only on the device.',
  module: 'System',
  riskLevel: 'read',
  deviceCount: 1,
  timeoutMs: 60_000,
  inputSchema: {},
  async execute(ctx) {
    const data = await ctx.client.getRaw('backup.swb');
    if (data.length === 0) throw new Error('Switch returned an empty backup (default configuration — nothing to save)');
    return {
      success: true,
      details: {
        sizeBytes: data.length,
        // Base64 so the binary survives JSON transport; the plan executor stores it in step results.
        backupBase64: data.toString('base64'),
      },
    };
  },
};

// --- Write actions ------------------------------------------------------------------------

const portConfigAction: ActionDescriptor = {
  id: 'port.config.set',
  label: 'Set port configuration',
  description: 'Renames a port and/or toggles its enabled state and auto-negotiation. GET-modify-POST on link.b (all ports sent as complete arrays).',
  module: 'Ports',
  riskLevel: 'write',
  deviceCount: 1,
  timeoutMs: 30_000,
  inputSchema: {
    port: { type: 'number', required: true, min: 1, max: 64, label: 'Port number (1-based)' },
    name: { type: 'string', maxLength: 32, pattern: '^[ -~]{0,32}$', description: 'New port name' },
    enabled: { type: 'boolean', description: 'Enable/disable the port' },
    autoNegotiation: { type: 'boolean', description: 'Auto-negotiation on/off' },
  },
  async execute(ctx, input) {
    const map = ctx.platform.map;
    const port = await resolvePort(ctx, num(input, 'port')!);
    const idx = port - 1;

    const data = (await ctx.client.get('link.b')) as Record<string, unknown>;

    if (str(input, 'name') !== undefined) {
      let names = getField(data, map, 'portNames');
      if (!Array.isArray(names)) throw new Error('Port name table not available on this device');
      const arr = [...(names as string[])];
      arr[idx] = encodeHexString(str(input, 'name')!);
      data[map.portNames] = arr;
    }
    if (typeof input.enabled === 'boolean') {
      const mask = typeof getField(data, map, 'portEnabled') === 'number' ? (getField(data, map, 'portEnabled') as number) : 0;
      data[map.portEnabled] = input.enabled ? mask | (1 << idx) : mask & ~(1 << idx);
    }
    if (typeof input.autoNegotiation === 'boolean') {
      const mask = typeof getField(data, map, 'portAutoNeg') === 'number' ? (getField(data, map, 'portAutoNeg') as number) : 0;
      data[map.portAutoNeg] = input.autoNegotiation ? mask | (1 << idx) : mask & ~(1 << idx);
    }

    // Writable link.b fields only — mirrors the reference implementation.
    const writable: Record<string, unknown> = {};
    for (const key of ['portEnabled', 'portNames', 'portAutoNeg', 'portSpeed', 'portDuplexConfig', 'portFlowTx', 'portFlowRx'] as const) {
      if (hasField(map, key)) {
        const id = map[key];
        if (data[id] !== undefined) writable[id] = data[id];
      }
    }
    await ctx.client.post('link.b', buildPostData(writable as Record<string, number | string | (number | string)[]>));

    return { success: true, applied: true, details: { port, name: str(input, 'name') ?? null, enabled: input.enabled ?? null, autoNegotiation: input.autoNegotiation ?? null } };
  },
};

const poeConfigAction: ActionDescriptor = {
  id: 'poe.config.set',
  label: 'Set PoE configuration',
  description: 'Sets PoE mode (off/on/auto), priority, voltage level and LLDP for one port. Arrays are truncated to the PoE-capable port count per the switch protocol.',
  module: 'PoE',
  riskLevel: 'write',
  deviceCount: 1,
  timeoutMs: 30_000,
  inputSchema: {
    port: { type: 'number', required: true, min: 1, max: 64 },
    mode: { type: 'string', enum: ['off', 'on', 'auto'] },
    priority: { type: 'number', min: 1, max: 8, description: 'PoE priority (1-8)' },
    voltageLevel: { type: 'string', enum: ['auto', 'low', 'high'] },
    lldpEnabled: { type: 'boolean' },
  },
  async execute(ctx, input) {
    const map = ctx.platform.map;
    if (!(await ctx.platform.hasPoe())) throw new Error('This device does not support PoE');
    const port = await resolvePort(ctx, num(input, 'port')!);
    const idx = port - 1;

    const data = (await ctx.client.get('poe.b')) as Record<string, unknown>;
    const modesRaw = getField(data, map, 'poeMode');
    if (!Array.isArray(modesRaw)) throw new Error('PoE mode table not available on this device');
    const poePortCount = (modesRaw as unknown[]).length; // PoE-capable ports only

    if (idx >= poePortCount) throw new Error(`Port ${port} is not a PoE port (this switch powers ports 1-${poePortCount})`);

    const modeMap: Record<string, number> = { off: 0x00, on: 0x01, auto: 0x02 };
    const voltMap: Record<string, number> = { auto: 0x00, low: 0x01, high: 0x02 };

    if (str(input, 'mode')) {
      const arr = [...(modesRaw as unknown[])];
      arr[idx] = modeMap[str(input, 'mode')!];
      data[map.poeMode] = arr;
    }
    if (num(input, 'priority') !== undefined) {
      let arr = getField(data, map, 'poePriority');
      if (!Array.isArray(arr)) throw new Error('PoE priority table not available on this device');
      const p = [...(arr as unknown[])];
      p[idx] = (num(input, 'priority') as number) - 1; // wire is 0-based
      data[map.poePriority] = p;
    }
    if (str(input, 'voltageLevel')) {
      let arr = getField(data, map, 'poeVoltage');
      if (!Array.isArray(arr)) throw new Error('PoE voltage table not available on this device');
      const v = [...(arr as unknown[])];
      v[idx] = voltMap[str(input, 'voltageLevel')!];
      data[map.poeVoltage] = v;
    }
    if (typeof input.lldpEnabled === 'boolean') {
      const mask = typeof getField(data, map, 'poeLldp') === 'number' ? (getField(data, map, 'poeLldp') as number) : 0;
      data[map.poeLldp] = input.lldpEnabled ? mask | (1 << idx) : mask & ~(1 << idx);
    }

    // PoE arrays must contain ONLY the first N (PoE-capable) elements.
    const writable: Record<string, unknown> = {};
    for (const key of ['poeMode', 'poePriority', 'poeVoltage'] as const) {
      if (hasField(map, key)) {
        const id = map[key];
        const v = data[id];
        if (Array.isArray(v)) writable[id] = (v as unknown[]).slice(0, poePortCount);
      }
    }
    if (hasField(map, 'poeLldp') && data[map.poeLldp] !== undefined) writable[map.poeLldp] = data[map.poeLldp];

    await ctx.client.post('poe.b', buildPostData(writable as Record<string, number | string | (number | string)[]>));
    return { success: true, applied: true, details: { port, mode: str(input, 'mode') ?? null } };
  },
};

const lagConfigAction: ActionDescriptor = {
  id: 'lag.config.set',
  label: 'Set LAG/LACP configuration',
  description: 'Sets the LACP mode (passive/active/static) and LAG group for one port on lacp.b.',
  module: 'LAG',
  riskLevel: 'write',
  deviceCount: 1,
  timeoutMs: 30_000,
  inputSchema: {
    port: { type: 'number', required: true, min: 1, max: 64 },
    mode: { type: 'string', enum: ['passive', 'active', 'static'] },
    group: { type: 'number', min: 0, max: 15, description: 'LAG group (0-15)' },
  },
  async execute(ctx, input) {
    const map = ctx.platform.map;
    if (!(await ctx.platform.hasLacp())) throw new Error('This device does not support LAG/LACP');
    const port = await resolvePort(ctx, num(input, 'port')!);
    const idx = port - 1;

    const data = (await ctx.client.get('lacp.b')) as Record<string, unknown>;
    const modeMap: Record<string, number> = { passive: 0x00, active: 0x01, static: 0x02 };

    if (str(input, 'mode')) {
      let arr = getField(data, map, 'lagMode');
      if (!Array.isArray(arr)) throw new Error('LAG mode table not available on this device');
      const m = [...(arr as unknown[])];
      m[idx] = modeMap[str(input, 'mode')!];
      data[map.lagMode] = m;
    }
    if (num(input, 'group') !== undefined) {
      let arr = getField(data, map, 'lagGroup');
      if (!Array.isArray(arr)) throw new Error('LAG group table not available on this device');
      const g = [...(arr as unknown[])];
      g[idx] = num(input, 'group')!;
      data[map.lagGroup] = g;
    }

    const writable: Record<string, unknown> = {};
    for (const key of ['lagMode', 'lagGroup'] as const) {
      if (hasField(map, key) && data[map[key]] !== undefined) writable[map[key]] = data[map[key]];
    }
    await ctx.client.post('lacp.b', buildPostData(writable as Record<string, number | string | (number | string)[]>));
    return { success: true, applied: true, details: { port, mode: str(input, 'mode') ?? null, group: num(input, 'group') ?? null } };
  },
};

const vlanPortAction: ActionDescriptor = {
  id: 'vlan.port.set',
  label: 'Set per-port VLAN configuration',
  description:
    'Sets the VLAN mode (Disabled/Optional[/Enabled]/Strict — platform-dependent), receive filter, default (untagged) VLAN and force-VLAN flag for one port on fwd.b.',
  module: 'VLANs',
  riskLevel: 'write',
  deviceCount: 1,
  timeoutMs: 30_000,
  inputSchema: {
    port: { type: 'number', required: true, min: 1, max: 64 },
    vlanMode: { type: 'string', enum: ['Disabled', 'Optional', 'Enabled', 'Strict'], description: 'VLAN mode for the port (SwOS Lite has no "Enabled")' },
    receive: { type: 'string', enum: ['Any', 'Only Tagged', 'Only Untagged'] },
    defaultVlanId: { type: 'number', min: 1, max: 4095, description: 'Default (untagged) VLAN ID' },
    forceVlanId: { type: 'boolean', description: 'Force the default VLAN ID on tagged frames' },
  },
  async execute(ctx, input) {
    const map = ctx.platform.map;
    const port = await resolvePort(ctx, num(input, 'port')!);
    const idx = port - 1;

    const data = (await ctx.client.get('fwd.b')) as Record<string, unknown>;

    if (str(input, 'vlanMode')) {
      const modeName = str(input, 'vlanMode')!;
      const code = map.vlanPortModes.indexOf(modeName);
      if (code < 0) throw new Error(`Invalid vlanMode "${modeName}" for ${map.platformName} — valid: ${map.vlanPortModes.join(', ')}`);
      let arr = getField(data, map, 'vlanPortMode');
      if (!Array.isArray(arr)) throw new Error('Per-port VLAN mode table not available on this device');
      const m = [...(arr as unknown[])];
      m[idx] = code;
      data[map.vlanPortMode] = m;
    }
    if (str(input, 'receive')) {
      const recvMap: Record<string, number> = { Any: 0, 'Only Tagged': 1, 'Only Untagged': 2 };
      let arr = getField(data, map, 'vlanPortReceive');
      if (!Array.isArray(arr)) throw new Error('Per-port VLAN receive table not available on this device');
      const r = [...(arr as unknown[])];
      r[idx] = recvMap[str(input, 'receive')!];
      data[map.vlanPortReceive] = r;
    }
    if (num(input, 'defaultVlanId') !== undefined) {
      let arr = getField(data, map, 'vlanPortDefaultId');
      if (!Array.isArray(arr)) throw new Error('Per-port default VLAN table not available on this device');
      const d = [...(arr as unknown[])];
      d[idx] = num(input, 'defaultVlanId')!;
      data[map.vlanPortDefaultId] = d;
    }
    if (typeof input.forceVlanId === 'boolean') {
      const mask = typeof getField(data, map, 'vlanPortForceId') === 'number' ? (getField(data, map, 'vlanPortForceId') as number) : 0;
      data[map.vlanPortForceId] = input.forceVlanId ? mask | (1 << idx) : mask & ~(1 << idx);
    }

    const writable: Record<string, unknown> = {};
    for (const key of ['vlanPortMode', 'vlanPortReceive', 'vlanPortDefaultId', 'vlanPortForceId'] as const) {
      if (hasField(map, key) && data[map[key]] !== undefined) writable[map[key]] = data[map[key]];
    }
    await ctx.client.post('fwd.b', buildPostData(writable as Record<string, number | string | (number | string)[]>));
    return { success: true, applied: true, details: { port, vlanMode: str(input, 'vlanMode') ?? null, defaultVlanId: num(input, 'defaultVlanId') ?? null } };
  },
};

const vlansTableAction: ActionDescriptor = {
  id: 'vlans.table.set',
  label: 'Replace the VLAN table',
  description:
    'Replaces the switch\'s complete VLAN table (vlan.b) with the given list. Each entry: vlan_id, member ports, IGMP snooping; name is a SwOS-only extra (ignored on SwOS Lite). Destructive — every VLAN not listed is removed.',
  module: 'VLANs',
  riskLevel: 'dangerous',
  deviceCount: 1,
  timeoutMs: 30_000,
  inputSchema: {
    vlans: {
      type: 'array',
      required: true,
      items: {
        type: 'object',
        properties: {
          id: { type: 'number', required: true, min: 1, max: 4094 },
          members: { type: 'array', required: true, items: { type: 'number', min: 1, max: 64 } },
          igmpSnooping: { type: 'boolean' },
          name: { type: 'string', description: 'VLAN name (SwOS only — ignored on SwOS Lite)' },
        },
      },
    },
  },
  async execute(ctx, input) {
    const map = ctx.platform.map;
    const portCount = await ctx.platform.portCount();
    const raw = Array.isArray(input.vlans) ? (input.vlans as Record<string, unknown>[]) : [];
    if (raw.length === 0) throw new Error('At least one VLAN is required');

    const vlanArray: Record<string, number | string>[] = [];
    for (const v of raw) {
      const id = num(v, 'id')!;
      if (!Number.isInteger(id) || id < 1 || id > 4094) throw new Error(`Invalid VLAN ID: ${v.id}`);
      const membersRaw = Array.isArray(v.members) ? (v.members as number[]) : [];
      const mask = encodePortMask(membersRaw, portCount > 0 ? portCount : undefined);

      const entry: Record<string, number | string> = {
        [map.vlanId]: id,
        [map.vlanMembers]: mask,
        [map.vlanIgmp]: v.igmpSnooping === true ? 1 : 0,
      };
      // SwOS-only fields — omitted on Lite (the map has no entry for them).
      if (hasField(map, 'vlanName') && str(v, 'name')) entry[map.vlanName!] = encodeHexString(str(v, 'name')!);

      vlanArray.push(entry);
    }

    await ctx.client.post('vlan.b', buildPostArray(vlanArray));
    return { success: true, applied: true, details: { vlans: raw.length, ids: raw.map((v) => num(v, 'id')) } };
  },
};

const snmpConfigAction: ActionDescriptor = {
  id: 'snmp.config.set',
  label: 'Set SNMP configuration',
  description: 'Enables/disables SNMP and sets the community string, contact and location on snmp.b (all four fields are sent).',
  module: 'SNMP',
  riskLevel: 'write',
  deviceCount: 1,
  timeoutMs: 30_000,
  inputSchema: {
    enabled: { type: 'boolean' },
    community: { type: 'string', pattern: '^[ -~]{0,63}$', description: 'SNMP community string (max 63 chars)' },
    contact: { type: 'string', pattern: '^[ -~]{0,63}$' },
    location: { type: 'string', pattern: '^[ -~]{0,63}$' },
  },
  async execute(ctx, input) {
    const map = ctx.platform.map;
    if (!(await ctx.platform.hasSnmp())) throw new Error('This device does not support SNMP');

    const data = (await ctx.client.get('snmp.b')) as Record<string, unknown>;
    if (typeof input.enabled === 'boolean') data[map.snmpEnabled] = input.enabled ? 1 : 0;
    if (str(input, 'community') !== undefined) data[map.snmpCommunity] = encodeHexString(str(input, 'community')!);
    if (str(input, 'contact') !== undefined) data[map.snmpContact] = encodeHexString(str(input, 'contact')!);
    if (str(input, 'location') !== undefined) data[map.snmpLocation] = encodeHexString(str(input, 'location')!);

    await postObject(ctx, 'snmp.b', data);
    return { success: true, applied: true, details: { enabled: input.enabled ?? null } };
  },
};

const systemIdentityAction: ActionDescriptor = {
  id: 'system.identity.set',
  label: 'Set device identity (name)',
  description: 'Renames the switch (identity field of sys.b). The full system page is re-sent, matching browser behavior.',
  module: 'System',
  riskLevel: 'write',
  deviceCount: 1,
  timeoutMs: 30_000,
  inputSchema: {
    identity: { type: 'string', required: true, pattern: '^[ -~]{1,63}$', description: 'New device name (max 63 chars)' },
  },
  async execute(ctx, input) {
    const map = ctx.platform.map;
    const data = (await ctx.client.get('sys.b')) as Record<string, unknown>;
    data[map.systemIdentity] = encodeHexString(str(input, 'identity')!);
    await postWritable(ctx, 'sys.b', data, SYS_WRITABLE_KEYS);
    return { success: true, applied: true, details: { identity: str(input, 'identity') } };
  },
};

const systemManagementAction: ActionDescriptor = {
  id: 'system.management.set',
  label: 'Set management access (IP / allow-from)',
  description:
    'DANGEROUS — changes the switch\'s own addressing and management ACL (address mode, static IP, allow-from IP/CIDR/ports/VLAN). A wrong value can lock you out of the device. The full system page is re-sent, matching browser behavior.',
  module: 'System',
  riskLevel: 'dangerous',
  deviceCount: 1,
  timeoutMs: 30_000,
  inputSchema: {
    addressAcquisition: { type: 'string', enum: ['DHCP with fallback', 'static', 'DHCP only'] },
    staticIp: { type: 'string', pattern: '^\\d{1,3}(\\.\\d{1,3}){3}$', description: 'Static/fallback IPv4 address' },
    allowFrom: { type: 'string', description: 'Management ACL as IP or CIDR (e.g. 192.168.1.0/24); empty string = no restriction' },
    allowFromPorts: { type: 'array', items: { type: 'number', min: 1, max: 64 }, description: 'Port numbers allowed for management access' },
    allowFromVlan: { type: 'number', min: 1, max: 4095 },
  },
  async execute(ctx, input) {
    const map = ctx.platform.map;
    const data = (await ctx.client.get('sys.b')) as Record<string, unknown>;

    const acqMap: Record<string, number> = { 'DHCP with fallback': 0x00, static: 0x01, 'DHCP only': 0x02 };
    if (str(input, 'addressAcquisition') !== undefined) {
      const mode = str(input, 'addressAcquisition')!;
      if (!(mode in acqMap)) throw new Error(`Invalid addressAcquisition: ${mode}`);
      data[map.systemAddressAcquisition] = acqMap[mode];
    }
    if (str(input, 'staticIp') !== undefined) {
      data[map.systemStaticIp] = encodeIpLe(str(input, 'staticIp')!); // little-endian wire encoding
    }
    if ('allowFrom' in input && typeof input.allowFrom === 'string') {
      const af = (input.allowFrom as string).trim();
      if (af === '') {
        data[map.systemAllowFromIp] = 0;
        data[map.systemAllowFromBits] = 0;
      } else {
        const [ipPart, bitsPart] = af.split('/');
        const bits = bitsPart !== undefined ? Number(bitsPart) : 32;
        if (!Number.isInteger(bits) || bits < 0 || bits > 32) throw new Error(`Invalid CIDR prefix in allowFrom: ${af}`);
        data[map.systemAllowFromIp] = encodeIpLe(ipPart.trim());
        data[map.systemAllowFromBits] = bits;
      }
    }
    if (Array.isArray(input.allowFromPorts)) {
      const portCount = await ctx.platform.portCount();
      data[map.systemAllowFromPorts] = encodePortMask(input.allowFromPorts as number[], portCount > 0 ? portCount : undefined);
    }
    if (num(input, 'allowFromVlan') !== undefined) {
      data[map.systemAllowFromVlan] = num(input, 'allowFromVlan')!;
    }

    await postWritable(ctx, 'sys.b', data, SYS_WRITABLE_KEYS);
    return {
      success: true,
      applied: true,
      details: {
        addressAcquisition: str(input, 'addressAcquisition') ?? null,
        staticIp: str(input, 'staticIp') ?? null,
        allowFrom: typeof input.allowFrom === 'string' ? (input.allowFrom as string) : null,
      },
    };
  },
};

// --- Registry ---------------------------------------------------------------------------

const ALL_ACTIONS: ActionDescriptor[] = [
  systemInfoAction,
  backupDownloadAction,
  portConfigAction,
  poeConfigAction,
  lagConfigAction,
  vlanPortAction,
  vlansTableAction,
  snmpConfigAction,
  systemIdentityAction,
  systemManagementAction,
];

const byId = new Map<string, ActionDescriptor>(ALL_ACTIONS.map((a) => [a.id, a]));

/** Returns the action for an id, or undefined. */
export function getAction(id: string): ActionDescriptor | undefined {
  return byId.get(id);
}

/** All actions (the full catalog). */
export function listActions(): ActionDescriptor[] {
  return ALL_ACTIONS;
}

/** Distinct module names, for catalog grouping in the webapp. */
export function listModules(): string[] {
  return [...new Set(ALL_ACTIONS.map((a) => a.module))];
}

// --- Catalog (for /discover) ---------------------------------------------------------------

export interface CatalogEntry {
  id: string;
  label: string;
  description?: string;
  module: string;
  riskLevel: RiskLevel;
  deviceCount: number | 'N';
  timeoutMs?: number;
  inputSchema: InputSchema;
}

/** The full action catalog (single-device actions only in v1 — no multi-device intents). */
export function listCatalog(): CatalogEntry[] {
  return ALL_ACTIONS.map((a) => ({
    id: a.id,
    label: a.label,
    description: a.description,
    module: a.module,
    riskLevel: a.riskLevel,
    deviceCount: 1 as const,
    timeoutMs: a.timeoutMs,
    inputSchema: a.inputSchema,
  }));
}

// --- Shared decode helper (avoids importing monitoring into the registry) -------------------

function decodeHex(v: unknown): string {
  if (typeof v !== 'string' || !v) return '';
  try {
    return Buffer.from(v, 'hex').toString('latin1');
  } catch {
    return String(v);
  }
}


