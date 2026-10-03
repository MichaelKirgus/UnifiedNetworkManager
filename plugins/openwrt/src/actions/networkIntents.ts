/**
 * Canonical fleet intents for OpenWRT — `network.create` / `network.delete`.
 *
 * A "network" on OpenWRT is a named interface section in the UCI `network`
 * package:
 *   - VLAN: `config interface '<name>'` with `device='<parent>.<vlanId>'` —
 *     the section NAME carries the network name, which makes create/delete
 *     idempotent by name (same convention as RouterOS's VLAN naming).
 *   - L3 address: `proto 'static'` + `ipaddr '<cidr>'` (+ `ipv6 '<cidrV6>'`)
 *     on the SAME section. A device that only needs to KNOW the VLAN (no IP)
 *     gets `proto 'none'`.
 * All writes are one uci batch + a single `uci commit network` + `/etc/init.d/
 * network reload` over SSH — verified by re-reading the package afterwards.
 */

import { INTENT_NETWORK_CREATE, INTENT_NETWORK_DELETE, INTENT_L2_TOPOLOGY_READ } from '@unm/plugin-sdk';
import type { L2Topology, PreflightResult, PreflightValue } from '@unm/plugin-sdk';
import { suggestL2AttachPoint } from '@unm/plugin-sdk';
import type { ActionContext, ActionDescriptor } from './types';
import { sshAvailable, noSshResult } from './types';
import { okResult, failResult, runCommands, readUciPackage } from './helpers';
import { uciSetCmd, uciDelCmd, uciCommitCmd, uciAddSectionCmds, uciSectionCount } from '../client/sshBackend';

// --- UCI interface-section model ----------------------------------------------------

/** One parsed `config interface` section of the network package. */
interface UciIfc {
  /** The concrete uci key (`lan`, `wan`, or `@interface[3]`). */
  key: string;
  /** The interface name (section name for named sections, `name` option otherwise). */
  name: string;
  /** Kernel device the section binds to (`br-lan`, `eth0.42`, …) — '' when unset. */
  device: string;
  proto: string;
  ipaddr?: string;
  ipv6?: string;
}

/** Splits a CIDR into [ip, prefix]; accepts ip+netmask form too. */
function parseV4(input: Record<string, unknown>): string | null {
  const cidr = typeof input.cidr === 'string' ? input.cidr.trim() : '';
  if (cidr) return /^\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}$/.test(cidr) ? cidr : null;
  const ip = typeof input.ip === 'string' ? input.ip.trim() : '';
  const netmask = typeof input.netmask === 'string' ? input.netmask.trim() : '';
  if (!ip || !netmask) return null;
  const octets = netmask.split('.').map((o) => parseInt(o, 10));
  if (octets.length !== 4 || octets.some((n) => Number.isNaN(n))) return null;
  let bits = 0;
  for (const o of octets) {
    const table: Record<number, number> = { 255: 8, 254: 7, 252: 6, 248: 5, 240: 4, 224: 3, 192: 2, 128: 1, 0: 0 };
    if (!(o in table)) return null; // non-contiguous netmask — reject
    bits += table[o];
  }
  return `${ip}/${bits}`;
}

function parseV6(input: Record<string, unknown>): string | null {
  const cidr = typeof input.cidrV6 === 'string' ? input.cidrV6.trim() : '';
  if (!cidr) return null;
  return /^[0-9a-fA-F:.]*:[0-9a-fA-F:.]*\/\d{1,3}$/.test(cidr) ? cidr : null;
}

/** Splits a VLAN device name (`eth0.42`) into [parent, tag]; null when not a VLAN sub-ifc. */
function splitVlanDevice(device: string): { parent: string; tag: number } | null {
  const m = /^(.+)\.(\d+)$/.exec(device);
  if (!m) return null;
  const tag = Number(m[2]);
  return tag >= 1 && tag <= 4094 ? { parent: m[1], tag } : null;
}

/** True when the section carries an L3 network (static/dhcp or a configured address). */
function isL3(ifc: UciIfc): boolean {
  return ifc.proto === 'static' || ifc.proto === 'dhcp' || !!ifc.ipaddr || !!ifc.ipv6;
}

/** Reads every interface section of the network package (SSH uci show). */
async function readUciInterfaces(ctx: ActionContext): Promise<UciIfc[]> {
  const ssh = ctx.backend.ssh;
  if (!ssh) return [];
  const tree = await readUciPackage(ssh, 'network');
  const out: UciIfc[] = [];
  for (const [key, opts] of Object.entries(tree['network'] ?? {})) {
    // Interface sections appear either named (`lan`) or as list entries
    // (`@interface[0]` with a `name` option). Switch/other sections have no
    // `device` and are skipped.
    const isList = /^@interface\[\d+\]$/.test(key);
    if (!isList && !('device' in opts)) continue;
    out.push({
      key,
      name: isList ? (opts['name'] ?? '') : key,
      device: opts['device'] ?? '',
      proto: opts['proto'] ?? '',
      ipaddr: opts['ipaddr'],
      ipv6: opts['ipv6'],
    });
  }
  return out;
}

/** Builds the L2 topology from UCI interface sections. */
function buildL2Topology(ifcs: UciIfc[]): L2Topology {
  const physicalPorts: Array<{ name: string; assignment: string | null }> = [];
  const bridges: Array<{ name: string; members: string[] }> = [];
  const l3Interfaces: Record<string, string[]> = {};
  const uplinks: string[] = [];
  const seenDevices = new Set<string>();

  for (const ifc of ifcs) {
    if (!ifc.name || !ifc.device || /^lo\d*$/.test(ifc.device)) continue; // loopbacks are never attach points
    if (ifc.name === 'wan') uplinks.push(ifc.device);
    const vlan = splitVlanDevice(ifc.device);
    if (ifc.device.startsWith('br-')) {
      if (!seenDevices.has(ifc.device)) { seenDevices.add(ifc.device); bridges.push({ name: ifc.device, members: [] }); }
    } else if (!vlan) {
      if (!seenDevices.has(ifc.device)) { seenDevices.add(ifc.device); physicalPorts.push({ name: ifc.device, assignment: ifc.name }); }
    }
    // L3 is keyed by the KERNEL DEVICE (the SDK's attach-point preference order
    // matches bridges/devices, not UCI section names).
    if (isL3(ifc)) {
      const key = ifc.device;
      l3Interfaces[key] = [...(l3Interfaces[key] ?? []), ifc.name];
    }
  }
  return { physicalPorts, bridges, bundles: [], l3Interfaces, uplinks };
}

/** Reads the L2 topology — UCI when SSH is available, else the live interface rows. */
async function readOpenWrtL2Topology(ctx: ActionContext): Promise<L2Topology> {
  if (ctx.backend.ssh) {
    const ifcs = await readUciInterfaces(ctx);
    if (ifcs.length > 0) return buildL2Topology(ifcs);
  }
  // Fallback (LuCI-only or empty uci): live rows — section names double as devices.
  const rows = await ctx.backend.networks().catch(() => []);
  const l3Interfaces: Record<string, string[]> = {};
  for (const r of rows) {
    if (!r.name || /^lo\d*$/.test(r.name)) continue;
    if (r.ip || r.version === 'v6') l3Interfaces[r.name] = [...(l3Interfaces[r.name] ?? []), r.name];
  }
  return { physicalPorts: [], bridges: [], bundles: [], l3Interfaces, uplinks: ['wan'] };
}

/**
 * Resolves the VLAN PARENT DEVICE for a new network. Accepts either a UCI
 * section name (`lan`) or a kernel device (`br-lan`); falls back to the bridge
 * carrying L3 networks (the LAN domain), else any bridge, else the first
 * physical port. Never returns an uplink.
 */
function pickVlanParent(ifcs: UciIfc[], preferred?: string): { parent: string; reason: string } | null {
  const devOf = (n: string): string | null => {
    if (!n) return null;
    const byName = ifcs.find((i) => i.name === n);
    if (byName?.device && !/^lo\d*$/.test(byName.device)) return byName.device;
    if (ifcs.some((i) => i.device === n && !/^lo\d*$/.test(n))) return n;
    return null;
  };
  const uplinkDevices = new Set(ifcs.filter((i) => i.name === 'wan').map((i) => i.device));

  if (preferred) {
    const d = devOf(preferred.trim());
    if (d && !uplinkDevices.has(d)) return { parent: d, reason: `requested interface ${preferred} resolves to device ${d}` };
  }

  // UCI view — prefer the L3-carrying bridge (the LAN domain).
  const l3Devices = new Set(ifcs.filter(isL3).map((i) => i.device));
  const bridges = [...new Set(ifcs.map((i) => i.device).filter((d) => d.startsWith('br-')))];
  for (const b of bridges) if (l3Devices.has(b)) return { parent: b, reason: `bridge ${b} carries existing L3 networks` };
  if (bridges.length > 0) return { parent: bridges[0], reason: `no L3-carrying bridge — using ${bridges[0]}` };
  const first = ifcs.find((i) => i.device && !i.device.startsWith('br-') && !splitVlanDevice(i.device) && !/^lo\d*$/.test(i.device));
  if (first?.device) return { parent: first.device, reason: `no bridges configured — using ${first.device}` };

  // Fallback view (live rows only): the SDK's preference order over section names.
  const topo = buildL2Topology(ifcs);
  const s = suggestL2AttachPoint(topo);
  if (s) return { parent: s.attach, reason: s.reason };
  return null;
}

// --- network.create -------------------------------------------------------------------

const NETWORK_CREATE_INPUTS = {
  name: { type: 'string' as const, required: true, minLength: 1, maxLength: 64, description: 'Network name (unique per device — becomes the UCI interface section name)' },
  vlanId: { type: 'number' as const, min: 1, max: 4094, description: 'VLAN ID — a VLAN sub-interface (device = parent.tag) is created/attached. Omit for an L3-only network on an existing interface.' },
  cidr: { type: 'string' as const, pattern: '^\\d{1,3}(\\.\\d{1,3}){3}/\\d{1,2}$', description: 'Optional static IPv4 address as CIDR (e.g. 10.42.0.1/24) — omit when the device only needs to know the VLAN' },
  cidrV6: { type: 'string' as const, pattern: '^[0-9a-fA-F:.]*:[0-9a-fA-F:.]*/\\d{1,3}$', description: 'Optional static IPv6 address as CIDR (dual-stack when set alongside cidr)' },
  ip: { type: 'string' as const, pattern: '^\\d{1,3}(\\.\\d{1,3}){3}$', description: 'L3 address (alternative to cidr)' },
  netmask: { type: 'string' as const, pattern: '^\\d{1,3}(\\.\\d{1,3}){3}$', description: 'Netmask for `ip`' },
  interface: { type: 'string' as const, maxLength: 64, description: 'VLAN parent (UCI section name or kernel device) — resolved per device in preflight' },
} as const;

/**
 * Creates one network on one OpenWRT box. Idempotent by UCI section name and
 * by address (an existing identical setup is left untouched). One uci batch +
 * commit + reload, verified by re-reading the package.
 */
export const networkCreateAction: ActionDescriptor = {
  id: INTENT_NETWORK_CREATE,
  label: 'Create network (VLAN + optional L3 address)',
  description:
    'Creates a named interface section in the UCI network package — a VLAN sub-interface (device = parent.tag) when vlanId is set, plus static IPv4/IPv6 addresses when given. Idempotent by name; an existing non-matching section is refused.',
  module: 'Network',
  riskLevel: 'write',
  deviceCount: 'N' as const,
  timeoutMs: 90_000,
  inputSchema: { ...NETWORK_CREATE_INPUTS },
  execute: async (ctx, input) => {
    if (!sshAvailable(ctx)) return noSshResult();
    const ssh = ctx.backend.ssh!;

    const name = String(input.name ?? '').trim();
    if (!name || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(name)) {
      return failResult('`name` must be 1..64 chars of [A-Za-z0-9_-] (UCI section name)');
    }
    const vlanId = typeof input.vlanId === 'number' ? Math.floor(input.vlanId as number) : null;
    const v4 = parseV4(input);
    if (typeof input.cidr === 'string' && input.cidr.trim() && !v4) return failResult(`Invalid IPv4 CIDR "${input.cidr}"`);
    const v6 = parseV6(input);
    if (typeof input.cidrV6 === 'string' && input.cidrV6.trim() && !v6) return failResult(`Invalid IPv6 CIDR "${input.cidrV6}"`);

    // 1. Live state.
    const ifcs = await readUciInterfaces(ctx);
    const existing = ifcs.find((i) => i.name === name);
    const details: Record<string, unknown> = {};

    // 2. Resolve the target device + desired proto/addresses.
    let device = '';
    let proto = 'none';
    if (vlanId !== null) {
      const existingVlan = existing ? splitVlanDevice(existing.device) : null;
      if (existing && existingVlan?.tag === vlanId) {
        device = existing.device; // reuse the existing VLAN sub-interface as-is
        details.vlan = `reused existing VLAN ${vlanId} (${device})`;
      } else if (existing) {
        return failResult(`Interface "${name}" already exists with device "${existing.device || '(none)'}" — refusing to overwrite it`);
      } else {
        const pick = pickVlanParent(ifcs, typeof input.interface === 'string' ? String(input.interface).trim() : undefined);
        if (!pick) return failResult('no parent for the VLAN — set `interface` explicitly (no bridge/physical port found on this device)');
        device = `${pick.parent}.${vlanId}`;
        details.vlan = `created VLAN ${vlanId} on ${pick.parent}`;
      }
    } else {
      // L3-only: the target must be an EXISTING interface (we never create a bare NIC).
      if (!existing) return failResult(`No VLAN requested and no interface named "${name}" exists — L3-only networks need an existing interface`);
      device = existing.device;
      if (!device) return failResult(`Interface "${name}" has no device bound — request a vlanId or fix the section's device option`);
    }

    // Desired L3 state (empty = this device only knows the VLAN).
    const wantV4 = v4 ?? null;
    const wantV6 = v6 ?? null;
    if (wantV4 || wantV6) proto = 'static';

    // 3. No-op detection — everything already in place?
    const curVlanOk = vlanId === null ? true : splitVlanDevice(existing?.device ?? '')?.tag === vlanId;
    const curProtoOk = existing ? (wantV4 || wantV6 ? existing.proto === 'static' : existing.proto !== 'static') : false;
    const curV4Ok = !wantV4 || existing?.ipaddr === wantV4;
    const curV6Ok = !wantV6 || existing?.ipv6 === wantV6;
    if (existing && curVlanOk && curProtoOk && curV4Ok && curV6Ok) {
      return okResult({ skipped: `interface "${name}" already matches the requested network`, ...details });
    }

    // 4. One uci batch + commit + reload.
    const cmds: string[] = [];
    if (existing) {
      for (const [opt, want] of [['device', device], ['proto', proto]] as Array<[string, string]>) {
        if ((existing[opt as 'device' | 'proto'] ?? '') !== want) cmds.push(uciSetCmd('network', existing.key, opt, want));
      }
      if (wantV4 && existing.ipaddr !== wantV4) cmds.push(uciSetCmd('network', existing.key, 'ipaddr', wantV4));
      if (!wantV4 && existing.ipaddr) cmds.push(`uci del network.${existing.key}.ipaddr || true`);
      if (wantV6 && existing.ipv6 !== wantV6) cmds.push(uciSetCmd('network', existing.key, 'ipv6', wantV6));
      if (!wantV6 && existing.ipv6) cmds.push(`uci del network.${existing.key}.ipv6 || true`);
    } else {
      // `uci add` assigns the count of existing @interface[i] LIST sections
      // (named sections like `lan` don't consume list indices).
      const tree = await readUciPackage(ssh, 'network');
      const idx = uciSectionCount(tree['network'], 'interface');
      const { sectionKey, cmds: addCmds } = uciAddSectionCmds('network', 'interface', idx);
      cmds.push(...addCmds);
      cmds.push(uciSetCmd('network', sectionKey, 'name', name));
      if (device) cmds.push(uciSetCmd('network', sectionKey, 'device', device));
      cmds.push(uciSetCmd('network', sectionKey, 'proto', proto));
      if (wantV4) cmds.push(uciSetCmd('network', sectionKey, 'ipaddr', wantV4));
      if (wantV6) cmds.push(uciSetCmd('network', sectionKey, 'ipv6', wantV6));
    }
    if (cmds.length === 0) return okResult({ skipped: `interface "${name}" already matches the requested network`, ...details });
    cmds.push(uciCommitCmd('network'));
    const r = await runCommands(ssh, [...cmds, '/etc/init.d/network reload >/dev/null 2>&1 || true']);
    if (!r.ok) return failResult(`network.create failed: ${r.stderr.slice(0, 300)}`);

    // 5. Verify by re-read (uci commit is immediate — a missing option means the write failed).
    const after = await readUciInterfaces(ctx);
    const final = after.find((i) => i.name === name);
    if (!final || final.device !== device || final.proto !== proto) {
      return failResult(`verification failed — interface "${name}" not present with device ${device} / proto ${proto} after write`);
    }
    if (wantV4 && final.ipaddr !== wantV4) return failResult(`verification failed — ${wantV4} not set on ${name}`);
    if (wantV6 && final.ipv6 !== wantV6) return failResult(`verification failed — ${wantV6} not set on ${name}`);

    // DHCP pool / SSID are NOT part of this intent for OpenWRT (separate
    // dnsmasq/wireless surfaces) — reported so the UI can show them as skipped.
    if (input.dhcpPool && typeof input.dhcpPool === 'object') details.dhcpSkipped = 'DHCP pool not created — configure dnsmasq separately';
    if (input.ssid && typeof input.ssid === 'object') details.ssidSkipped = 'SSID not created — use the wireless actions for WLAN rollout';

    return okResult({ interface: name, device, proto, addresses: [wantV4, wantV6].filter(Boolean), ...details });
  },
};

// --- network.delete -------------------------------------------------------------------

/**
 * Removes one network (name-addressed, idempotent). Deletes the whole UCI
 * interface section — its VLAN sub-interface and addresses go with it. The
 * built-in `lan`/`wan` sections are never touched (deleting them would break
 * the appliance's own connectivity and the management path).
 */
export const networkDeleteAction: ActionDescriptor = {
  id: INTENT_NETWORK_DELETE,
  label: 'Delete network',
  description: 'Removes the named UCI interface section from the network package (VLAN + addresses go with it). Idempotent — a missing name is a no-op. Built-in lan/wan are protected.',
  module: 'Network',
  riskLevel: 'write',
  deviceCount: 'N' as const,
  timeoutMs: 60_000,
  inputSchema: { name: { type: 'string' as const, required: true, minLength: 1, maxLength: 64, description: 'Network (interface section) name to remove' } },
  execute: async (ctx, input) => {
    if (!sshAvailable(ctx)) return noSshResult();
    const ssh = ctx.backend.ssh!;

    const name = String(input.name ?? '').trim();
    if (!name) return failResult('Network name is required');
    if (name === 'lan' || name === 'wan') {
      return failResult(`refusing to delete the built-in "${name}" interface — that would break the appliance's connectivity`);
    }

    const ifcs = await readUciInterfaces(ctx);
    const existing = ifcs.find((i) => i.name === name);
    if (!existing) return okResult({ skipped: `no interface named "${name}" on this device` });

    const r = await runCommands(ssh, [uciDelCmd('network', existing.key), uciCommitCmd('network'), '/etc/init.d/network reload >/dev/null 2>&1 || true']);
    if (!r.ok) return failResult(`network.delete failed: ${r.stderr.slice(0, 300)}`);

    const after = await readUciInterfaces(ctx);
    if (after.some((i) => i.name === name)) {
      return failResult(`verification failed — interface "${name}" still present after delete`);
    }
    return okResult({ removed: name, device: existing.device || undefined });
  },
};

// --- l2.topology.read -------------------------------------------------------------------

/** The box's L2 hierarchy (physical ports + bridges + L3-carrying devices). */
export const l2TopologyReadAction: ActionDescriptor = {
  id: INTENT_L2_TOPOLOGY_READ,
  label: 'Read L2 topology',
  description: 'Physical/bridge devices and which of them carry L3 networks from the UCI network package — the attach-point source for network.create preflight.',
  module: 'Network',
  riskLevel: 'read',
  deviceCount: 'N' as const,
  inputSchema: {},
  execute: async (ctx) => {
    const topo = await readOpenWrtL2Topology(ctx);
    return okResult({ topology: topo });
  },
};

export const networkIntentActions: ActionDescriptor[] = [networkCreateAction, networkDeleteAction, l2TopologyReadAction];

// --- Preflight --------------------------------------------------------------------------

/**
 * Preflight resolver for `network.create` on one OpenWRT box. Read-only: the
 * UCI interface list (or live rows without SSH) yields the VLAN parent
 * suggestion + reuse/idempotency hints.
 */
export async function preflightNetworkCreate(ctx: ActionContext, inputs: Record<string, unknown>): Promise<PreflightResult> {
  const values: PreflightValue[] = [];
  try {
    const ifcs = await readUciInterfaces(ctx);
    // UCI view when available, else the live interface rows (LuCI-only boxes).
    const topo = ifcs.length > 0 ? buildL2Topology(ifcs) : await readOpenWrtL2Topology(ctx);

    const name = typeof inputs.name === 'string' ? String(inputs.name).trim() : '';
    const vlanId = typeof inputs.vlanId === 'number' ? Math.floor(inputs.vlanId as number) : null;

    // Idempotency hint — a section with this name already exists.
    if (name) {
      const existing = ifcs.find((i) => i.name === name);
      values.push(
        existing
          ? { key: 'name', value: name, confidence: 'high', note: `interface "${name}" already exists (device ${existing.device || '(none)'}) — the step will be a no-op / address top-up only` }
          : { key: 'name', value: name, confidence: 'medium', note: `no interface named "${name}" yet — one will be created` },
      );
    }

    // VLAN parent suggestion (UCI view when available, else live rows).
    if (vlanId !== null) {
      const preferred = typeof inputs.interface === 'string' ? String(inputs.interface).trim() : undefined;
      let pick: { parent: string; reason: string } | null = null;
      if (ifcs.length > 0) {
        pick = pickVlanParent(ifcs, preferred);
      } else {
        const s = suggestL2AttachPoint(topo);
        if (s) pick = { parent: s.attach, reason: s.reason };
      }
      // An existing VLAN sub-interface with that tag is reused wherever it sits.
      const byTag = ifcs.find((i) => splitVlanDevice(i.device)?.tag === vlanId);
      if (byTag) {
        values.push({ key: 'interface', value: byTag.name, confidence: 'high', note: `VLAN ${vlanId} already exists as "${byTag.name}" (${byTag.device}) — it will be reused` });
      } else if (pick) {
        const conf = /carries existing L3/i.test(pick.reason) ? 'medium' : 'low';
        values.push({ key: 'interface', value: pick.parent, confidence: conf, note: `new VLAN ${vlanId} would be created as ${pick.parent}.${vlanId} — ${pick.reason}` });
      } else {
        values.push({ key: 'interface', value: null, confidence: 'low', note: 'no bridge/physical port found — set the VLAN parent explicitly' });
      }

      // Platform note — no per-port VLAN assignment on OpenWrt (DSA swconfig support planned).
      const last = [...values].reverse().find((v) => v.key === 'interface');
      if (last?.note) last.note += ' · Port-level VLAN assignment is not supported on this platform (DSA swconfig support planned)';
    }

    return { deviceId: ctx.deviceId ?? '', values, capabilities: { vlanPorts: false } };
  } catch (e) {
    return { deviceId: ctx.deviceId ?? '', values, degraded: true, error: e instanceof Error ? e.message : String(e) };
  }
}

/** Registry of preflight resolvers per canonical intent id. */
export const PREFLIGHT_RESOLVERS: Record<string, (ctx: ActionContext, inputs: Record<string, unknown>) => Promise<PreflightResult>> = {
  [INTENT_NETWORK_CREATE]: preflightNetworkCreate,
};
