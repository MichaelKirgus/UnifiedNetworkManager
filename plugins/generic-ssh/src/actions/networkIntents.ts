/**
 * Canonical fleet intents for the Generic SSH plugin — `network.create` /
 * `network.delete`.
 *
 * A "network" on a generic Linux box is an iproute2 802.1q VLAN sub-interface:
 *   - VLAN: `ip link add link <parent> name <ifc> type vlan id <tag>` — the
 *     kernel ifname is derived deterministically from the network name (kernel
 *     names are capped at 15 chars) and the FULL name is stored as the
 *     interface ALIAS (`ip link set dev <ifc> alias <name>`), which makes
 *     create/delete idempotent by name.
 *   - L3 address: `ip addr replace <cidr> dev <ifc>` (+ v6) when given — a box
 *     that only needs to KNOW the VLAN (no IP) gets just the sub-interface.
 * Persistence is best-effort via an ifupdown hook in /etc/network/if-up.d/
 * (same convention as the route actions): netplan-only boxes get the live
 * interface plus an explicit note, because editing vendor YAML from shell is
 * too fragile to automate safely.
 */

import { INTENT_NETWORK_CREATE, INTENT_NETWORK_DELETE, INTENT_L2_TOPOLOGY_READ } from '@unm/plugin-sdk';
import type { L2Topology, PreflightResult, PreflightValue } from '@unm/plugin-sdk';
import { suggestL2AttachPoint } from '@unm/plugin-sdk';
import type { ActionContext, ActionDescriptor } from './types';
import { okResult, failResult, runCommands, shq, isV4Cidr, isSafeName } from './types';

const HOOK_DIR = '/etc/network/if-up.d';

// --- Input parsing --------------------------------------------------------------------

/** Splits a CIDR into [ip, prefix]; accepts ip+netmask form too. */
function parseV4(input: Record<string, unknown>): string | null {
  const cidr = typeof input.cidr === 'string' ? input.cidr.trim() : '';
  if (cidr) return isV4Cidr(cidr) && cidr.includes('/') ? cidr : null;
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

/**
 * Derives the kernel interface name for a network (≤15 chars — IFNAMSIZ).
 * Deterministic in BOTH arguments so create and delete always agree:
 *   "NET_XY" + 42 → "netyx.42"; no vlanId → "unm-netyx".
 */
export function ifcNameFor(name: string, vlanId: number | null): string {
  const base = name.toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 10) || 'net';
  return vlanId !== null ? `${base}.${vlanId}` : `unm-${base.slice(0, 11)}`;
}

// --- Live state -----------------------------------------------------------------------

/** One link row from the batched read. */
interface LinkRow {
  name: string;
  /** iproute2 kind (`vlan`, `bridge`, `bond`, …) — '' for plain devices. */
  kind: string;
  /** The VLAN id when kind === 'vlan' (from `ip -d link show`). */
  vlanId?: number;
  /** The interface alias (we store the network name here). */
  alias?: string;
}

/** One batched read of links + addresses + bridge membership. */
async function readLiveNetwork(ctx: ActionContext): Promise<{
  links: LinkRow[];
  l3ByIfc: Record<string, string[]>;
}> {
  const script = [
    'ip -o link show 2>/dev/null',
    'echo ---DETAIL---',
    // One detail line per interface (`-o`), followed by its marker.
    'for i in /sys/class/net/*; do n=$(basename $i); ip -d -o link show dev $n 2>/dev/null && echo "ifc:$n"; done',
    'echo ---ADDRS4---',
    'ip -4 -o addr show 2>/dev/null',
    'echo ---ADDRS6---',
    'ip -6 -o addr show 2>/dev/null',
    'echo ---BRIF---',
    'for b in /sys/class/net/*; do n=$(basename $b); [ -d "$b/brif" ] && echo "bridge:$n:$(ls $b/brif 2>/dev/null | tr "\\n" " ")"; done',
  ].join('\n');
  const r = await ctx.backend.exec(script, 15_000).catch(() => null);
  if (!r) return { links: [], l3ByIfc: {} };

  const sections = new Map<string, string>();
  let current = 'links';
  for (const line of r.stdout.split('\n')) {
    if (line.startsWith('---') && line.endsWith('---')) { current = line.slice(3, -3); continue; }
    sections.set(current, `${sections.get(current) ?? ''}\n${line}`);
  }

  const links: LinkRow[] = [];
  for (const line of (sections.get('links') ?? '').split('\n')) {
    // "2: eth0: <BROADCAST,MULTICAST,UP> mtu 1500 ... link/ether ..."
    const m = line.match(/^\d+:\s+(\S+?)(?:@(\S+))?:\s*</);
    if (!m) continue;
    links.push({ name: m[1], kind: '' });
  }

  // Detail lines: "ifc:<name>" follows the matching `ip -d` line(s).
  const detailLines = (sections.get('DETAIL') ?? '').split('\n');
  for (let i = 0; i < detailLines.length; i++) {
    const ifm = detailLines[i].match(/^ifc:(\S+)$/);
    if (!ifm) continue;
    const link = links.find((l) => l.name === ifm[1]);
    if (!link) continue;
    for (let j = i - 1; j >= 0 && !detailLines[j].startsWith('ifc:'); j--) {
      const d = detailLines[j];
      // iproute2 detail: "… vlan protocol 802.1Q id 42 …" / alias "name".
      const vm = d.match(/\bid (\d+)/);
      if (vm && /vlan/.test(d)) { link.kind = 'vlan'; link.vlanId = Number(vm[1]); }
      const am = d.match(/\balias "([^"]*)"/);
      if (am) link.alias = am[1];
    }
  }

  // Bridge membership from sysfs.
  for (const line of (sections.get('BRIF') ?? '').split('\n')) {
    const m = line.match(/^bridge:(\S+):(.*)$/);
    if (!m) continue;
    const link = links.find((l) => l.name === m[1]);
    if (link && !link.kind) link.kind = 'bridge';
  }

  // L3 addresses per interface.
  const l3ByIfc: Record<string, string[]> = {};
  for (const [key, ver] of [['ADDRS4', 'v4'], ['ADDRS6', 'v6']] as Array<[string, string]>) {
    for (const line of (sections.get(key) ?? '').split('\n')) {
      // "2: eth0    inet 10.0.0.5/24 brd ... scope global eth0"
      const m = line.match(/^\d+:\s+(\S+)\s+(?:inet|inet6)\s+(\S+)/);
      if (!m) continue;
      l3ByIfc[m[1]] = [...(l3ByIfc[m[1]] ?? []), `${m[2]} (${ver})`];
    }
  }

  return { links, l3ByIfc };
}

/** Builds the L2 topology from live iproute2 state. */
function buildL2Topology(links: LinkRow[], l3ByIfc: Record<string, string[]>): L2Topology {
  const physicalPorts: Array<{ name: string; assignment: string | null }> = [];
  const bridges: Array<{ name: string; members: string[] }> = [];
  const bundles: Array<{ name: string; protocol?: string | null; members: string[] }> = [];
  for (const l of links) {
    if (/^lo\d*$/.test(l.name)) continue; // loopbacks are never attach points
    if (l.kind === 'bridge') bridges.push({ name: l.name, members: [] });
    else if (l.kind === 'bond' || l.kind === 'team') bundles.push({ name: l.name, protocol: l.kind, members: [] });
    else physicalPorts.push({ name: l.name, assignment: l.name });
  }
  return { physicalPorts, bridges, bundles, l3Interfaces: l3ByIfc };
}

/** Finds the link for a network — by alias (the stored name) or derived ifname. */
function findNetworkLink(links: LinkRow[], name: string, vlanId: number | null): LinkRow | undefined {
  const needle = name.toUpperCase();
  return links.find((l) => (l.alias ?? '').toUpperCase() === needle) ?? links.find((l) => l.name === ifcNameFor(name, vlanId));
}

// --- network.create -------------------------------------------------------------------

const NETWORK_CREATE_INPUTS = {
  name: { type: 'string' as const, required: true, minLength: 1, maxLength: 64, description: 'Network name (unique per device — stored as the interface alias)' },
  vlanId: { type: 'number' as const, min: 1, max: 4094, description: 'VLAN ID — an 802.1q sub-interface is created on the parent. Omit for an L3-only network on an existing interface.' },
  cidr: { type: 'string' as const, pattern: '^\\d{1,3}(\\.\\d{1,3}){3}/\\d{1,2}$', description: 'Optional static IPv4 address as CIDR (e.g. 10.42.0.1/24) — omit when the box only needs to know the VLAN' },
  cidrV6: { type: 'string' as const, pattern: '^[0-9a-fA-F:.]*:[0-9a-fA-F:.]*/\\d{1,3}$', description: 'Optional static IPv6 address as CIDR (dual-stack when set alongside cidr)' },
  ip: { type: 'string' as const, pattern: '^\\d{1,3}(\\.\\d{1,3}){3}$', description: 'L3 address (alternative to cidr)' },
  netmask: { type: 'string' as const, pattern: '^\\d{1,3}(\\.\\d{1,3}){3}$', description: 'Netmask for `ip`' },
  interface: { type: 'string' as const, maxLength: 64, description: 'Parent device for the VLAN (kernel ifname) — resolved per device in preflight' },
} as const;

/** The idempotent persistence hook body for one network. */
function vlanHookScript(ifc: string, parent: string | null, vlanId: number | null, v4?: string, v6?: string): string {
  const lines = [
    '#!/bin/sh',
    '# UNM-managed VLAN (managed by the Generic SSH plugin)',
    `[ "$IFACE" = "lo" ] && exit 0`,
  ];
  if (vlanId !== null && parent) {
    lines.push(`ip link show dev ${ifc} >/dev/null 2>&1 || ip link add link ${parent} name ${ifc} type vlan id ${vlanId}`);
    lines.push(`ip link set dev ${ifc} up`);
  }
  if (v4) lines.push(`ip addr replace ${v4} dev ${ifc}`);
  if (v6) lines.push(`ip -6 addr replace ${v6} dev ${ifc}`);
  lines.push('exit 0');
  return lines.join('\n');
}

/**
 * Creates one network on one box. Idempotent by alias/ifname and by address —
 * an existing identical setup is left untouched, a conflicting one refused.
 */
export const networkCreateAction: ActionDescriptor = {
  id: INTENT_NETWORK_CREATE,
  label: 'Create network (VLAN + optional L3 address)',
  description:
    'Creates an 802.1q VLAN sub-interface (ip link add … type vlan) named after the network and optionally binds static IPv4/IPv6 addresses to it. Idempotent by name; persistence is best-effort via an ifupdown hook.',
  module: 'Network',
  riskLevel: 'write',
  deviceCount: 'N' as const,
  timeoutMs: 60_000,
  inputSchema: { ...NETWORK_CREATE_INPUTS },
  execute: async (ctx, input) => {
    const name = String(input.name ?? '').trim();
    if (!name || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(name)) {
      return failResult('`name` must be 1..64 chars of [A-Za-z0-9_-]');
    }
    const vlanId = typeof input.vlanId === 'number' ? Math.floor(input.vlanId as number) : null;
    const v4 = parseV4(input);
    if (typeof input.cidr === 'string' && input.cidr.trim() && !v4) return failResult(`Invalid IPv4 CIDR "${input.cidr}"`);
    const v6 = parseV6(input);
    if (typeof input.cidrV6 === 'string' && input.cidrV6.trim() && !v6) return failResult(`Invalid IPv6 CIDR "${input.cidrV6}"`);

    // 1. Live state.
    const { links, l3ByIfc } = await readLiveNetwork(ctx);
    if (links.length === 0) return failResult('could not read the interface list — is iproute2 available on this box?');
    const existing = findNetworkLink(links, name, vlanId);
    const details: Record<string, unknown> = {};

    // 2. Resolve target + parent.
    let ifc = '';
    let parent: string | null = null;
    if (vlanId !== null) {
      if (existing && existing.kind === 'vlan' && existing.vlanId === vlanId) {
        ifc = existing.name; // reuse the existing sub-interface as-is
        details.vlan = `reused existing VLAN ${vlanId} (${ifc})`;
      } else if (existing) {
        return failResult(`Interface "${existing.name}" already exists but is not a VLAN with tag ${vlanId} — refusing to overwrite it`);
      } else {
        const topo = buildL2Topology(links, l3ByIfc);
        let attach: string | null = null;
        if (typeof input.interface === 'string' && String(input.interface).trim()) {
          const p = String(input.interface).trim();
          if (!isSafeName(p)) return failResult(`Invalid parent interface name "${p}"`);
          if (!links.some((l) => l.name === p)) return failResult(`Parent device "${p}" does not exist on this box`);
          attach = p;
        } else {
          const s = suggestL2AttachPoint(topo);
          attach = s?.attach ?? null;
        }
        if (!attach) return failResult('no parent for the VLAN — set `interface` explicitly (no suitable device found on this box)');
        parent = attach;
        ifc = ifcNameFor(name, vlanId);
        details.vlan = `created VLAN ${vlanId} on ${parent}`;
      }
    } else {
      // L3-only: the target must be an EXISTING interface (we never create a bare NIC).
      const p = typeof input.interface === 'string' ? String(input.interface).trim() : '';
      if (!p) return failResult('L3-only networks need `interface` set to the existing device');
      if (!isSafeName(p)) return failResult(`Invalid interface name "${p}"`);
      const link = links.find((l) => l.name === p);
      if (!link) return failResult(`Interface "${p}" does not exist on this box`);
      ifc = p;
    }

    // 3. No-op detection — everything already in place?
    const curVlanOk = vlanId === null ? true : existing?.kind === 'vlan' && existing.vlanId === vlanId;
    const hasAddr = (ver: string) => (l3ByIfc[ifc] ?? []).some((a) => a.endsWith(`(${ver})`));
    if (existing && curVlanOk && (!v4 || hasAddr('v4')) && (!v6 || hasAddr('v6'))) {
      return okResult({ skipped: `network "${name}" already matches the requested setup on ${ifc}`, ...details }, true);
    }

    // 4. Apply (immediate — iproute2 writes are live).
    const cmds: string[] = [];
    if (vlanId !== null && !existing) {
      cmds.push(`ip link add link ${parent} name ${ifc} type vlan id ${vlanId}`);
    }
    cmds.push(`ip link set dev ${ifc} alias ${name}`); // raw value — validated [A-Za-z0-9_-] above
    if (v4) cmds.push(`ip addr replace ${v4} dev ${ifc}`);
    if (v6) cmds.push(`ip -6 addr replace ${v6} dev ${ifc}`);
    cmds.push(`ip link set dev ${ifc} up`);
    const r = await runCommands(ctx.backend, cmds, 30_000);
    if (!r.ok) return failResult(`network.create failed: ${(r.stderr || r.stdout).slice(0, 300)}`);

    // 5. Persist best-effort via an ifupdown hook (idempotent re-add on boot).
    let persisted = false;
    const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').slice(0, 24);
    const hook = `${HOOK_DIR}/unm-vlan-${slug}`;
    const persist = await runCommands(ctx.backend, [
      `[ -d ${HOOK_DIR} ] || exit 0`, // netplan-only box — no ifupdown hooks here
      `printf '%s' ${shq(vlanHookScript(ifc, parent, vlanId, v4 ?? undefined, v6 ?? undefined))} > ${hook}`,
      'chmod +x ' + hook,
    ], 30_000);
    persisted = persist.ok;

    // 6. Verify by re-read.
    const after = await readLiveNetwork(ctx);
    const finalLink = after.links.find((l) => l.name === ifc);
    if (!finalLink || (vlanId !== null && !(finalLink.kind === 'vlan' && finalLink.vlanId === vlanId))) {
      return failResult(`verification failed — ${ifc} not present as VLAN ${vlanId ?? ''} after write`);
    }
    const hasAddrAfter = (ver: string) => (after.l3ByIfc[ifc] ?? []).some((a) => a.endsWith(`(${ver})`));
    if (v4 && !hasAddrAfter('v4')) return failResult(`verification failed — ${v4} not present on ${ifc}`);
    if (v6 && !hasAddrAfter('v6')) return failResult(`verification failed — ${v6} not present on ${ifc}`);

    // DHCP pool / SSID are NOT part of this intent for generic boxes.
    if (input.dhcpPool && typeof input.dhcpPool === 'object') details.dhcpSkipped = 'DHCP pool not created — configure the box\'s DHCP server separately';
    if (input.ssid && typeof input.ssid === 'object') details.ssidSkipped = 'SSID not created — this plugin has no WLAN surface';

    return okResult({
      interface: ifc, parent, vlanId, addresses: [v4, v6].filter(Boolean),
      persisted,
      persistenceNote: persisted
        ? 'ifupdown hook installed — VLAN re-applies on boot.'
        : 'No ifupdown hooks on this system (netplan-only?) — the interface is live now but add it to your netplan YAML for reboot survival.',
      ...details,
    }, true);
  },
};

// --- network.delete -------------------------------------------------------------------

/**
 * Removes one network (name-addressed, idempotent). Finds the sub-interface by
 * its alias (the stored name) or derived ifname, strips its addresses and
 * deletes it. Plain (non-VLAN) devices are never deleted — only their UNM-added
 * addresses would be, which we also skip to stay non-destructive.
 */
export const networkDeleteAction: ActionDescriptor = {
  id: INTENT_NETWORK_DELETE,
  label: 'Delete network',
  description: 'Removes the named VLAN sub-interface (found by alias or derived ifname) and its addresses. Idempotent — a missing name is a no-op.',
  module: 'Network',
  riskLevel: 'write',
  deviceCount: 'N' as const,
  timeoutMs: 60_000,
  inputSchema: { name: { type: 'string' as const, required: true, minLength: 1, maxLength: 64, description: 'Network (interface alias) name to remove' } },
  execute: async (ctx, input) => {
    const name = String(input.name ?? '').trim();
    if (!name) return failResult('Network name is required');

    const { links } = await readLiveNetwork(ctx);
    // The alias (set at create time) is the primary key — it covers any tag.
    const target = findNetworkLink(links, name, null);
    if (!target || target.kind !== 'vlan') {
      return okResult({ skipped: `no VLAN network named "${name}" on this box` }, true);
    }

    // Strip addresses first, then the link itself.
    const r = await runCommands(ctx.backend, [
      `ip -4 addr flush dev ${target.name} 2>/dev/null || true`,
      `ip -6 addr flush dev ${target.name} 2>/dev/null || true`,
      `ip link del dev ${target.name}`,
    ], 30_000);
    if (!r.ok) return failResult(`network.delete failed: ${(r.stderr || r.stdout).slice(0, 300)}`);

    // Remove the persistence hook (best-effort).
    const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').slice(0, 24);
    await runCommands(ctx.backend, [`rm -f ${HOOK_DIR}/unm-vlan-${slug}`], 10_000).catch(() => undefined);

    const after = await readLiveNetwork(ctx);
    if (after.links.some((l) => l.name === target.name)) {
      return failResult(`verification failed — ${target.name} still present after delete`);
    }
    return okResult({ removed: target.name, vlanId: target.vlanId ?? null }, true);
  },
};

// --- l2.topology.read -------------------------------------------------------------------

/** The box's L2 hierarchy (physical devices + bridges/bonds + L3-carrying ifcs). */
export const l2TopologyReadAction: ActionDescriptor = {
  id: INTENT_L2_TOPOLOGY_READ,
  label: 'Read L2 topology',
  description: 'Live iproute2 interface list with kinds (vlan/bridge/bond) and which devices carry L3 addresses — the attach-point source for network.create preflight.',
  module: 'Network',
  riskLevel: 'read',
  deviceCount: 'N' as const,
  inputSchema: {},
  execute: async (ctx) => {
    const { links, l3ByIfc } = await readLiveNetwork(ctx);
    return okResult({ topology: buildL2Topology(links, l3ByIfc) });
  },
};

export const networkIntentActions: ActionDescriptor[] = [networkCreateAction, networkDeleteAction, l2TopologyReadAction];

// --- Preflight --------------------------------------------------------------------------

/**
 * Preflight resolver for `network.create` on one box. Read-only: the batched
 * iproute2 read yields the parent suggestion + reuse/idempotency hints.
 */
export async function preflightNetworkCreate(ctx: ActionContext, inputs: Record<string, unknown>): Promise<PreflightResult> {
  const values: PreflightValue[] = [];
  try {
    const { links, l3ByIfc } = await readLiveNetwork(ctx);
    if (links.length === 0) return { deviceId: ctx.deviceId ?? '', values, degraded: true, error: 'could not read the interface list' };

    const name = typeof inputs.name === 'string' ? String(inputs.name).trim() : '';
    const vlanId = typeof inputs.vlanId === 'number' ? Math.floor(inputs.vlanId as number) : null;

    // Idempotency hint — a link with this alias already exists.
    if (name) {
      const existing = findNetworkLink(links, name, vlanId);
      values.push(
        existing
          ? { key: 'name', value: name, confidence: 'high', note: `network "${name}" already exists as ${existing.name} — the step will be a no-op / address top-up only` }
          : { key: 'name', value: name, confidence: 'medium', note: `no network named "${name}" yet — one will be created` },
      );
    }

    // Parent suggestion (the SDK's preference order over the live topology).
    if (vlanId !== null) {
      const byTag = links.find((l) => l.kind === 'vlan' && l.vlanId === vlanId);
      if (byTag) {
        values.push({ key: 'interface', value: byTag.name, confidence: 'high', note: `VLAN ${vlanId} already exists as "${byTag.name}" — it will be reused` });
      } else {
        const topo = buildL2Topology(links, l3ByIfc);
        const s = suggestL2AttachPoint(topo);
        if (s) values.push({ key: 'interface', value: s.attach, confidence: /carries existing L3/i.test(s.reason) ? 'medium' : 'low', note: `new VLAN ${vlanId} would be created on ${s.attach} — ${s.reason}` });
        else values.push({ key: 'interface', value: null, confidence: 'low', note: 'no suitable parent found — set the device explicitly' });
      }

      // Platform note — a host VLAN is a sub-interface of its parent NIC; no per-port selection.
      const last = [...values].reverse().find((v) => v.key === 'interface');
      if (last?.note) last.note += ' · The VLAN is created as a sub-interface of the selected parent NIC — per-port selection is not available on this host';
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
