/**
 * RouterOS L2 topology — the device's interface layering, read-only.
 *
 * RouterOS layers interfaces in three steps (REST tables, all values strings):
 *   1. PHYSICAL: `/interface` rows with type `ether` (+ `sfp-sfpplus`, …). A
 *      port's "assignment" is explicit via the `master-name` property — it
 *      points at a bridge or bonding interface; otherwise the port stands alone.
 *   2. BUNDLES: `/interface/bonding` rows (name, mode=lacp/round-robin/…,
 *      slaves = space-separated member list).
 *   3. LOGICAL: bridges (`type=bridge`, members from `/interface/bridge/port`)
 *      and VLANs (`type=vlan`, `vlan-id` + parent interface in the row's
 *      `interface` property — verified against /interface/vlan rows). The L3
 *      address of a network binds to ANY of these via `/ip/address`.
 */

import { INTENT_L2_TOPOLOGY_READ } from '@unm/plugin-sdk';
import type { L2Bridge, L2Bundle, L2PhysicalPort, L2Topology } from '@unm/plugin-sdk';
import { rosString } from '../routerosClient';
import type { ActionContext, ActionDescriptor } from './types';

type Row = Record<string, unknown>;

/** One `/interface` row (the union of all interface types). */
function ifcName(row: Row): string | null {
  return rosString(row, ['name']) ?? null;
}

/** Builds the L2 topology from one set of read-only REST responses. */
export function buildRouterOsL2Topology(
  ifaceRows: Row[],
  bridgePortRows: Row[],
  vlanRows: Row[],
  bondingRows: Row[],
  ipAddrRows: Row[],
  ipv6AddrRows: Row[],
  switchVlanRows: Row[] = [],
): L2Topology {
  // --- Bundles (bonding) ------------------------------------------------------
  const bundles: L2Bundle[] = [];
  for (const b of bondingRows) {
    const name = rosString(b, ['name']);
    if (!name) continue;
    const slaves = String(b['slaves'] ?? '').split(/\s+/).filter(Boolean);
    bundles.push({
      name,
      protocol: rosString(b, ['mode']) ?? null, // lacp / round-robin / active-backup / …
      members: slaves,
      operating: b['running'] === 'true' ? true : b['disabled'] === 'true' ? false : null,
    });
  }

  // --- Bridges -----------------------------------------------------------------
  const bridgeNames = new Set(ifaceRows.filter((r) => rosString(r, ['type']) === 'bridge').map((r) => ifcName(r)).filter((n): n is string => !!n));
  const bridges: L2Bridge[] = [];
  for (const name of [...bridgeNames].sort()) {
    // Members: bridge/port rows first (authoritative), fall back to master-name.
    const members = new Set<string>();
    for (const bp of bridgePortRows) {
      if (rosString(bp, ['interface']) === name && rosString(bp, ['slave'])) members.add(rosString(bp, ['slave']) as string);
    }
    for (const r of ifaceRows) {
      const n = ifcName(r);
      if (n && rosString(r, ['master-name']) === name) members.add(n);
    }
    bridges.push({ name, members: [...members].sort() });
  }

  // --- Physical ports -----------------------------------------------------------
  const PHYSICAL_TYPES = new Set(['ether', 'sfp-sfpplus', 'sfp+', '25g-ether']);
  const vlanByParent = new Map<string, string>(); // parent ifc → first vlan child name
  for (const v of vlanRows) {
    const parent = rosString(v, ['interface']);
    const child = rosString(v, ['name']) ?? (parent && rosString(v, ['vlan-id']) ? `${parent}.${rosString(v, ['vlan-id'])}` : null);
    if (parent && child && !vlanByParent.has(parent)) vlanByParent.set(parent, child);
  }

  // Per-port VLAN facts from the switch chip's /interface/switch.vlan table —
  // a port carrying >1 VLAN id or any tagged row is a trunk/uplink.
  const portVlans = new Map<string, Set<number>>();
  const taggedPorts = new Set<string>();
  for (const sv of switchVlanRows) {
    const p = rosString(sv, ['port']);
    const vid = Number(rosString(sv, ['vlan-id']));
    if (!p || !vid) continue;
    let s = portVlans.get(p);
    if (!s) { s = new Set(); portVlans.set(p, s); }
    s.add(vid);
    if (sv['tagged'] === true || sv['tagged'] === 'true') taggedPorts.add(p);
  }

  const physicalPorts: L2PhysicalPort[] = [];
  for (const r of ifaceRows) {
    const type = rosString(r, ['type']);
    if (!type || !PHYSICAL_TYPES.has(type)) continue;
    const name = ifcName(r);
    if (!name) continue;
    // Explicit master-name wins (bridge/bonding membership); otherwise a VLAN
    // parented on this port is its implicit assignment.
    const master = rosString(r, ['master-name']);
    const vset = portVlans.get(name);
    if (vset && vset.size > 0) {
      physicalPorts.push({
        name,
        assignment: master ?? vlanByParent.get(name) ?? null,
        trunk: vset.size > 1 || taggedPorts.has(name),
        vlans: [...vset].sort((a, b) => a - b),
      });
    } else {
      physicalPorts.push({ name, assignment: master ?? vlanByParent.get(name) ?? null });
    }
  }

  // --- L3 interfaces --------------------------------------------------------------
  // Every address row maps its interface to the network's CIDR label (RouterOS
  // has no per-interface "description" — the address itself is the identity).
  // Loopback is excluded: it carries addresses but is never a valid attach
  // point for a new network.
  const l3Interfaces: Record<string, string[]> = {};
  for (const a of [...ipAddrRows, ...ipv6AddrRows]) {
    const ifc = rosString(a, ['interface', 'actual-interface']);
    const addr = rosString(a, ['address']);
    if (!ifc || !addr) continue;
    if (/^lo$/.test(ifc)) continue;
    let names = l3Interfaces[ifc];
    if (!names) { names = []; l3Interfaces[ifc] = names; }
    if (!names.includes(addr)) names.push(addr);
  }

  return { physicalPorts, bridges, bundles, l3Interfaces };
}

/** Reads the full L2 topology of one router (read-only REST batch). */
export async function readRouterOsL2Topology(ctx: ActionContext): Promise<L2Topology> {
  const [ifaceRes, bridgePortRes, vlanRes, bondingRes, ipAddrRes, ipv6AddrRes, switchVlanRes] = await Promise.allSettled([
    ctx.client.get<Row[]>('/interface'),
    ctx.client.get<Row[]>('/interface/bridge/port'),
    ctx.client.get<Row[]>('/interface/vlan'),
    ctx.client.get<Row[]>('/interface/bonding'),
    ctx.client.get<Row[]>('/ip/address'),
    ctx.client.get<Row[]>('/ipv6/address'),
    ctx.client.get<Row[]>('/interface/switch.vlan'),
  ]);
  const rows = (r: PromiseSettledResult<unknown>): Row[] => (r.status === 'fulfilled' && Array.isArray(r.value) ? (r.value as Row[]) : []);
  // /interface is the only hard requirement — the rest degrade to empty tables.
  if (ifaceRes.status !== 'fulfilled') {
    throw new Error(`L2 topology read failed: ${ifaceRes.reason instanceof Error ? ifaceRes.reason.message : String(ifaceRes.reason)}`);
  }
  return buildRouterOsL2Topology(
    rows(ifaceRes),
    rows(bridgePortRes),
    rows(vlanRes),
    rows(bondingRes),
    rows(ipAddrRes),
    rows(ipv6AddrRes),
    rows(switchVlanRes),
  );
}

/**
 * Reads `/interface/switch.vlan` — the per-port VLAN table on switch-capable SoCs
 * (hEX, cCR, CRS…). Returns null when the device has NO integrated switch chip
 * (the endpoint is absent → REST rejects), else the row array of shape
 * `{port, vlan-id, tagged}`. Callers use null to mean "L2 port selection N/A".
 */
export async function readSwitchVlanTable(ctx: ActionContext): Promise<Row[] | null> {
  try {
    const rows = await ctx.client.get<Row[]>('/interface/switch.vlan');
    return Array.isArray(rows) ? rows : [];
  } catch {
    return null; // no switch chip on this device
  }
}

/** The canonical `l2.topology.read` action. */
export const l2TopologyAction: ActionDescriptor = {
  id: INTENT_L2_TOPOLOGY_READ,
  label: 'Read L2 topology (ports → bundles/bridges)',
  module: 'Network',
  riskLevel: 'read',
  deviceCount: 1,
  timeoutMs: 30_000,
  inputSchema: {},
  execute: async (ctx) => {
    const topology = await readRouterOsL2Topology(ctx);
    return { success: true, details: { ...topology } };
  },
};
