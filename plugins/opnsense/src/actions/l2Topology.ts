/**
 * OPNsense L2 topology — the device's interface layering, read-only.
 *
 * OPNsense layers interfaces in three steps (verified live on OPNSENSE01,
 * 26.4.2p2):
 *   1. PHYSICAL: `interfaces_info` rows with is_physical=true (igc0..3, ax0/ax1,
 *      vtnet0..). A physical port's "assignment" is IMPLICIT — it is the parent
 *      of a VLAN row or a member of a LAGG; otherwise it is idle.
 *   2. BUNDLES: `lagg_settings` rows (lagg0 = ax0+ax1, proto lacp/failover/…).
 *   3. LOGICAL: VLANs (`vlan_settings`, parent + tag) and bridges
 *      (`bridge_settings`) sit on top of physical/bundle ifcs. The L3 address
 *      of a network binds to the LOGICAL interface (vlan0042 / lagg0 / bridge0),
 *      which carries an identifier (lan/optN) — that is what `l3Interfaces` maps.
 */

import { INTENT_L2_TOPOLOGY_READ } from '@unm/plugin-sdk';
import type { L2Bridge, L2Bundle, L2PhysicalPort, L2Topology } from '@unm/plugin-sdk';
import * as ifaces from '../client/interfaces';
import type { ActionContext, ActionDescriptor } from './types';

// --- Row shapes (verified live) ---------------------------------------------------

interface IfcRow {
  device?: string;
  is_physical?: boolean;
  identifier?: string;
  description?: string;
  enabled?: boolean;
  vlan?: { tag?: string; parent?: string };
  ipv4?: Array<{ ipaddr?: string }>;
  ipv6?: Array<{ ipaddr?: string }>;
}

interface VlanRow {
  if?: Record<string, { selected?: number | string }>;
  tag?: string;
  vlanif?: string;
  descr?: string;
}

interface LaggRow {
  laggif?: string;
  members?: Record<string, { selected?: number | string }>;
  proto?: Record<string, { value?: string; selected?: number | string }>;
  descr?: string;
}

/** The key of a `selected` map (OPNsense form encoding: {opt:{value,selected}}). */
function selectedKey(map: Record<string, { selected?: number | string }> | undefined): string | null {
  if (!map || typeof map !== 'object') return null;
  for (const [k, v] of Object.entries(map)) {
    const sel = v?.selected;
    if (sel === 1 || sel === '1' || sel === 'true') return k;
  }
  return null;
}

/** Parses the interfaces_info recordset into typed rows. */
function parseIfcRows(data: unknown): IfcRow[] {
  const d = data as { rows?: IfcRow[] };
  return Array.isArray(d?.rows) ? d.rows : [];
}

/** Builds the L2 topology from one set of read-only API responses. */
export function buildOpnsenseL2Topology(
  infoData: unknown,
  vlanData: unknown,
  laggData: unknown,
  bridgeData: unknown,
): L2Topology {
  const rows = parseIfcRows(infoData);

  // VLANs: parent (selected key of .if) + tag.
  const vlans: Array<{ ifc: string; parent: string | null; tag: number | null }> = [];
  for (const v of Object.values((vlanData as { vlan?: { vlan?: Record<string, VlanRow> } })?.vlan?.vlan ?? {})) {
    const parent = selectedKey(v.if);
    vlans.push({ ifc: v.vlanif ?? '', parent, tag: v.tag !== undefined && v.tag !== '' ? Number(v.tag) : null });
  }

  // LAGGs: members (selected keys of .members) + protocol.
  const laggs: Array<{ ifc: string; members: string[]; protocol: string | null }> = [];
  for (const l of Object.values((laggData as { lagg?: { lagg?: Record<string, LaggRow> } })?.lagg?.lagg ?? {})) {
    const members = Object.entries(l.members ?? {}).filter(([, m]) => {
      const sel = m.selected;
      return sel === 1 || sel === '1' || sel === 'true';
    }).map(([k]) => k);
    laggs.push({ ifc: l.laggif ?? '', members, protocol: selectedKey(l.proto) });
  }

  // Bridges (bridge_settings rows: bridgeif + members list).
  const bridgesRaw = ((bridgeData as { bridge?: { bridged?: Array<{ bridgeif?: string; members?: unknown }> } })?.bridge?.bridged ?? []);
  const bridges: L2Bridge[] = bridgesRaw.map((b) => ({
    name: b.bridgeif ?? '',
    members: Array.isArray(b.members) ? (b.members as string[]) : [],
  })).filter((b) => !!b.name);

  // Physical ports — the assignment is implicit: parent of a VLAN, member of a
  // LAGG, or idle.
  const physicalPorts: L2PhysicalPort[] = rows.filter((r) => r.is_physical && r.device).map((r) => {
    const vlanParent = vlans.find((v) => v.parent === r.device);
    const laggMember = laggs.find((l) => l.members.includes(r.device as string));
    let assignment: string | null = null;
    if (vlanParent?.ifc) assignment = vlanParent.ifc; // e.g. igc0 → vlan0042
    else if (laggMember?.ifc) assignment = laggMember.ifc; // e.g. ax0 → lagg0
    return { name: r.device as string, assignment };
  });

  // L3 interfaces — every assigned logical ifc with an address maps to its
  // description (the network name in UNM's inventory). Loopback is excluded:
  // it carries addresses but is never a valid attach point for a new network,
  // and including it would let `lo0` win the SDK's alphabetical tie-break.
  const l3Interfaces: Record<string, string[]> = {};
  for (const r of rows) {
    if (!r.device || !r.identifier) continue;
    if (/^lo\d*$/.test(r.device)) continue;
    const hasV4 = (r.ipv4 ?? []).some((a) => !!a.ipaddr);
    const hasV6 = (r.ipv6 ?? []).some((a) => !!a.ipaddr && !a.ipaddr.startsWith('fe80'));
    if (!hasV4 && !hasV6) continue;
    const name = r.description?.trim() || r.identifier;
    let names = l3Interfaces[r.device];
    if (!names) { names = []; l3Interfaces[r.device] = names; }
    if (!names.includes(name)) names.push(name);
  }

  return { physicalPorts, bridges, bundles: laggs.map((l) => ({ name: l.ifc, protocol: l.protocol, members: l.members })), l3Interfaces };
}

/** Reads the full L2 topology of one OPNsense appliance (read-only). */
export async function readOpnsenseL2Topology(ctx: ActionContext): Promise<L2Topology> {
  const [info, vlans, laggs, bridges] = await Promise.all([
    ifaces.getInterfacesInfo(ctx.client),
    ifaces.vlans.get(ctx.client),
    ifaces.laggs.get(ctx.client),
    ifaces.bridges.get(ctx.client),
  ]);
  const firstFail = [info, vlans, laggs, bridges].find((r) => !r.ok);
  if (firstFail) {
    throw new Error(`L2 topology read failed: ${firstFail.status} on interfaces API`);
  }
  return buildOpnsenseL2Topology(info.data, vlans.data, laggs.data, bridges.data);
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
    const topology = await readOpnsenseL2Topology(ctx);
    return { success: true, details: { ...topology } };
  },
};
