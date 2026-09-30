/**
 * LCOS L2 topology — the device's interface layering, read-only.
 *
 * LCOS layers interfaces in four steps (verified live on WLC01 vRouter and
 * GW_Ralf 1803VAW-5G, LCOS 10.94):
 *   1. PHYSICAL → LOGICAL: `Setup/Interfaces/Ethernet-Ports` maps ETH-x / WAN /
 *      SFP-x onto logical ifcs via the Assignment column (e.g. ETH-4→LAN-1,
 *      WAN→LAN-5; "Idle" = unassigned).
 *   2. LACP BUNDLES: `Setup/LAN/Interface-Bundling/Interfaces` — rows like
 *      BUNDLE-1 = LAN-1+LAN-2 (Protocol LACP or Static). A bundle is itself a
 *      logical ifc that can carry networks.
 *   3. BRIDGES: `Setup/LAN-Bridge/Port-Data` maps every logical ifc to a
 *      Bridge-Group (BRG-1..8 / none). There is NO "create bridge" row — a
 *      BRG-x exists when ports point at it. The L3 address of a LAN network
 *      binds to the BRIDGE, not to member ports.
 *   4. VLAN TAGGING: `Setup/VLAN/Port-Table` (per-port Tagging-Mode) +
 *      `VLAN/Networks.Ports` (the member list per named VLAN).
 *
 * The canonical contract for this is @unm/plugin-sdk's L2Topology /
 * INTENT_L2_TOPOLOGY_READ — other vendors implement the same read against
 * their own layering (OPNsense lagg/vlan, RouterOS bridge/bonding, …).
 */

import { INTENT_L2_TOPOLOGY_READ } from '@unm/plugin-sdk';
import type { L2Bridge, L2Bundle, L2PhysicalPort, L2Topology } from '@unm/plugin-sdk';
import { snmpWalk } from '@unm/snmp-client';
import { NET_LIST } from '../lcosOids';
import { decodeNetIfc } from '../lcosClient';
import { cliTableRowsBatch, decodeTextIndex, firstToken, sshCreds } from './networkIntents';
import type { ActionContext, ActionDescriptor, ActionResult } from './types';

/** The three setup tables that make up the L2 hierarchy (dir -a order). */
const TOPOLOGY_TABLES = ['Interfaces/Ethernet-Ports', 'LAN-Bridge/Port-Data', 'LAN/Interface-Bundling/Interfaces'] as const;

/** Parses the physical→logical port map rows (Ethernet-Ports table). */
function parsePhysicalPorts(rows: string[]): L2PhysicalPort[] {
  // Columns in tab-header order: Port Assignment Connector [MDI-Mode] Clock-Role …
  const out: L2PhysicalPort[] = [];
  for (const row of rows) {
    const parts = row.trim().split(/\s+/);
    if (parts.length < 2) continue;
    const name = firstToken(row);
    if (!name) continue;
    const assignment = parts[1] === 'Idle' ? null : parts[1];
    out.push({ name, assignment });
  }
  return out;
}

/** Parses bridge groups from LAN-Bridge/Port-Data rows (port → Bridge-Group). */
function parseBridges(rows: string[]): L2Bridge[] {
  // Columns in tab-header order: Port Active Bridge-Group Private-Mode DHCP-Limit Point-To-Point-Port.
  const byName = new Map<string, string[]>();
  for (const row of rows) {
    const parts = row.trim().split(/\s+/);
    if (parts.length < 3) continue;
    const port = firstToken(row);
    const group = parts[2];
    if (!port || !group || group === 'none') continue;
    let members = byName.get(group);
    if (!members) { members = []; byName.set(group, members); }
    if (!members.includes(port)) members.push(port);
  }
  return [...byName.entries()].map(([name, members]) => ({ name, members }));
}

/** Parses LACP bundles from Interface-Bundling/Interfaces rows. */
function parseBundles(rows: string[]): L2Bundle[] {
  // Columns in tab-header order (6): Interface Operating Protocol MAC-Address
  // Interface-A Interface-B. Long rows wrap — cliTableRows merges continuations.
  const out: L2Bundle[] = [];
  for (const row of rows) {
    const parts = row.trim().split(/\s+/);
    if (parts.length < 3) continue;
    const name = firstToken(row);
    if (!name || !/^BUNDLE-\d+$/i.test(name)) continue;
    out.push({
      name,
      protocol: parts[2] ?? null, // LACP / Static
      members: [parts[4], parts[5]].filter((m): m is string => !!m && m !== 'none'),
      operating: parts[1] === 'Yes' ? true : parts[1] === 'No' ? false : null,
    });
  }
  return out;
}

/** Reads which logical ifcs carry an L3 network (SNMP NET_LIST walk). */
async function readL3Interfaces(ctx: ActionContext): Promise<Record<string, string[]>> {
  const out: Record<string, string[]> = {};
  try {
    const m = await snmpWalk(ctx.host, ctx.credentials.snmp, [NET_LIST.base], ctx.opts);
    for (const [oid, value] of m) {
      if (!oid.startsWith(`${NET_LIST.base}.1.`)) continue;
      const rel = oid.slice(`${NET_LIST.base}.1.`.length).split('.');
      if (Number(rel[0]) !== NET_LIST.COL_IFC) continue; // interface column only
      const key = decodeTextIndex(rel.slice(1));
      const label = decodeNetIfc(value);
      if (!key || !label) continue;
      let names = out[label];
      if (!names) { names = []; out[label] = names; }
      if (!names.includes(key)) names.push(key); // ifc → network names (several may share one ifc)
    }
  } catch { /* no status tree — empty */ }
  return out;
}

/**
 * Reads the full L2 topology of one LCOS device. Read-only: CLI `dir -a` on
 * three setup tables + one SNMP walk. Never throws — missing tables degrade to
 * empty lists (vRouter models have no bundles, some models no bridge table).
 *
 * The three CLI reads run in ONE session (`cliTableRowsBatch`) on purpose: LCOS
 * vRouters drop a second concurrent SSH connection (`CONNECTION_LOST` / "No
 * response from server") — verified live on WLC01 (physical hardware tolerates
 * it, but the fleet must work on both) — and each fresh session costs a full
 * login + 2.5s banner settle, so batching is also ~3× faster. Only the SNMP
 * walk overlaps with them.
 */
export async function readLcosL2Topology(ctx: ActionContext): Promise<L2Topology> {
  const l3Promise = readL3Interfaces(ctx); // SNMP — no SSH session, safe to overlap
  let tables: string[][];
  try {
    const creds = sshCreds(ctx);
    if (!creds) return { physicalPorts: [], bridges: [], bundles: [], l3Interfaces: await l3Promise };
    tables = await cliTableRowsBatch(ctx, creds, [...TOPOLOGY_TABLES]);
  } catch (e) {
    console.warn(`L2 topology: CLI batch read failed (${e instanceof Error ? e.message : String(e)})`);
    return { physicalPorts: [], bridges: [], bundles: [], l3Interfaces: await l3Promise };
  }
  const [physicalRows, bridgeRows, bundleRows] = tables;
  return {
    physicalPorts: parsePhysicalPorts(physicalRows),
    bridges: parseBridges(bridgeRows),
    bundles: parseBundles(bundleRows),
    l3Interfaces: await l3Promise,
  };
}

/** Canonical read action — the LCOS implementation of `l2.topology.read`. */
const l2TopologyRead: ActionDescriptor = {
  id: INTENT_L2_TOPOLOGY_READ,
  label: 'Read L2 topology (ports → bundles/bridges)',
  description:
    "Read-only map of this device's interface layering: physical ports and their logical assignments (Ethernet-Ports), LACP bundles with members (Interface-Bundling), bridge groups with member ifcs (LAN-Bridge/Port-Data) and which interfaces carry L3 networks. Use to resolve the right attach point for network.create — on LCOS the L3 address binds to a BRG-x bridge or BUNDLE, not to a physical port.",
  module: 'Network',
  riskLevel: 'read',
  deviceCount: 1,
  timeoutMs: 60_000,
  inputSchema: {},
  async execute(ctx): Promise<ActionResult> {
    const topology = await readLcosL2Topology(ctx);
    return { success: true, details: { ...topology } };
  },
};

export const L2_TOPOLOGY_ACTIONS: ActionDescriptor[] = [l2TopologyRead];
