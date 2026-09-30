/**
 * Preflight resolvers for the canonical fleet intents — the "smart" half of a
 * network rollout. Before plans are created, the webapp asks this plugin to
 * RESOLVE best-guess values per device against its LIVE state (read-only):
 *   - which L2 interface should carry the new VLAN on THIS router,
 *   - whether an SSID slot is available (and which one),
 *   - what already exists for the requested name/VLAN (idempotency hints).
 *
 * Transport contract: POST /preflight { intentActionId, device } — same body
 * shape as a single-device step dispatch. Resolvers NEVER write; they return
 * PreflightResult values that the UI renders and the user can override before
 * plan creation (overrides ride back in PlanRequest.deviceInputs).
 */

import type { L2Bridge, L2Bundle, L2PhysicalPort, L2Topology, PreflightResult, PreflightValue } from '@unm/plugin-sdk';
import { suggestL2AttachPoint, suggestL2VlanPorts } from '@unm/plugin-sdk';
import { snmpWalk } from '@unm/snmp-client';
import { NET_LIST } from '../lcosOids';
import { decodeNetIfc } from '../lcosClient';
import type { ActionContext } from './types';
import { cliTableRowsBatch, decodeTextIndex, firstToken, parseVlanRows, sshCreds } from './networkIntents';
import { readWlanTable } from './wlanSlots';

/** Reads the L3 network list via SNMP (read-only) — per-network attach ifc. */
async function readL3Networks(ctx: ActionContext): Promise<Array<{ name: string; ifcLabel: string }>> {
  const out: Array<{ name: string; ifcLabel: string }> = [];
  try {
    const m = await snmpWalk(ctx.host, ctx.credentials.snmp, [NET_LIST.base], ctx.opts);
    const rows = new Map<string, Record<number, string>>();
    for (const [oid, value] of m) {
      if (!oid.startsWith(`${NET_LIST.base}.1.`)) continue;
      const rel = oid.slice(`${NET_LIST.base}.1.`.length).split('.');
      const col = Number(rel[0]);
      const key = decodeTextIndex(rel.slice(1));
      if (key === null || !Number.isInteger(col)) continue;
      let row = rows.get(key);
      if (!row) { row = {}; rows.set(key, row); }
      row[col] = String(value);
    }
    for (const [name, cols] of rows.entries()) {
      out.push({ name, ifcLabel: decodeNetIfc(cols[NET_LIST.COL_IFC]) });
    }
  } catch { /* no status tree — empty */ }
  return out;
}

/** True when a v6 row for this network name exists in either Setup/IPv6 table. */
function hasExistingV6Rows(name: string, lanIfcRows: string[], addrRows: string[]): boolean {
  // Same first-token extraction as the executor's tableHasName (quoted or bare), case-insensitive.
  const has = (rows: string[]) => {
    const needle = name.toUpperCase();
    for (const row of rows) {
      const m = /^"([^"]+)"|^\S+/.exec(row.trim());
      if (!m) continue;
      if ((m[1] ?? m[0]).toUpperCase() === needle) return true;
    }
    return false;
  };
  return has(lanIfcRows) || has(addrRows);
}

/**
 * Reads every table the network.create preflight needs in ONE CLI session:
 * VLAN/Networks (idempotency + tag-port convention), the three L2-topology
 * tables and both Setup/IPv6 tables (v6 existence hint). LCOS vRouters drop
 * concurrent SSH connections AND each fresh session costs a full login + 2.5s
 * banner settle — five separate sessions would blow the API's 45s preflight
 * budget on WLC01, so everything rides one batched `dir -a` run (~15-20s).
 */
async function readPreflightTables(ctx: ActionContext): Promise<{
  vlanRows: Array<{ name: string; vlanId: number | null; ports: string[] }>;
  topo: L2Topology | null;
  v6LanIfcRows: string[];
  v6AddrRows: string[];
}> {
  const creds = sshCreds(ctx);
  if (!creds) return { vlanRows: [], topo: null, v6LanIfcRows: [], v6AddrRows: [] };
  try {
    const [vlanRaw, ethRows, bridgeRows, bundleRows, v6LanIfcRows, v6AddrRows] = await cliTableRowsBatch(
      ctx, creds,
      ['VLAN/Networks', 'Interfaces/Ethernet-Ports', 'LAN-Bridge/Port-Data', 'LAN/Interface-Bundling/Interfaces', 'IPv6/LAN-Interfaces', 'IPv6/Network/Addresses'],
    );
    // Shared parser (same as the executor) — cuts at the closing quote of the
    // Ports column so trailing empty columns can't leak into `ports`.
    const vlanRows = parseVlanRows(vlanRaw);
    const l3Interfaces = await readL3NetworksAsMap(ctx); // SNMP — overlaps nothing, cheap
    return {
      vlanRows,
      topo: { physicalPorts: parsePhysicalPortRows(ethRows), bridges: parseBridgeRows(bridgeRows), bundles: parseBundleRows(bundleRows), l3Interfaces },
      v6LanIfcRows,
      v6AddrRows,
    };
  } catch (e) {
    console.warn(`Preflight table batch read failed (${e instanceof Error ? e.message : String(e)})`);
    return { vlanRows: [], topo: null, v6LanIfcRows: [], v6AddrRows: [] };
  }
}

/** SNMP NET_LIST walk → interface label → network names (same data as readL3Networks). */
async function readL3NetworksAsMap(ctx: ActionContext): Promise<Record<string, string[]>> {
  const out: Record<string, string[]> = {};
  for (const n of await readL3Networks(ctx)) {
    if (!n.ifcLabel) continue;
    let names = out[n.ifcLabel];
    if (!names) { names = []; out[n.ifcLabel] = names; }
    if (!names.includes(n.name)) names.push(n.name);
  }
  return out;
}

/** Ethernet-Ports rows → physical port map (same grammar as l2Topology.ts). */
function parsePhysicalPortRows(rows: string[]): L2PhysicalPort[] {
  const out: L2PhysicalPort[] = [];
  for (const row of rows) {
    const parts = row.trim().split(/\s+/);
    if (parts.length < 2) continue;
    const name = firstToken(row);
    if (!name) continue;
    out.push({ name, assignment: parts[1] === 'Idle' ? null : parts[1] });
  }
  return out;
}

/** LAN-Bridge/Port-Data rows → bridge groups (same grammar as l2Topology.ts). */
function parseBridgeRows(rows: string[]): L2Bridge[] {
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

/** Interface-Bundling rows → bundles (same grammar as l2Topology.ts). */
function parseBundleRows(rows: string[]): L2Bundle[] {
  const out: L2Bundle[] = [];
  for (const row of rows) {
    const parts = row.trim().split(/\s+/);
    if (parts.length < 3) continue;
    const name = firstToken(row);
    if (!name || !/^BUNDLE-\d+$/i.test(name)) continue;
    out.push({
      name,
      protocol: parts[2] ?? null,
      members: [parts[4], parts[5]].filter((m): m is string => !!m && m !== 'none'),
      operating: parts[1] === 'Yes' ? true : parts[1] === 'No' ? false : null,
    });
  }
  return out;
}

/**
 * Resolves the L3 attach point + VLAN tag ports for a new network on this
 * device. LCOS layers interfaces (ETH-x → LAN-x / BUNDLE-x(LACP) → BRG-x
 * bridges): the L3 address binds to the BRIDGE or bundle, while VLAN tagging
 * follows the member ports — so both are resolved from the live topology
 * instead of hardcoding a port.
 */
function resolveAttachPoints(
  topo: L2Topology | null,
  vlanRows: Array<{ name: string; vlanId: number | null; ports: string[] }>,
  l3: Array<{ name: string; ifcLabel: string }>,
): PreflightValue[] {
  const out: PreflightValue[] = [];
  if (!topo) {
    out.push({ key: 'interface', value: 'LAN-1', confidence: 'low', note: 'device not reachable for L2 inspection — defaulting to LAN-1 (override if needed)' });
    return out;
  }

  const existing = vlanRows.map((v) => ({ name: v.name, ports: v.ports }));
  const suggestion = suggestL2AttachPoint(topo);
  if (!suggestion) {
    out.push({ key: 'interface', value: 'LAN-1', confidence: 'low', note: 'no bridges/bundles/assigned ports found on this device — defaulting to LAN-1' });
    return out;
  }

  // Enrich the reason with the actual network names riding the attach point.
  const bridge = topo.bridges.find((b) => b.name === suggestion.attach);
  const domainIfcs = new Set([suggestion.attach, ...(bridge?.members ?? [])]);
  const netsOnAttach = l3.filter((n) => n.ifcLabel && domainIfcs.has(n.ifcLabel)).map((n) => n.name);

  out.push({
    key: 'interface',
    value: suggestion.attach,
    confidence: /carries existing L3/.test(suggestion.reason) ? 'high' : 'medium',
    note: `${suggestion.reason}${netsOnAttach.length > 0 ? ` (${netsOnAttach.join(', ')})` : ''} — the L3 address (v4/v6) binds here`,
  });

  // VLAN tag ports follow the device's existing convention on this bridge.
  const ports = suggestL2VlanPorts(topo, suggestion.attach, existing);
  if (ports.length > 1) {
    out.push({ key: 'vlanPorts', value: ports, confidence: 'medium', note: `VLAN tag follows the device's convention on ${suggestion.attach}: ${ports.join(', ')}` });
  }
  return out;
}

/** Suggests a free WLAN slot for an SSID (fixed slots — read-only check). */
async function suggestSsidSlot(ctx: ActionContext): Promise<PreflightValue | null> {
  const creds = sshCreds(ctx);
  if (!creds) return null; // no SSH → cannot inspect slots; the executor auto-picks at runtime.
  try {
    const t = await readWlanTable(ctx, creds, 'Network');
    const free = ['WLAN-1-2', 'WLAN-1-3', 'WLAN-1-4', 'WLAN-1-5', 'WLAN-1-6', 'WLAN-1-7', 'WLAN-2-2', 'WLAN-2-3']
      .find((c) => {
        const row = t.rows.get(c);
        return !!row && row[1] === 'No' && row[2].toUpperCase() === 'LANCOM';
      });
    if (free) {
      return { key: 'ssid.slot', value: free, confidence: 'high', note: `slot ${free} is at factory defaults (off, name LANCOM)` };
    }
    // Slots exist but none are free — or the main slots only.
    const anyRow = t.rows.size > 0;
    return {
      key: 'ssid.slot',
      value: null,
      confidence: 'low',
      note: anyRow ? 'no free WLAN slot at factory defaults — SSID will be skipped unless a slot is overridden' : 'WLAN table empty on this device (vRouter?) — no local radios',
    };
  } catch {
    return null; // no WLAN tables → no local radios; nothing to suggest.
  }
}

/**
 * Preflight for `network.create` on one LCOS router. Read-only: SNMP walk of
 * the L3 status table + CLI `dir -a` of VLAN/Networks and the WLAN slot table.
 */
export async function preflightNetworkCreate(ctx: ActionContext, inputs: Record<string, unknown>): Promise<PreflightResult> {
  const values: PreflightValue[] = [];

  const name = String(inputs.name ?? '').trim();
  const vlanId = typeof inputs.vlanId === 'number' ? Math.floor(inputs.vlanId as number) : NaN;
  const hasVlan = Number.isInteger(vlanId);
  const wantsSsid = Boolean(inputs.ssid && typeof (inputs.ssid as Record<string, unknown>).name === 'string');
  const cidrV6 = typeof inputs.cidrV6 === 'string' ? inputs.cidrV6.trim() : '';

  // ONE batched CLI session for every table this preflight needs (see
  // readPreflightTables) — sequential per-table sessions would blow the API's
  // 45s budget on LCOS vRouters.
  const tables = await readPreflightTables(ctx);
  const { vlanRows, topo } = tables;

  if (name && hasVlan) {
    const existing = vlanRows.find((v) => v.name.toUpperCase() === name.toUpperCase());
    if (existing) {
      values.push({ key: 'vlanId', value: existing.vlanId, confidence: 'high', note: `VLAN network "${name}" already exists with VLAN ${existing.vlanId} — left untouched${existing.vlanId !== vlanId ? ` (requested VLAN was ${vlanId})` : ''}` });
    } else {
      values.push({ key: 'vlanId', value: vlanId, confidence: 'high', note: `no existing VLAN network named "${name}" — will be created` });
    }
  } else if (name && !hasVlan) {
    const existing = vlanRows.find((v) => v.name.toUpperCase() === name.toUpperCase());
    values.push({
      key: 'vlanId',
      value: null,
      confidence: 'medium',
      note: existing
        ? `no VLAN ID requested — L3/DHCP will bind to default VLAN 1 (a VLAN network named "${name}" already exists with VLAN ${existing.vlanId})`
        : 'no VLAN ID requested — no dedicated L2 VLAN row, L3/DHCP bind to default VLAN 1. Set a value here to create one.',
    });
  }

  // Attach-point resolution — LCOS layers interfaces (ETH-x → LAN-x / BUNDLE-x
  // LACP → BRG-x bridges), so resolve BOTH the L3 attach ifc and the VLAN tag
  // ports from the live topology instead of hardcoding a port. The l3 list is
  // reshaped from the topology's interface→names map (same SNMP data).
  const l3 = Object.entries(topo?.l3Interfaces ?? {}).flatMap(([ifcLabel, names]) => names.map((n) => ({ name: n, ifcLabel })));
  values.push(...resolveAttachPoints(topo, vlanRows, l3));

  // Dual-stack hint — LCOS keeps IPv6 in a separate tree; when the rollout
  // carries a v6 CIDR tell the user what already exists for this name.
  if (cidrV6) {
    const existing = hasExistingV6Rows(name, tables.v6LanIfcRows, tables.v6AddrRows);
    values.push({
      key: 'cidrV6',
      value: cidrV6,
      confidence: existing ? 'high' : 'medium',
      note: existing
        ? `an IPv6 row for "${name}" already exists on this device — the v6 tables will be left untouched`
        : `no IPv6 rows for "${name}" yet — will create Setup/IPv6/LAN-Interfaces + Network/Addresses rows`,
    });
  }

  // SSID slot suggestion.
  if (wantsSsid) {
    const slot = await suggestSsidSlot(ctx);
    if (slot) values.push(slot);
  }

  return {
    deviceId: ctx.deviceId ?? '',
    values,
    ...(topo === null ? { degraded: true, error: 'L2 topology could not be read (no SSH slot or CLI failed) — attach point defaults to LAN-1' } : {}),
  };
}

/** Registry of preflight resolvers per canonical intent id. */
export const PREFLIGHT_RESOLVERS: Record<string, (ctx: ActionContext, inputs: Record<string, unknown>) => Promise<PreflightResult>> = {
  'network.create': preflightNetworkCreate,
};
