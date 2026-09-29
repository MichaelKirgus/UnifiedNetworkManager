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

import type { PreflightConfidence, PreflightResult, PreflightValue } from '@unm/plugin-sdk';
import { snmpWalk } from '@unm/snmp-client';
import { NET_LIST } from '../lcosOids';
import type { ActionContext } from './types';
import { cliTableRows, decodeTextIndex, sshCreds } from './networkIntents';
import { readWlanTable } from './wlanSlots';

/** Decodes the network-list interface enum (same mapping as lcosClient.decodeNetIfc). */
function netIfcLabel(raw: string | undefined): string {
  const n = Number(raw ?? '');
  if (!Number.isInteger(n)) return '';
  if (n >= 256 && n <= 511) return `LAN-${n - 255}`;
  if (n === 512 || n === 513) return `WLAN-${n - 511}`;
  return '';
}

/** Reads the L3 network list via SNMP (read-only). */
async function readL3Networks(ctx: ActionContext): Promise<Array<{ name: string; ip: string | null; netmask: string | null; vlanId: number | null; ifcLabel: string }>> {
  const out: Array<{ name: string; ip: string | null; netmask: string | null; vlanId: number | null; ifcLabel: string }> = [];
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
      out.push({
        name,
        ip: cols[NET_LIST.COL_IP] ?? null,
        netmask: cols[NET_LIST.COL_NETMASK] ?? null,
        vlanId: cols[NET_LIST.COL_VLAN] !== undefined ? Number(cols[NET_LIST.COL_VLAN]) : null,
        ifcLabel: netIfcLabel(cols[NET_LIST.COL_IFC]),
      });
    }
  } catch { /* no status tree — empty */ }
  return out;
}

/** Reads the VLAN/Networks table rows via CLI (read-only `dir -a`). */
async function readVlanRows(ctx: ActionContext): Promise<Array<{ name: string; vlanId: number | null; ports: string }>> {
  const creds = sshCreds(ctx);
  if (!creds) return [];
  try {
    const rows = await cliTableRows(ctx, creds, 'VLAN/Networks');
    const out: Array<{ name: string; vlanId: number | null; ports: string }> = [];
    for (const row of rows) {
      // Row shape: "NAME" <vlanId> "<ports>"  (LCOS upper-cases names).
      const m = /^"([^"]+)"\s+(\d+)\s+(.*)$/.exec(row.trim());
      if (!m) continue;
      out.push({ name: m[1], vlanId: Number(m[2]), ports: (m[3] ?? '').replace(/^"|"$/g, '') });
    }
    return out;
  } catch { /* no SSH slot or CLI failed — empty */ }
  return [];
}

/** Picks the best-guess L2 interface for a new VLAN on this device. */
function suggestInterface(vlanRows: Array<{ name: string; vlanId: number | null; ports: string }>, l3: Array<{ ifcLabel: string }>): PreflightValue {
  // Interfaces already used by existing VLAN networks (their Ports column).
  const used = new Set<string>();
  for (const v of vlanRows) for (const p of v.ports.split(/[\s,]+/)) if (p) used.add(p);

  // LAN ports that carry an L3 network — the device's established routing ifcs.
  const l3Ifcs = new Set(l3.map((n) => n.ifcLabel).filter(Boolean));

  // Candidate order: L3-carrying LAN ports first (that's where this router
  // routes), then any other known LAN port, then the LCOS default LAN-1.
  const candidates: string[] = [];
  for (const ifc of [...l3Ifcs].sort()) if (!candidates.includes(ifc)) candidates.push(ifc);
  for (let i = 1; i <= 8; i++) {
    const p = `LAN-${i}`;
    if (!used.has(p) && !candidates.includes(p)) candidates.push(p);
  }
  if (!candidates.includes('LAN-1')) candidates.unshift('LAN-1');

  const pick = candidates[0];
  const confidence: PreflightConfidence = l3Ifcs.size === 1 ? 'high' : l3Ifcs.size > 1 || used.size > 0 ? 'medium' : 'low';
  return {
    key: 'interface',
    value: pick,
    confidence,
    note: l3Ifcs.size === 1
      ? `only ${pick} carries an L3 network on this device`
      : used.size > 0
        ? `${[...used].join(', ')} already carry VLANs — ${pick} is the first free candidate (override if needed)`
        : `no existing VLAN networks found — defaulting to ${pick}`,
  };
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
  const notes: string[] = [];

  const name = String(inputs.name ?? '').trim();
  const vlanId = typeof inputs.vlanId === 'number' ? Math.floor(inputs.vlanId as number) : NaN;
  const hasVlan = Number.isInteger(vlanId);
  const wantsSsid = Boolean(inputs.ssid && typeof (inputs.ssid as Record<string, unknown>).name === 'string');

  // Existing state for this name/VLAN — idempotency hints.
  let vlanRows: Array<{ name: string; vlanId: number | null; ports: string }> = [];
  try {
    vlanRows = await readVlanRows(ctx);
  } catch { /* no SSH slot */ }

  if (name && hasVlan) {
    const existing = vlanRows.find((v) => v.name.toUpperCase() === name.toUpperCase());
    if (existing) {
      values.push({ key: 'vlanId', value: existing.vlanId, confidence: 'high', note: `VLAN network "${name}" already exists with VLAN ${existing.vlanId} — left untouched` });
      if (existing.vlanId !== vlanId) notes.push(`requested VLAN ${vlanId} but existing row uses ${existing.vlanId}`);
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

  // Interface suggestion — the L2 port matters whenever an L3 address or SSID
  // is involved (or always, so the user can pin it per device).
  const l3 = await readL3Networks(ctx);
  values.push(suggestInterface(vlanRows, l3));

  // SSID slot suggestion.
  if (wantsSsid) {
    const slot = await suggestSsidSlot(ctx);
    if (slot) values.push(slot);
  }

  return { deviceId: ctx.deviceId ?? '', values, ...(notes.length > 0 ? { degraded: false } : {}) };
}

/** Registry of preflight resolvers per canonical intent id. */
export const PREFLIGHT_RESOLVERS: Record<string, (ctx: ActionContext, inputs: Record<string, unknown>) => Promise<PreflightResult>> = {
  'network.create': preflightNetworkCreate,
};
