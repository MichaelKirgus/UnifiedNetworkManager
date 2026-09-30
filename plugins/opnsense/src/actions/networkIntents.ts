/**
 * Canonical fleet intents for OPNsense — `network.create` / `network.delete`.
 *
 * A "network" on OPNsense is an interface ASSIGNMENT: a `<interfaces>` node in
 * config.xml (identifier lan/optN → device + descr + ipaddr/subnet [+ v6]),
 * optionally riding a dedicated 802.1q VLAN created via the vlan_settings API.
 * The write paths per appliance era (verified against stable/26.1 source and
 * live on OPNSENSE01/GWBN01, both 26.4):
 *   - VLAN CRUD: REST `vlan_settings` item controller (all versions), staged +
 *     reconfigured. The new device is named `vlan<NNNN>` (tag zero-padded to 4).
 *   - Assignment (identifier + IP): REST `/api/interfaces/assignment/*` on
 *     26.7+; SSH config.xml edit + rc.configure_interface on ≤26.4 (see
 *     assignmentSsh.ts — needs a bound `ssh` slot).
 *   - DHCP range: REST `dnsmasq/settings/add_range` (dnsmasq backend only; Kea
 *     is reported as skipped in v1).
 */

import { INTENT_NETWORK_CREATE, INTENT_NETWORK_DELETE } from '@unm/plugin-sdk';
import type { L2Topology } from '@unm/plugin-sdk';
import { suggestL2AttachPoint } from '@unm/plugin-sdk';
import * as ifaces from '../client/interfaces';
import { reconfigureDhcp } from '../client/dhcp';
import { get, post } from '../client/http';
import { removeInterfaceAssignment, writeInterfaceAssignment } from '../assignmentSsh';
import type { ActionContext, ActionDescriptor } from './types';
import { readOpnsenseL2Topology } from './l2Topology';

// --- Shared helpers -----------------------------------------------------------------

interface IfcRowLite {
  device?: string;
  identifier?: string;
  description?: string;
  vlan?: { tag?: string; parent?: string };
  config?: { if?: string; descr?: string; ipaddr?: string; subnet?: string; ipaddrv6?: string; subnetv6?: string };
  ipv4?: Array<{ ipaddr?: string }>;
  ipv6?: Array<{ ipaddr?: string }>;
}

interface VlanRowLite {
  tag?: string;
  vlanif?: string;
}

function rowsOf(data: unknown): IfcRowLite[] {
  const d = data as { rows?: IfcRowLite[] };
  return Array.isArray(d?.rows) ? d.rows : [];
}

/** Splits a CIDR into [ip, prefix]; accepts ip+netmask form too. */
function parseV4(input: Record<string, unknown>): { ipaddr: string; subnet: string } | null {
  const cidr = typeof input.cidr === 'string' ? input.cidr.trim() : '';
  if (cidr) {
    const m = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(cidr);
    if (!m) return null;
    return { ipaddr: m[1], subnet: m[2] };
  }
  const ip = typeof input.ip === 'string' ? input.ip.trim() : '';
  const netmask = typeof input.netmask === 'string' ? input.netmask.trim() : '';
  if (!ip || !netmask) return null;
  // Convert dotted netmask to prefix length.
  const octets = netmask.split('.').map((o) => parseInt(o, 10));
  if (octets.length !== 4 || octets.some((n) => Number.isNaN(n))) return null;
  let bits = 0;
  for (const o of octets) {
    const table: Record<number, number> = { 255: 8, 254: 7, 252: 6, 248: 5, 240: 4, 224: 3, 192: 2, 128: 1, 0: 0 };
    if (!(o in table)) return null; // non-contiguous netmask — reject
    bits += table[o];
  }
  return { ipaddr: ip, subnet: String(bits) };
}

function parseV6(input: Record<string, unknown>): { ipaddr: string; subnet: string } | null {
  const cidr = typeof input.cidrV6 === 'string' ? input.cidrV6.trim() : '';
  if (!cidr) return null;
  const m = /^(.*):.*\/(\d{1,3})$/.exec(cidr);
  if (!m) return null;
  return { ipaddr: m[1], subnet: m[2] };
}

/** The next free optN identifier (lan/wan are reserved roles — never reused). */
function nextFreeIdentifier(rows: IfcRowLite[]): string {
  let max = 0;
  for (const r of rows) {
    const m = /^opt(\d+)$/.exec(r.identifier ?? '');
    if (m) max = Math.max(max, parseInt(m[1], 10));
  }
  return `opt${max + 1}`;
}

/** Finds the row whose description matches a network name (case-insensitive). */
function findNetworkRow(rows: IfcRowLite[], name: string): IfcRowLite | undefined {
  const needle = name.toUpperCase();
  return rows.find((r) => (r.description ?? '').toUpperCase() === needle || (r.config?.descr ?? '').toUpperCase() === needle);
}

/** The device a new VLAN with `tag` would get (OPNsense names them vlanNNNN). */
function vlanDeviceName(tag: number): string {
  return `vlan${String(tag).padStart(4, '0')}`;
}

// --- network.create -------------------------------------------------------------------

const NETWORK_CREATE_INPUTS = {
  name: { type: 'string' as const, required: true, minLength: 1, maxLength: 64, description: 'Network name (unique per device)' },
  vlanId: { type: 'number' as const, min: 1, max: 4094, description: 'VLAN ID — a dedicated 802.1q VLAN is created/attached on the attach point' },
  cidr: { type: 'string' as const, pattern: '^\\d{1,3}(\\.\\d{1,3}){3}/\\d{1,2}$', description: 'L3 address as CIDR (e.g. 10.42.0.1/24)' },
  cidrV6: { type: 'string' as const, pattern: '^[0-9a-fA-F:.]*:[0-9a-fA-F:.]*/\\d{1,3}$', description: 'Optional IPv6 L3 address (dual-stack when set alongside cidr)' },
  ip: { type: 'string' as const, pattern: '^\\d{1,3}(\\.\\d{1,3}){3}$', description: 'L3 address (alternative to cidr)' },
  netmask: { type: 'string' as const, pattern: '^\\d{1,3}(\\.\\d{1,3}){3}$', description: 'Netmask for `ip`' },
  interface: { type: 'string' as const, maxLength: 64, description: 'L2 attach point (parent ifc for the new VLAN / device for L3-only) — resolved per device in preflight' },
} as const;

/**
 * Creates one network on one appliance. Idempotent: a network with the same
 * name is left untouched. Steps (all staged where the API stages):
 *   1. Read live state (interfaces_info + vlan_settings).
 *   2. Ensure the VLAN exists when `vlanId` is set (create on the attach point,
 *      reconfigure) — or reuse an existing one with that tag.
 *   3. Write the interface assignment (identifier + IP) via REST (26.7+) or SSH (≤26.4).
 *   4. Optionally add a dnsmasq DHCP range for the new identifier.
 */
export const networkCreateAction: ActionDescriptor = {
  id: INTENT_NETWORK_CREATE,
  label: 'Create network (VLAN + L3 address)',
  module: 'Network',
  riskLevel: 'write',
  deviceCount: 1,
  timeoutMs: 120_000,
  inputSchema: { ...NETWORK_CREATE_INPUTS },
  execute: async (ctx, input) => {
    const name = String(input.name ?? '').trim();
    const vlanId = typeof input.vlanId === 'number' ? Math.floor(input.vlanId as number) : null;
    const v4 = parseV4(input);
    const v6 = parseV6(input);
    if (!v4 && !v6) {
      return { success: false, error: 'nothing to create — provide cidr (or ip+netmask) and/or cidrV6' };
    }

    // 1. Live state.
    const [infoRes, vlanRes] = await Promise.all([ifaces.getInterfacesInfo(ctx.client), ifaces.vlans.get(ctx.client)]);
    if (!infoRes.ok || !vlanRes.ok) {
      return { success: false, error: `state read failed (interfaces_info ${infoRes.status}, vlan_settings ${vlanRes.status})` };
    }
    const rows = rowsOf(infoRes.data);

    // Idempotency — same name already exists.
    const existing = findNetworkRow(rows, name);
    if (existing) {
      return { success: true, details: { skipped: `network "${name}" already exists on ${existing.device} (${existing.identifier})` } };
    }

    // 2. Attach point + VLAN device.
    const topo = await readOpnsenseL2Topology(ctx);
    let attach = typeof input.interface === 'string' && input.interface.trim() ? input.interface.trim() : null;
    if (!attach) {
      const suggestion = suggestL2AttachPoint(topo);
      // Walk up from a VLAN device to its parent — the new network's VLAN is
      // created as a SIBLING of existing VLANs, not on top of another VLAN.
      let a = suggestion?.attach ?? null;
      if (a) {
        const vlanRow = rows.find((r) => r.device === a && r.vlan?.parent);
        if (vlanRow?.vlan?.parent) a = vlanRow.vlan.parent;
      }
      attach = a;
    }
    if (!attach) {
      return { success: false, error: 'no attach point — set `interface` explicitly (no L3-carrying interface found on this device)' };
    }

    let device = attach;
    const details: Record<string, unknown> = { attachPoint: attach };
    if (vlanId !== null) {
      // Existing VLAN with that tag? Reuse it wherever it sits.
      const vlanMap = ((vlanRes.data as { vlan?: { vlan?: Record<string, VlanRowLite> } })?.vlan?.vlan ?? {});
      const vlanRows = Object.values(vlanMap);
      const existingVlan = vlanRows.find((v) => Number(v.tag) === vlanId);
      if (existingVlan?.vlanif) {
        device = existingVlan.vlanif;
        details.vlan = `reused existing VLAN ${vlanId} (${device})`;
      } else {
        // Create the VLAN on the attach point. Parent must be a physical or
        // bundle ifc — walk up one more level when the user pointed at a VLAN.
        let parent = attach;
        const attachVlanRow = rows.find((r) => r.device === attach && r.vlan?.parent);
        if (attachVlanRow?.vlan?.parent) parent = attachVlanRow.vlan.parent;
        const addRes = await ifaces.vlans.add(ctx.client, { if: parent, tag: String(vlanId), descr: name });
        if (!addRes.ok) return { success: false, error: `VLAN ${vlanId} creation failed: HTTP ${addRes.status}` };
        const reconf = await ifaces.vlans.reconfigure(ctx.client);
        if (!reconf.ok) return { success: false, error: `VLAN reconfigure failed: HTTP ${reconf.status}` };
        device = vlanDeviceName(vlanId);
        details.vlan = `created VLAN ${vlanId} on ${parent} → ${device}`;
      }
    }

    // 3. Interface assignment (identifier + IP).
    const identifier = nextFreeIdentifier(rows);
    const w = {
      identifier,
      device,
      descr: name,
      ...(v4 ? { ipaddr: v4.ipaddr, subnet: v4.subnet } : {}),
      ...(v6 ? { ipaddrv6: v6.ipaddr, subnetv6: v6.subnet } : {}),
    };
    const sshPort = typeof ctx.extra?.sshPort === 'number' ? (ctx.extra.sshPort as number) : undefined;
    const assigned = await writeInterfaceAssignment(ctx.client, ctx.credentials as Record<string, unknown>, ctx.host, w, sshPort);
    details.assignment = assigned.detail;

    // 4. Optional DHCP range (dnsmasq backend only).
    if (v4 && input.dhcpPool && typeof input.dhcpPool === 'object') {
      const pool = input.dhcpPool as { start?: unknown; end?: unknown };
      const start = typeof pool.start === 'string' ? pool.start : '';
      const end = typeof pool.end === 'string' ? pool.end : '';
      if (start && end) {
        if (ctx.dhcpBackend === 'dnsmasq') {
          const addRange = await post(ctx.client, '/api/dnsmasq/settings/add_range', { item: { interface: identifier, start_addr: start, end_addr: end } });
          if (!addRange.ok) return { success: false, error: `DHCP range creation failed: HTTP ${addRange.status}` };
          const reconf = await reconfigureDhcp(ctx.client, 'dnsmasq');
          if (!reconf.ok) return { success: false, error: `DHCP reconfigure failed: HTTP ${reconf.status}` };
          details.dhcpPool = `${start}–${end} on ${identifier} (dnsmasq)`;
        } else {
          details.dhcpSkipped = 'Kea DHCP backend — range not created in v1';
        }
      }
    }

    return { success: true, applied: true, details };
  },
};

// --- network.delete -------------------------------------------------------------------

/**
 * Removes one network (name-addressed, idempotent). Tears down in reverse
 * order of creation: DHCP range → interface assignment (+ running addresses)
 * → orphaned VLAN (only when no other assignment references the device).
 */
export const networkDeleteAction: ActionDescriptor = {
  id: INTENT_NETWORK_DELETE,
  label: 'Delete network',
  module: 'Network',
  riskLevel: 'write',
  deviceCount: 1,
  timeoutMs: 120_000,
  inputSchema: { name: { type: 'string' as const, required: true, minLength: 1, maxLength: 64, description: 'Network name to remove' } },
  execute: async (ctx, input) => {
    const name = String(input.name ?? '').trim();

    const infoRes = await ifaces.getInterfacesInfo(ctx.client);
    if (!infoRes.ok) return { success: false, error: `state read failed: HTTP ${infoRes.status}` };
    const rows = rowsOf(infoRes.data);
    const row = findNetworkRow(rows, name);
    if (!row?.identifier || !row.device) {
      return { success: true, details: { skipped: `no network named "${name}" on this device` } };
    }

    const details: Record<string, unknown> = {};
    const sshPort = typeof ctx.extra?.sshPort === 'number' ? (ctx.extra.sshPort as number) : undefined;

    // 1. DHCP ranges for the identifier (dnsmasq).
    if (ctx.dhcpBackend === 'dnsmasq') {
      try {
        const rangeRes = await get(ctx.client, '/api/dnsmasq/settings/search_range');
        if (rangeRes.ok) {
          const rdata = rangeRes.data as { rows?: Array<{ uuid?: string; interface?: string }> };
          for (const r of rdata.rows ?? []) {
            if (r.interface === row.identifier && r.uuid) {
              await post(ctx.client, `/api/dnsmasq/settings/del_range/${encodeURIComponent(r.uuid)}`, {});
            }
          }
          const reconf = await reconfigureDhcp(ctx.client, 'dnsmasq');
          if (reconf.ok) details.dhcpRanges = `removed for ${row.identifier}`;
        }
      } catch { /* best-effort — the assignment removal below is the critical part */ }
    }

    // 2. Interface assignment + running addresses.
    const teardown = {
      device: row.device,
      v4: row.config?.ipaddr ? [row.config.ipaddr] : [],
      v6: row.config?.ipaddrv6 ? [row.config.ipaddrv6] : [],
    };
    const removed = await removeInterfaceAssignment(ctx.client, ctx.credentials as Record<string, unknown>, ctx.host, row.identifier, teardown, sshPort);
    details.assignment = removed.detail;

    // 3. Orphaned VLAN cleanup — only when the device is a vlanNNNN and no
    //    remaining assignment references it (shared VLANs stay).
    const m = /^vlan(\d+)$/.exec(row.device);
    if (m) {
      const tag = parseInt(m[1], 10);
      const afterRes = await ifaces.getInterfacesInfo(ctx.client);
      if (afterRes.ok) {
        const stillUsed = rowsOf(afterRes.data).some((r) => r.config?.if === row.device || r.device === row.device && !!r.identifier);
        if (!stillUsed) {
          const vlanRes = await ifaces.vlans.get(ctx.client);
          if (vlanRes.ok) {
            const vdata = vlanRes.data as { vlan?: { vlan?: Record<string, { tag?: string }> } };
            for (const [uuid, v] of Object.entries(vdata?.vlan?.vlan ?? {})) {
              if (Number(v.tag) === tag) {
                const del = await ifaces.vlans.del(ctx.client, uuid);
                if (del.ok) {
                  await ifaces.vlans.reconfigure(ctx.client);
                  details.vlan = `removed orphaned VLAN ${tag}`;
                }
                break;
              }
            }
          }
        } else {
          details.vlanKept = `VLAN ${tag} still referenced by another network`;
        }
      }
    }

    return { success: true, applied: true, details };
  },
};

export const networkIntentActions: ActionDescriptor[] = [networkCreateAction, networkDeleteAction];
