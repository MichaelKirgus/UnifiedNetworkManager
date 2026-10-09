/**
 * Canonical fleet intents for OPNsense — `network.create` / `network.delete`.
 *
 * A "network" on OPNsense is an interface ASSIGNMENT: a `<interfaces>` node in
 * config.xml (identifier lan/optN → device + descr + ipaddr/subnet [+ v6]),
 * optionally riding a dedicated 802.1q VLAN created via the vlan_settings API.
 * The write paths per appliance era (verified against stable/26.1 source and
 * live on OPNSENSE01/GWBN01, both 26.4):
 *   - VLAN CRUD: REST `vlan_settings` item controller (all versions), staged +
 *     reconfigured. The firmware AUTO-NUMBERS the new device name (vlan01,
 *     vlan02… — NOT derived from the tag; verified live on 26.4) — so after
 *     add we read the row back by uuid and use its actual `vlanif`.
 *   - Assignment (identifier + IP): REST `/api/interfaces/assignment/*` on
 *     26.7+; SSH config.xml edit + rc.configure_interface on ≤26.4 (see
 *     interfaceAssignment.ts — needs a bound `ssh` slot).
 *   - DHCP range: REST `dnsmasq/settings/add_range` (dnsmasq backend only; Kea
 *     is reported as skipped in v1).
 */

import { INTENT_NETWORK_CREATE, INTENT_NETWORK_DELETE } from '@unm/plugin-sdk';
import type { L2Topology } from '@unm/plugin-sdk';
import { suggestL2AttachPoint } from '@unm/plugin-sdk';
import * as ifaces from '../client/interfaces';
import { opnsenseWriteOk } from '../client/interfaces';
import { reconfigureDhcp } from '../client/dhcp';
import { get, post } from '../client/http';
import { removeInterfaceAssignment, resolveAssignmentPath, writeInterfaceAssignment } from '../interfaceAssignment';
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

type VlanField = { value?: unknown; selected?: number | string } | string | null | undefined;

/**
 * Normalizes one vlan_settings field. The item controllers return form-encoded
 * values — Option/TextField as `{value, selected, options}`, TextField often a
 * plain string (verified live on 26.4: tag → {"value":"3998","selected":1},
 * vlanif → "vlan3998", if → per-option map). Callers must not assume strings.
 */
function vlanFieldVal(f: VlanField): string | null {
  if (f === null || f === undefined) return null;
  if (typeof f === 'string') return f;
  if (typeof f === 'object' && typeof (f as { value?: unknown }).value === 'string') return (f as { value: string }).value;
  return null;
}

interface VlanRowLite {
  tag?: VlanField;
  vlanif?: VlanField;
}

function rowsOf(data: unknown): IfcRowLite[] {
  const d = data as { rows?: IfcRowLite[] };
  return Array.isArray(d?.rows) ? d.rows : [];
}

/** Splits an IPv4 CIDR into [ip, prefix]. */
function parseV4(input: Record<string, unknown>): { ipaddr: string; subnet: string } | null {
  const cidr = typeof input.cidr === 'string' ? input.cidr.trim() : '';
  if (!cidr) return null;
  const m = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(cidr);
  if (!m) return null;
  return { ipaddr: m[1], subnet: m[2] };
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

// --- network.create -------------------------------------------------------------------

const NETWORK_CREATE_INPUTS = {
  name: { type: 'string' as const, required: true, minLength: 1, maxLength: 64, description: 'Network name (unique per device)' },
  vlanId: { type: 'number' as const, min: 1, max: 4094, description: 'VLAN ID — a dedicated 802.1q VLAN is created/attached on the attach point' },
  cidr: { type: 'string' as const, pattern: '^\\d{1,3}(\\.\\d{1,3}){3}/\\d{1,2}$', description: 'L3 address as CIDR (e.g. 10.42.0.1/24)' },
  cidrV6: { type: 'string' as const, pattern: '^[0-9a-fA-F:.]*:[0-9a-fA-F:.]*/\\d{1,3}$', description: 'Optional IPv6 L3 address (dual-stack when set alongside cidr)' },
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
  // Canonical fleet intent — FANS OUT across the batch (one step per appliance).
  deviceCount: 'N' as const,
  timeoutMs: 120_000,
  inputSchema: { ...NETWORK_CREATE_INPUTS },
  execute: async (ctx, input) => {
    const name = String(input.name ?? '').trim();
    const vlanId = typeof input.vlanId === 'number' ? Math.floor(input.vlanId as number) : null;
    const v4 = parseV4(input);
    const v6 = parseV6(input);
    if (!v4 && !v6) {
      return { success: false, error: 'nothing to create — provide cidr and/or cidrV6' };
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

    // 1b. Capability gate — BEFORE any device state is written. resolveAssignmentPath
    // already folds in the 26.7.x case (REST endpoint present but its minimal model
    // cannot hold an L3 address → falls back to SSH when a slot is bound). Only a
    // null path means "no way to write this" — refuse before creating any VLAN.
    if ((v4 || v6) && !(await resolveAssignmentPath(ctx.client, ctx.credentials as Record<string, unknown>))) {
      return { success: false, error: 'no write path for interface assignments on this appliance: the assignment REST model cannot hold an L3 address and no `ssh` credential slot is bound — bind one to enable config-edit writes' };
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
      const existingVlan = vlanRows.find((v) => Number(vlanFieldVal(v.tag)) === vlanId && vlanFieldVal(v.vlanif));
      if (existingVlan) {
        device = vlanFieldVal(existingVlan.vlanif) as string;
        details.vlan = `reused existing VLAN ${vlanId} (${device})`;
      } else {
        // Create the VLAN on the attach point. Parent must be a physical or
        // bundle ifc — walk up one more level when the user pointed at a VLAN.
        let parent = attach;
        const attachVlanRow = rows.find((r) => r.device === attach && r.vlan?.parent);
        if (attachVlanRow?.vlan?.parent) parent = attachVlanRow.vlan.parent;
        const addRes = await ifaces.vlans.add(ctx.client, { if: parent, tag: String(vlanId), descr: name });
        // OPNsense answers validation failures with HTTP 200 + {"result":"failed","validations":{…}} — check the body.
        if (!opnsenseWriteOk(addRes)) return { success: false, error: `VLAN ${vlanId} creation failed: ${JSON.stringify((addRes.data as Record<string, unknown>)?.validations ?? addRes.data).slice(0, 300)}` };
        const reconf = await ifaces.vlans.reconfigure(ctx.client);
        if (!opnsenseWriteOk(reconf)) return { success: false, error: `VLAN reconfigure failed: ${JSON.stringify(reconf.data).slice(0, 200)}` };
        // The device name is NOT the tag — firmware auto-numbers (vlan01…). Read
        // back the saved row by uuid and use its actual vlanif.
        const newUuid = (addRes.data as { uuid?: string } | null)?.uuid;
        let createdIfc: string | null = null;
        if (newUuid) {
          const afterAdd = await ifaces.vlans.get(ctx.client);
          if (afterAdd.ok) {
            const rowMap = ((afterAdd.data as { vlan?: { vlan?: Record<string, VlanRowLite> } })?.vlan?.vlan ?? {});
            createdIfc = vlanFieldVal(rowMap[newUuid]?.vlanif);
          }
        }
        if (!createdIfc) return { success: false, error: `VLAN ${vlanId} was saved but its device name could not be read back` };
        device = createdIfc;
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
  // Canonical fleet intent — FANS OUT across the batch (one step per appliance).
  deviceCount: 'N' as const,
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

    // 3. Orphaned VLAN cleanup — only when the device is a VLAN-family ifc
    //    (vlanNN/qinqNN) and no remaining assignment references it (shared
    //    VLANs stay). Match the vlan_settings row by its ACTUAL vlanif name,
    //    not by parsing digits out of the name: firmware auto-numbers devices
    //    (vlan01…), so the digits are NOT the tag.
    if (/^(?:vlan|qinq)\d+$/.test(row.device)) {
      const afterRes = await ifaces.getInterfacesInfo(ctx.client);
      if (afterRes.ok) {
        const stillUsed = rowsOf(afterRes.data).some((r) => r.config?.if === row.device || (r.device === row.device && !!r.identifier));
        if (!stillUsed) {
          const vlanRes = await ifaces.vlans.get(ctx.client);
          if (vlanRes.ok) {
            const vdata = vlanRes.data as { vlan?: { vlan?: Record<string, VlanRowLite> } };
            for (const [uuid, v] of Object.entries(vdata?.vlan?.vlan ?? {})) {
              if (vlanFieldVal(v.vlanif) === row.device) {
                const del = await ifaces.vlans.del(ctx.client, uuid);
                // HTTP 200 alone is not proof — the body says deleted/failed.
                if (opnsenseWriteOk(del)) {
                  await ifaces.vlans.reconfigure(ctx.client);
                  details.vlan = `removed orphaned VLAN ${vlanFieldVal(v.tag) ?? row.device}`;
                }
                break;
              }
            }
          }
        } else {
          details.vlanKept = `VLAN device ${row.device} still referenced by another network`;
        }
      }
    }

    return { success: true, applied: true, details };
  },
};

export const networkIntentActions: ActionDescriptor[] = [networkCreateAction, networkDeleteAction];
