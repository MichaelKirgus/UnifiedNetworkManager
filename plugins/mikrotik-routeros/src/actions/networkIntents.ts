/**
 * Canonical fleet intents for RouterOS — `network.create` / `network.delete`.
 *
 * A "network" on RouterOS is an L3 address bound to a logical interface,
 * optionally riding a dedicated 802.1q VLAN:
 *   - VLAN: `PUT /rest/interface/vlan {name, vlan-id, interface=<parent>}` — the
 *     VLAN's NAME carries the network name (RouterOS has no per-interface
 *     description), which is what makes create/delete idempotent by name.
 *   - L3 address: `PUT /rest/ip/address {address=<cidr>, interface=<ifc>}` (+
 *     `/ipv6/address` for dual-stack). Removals use the command-word form
 *     `POST <table>/remove {".id": ...}` (one record per request — array bodies
 *     are rejected by RouterOS REST). Writes apply IMMEDIATELY — RouterOS has
 *     no staged/reconfigure model; every write is verified by a re-read.
 *
 * Attach-point semantics (resolved per device in preflight via the L2
 * topology): when the attach point is a BRIDGE and a VLAN is requested, the
 * VLAN is created on one of the bridge's physical/bonding members and added to
 * the bridge as a slave — that is how RouterOS LANs carry tagged networks.
 */

import { INTENT_NETWORK_CREATE, INTENT_NETWORK_DELETE } from '@unm/plugin-sdk';
import type { L2Topology } from '@unm/plugin-sdk';
import { suggestL2AttachPoint } from '@unm/plugin-sdk';
import { rosString } from '../routerosClient';
import type { ActionContext, ActionDescriptor } from './types';
import { readRouterOsL2Topology, readSwitchVlanTable } from './l2Topology';

type Row = Record<string, unknown>;

// --- Shared helpers -----------------------------------------------------------------

/** Validates an IPv4 CIDR (returns it as-is when well-formed). */
function parseV4(input: Record<string, unknown>): string | null {
  const cidr = typeof input.cidr === 'string' ? input.cidr.trim() : '';
  if (!cidr) return null;
  return /^\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}$/.test(cidr) ? cidr : null;
}

function parseV6(input: Record<string, unknown>): string | null {
  const cidr = typeof input.cidrV6 === 'string' ? input.cidrV6.trim() : '';
  if (!cidr) return null;
  return /^[0-9a-fA-F:.]*:[0-9a-fA-F:.]*\/\d{1,3}$/.test(cidr) ? cidr : null;
}

/** Finds a VLAN row by its name (the network name), case-insensitive. */
function findVlanByName(vlans: Row[], name: string): Row | undefined {
  const needle = name.toUpperCase();
  return vlans.find((v) => (rosString(v, ['name']) ?? '').toUpperCase() === needle);
}

/** Finds a VLAN row by tag (+ optional parent). */
function findVlanByTag(vlans: Row[], vlanId: number, parent?: string): Row | undefined {
  return vlans.find((v) => Number(rosString(v, ['vlan-id'])) === vlanId && (!parent || rosString(v, ['interface']) === parent));
}

/** Picks the VLAN parent when the attach point is a bridge (first physical/bonding member). */
function pickBridgeVlanParent(topo: L2Topology, bridgeName: string): string | null {
  const bridge = topo.bridges.find((b) => b.name === bridgeName);
  if (!bridge) return null;
  for (const m of bridge.members) {
    // Prefer plain physical ports and bundles over nested VLANs.
    const isPhysical = topo.physicalPorts.some((p) => p.name === m);
    const isBundle = topo.bundles.some((b) => b.name === m);
    if (isPhysical || isBundle) return m;
  }
  return bridge.members[0] ?? null;
}

// --- network.create -------------------------------------------------------------------

const NETWORK_CREATE_INPUTS = {
  name: { type: 'string' as const, required: true, minLength: 1, maxLength: 64, description: 'Network name (unique per device — becomes the VLAN interface name)' },
  vlanId: { type: 'number' as const, min: 1, max: 4094, description: 'VLAN ID — a dedicated 802.1q VLAN is created/attached on the attach point' },
  cidr: { type: 'string' as const, pattern: '^\\d{1,3}(\\.\\d{1,3}){3}/\\d{1,2}$', description: 'L3 address as CIDR (e.g. 10.42.0.1/24)' },
  cidrV6: { type: 'string' as const, pattern: '^[0-9a-fA-F:.]*:[0-9a-fA-F:.]*/\\d{1,3}$', description: 'Optional IPv6 L3 address (dual-stack when set alongside cidr)' },
  interface: { type: 'string' as const, maxLength: 64, description: 'L2 attach point (bridge/bundle/port) — resolved per device in preflight' },
  vlanPorts: { type: 'array' as const, items: { type: 'string' } as const, description: 'Physical ports that carry this VLAN tagged on the switch chip (/interface/switch.vlan). Switch-capable SoCs only (hEX/cCR/CRS); ignored on devices without a switch chip.' },
} as const;

/**
 * Ensures one TAGGED /interface/switch.vlan row per requested port for this VLAN.
 * Idempotent: existing rows for the same (port, vlan-id) are left untouched; only
 * missing combinations are PUT. Returns { applied, skipped } counts + a note when
 * the device has no switch chip at all.
 */
async function applySwitchVlanPorts(ctx: ActionContext, vlanId: number, ports: string[]): Promise<Record<string, unknown>> {
  const table = await readSwitchVlanTable(ctx);
  if (table === null) {
    return { switchVlansSkipped: 'device has no integrated switch chip — VLAN was created on the interface only' };
  }
  const rowKey = (r: Row) => `${rosString(r, ['port'])}:${Number(rosString(r, ['vlan-id']))}`;
  const existing = new Set(table.map(rowKey));
  let added = 0;
  for (const p of ports) {
    if (existing.has(`${p}:${vlanId}`)) continue;
    const res = await ctx.client.put('/interface/switch.vlan', { port: p, 'vlan-id': String(vlanId), tagged: true });
    if (!res) return { switchVlansError: `could not add switch.vlan row for port ${p} (no response)` };
    added += 1;
  }
  // Verify by re-read.
  const after = await readSwitchVlanTable(ctx);
  const present = new Set((after ?? []).map(rowKey));
  for (const p of ports) {
    if (!present.has(`${p}:${vlanId}`)) return { switchVlansError: `verification failed — switch.vlan row ${p}:${vlanId} missing after write` };
  }
  return added > 0 ? { switchVlansAdded: added, switchVlanPorts: ports } : { switchVlansSkipped: `all requested ports already carry VLAN ${vlanId}` };
}

/**
 * Creates one network on one router. Idempotent by name (VLANs carry the
 * network name) and by address (an existing identical CIDR is left untouched).
 * Steps: ensure VLAN → add v4/v6 addresses → verify by re-read.
 */
export const networkCreateAction: ActionDescriptor = {
  id: INTENT_NETWORK_CREATE,
  label: 'Create network (VLAN + L3 address)',
  module: 'Network',
  riskLevel: 'write',
  // Canonical fleet intent — FANS OUT across the batch (one step per router).
  deviceCount: 'N' as const,
  timeoutMs: 60_000,
  inputSchema: { ...NETWORK_CREATE_INPUTS },
  execute: async (ctx, input) => {
    const name = String(input.name ?? '').trim();
    const vlanId = typeof input.vlanId === 'number' ? Math.floor(input.vlanId as number) : null;
    const v4 = parseV4(input);
    const v6 = parseV6(input);
    if (!v4 && !v6 && vlanId === null) {
      return { success: false, error: 'nothing to create — provide cidr and/or cidrV6 and/or vlanId' };
    }

    // 1. Live state.
    const [topo, vlans, addrs] = await Promise.all([
      readRouterOsL2Topology(ctx),
      ctx.client.get<Row[]>('/interface/vlan').catch(() => [] as Row[]),
      ctx.client.get<Row[]>('/ip/address').catch(() => [] as Row[]),
    ]);

    // Idempotency — same name already exists (VLAN carries the network name).
    const existing = findVlanByName(vlans, name);
    if (existing) {
      return { success: true, details: { skipped: `network "${name}" already exists as VLAN ${rosString(existing, ['name'])} (vlan-id ${rosString(existing, ['vlan-id'])})` } };
    }

    // 2. Attach point + target interface.
    let attach = typeof input.interface === 'string' && input.interface.trim() ? input.interface.trim() : null;
    if (!attach) {
      const suggestion = suggestL2AttachPoint(topo);
      attach = suggestion?.attach ?? null;
    }
    // L2-only (VLAN, no addresses): the VLAN just needs a parent — fall back to
    // bridge1 (always present on RouterOS) instead of failing. With an address
    // there must be a real attach point to bind it to.
    if (!attach && vlanId !== null && !v4 && !v6) {
      const hasBridge1 = topo.bridges.some((b) => b.name === 'bridge1');
      attach = hasBridge1 ? 'bridge1' : (topo.bridges[0]?.name ?? null);
    }
    if (!attach) {
      return { success: false, error: 'no attach point — set `interface` explicitly (no L3-carrying interface found on this device)' };
    }

    const details: Record<string, unknown> = { attachPoint: attach };
    let targetIfc = attach;

    if (vlanId !== null) {
      // Reuse an existing VLAN with that tag sitting on the attach domain.
      const byTag = findVlanByTag(vlans, vlanId);
      if (byTag && rosString(byTag, ['name'])) {
        targetIfc = rosString(byTag, ['name']) as string;
        details.vlan = `reused existing VLAN ${vlanId} (${targetIfc})`;
      } else {
        const isBridge = topo.bridges.some((b) => b.name === attach);
        let parent = attach;
        if (isBridge) {
          parent = pickBridgeVlanParent(topo, attach) ?? '';
          if (!parent) return { success: false, error: `bridge ${attach} has no physical/bonding member to host the VLAN` };
        }
        const addRes = await ctx.client.put('/interface/vlan', { name, 'vlan-id': String(vlanId), interface: parent });
        if (!addRes) return { success: false, error: `VLAN ${vlanId} creation failed (no response from /interface/vlan)` };
        targetIfc = name; // RouterOS names the new VLAN after our `name` property.
        details.vlan = isBridge ? `created VLAN ${vlanId} on ${parent}, added to bridge ${attach}` : `created VLAN ${vlanId} on ${parent}`;
        if (isBridge) {
          await ctx.client.put('/interface/bridge/port', { interface: attach, slave: name }).catch(() => undefined);
        }
      }
    }

    // L2-only rollout — no address was requested for this device.
    if (!v4 && !v6) {
      details.l3Skipped = 'no L3 address requested — VLAN only';
    }

    // 2b. Per-port tagging on the switch chip (switch-capable SoCs only).
    const vlanPortsRaw = Array.isArray(input.vlanPorts) ? (input.vlanPorts as unknown[]).map((p) => String(p).trim()).filter(Boolean) : null;
    if (vlanId !== null && vlanPortsRaw && vlanPortsRaw.length > 0) {
      Object.assign(details, await applySwitchVlanPorts(ctx, vlanId, [...new Set(vlanPortsRaw)]));
    }

    // 3. L3 addresses (immediate writes — verified by re-read).
    const added: string[] = [];
    if (v4) {
      const already = addrs.some((a) => rosString(a, ['address']) === v4 && rosString(a, ['interface', 'actual-interface']) === targetIfc);
      if (!already) {
        await ctx.client.put('/ip/address', { address: v4, interface: targetIfc });
        added.push(v4);
      } else {
        details.v4Kept = `address ${v4} already present on ${targetIfc}`;
      }
    }
    if (v6) {
      const v6Addrs = await ctx.client.get<Row[]>('/ipv6/address').catch(() => [] as Row[]);
      const already = v6Addrs.some((a) => rosString(a, ['address']) === v6 && rosString(a, ['interface', 'actual-interface']) === targetIfc);
      if (!already) {
        await ctx.client.put('/ipv6/address', { address: v6, interface: targetIfc });
        added.push(v6);
      } else {
        details.v6Kept = `address ${v6} already present on ${targetIfc}`;
      }
    }

    // 4. Verify by re-read (RouterOS applies immediately — a missing row means the write failed).
    const afterAddrs = await ctx.client.get<Row[]>('/ip/address').catch(() => [] as Row[]);
    for (const addr of added) {
      if (!afterAddrs.some((a) => rosString(a, ['address']) === addr && rosString(a, ['interface', 'actual-interface']) === targetIfc)) {
        return { success: false, error: `verification failed — address ${addr} not present on ${targetIfc} after write` };
      }
    }

    // DHCP pool is NOT created in v1 (a full /ip/dhcp-server + network + lease
    // setup is a separate intent) — reported so the UI can show it as skipped.
    if (input.dhcpPool && typeof input.dhcpPool === 'object') {
      details.dhcpSkipped = 'DHCP pool not created in v1 — configure /ip/dhcp-server separately';
    }

    return { success: true, applied: added.length > 0 || !!details.vlan, details };
  },
};

// --- network.delete -------------------------------------------------------------------

/**
 * Removes one network (name-addressed, idempotent). Tears down in reverse
 * order of creation: L3 addresses → bridge-port membership → the VLAN itself.
 */
export const networkDeleteAction: ActionDescriptor = {
  id: INTENT_NETWORK_DELETE,
  label: 'Delete network',
  module: 'Network',
  riskLevel: 'write',
  // Canonical fleet intent — FANS OUT across the batch (one step per router).
  deviceCount: 'N' as const,
  timeoutMs: 60_000,
  inputSchema: { name: { type: 'string' as const, required: true, minLength: 1, maxLength: 64, description: 'Network name to remove (the VLAN interface name)' } },
  execute: async (ctx, input) => {
    const name = String(input.name ?? '').trim();

    const vlans = await ctx.client.get<Row[]>('/interface/vlan').catch(() => [] as Row[]);
    const vlan = findVlanByName(vlans, name);
    if (!vlan) {
      return { success: true, details: { skipped: `no network named "${name}" on this device` } };
    }

    const vlanName = rosString(vlan, ['name']) as string;
    const id = rosString(vlan, ['.id']);
    if (!id) return { success: false, error: `VLAN ${vlanName} has no .id — cannot remove it` };

    const details: Record<string, unknown> = {};

    // 1. Addresses on the VLAN (v4 + v6).
    const addrTables: Array<[string, string]> = [['/ip/address', 'ipv4Addresses'], ['/ipv6/address', 'ipv6Addresses']];
    for (const [table, key] of addrTables) {
      try {
        const addrs = await ctx.client.get<Row[]>(table);
        const mine = addrs.filter((a) => rosString(a, ['interface', 'actual-interface']) === vlanName).map((a) => rosString(a, ['.id'])).filter(Boolean);
        if (mine.length > 0) {
          // Command-word /remove takes ONE object per request — loop.
          for (const i of mine) await ctx.client.post(`${table}/remove`, { '.id': i });
          details[key] = `removed ${mine.length}`;
        }
      } catch { /* best-effort — the VLAN removal below is the critical part */ }
    }

    // 2. Bridge-port membership (auto-removed with the interface, but explicit).
    try {
      const ports = await ctx.client.get<Row[]>('/interface/bridge/port');
      const mine = ports.filter((p) => rosString(p, ['slave']) === vlanName).map((p) => rosString(p, ['.id'])).filter(Boolean);
      if (mine.length > 0) {
        for (const i of mine) await ctx.client.post('/interface/bridge/port/remove', { '.id': i });
        details.bridgePorts = `removed ${mine.length}`;
      }
    } catch { /* best-effort */ }

    // 2b. Per-port tagging on the switch chip — remove rows for this VLAN's tag.
    const vlanTag = Number(rosString(vlan, ['vlan-id']));
    if (Number.isFinite(vlanTag) && vlanTag > 0) {
      try {
        const svTable = await readSwitchVlanTable(ctx);
        if (svTable !== null) {
          const mine = svTable.filter((r) => Number(rosString(r, ['vlan-id'])) === vlanTag).map((r) => rosString(r, ['.id'])).filter(Boolean);
          for (const i of mine) await ctx.client.post('/interface/switch.vlan/remove', { '.id': i });
          if (mine.length > 0) details.switchVlans = `removed ${mine.length} port row(s)`;
        }
      } catch { /* best-effort — no switch chip or table gone */ }
    }

    // 3. The VLAN itself (single-object /remove — array bodies are rejected).
    await ctx.client.post('/interface/vlan/remove', { '.id': id });

    // Verify by re-read.
    const afterVlans = await ctx.client.get<Row[]>('/interface/vlan').catch(() => [] as Row[]);
    if (afterVlans.some((v) => rosString(v, ['.id']) === id)) {
      return { success: false, error: `verification failed — VLAN ${vlanName} still present after remove` };
    }

    return { success: true, applied: true, details: { ...details, vlan: `removed VLAN ${vlanName}` } };
  },
};

export const networkIntentActions: ActionDescriptor[] = [networkCreateAction, networkDeleteAction];
