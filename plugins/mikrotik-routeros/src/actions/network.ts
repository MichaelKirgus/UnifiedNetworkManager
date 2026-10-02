/**
 * Network-module actions for RouterOS (verified live on 7.21 LTS).
 *
 * Covers the L3 surface a complex deployment needs: interface inventory +
 * per-interface settings, VLANs, static routes, default gateways, the full
 * DHCP server stack (server + pool + network + static leases) and DNS
 * (servers singleton + static hosts). All writes apply IMMEDIATELY — RouterOS
 * has no staged/reconfigure model; every write is verified by a re-read.
 */

import { rosNumber, rosString } from '../routerosClient';
import type { ActionContext, ActionDescriptor } from './types';

type Row = Record<string, unknown>;

// --- small v4 CIDR helpers -----------------------------------------------------------------

/** Parses "a.b.c.d/p" into [base, prefix]; null when malformed. */
function parseV4Cidr(cidr: string): { base: number; prefix: number } | null {
  const m = cidr.trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/);
  if (!m) return null;
  const octets = [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])];
  if (octets.some((o) => o > 255)) return null;
  const prefix = Number(m[5]);
  if (prefix < 8 || prefix > 30) return null; // need at least a handful of hosts
  const base = ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  return { base: (base & mask) >>> 0, prefix };
}

function numToIp(n: number): string {
  return `${(n >>> 24) & 255}.${(n >>> 16) & 255}.${(n >>> 8) & 255}.${n & 255}`;
}

/** Derives a DHCP range from a LAN CIDR: skips the network address, .1 (the router itself) and the broadcast. */
function cidrToDhcpRange(cidr: string): { start: string; end: string } | null {
  const parsed = parseV4Cidr(cidr);
  if (!parsed) return null;
  const size = 2 ** (32 - parsed.prefix);
  const start = (parsed.base + 2) >>> 0; // skip network + .1
  const end = (parsed.base + size - 2) >>> 0; // skip broadcast
  if (start > end) return null;
  return { start: numToIp(start), end: numToIp(end) };
}

// --- interfaces.read --------------------------------------------------------------------------

export const interfacesReadAction: ActionDescriptor = {
  id: 'interfaces.read',
  label: 'Read all interfaces',
  description: "Lists every interface on the router — ethernet, bridge, VLAN, bonding and WireGuard — with running/disabled state and MTU.",
  module: 'Network',
  riskLevel: 'read',
  deviceCount: 1,
  inputSchema: {},
  execute: async (ctx) => {
    const tables: Array<[string, string]> = [
      ['/interface/ethernet', 'ether'],
      ['/interface/bridge', 'bridge'],
      ['/interface/vlan', 'vlan'],
      ['/interface/bonding', 'bonding'],
      ['/interface/wireguard', 'wireguard'],
    ];
    const results = await Promise.all(tables.map(([t]) => ctx.client.get<Row[]>(t).catch(() => [] as Row[])));
    const interfaces: Array<Record<string, unknown>> = [];
    results.forEach((rows, i) => {
      for (const r of rows) {
        interfaces.push({
          name: rosString(r, ['name']) ?? null,
          type: tables[i][1],
          running: rosString(r, ['running']) === 'true',
          disabled: rosString(r, ['disabled']) === 'true',
          mtu: rosNumber(r, ['mtu']),
        });
      }
    });
    return { success: true, details: { interfaces } };
  },
};

// --- interface.settings.set ---------------------------------------------------------------------

/** Interface tables that support PATCH-by-name with the settings below. */
const SETTINGS_TABLES = ['/interface/ethernet', '/interface/bridge', '/interface/vlan', '/interface/bonding'] as const;

export const interfaceSettingsSetAction: ActionDescriptor = {
  id: 'interface.settings.set',
  label: 'Set interface settings (MTU/comment/enabled)',
  description: "Updates an existing interface's MTU, comment and/or enabled state (ethernet/bridge/VLAN/bonding). The interface must already exist — create VLANs with vlan.add.",
  module: 'Network',
  riskLevel: 'write',
  deviceCount: 1,
  inputSchema: {
    interface: { type: 'string', required: true, minLength: 1, maxLength: 64, description: 'Interface name (e.g. ether1, bridge1)' },
    mtu: { type: 'number', min: 68, max: 65_535, description: 'New MTU' },
    comment: { type: 'string', maxLength: 256, description: 'Interface comment/description' },
    disabled: { type: 'boolean', description: 'Enable (false) or disable (true) the interface' },
  },
  execute: async (ctx, input) => {
    const name = String(input.interface ?? '').trim();
    const body: Record<string, unknown> = {};
    if (typeof input.mtu === 'number') body['mtu'] = Math.floor(input.mtu as number);
    if (typeof input.comment === 'string') body['comment'] = input.comment;
    if (typeof input.disabled === 'boolean') body['disabled'] = input.disabled;
    if (Object.keys(body).length === 0) return { success: false, error: 'Nothing to set — provide mtu and/or comment and/or disabled.' };

    // Find which table owns this interface.
    let ownerTable: string | null = null;
    for (const t of SETTINGS_TABLES) {
      const rows = await ctx.client.get<Row[]>(t).catch(() => [] as Row[]);
      if (rows.some((r) => rosString(r, ['name']) === name)) {
        ownerTable = t;
        break;
      }
    }
    if (!ownerTable) return { success: false, error: `No interface named "${name}" found (ethernet/bridge/VLAN/bonding).` };

    try {
      await ctx.client.patch(`${ownerTable}/${encodeURIComponent(name)}`, body);
    } catch (e) {
      return { success: false, error: `Updating ${name} failed: ${e instanceof Error ? e.message : String(e)}` };
    }

    const rows = await ctx.client.get<Row[]>(ownerTable).catch(() => [] as Row[]);
    const after = rows.find((r) => rosString(r, ['name']) === name);
    if (!after) return { success: false, error: `Verification failed — ${name} vanished after update.` };
    if (typeof input.mtu === 'number' && rosNumber(after, ['mtu']) !== Math.floor(input.mtu as number)) {
      return { success: false, error: `Verification failed — MTU of ${name} is ${rosString(after, ['mtu'])}, expected ${Math.floor(input.mtu as number)}.` };
    }
    if (typeof input.disabled === 'boolean' && rosString(after, ['disabled']) === 'true' !== input.disabled) {
      return { success: false, error: `Verification failed — enabled state of ${name} unchanged.` };
    }
    return { success: true, applied: true, details: { interface: name, table: ownerTable.replace('/interface/', ''), ...body } };
  },
};

// --- vlan.add / vlan.delete ------------------------------------------------------------------------

export const vlanAddAction: ActionDescriptor = {
  id: 'vlan.add',
  label: 'Create a VLAN',
  description: "Creates an 802.1q VLAN interface (/interface/vlan) on the given parent port/bridge. Idempotent — an existing VLAN with the same name (or tag+parent) is left untouched.",
  module: 'Network',
  riskLevel: 'write',
  deviceCount: 1,
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, maxLength: 64, description: 'VLAN interface name' },
    vlanId: { type: 'number', required: true, min: 1, max: 4094, description: '802.1q tag (1-4094)' },
    parent: { type: 'string', required: true, minLength: 1, maxLength: 64, description: 'Parent interface (physical port or bridge)' },
  },
  execute: async (ctx, input) => {
    const name = String(input.name ?? '').trim();
    const vlanId = Math.floor(Number(input.vlanId));
    const parent = String(input.parent ?? '').trim();

    const vlans = await ctx.client.get<Row[]>('/interface/vlan').catch(() => [] as Row[]);
    const byName = vlans.find((v) => rosString(v, ['name']) === name);
    if (byName) {
      return { success: true, applied: false, details: { skipped: `VLAN "${name}" already exists (tag ${rosString(byName, ['vlan-id'])} on ${rosString(byName, ['interface'])})` } };
    }
    const byTag = vlans.find((v) => Number(rosString(v, ['vlan-id'])) === vlanId && rosString(v, ['interface']) === parent);
    if (byTag) {
      return { success: true, applied: false, details: { skipped: `VLAN ${vlanId} on ${parent} already exists as "${rosString(byTag, ['name'])}"` } };
    }

    try {
      await ctx.client.put('/interface/vlan', { name, 'vlan-id': String(vlanId), interface: parent });
    } catch (e) {
      return { success: false, error: `Creating VLAN ${name} failed: ${e instanceof Error ? e.message : String(e)}` };
    }

    const after = (await ctx.client.get<Row[]>('/interface/vlan').catch(() => [] as Row[])).find((v) => rosString(v, ['name']) === name);
    if (!after || Number(rosString(after, ['vlan-id'])) !== vlanId) {
      return { success: false, error: `Verification failed — VLAN ${name} not present after create.` };
    }
    return { success: true, applied: true, details: { created: name, vlanId, parent } };
  },
};

export const vlanDeleteAction: ActionDescriptor = {
  id: 'vlan.delete',
  label: 'Delete a VLAN',
  description: "Removes an 802.1q VLAN interface by name (and any L3 addresses bound to it). Idempotent — an unknown name is a no-op.",
  module: 'Network',
  riskLevel: 'write',
  deviceCount: 1,
  inputSchema: { name: { type: 'string', required: true, minLength: 1, maxLength: 64, description: 'VLAN interface name to remove' } },
  execute: async (ctx, input) => {
    const name = String(input.name ?? '').trim();
    const vlans = await ctx.client.get<Row[]>('/interface/vlan').catch(() => [] as Row[]);
    const target = vlans.find((v) => rosString(v, ['name']) === name);
    if (!target) return { success: true, applied: false, details: { skipped: `no VLAN named "${name}"` } };

    const id = rosString(target, ['.id']);
    if (!id) return { success: false, error: `VLAN ${name} has no .id — cannot remove it.` };

    // Addresses bound to the VLAN (v4 + v6) go first.
    let removedAddrs = 0;
    for (const table of ['/ip/address', '/ipv6/address']) {
      const addrs = await ctx.client.get<Row[]>(table).catch(() => [] as Row[]);
      const mine = addrs.filter((a) => rosString(a, ['interface', 'actual-interface']) === name).map((a) => rosString(a, ['.id'])).filter(Boolean);
      for (const i of mine) await ctx.client.delete(`${table}/${i}`).catch(() => undefined);
      removedAddrs += mine.length;
    }

    try {
      await ctx.client.delete(`/interface/vlan/${id}`);
    } catch (e) {
      return { success: false, error: `Deleting VLAN ${name} failed: ${e instanceof Error ? e.message : String(e)}` };
    }

    const after = (await ctx.client.get<Row[]>('/interface/vlan').catch(() => [] as Row[])).find((v) => rosString(v, ['name']) === name);
    if (after) return { success: false, error: `Verification failed — VLAN ${name} still present.` };
    return { success: true, applied: true, details: { deleted: name, removedAddresses: removedAddrs } };
  },
};

// --- routes.read / route.add / route.delete -----------------------------------------------------------

export const routesReadAction: ActionDescriptor = {
  id: 'routes.read',
  label: 'Read IP routes',
  description: "Lists the router's IPv4 routes (/ip/route) — destination, gateway, protocol and active state.",
  module: 'Network',
  riskLevel: 'read',
  deviceCount: 1,
  inputSchema: {},
  execute: async (ctx) => {
    const rows = await ctx.client.get<Row[]>('/ip/route').catch(() => [] as Row[]);
    return {
      success: true,
      details: {
        routes: rows.map((r) => ({
          destination: rosString(r, ['dst-address']) ?? null,
          gateway: rosString(r, ['gateway', 'immediate-gw']) ?? '',
          protocol: rosString(r, ['protocol']) ?? null,
          distance: rosNumber(r, ['distance']),
          active: rosString(r, ['active']) === 'true' || rosString(r, ['static']) === 'true',
        })),
      },
    };
  },
};

export const routeAddAction: ActionDescriptor = {
  id: 'route.add',
  label: 'Add a static route',
  description: "Adds a static IPv4 route (/ip/route). Idempotent — an identical destination+gateway is left untouched; a conflicting gateway for the same destination is updated in place.",
  module: 'Network',
  riskLevel: 'write',
  deviceCount: 1,
  inputSchema: {
    destination: { type: 'string', required: true, pattern: '^\\d{1,3}(\\.\\d{1,3}){3}/\\d{1,2}$', description: 'Destination CIDR (e.g. 10.42.0.0/24)' },
    gateway: { type: 'string', required: true, pattern: '^\\d{1,3}(\\.\\d{1,3}){3}$', description: 'Next-hop IP address' },
    distance: { type: 'number', min: 1, max: 255, description: 'Route distance (default 1)' },
    comment: { type: 'string', maxLength: 256, description: 'Route comment' },
  },
  execute: async (ctx, input) => {
    const destination = String(input.destination ?? '').trim();
    const gateway = String(input.gateway ?? '').trim();

    const rows = await ctx.client.get<Row[]>('/ip/route').catch(() => [] as Row[]);
    const sameDst = rows.filter((r) => rosString(r, ['dst-address']) === destination && rosString(r, ['protocol']) !== 'connected');
    const exact = sameDst.find((r) => (rosString(r, ['gateway', 'immediate-gw']) ?? '').split('%')[0] === gateway);
    if (exact) {
      return { success: true, applied: false, details: { skipped: `route ${destination} via ${gateway} already exists` } };
    }

    const body: Record<string, unknown> = { 'dst-address': destination, gateway };
    if (typeof input.distance === 'number') body['distance'] = Math.floor(input.distance as number);
    if (typeof input.comment === 'string' && input.comment) body['comment'] = input.comment;

    try {
      await ctx.client.put('/ip/route', body);
    } catch (e) {
      return { success: false, error: `Adding route ${destination} failed: ${e instanceof Error ? e.message : String(e)}` };
    }

    const after = (await ctx.client.get<Row[]>('/ip/route').catch(() => [] as Row[])).find(
      (r) => rosString(r, ['dst-address']) === destination && (rosString(r, ['gateway', 'immediate-gw']) ?? '').split('%')[0] === gateway
    );
    if (!after) return { success: false, error: `Verification failed — route ${destination} via ${gateway} not present after create.` };
    return { success: true, applied: true, details: { added: `${destination} via ${gateway}` } };
  },
};

export const routeDeleteAction: ActionDescriptor = {
  id: 'route.delete',
  label: 'Delete a static route',
  description: "Removes static IPv4 routes by destination (and optionally gateway). Connected routes are never touched. Idempotent — nothing matching is a no-op.",
  module: 'Network',
  riskLevel: 'write',
  deviceCount: 1,
  inputSchema: {
    destination: { type: 'string', required: true, pattern: '^\\d{1,3}(\\.\\d{1,3}){3}/\\d{1,2}$', description: 'Destination CIDR to remove' },
    gateway: { type: 'string', pattern: '^\\d{1,3}(\\.\\d{1,3}){3}$', description: 'Only remove the route via this next-hop (omit = all static routes for the destination)' },
  },
  execute: async (ctx, input) => {
    const destination = String(input.destination ?? '').trim();
    const gateway = typeof input.gateway === 'string' && input.gateway.trim() ? input.gateway.trim() : null;

    const rows = await ctx.client.get<Row[]>('/ip/route').catch(() => [] as Row[]);
    const mine = rows.filter((r) => {
      if (rosString(r, ['dst-address']) !== destination || rosString(r, ['protocol']) === 'connected') return false;
      if (!gateway) return true;
      return (rosString(r, ['gateway', 'immediate-gw']) ?? '').split('%')[0] === gateway;
    });
    if (mine.length === 0) {
      return { success: true, applied: false, details: { skipped: `no static route for ${destination}${gateway ? ` via ${gateway}` : ''}` } };
    }

    let removed = 0;
    for (const r of mine) {
      const id = rosString(r, ['.id']);
      if (!id) continue;
      await ctx.client.delete(`/ip/route/${id}`).catch(() => undefined);
      removed += 1;
    }

    const after = (await ctx.client.get<Row[]>('/ip/route').catch(() => [] as Row[])).filter(
      (r) => rosString(r, ['dst-address']) === destination && rosString(r, ['protocol']) !== 'connected' && (!gateway || (rosString(r, ['gateway', 'immediate-gw']) ?? '').split('%')[0] === gateway)
    );
    if (after.length > 0) return { success: false, error: `Verification failed — ${after.length} route(s) for ${destination} still present.` };
    return { success: true, applied: true, details: { removed } };
  },
};

// --- gateways (default routes) ---------------------------------------------------------------------------

/** Reads the current default gateway routes (v4 + v6). */
async function readDefaultGateways(ctx: ActionContext): Promise<Array<{ version: 'v4' | 'v6'; destination: string; gateway: string }>> {
  const out: Array<{ version: 'v4' | 'v6'; destination: string; gateway: string }> = [];
  for (const [table, dst, ver] of [['/ip/route', '0.0.0.0/0', 'v4'], ['/ipv6/route', '::/0', 'v6']] as const) {
    const rows = await ctx.client.get<Row[]>(table).catch(() => [] as Row[]);
    for (const r of rows) {
      if (rosString(r, ['dst-address']) !== dst || rosString(r, ['protocol']) === 'connected') continue;
      const gw = (rosString(r, ['gateway', 'immediate-gw']) ?? '').split('%')[0];
      if (gw) out.push({ version: ver, destination: dst, gateway: gw });
    }
  }
  return out;
}

export const gatewaysReadAction: ActionDescriptor = {
  id: 'gateways.read',
  label: 'Read default gateways',
  description: "Shows the router's default routes (0.0.0.0/0 and ::/0) — the effective upstream next-hops.",
  module: 'Network',
  riskLevel: 'read',
  deviceCount: 1,
  inputSchema: {},
  execute: async (ctx) => {
    const gateways = await readDefaultGateways(ctx);
    return { success: true, details: { gateways } };
  },
};

export const gatewayAddAction: ActionDescriptor = {
  id: 'gateway.add',
  label: 'Set default gateway',
  description: "Adds the default route(s) (0.0.0.0/0 and/or ::/0). Idempotent — an identical next-hop is left untouched; a different existing default for the same family is replaced.",
  module: 'Network',
  riskLevel: 'write',
  deviceCount: 1,
  inputSchema: {
    gateway: { type: 'string', pattern: '^\\d{1,3}(\\.\\d{1,3}){3}$', description: 'IPv4 next-hop (set for a v4 default route)' },
    gatewayV6: { type: 'string', description: 'IPv6 next-hop (set for a v6 default route)' },
    distance: { type: 'number', min: 1, max: 255, description: 'Route distance (default 1)' },
  },
  execute: async (ctx, input) => {
    const gw4 = typeof input.gateway === 'string' && input.gateway.trim() ? input.gateway.trim() : null;
    const gw6 = typeof input.gatewayV6 === 'string' && input.gatewayV6.trim() ? input.gatewayV6.trim() : null;
    if (!gw4 && !gw6) return { success: false, error: 'Provide gateway (IPv4) and/or gatewayV6.' };

    const existing = await readDefaultGateways(ctx);
    const details: Record<string, unknown> = {};
    let applied = false;

    for (const [family, dst, table, gw] of [['v4', '0.0.0.0/0', '/ip/route', gw4], ['v6', '::/0', '/ipv6/route', gw6]] as const) {
      if (!gw) continue;
      const current = existing.filter((g) => g.version === family);
      const same = current.find((g) => g.gateway === gw);
      if (same) {
        details[family] = `unchanged (${gw})`;
        continue;
      }
      // Replace any conflicting default for this family.
      for (const c of current) {
        const rows = await ctx.client.get<Row[]>(table).catch(() => [] as Row[]);
        const row = rows.find((r) => rosString(r, ['dst-address']) === dst && (rosString(r, ['gateway', 'immediate-gw']) ?? '').split('%')[0] === c.gateway && rosString(r, ['protocol']) !== 'connected');
        if (row) {
          const id = rosString(row, ['.id']);
          if (id) await ctx.client.delete(`${table}/${id}`).catch(() => undefined);
        }
      }
      const body: Record<string, unknown> = { 'dst-address': dst, gateway: gw };
      if (typeof input.distance === 'number') body['distance'] = Math.floor(input.distance as number);
      try {
        await ctx.client.put(table, body);
      } catch (e) {
        return { success: false, error: `Setting ${family} default gateway failed: ${e instanceof Error ? e.message : String(e)}` };
      }
      details[family] = current.length > 0 ? `replaced ${current.map((c) => c.gateway).join(',')} → ${gw}` : `set to ${gw}`;
      applied = true;
    }

    const after = await readDefaultGateways(ctx);
    if (gw4 && !after.some((g) => g.version === 'v4' && g.gateway === gw4)) {
      return { success: false, error: `Verification failed — v4 default gateway is not ${gw4}.` };
    }
    if (gw6 && !after.some((g) => g.version === 'v6' && g.gateway === gw6)) {
      return { success: false, error: `Verification failed — v6 default gateway is not ${gw6}.` };
    }
    return { success: true, applied, details };
  },
};

export const gatewayDeleteAction: ActionDescriptor = {
  id: 'gateway.delete',
  label: 'Remove default gateway',
  description: "Removes a specific default route by its next-hop — 0.0.0.0/0 via `gateway` and/or ::/0 via `gatewayV6`. Only the exact next-hops given are touched (no bulk removal). Idempotent — nothing matching is a no-op.",
  module: 'Network',
  riskLevel: 'write',
  deviceCount: 1,
  inputSchema: {
    gateway: { type: 'string', pattern: '^\\d{1,3}(\\.\\d{1,3}){3}$', description: 'Remove the v4 default route via this next-hop' },
    gatewayV6: { type: 'string', description: 'Remove the v6 default route via this next-hop' },
  },
  execute: async (ctx, input) => {
    const gw4 = typeof input.gateway === 'string' && input.gateway.trim() ? input.gateway.trim() : null;
    const gw6 = typeof input.gatewayV6 === 'string' && input.gatewayV6.trim() ? input.gatewayV6.trim() : null;
    if (!gw4 && !gw6) return { success: false, error: 'Provide gateway (v4 family) and/or gatewayV6 — at least one must be set.' };

    let removed = 0;
    for (const [table, dst, filter] of [['/ip/route', '0.0.0.0/0', gw4], ['/ipv6/route', '::/0', gw6]] as const) {
      if (filter === null) continue; // only the families explicitly asked for
      const rows = await ctx.client.get<Row[]>(table).catch(() => [] as Row[]);
      const mine = rows.filter((r) => {
        if (rosString(r, ['dst-address']) !== dst || rosString(r, ['protocol']) === 'connected') return false;
        const gw = (rosString(r, ['gateway', 'immediate-gw']) ?? '').split('%')[0];
        return filter ? gw === filter : gw.length > 0;
      });
      for (const r of mine) {
        const id = rosString(r, ['.id']);
        if (!id) continue;
        await ctx.client.delete(`${table}/${id}`).catch(() => undefined);
        removed += 1;
      }
    }

    if (removed === 0) return { success: true, applied: false, details: { skipped: 'no matching default route' } };
    const after = await readDefaultGateways(ctx);
    return { success: true, applied: true, details: { removed, remaining: after.map((g) => `${g.version}:${g.gateway}`) } };
  },
};

// --- DHCP server stack -------------------------------------------------------------------------------

/** Reads the three tables of the DHCP stack in one pass. */
async function readDhcpStack(ctx: ActionContext): Promise<{ servers: Row[]; pools: Row[]; networks: Row[] }> {
  const [servers, pools, networks] = await Promise.all([
    ctx.client.get<Row[]>('/ip/dhcp-server').catch(() => [] as Row[]),
    ctx.client.get<Row[]>('/ip/pool').catch(() => [] as Row[]),
    ctx.client.get<Row[]>('/ip/dhcp-server/network').catch(() => [] as Row[]),
  ]);
  return { servers, pools, networks };
}

export const dhcpReconfigureAction: ActionDescriptor = {
  id: 'dhcp.reconfigure',
  label: 'Configure DHCP server (pool + range + server)',
  description:
    "Idempotently provisions the full DHCP stack for one LAN interface: an address pool (/ip/pool), a network entry with lease time + DNS (/ip/dhcp-server/network) and the server itself (/ip/dhcp-server). The range is derived from `cidr` (skipping .1 = the router) or given explicitly. Existing matching entries are updated in place.",
  module: 'Network',
  riskLevel: 'write',
  deviceCount: 1,
  timeoutMs: 90_000,
  inputSchema: {
    interface: { type: 'string', required: true, minLength: 1, maxLength: 64, description: 'LAN interface to serve (e.g. bridge1)' },
    cidr: { type: 'string', pattern: '^\\d{1,3}(\\.\\d{1,3}){3}/\\d{1,2}$', description: 'LAN CIDR — the lease range is derived from it (skips .1 and the broadcast)' },
    rangeStart: { type: 'string', pattern: '^\\d{1,3}(\\.\\d{1,3}){3}$', description: 'Explicit first address of the pool (overrides cidr derivation)' },
    rangeEnd: { type: 'string', pattern: '^\\d{1,3}(\\.\\d{1,3}){3}$', description: 'Explicit last address of the pool (overrides cidr derivation)' },
    leaseTime: { type: 'string', maxLength: 32, description: "Lease time (e.g. 30m, 2h — default 30m)" },
    dnsServers: { type: 'array', items: { type: 'string' }, description: 'DNS servers handed out to clients (comma-joined into the network entry)' },
    poolName: { type: 'string', maxLength: 64, description: "Pool name (default: dhcp-<interface>)" },
  },
  execute: async (ctx, input) => {
    const iface = String(input.interface ?? '').trim();
    const leaseTime = typeof input.leaseTime === 'string' && input.leaseTime.trim() ? input.leaseTime.trim() : '30m';
    const poolName = typeof input.poolName === 'string' && input.poolName.trim() ? input.poolName.trim() : `dhcp-${iface}`;
    const dnsServers = Array.isArray(input.dnsServers) ? (input.dnsServers as unknown[]).map((s) => String(s).trim()).filter(Boolean) : [];

    // Resolve the lease range.
    let start: string | null = null;
    let end: string | null = null;
    if (typeof input.rangeStart === 'string' && typeof input.rangeEnd === 'string') {
      start = input.rangeStart.trim();
      end = input.rangeEnd.trim();
    } else if (typeof input.cidr === 'string' && input.cidr) {
      const derived = cidrToDhcpRange(input.cidr);
      if (!derived) return { success: false, error: `Could not derive a lease range from CIDR "${input.cidr}" — provide rangeStart/rangeEnd explicitly.` };
      start = derived.start;
      end = derived.end;
    } else {
      return { success: false, error: 'Provide cidr (or explicit rangeStart + rangeEnd).' };
    }

    const stack = await readDhcpStack(ctx);
    const details: Record<string, unknown> = {};

    // 1. Pool — match by name; update ranges when they differ.
    let pool = stack.pools.find((p) => rosString(p, ['name']) === poolName);
    if (pool) {
      const currentRanges = rosString(pool, ['ranges']) ?? '';
      if (currentRanges !== `${start}-${end}`) {
        try {
          await ctx.client.patch(`/ip/pool/${encodeURIComponent(poolName)}`, { ranges: `${start}-${end}` });
          details.pool = `updated ranges to ${start}-${end}`;
        } catch (e) {
          return { success: false, error: `Updating pool "${poolName}" failed: ${e instanceof Error ? e.message : String(e)}` };
        }
      } else {
        details.pool = 'unchanged';
      }
    } else {
      try {
        await ctx.client.put('/ip/pool', { name: poolName, ranges: `${start}-${end}` });
        details.pool = `created with ${start}-${end}`;
      } catch (e) {
        return { success: false, error: `Creating pool "${poolName}" failed: ${e instanceof Error ? e.message : String(e)}` };
      }
    }

    // 2. Network entry — match by interface + address-range.
    const range = `${start}-${end}`;
    let network = stack.networks.find((n) => rosString(n, ['interface']) === iface && (rosString(n, ['address-range']) ?? '').includes(start));
    if (!network) {
      // A different range on the same interface would overlap — replace it.
      const conflicting = stack.networks.filter((n) => rosString(n, ['interface']) === iface);
      for (const c of conflicting) {
        const id = rosString(c, ['.id']);
        if (id) await ctx.client.delete(`/ip/dhcp-server/network/${id}`).catch(() => undefined);
      }
      try {
        await ctx.client.put('/ip/dhcp-server/network', { 'address-range': range, interface: iface, ...(dnsServers.length > 0 ? { 'dns-server': dnsServers.join(',') } : {}) });
        details.network = `created for ${range} on ${iface}`;
      } catch (e) {
        return { success: false, error: `Creating DHCP network entry failed: ${e instanceof Error ? e.message : String(e)}` };
      }
    } else {
      const body: Record<string, unknown> = {};
      if ((rosString(network, ['address-range']) ?? '') !== range) body['address-range'] = range;
      if (dnsServers.length > 0 && rosString(network, ['dns-server']) !== dnsServers.join(',')) body['dns-server'] = dnsServers.join(',');
      const id = rosString(network, ['.id']);
      if (Object.keys(body).length > 0) {
        try {
          await ctx.client.patch(`/ip/dhcp-server/network/${id ?? ''}`, body);
          details.network = 'updated';
        } catch (e) {
          return { success: false, error: `Updating DHCP network entry failed: ${e instanceof Error ? e.message : String(e)}` };
        }
      } else {
        details.network = 'unchanged';
      }
    }

    // 3. Server — match by name (default dhcp-<iface>) or interface.
    let server = stack.servers.find((s) => rosString(s, ['name']) === poolName || rosString(s, ['interface']) === iface);
    const serverBody: Record<string, unknown> = { name: poolName, interface: iface, 'address-pool': poolName, 'lease-time': leaseTime };
    if (server) {
      const id = rosString(server, ['.id']);
      try {
        await ctx.client.patch(`/ip/dhcp-server/${id ?? ''}`, serverBody);
        details.server = `updated (${poolName} on ${iface})`;
      } catch (e) {
        return { success: false, error: `Updating DHCP server failed: ${e instanceof Error ? e.message : String(e)}` };
      }
    } else {
      try {
        await ctx.client.put('/ip/dhcp-server', serverBody);
        details.server = `created (${poolName} on ${iface})`;
      } catch (e) {
        return { success: false, error: `Creating DHCP server failed: ${e instanceof Error ? e.message : String(e)}` };
      }
    }

    // 4. Verify by re-read.
    const after = await readDhcpStack(ctx);
    if (!after.servers.some((s) => rosString(s, ['interface']) === iface && rosString(s, ['address-pool']) === poolName)) {
      return { success: false, error: `Verification failed — no DHCP server for ${iface} with pool ${poolName}.` };
    }
    if (!after.pools.some((p) => rosString(p, ['name']) === poolName && (rosString(p, ['ranges']) ?? '') === range)) {
      return { success: false, error: `Verification failed — pool "${poolName}" does not carry ${range}.` };
    }
    return { success: true, applied: true, details: { ...details, interface: iface, pool: poolName, range } };
  },
};

// --- DHCP static mappings -------------------------------------------------------------------------------

export const dhcpStaticMappingsReadAction: ActionDescriptor = {
  id: 'dhcp.staticMappings.read',
  label: 'Read DHCP static leases',
  description: "Lists the router's DHCP static lease bindings (/ip/dhcp-server/lease) — MAC → fixed IP.",
  module: 'Network',
  riskLevel: 'read',
  deviceCount: 1,
  inputSchema: {},
  execute: async (ctx) => {
    const rows = await ctx.client.get<Row[]>('/ip/dhcp-server/lease').catch(() => [] as Row[]);
    return {
      success: true,
      details: {
        mappings: rows.map((l) => ({ macAddress: rosString(l, ['mac-address']) ?? null, address: rosString(l, ['address']) ?? null, status: rosString(l, ['status']) ?? null })),
      },
    };
  },
};

export const dhcpStaticMappingAddAction: ActionDescriptor = {
  id: 'dhcp.staticMapping.add',
  label: 'Add a DHCP static lease',
  description: "Binds a MAC address to a fixed IP (/ip/dhcp-server/lease). Idempotent — an existing binding for the MAC is updated in place.",
  module: 'Network',
  riskLevel: 'write',
  deviceCount: 1,
  inputSchema: {
    macAddress: { type: 'string', required: true, pattern: '^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$', description: 'Client MAC address' },
    address: { type: 'string', required: true, pattern: '^\\d{1,3}(\\.\\d{1,3}){3}$', description: 'Fixed IP to hand out' },
  },
  execute: async (ctx, input) => {
    const mac = String(input.macAddress ?? '').trim().toLowerCase();
    const address = String(input.address ?? '').trim();

    const rows = await ctx.client.get<Row[]>('/ip/dhcp-server/lease').catch(() => [] as Row[]);
    const existing = rows.find((l) => (rosString(l, ['mac-address']) ?? '').toLowerCase() === mac);
    if (existing && rosString(existing, ['address']) === address) {
      return { success: true, applied: false, details: { skipped: `lease ${mac} → ${address} already exists` } };
    }

    try {
      if (existing) {
        const id = rosString(existing, ['.id']);
        await ctx.client.patch(`/ip/dhcp-server/lease/${id ?? ''}`, { address });
      } else {
        await ctx.client.put('/ip/dhcp-server/lease', { 'mac-address': mac, address });
      }
    } catch (e) {
      return { success: false, error: `Setting static lease ${mac} failed: ${e instanceof Error ? e.message : String(e)}` };
    }

    const after = (await ctx.client.get<Row[]>('/ip/dhcp-server/lease').catch(() => [] as Row[])).find((l) => (rosString(l, ['mac-address']) ?? '').toLowerCase() === mac);
    if (!after || rosString(after, ['address']) !== address) {
      return { success: false, error: `Verification failed — static lease ${mac} → ${address} not present.` };
    }
    return { success: true, applied: true, details: { [existing ? 'updated' : 'created']: `${mac} → ${address}` } };
  },
};

export const dhcpStaticMappingDeleteAction: ActionDescriptor = {
  id: 'dhcp.staticMapping.delete',
  label: 'Remove a DHCP static lease',
  description: "Removes a DHCP static lease binding by MAC address. Idempotent — an unknown MAC is a no-op.",
  module: 'Network',
  riskLevel: 'write',
  deviceCount: 1,
  inputSchema: { macAddress: { type: 'string', required: true, pattern: '^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$', description: 'MAC address whose binding to remove' } },
  execute: async (ctx, input) => {
    const mac = String(input.macAddress ?? '').trim().toLowerCase();
    const rows = await ctx.client.get<Row[]>('/ip/dhcp-server/lease').catch(() => [] as Row[]);
    const target = rows.find((l) => (rosString(l, ['mac-address']) ?? '').toLowerCase() === mac);
    if (!target) return { success: true, applied: false, details: { skipped: `no static lease for ${mac}` } };

    const id = rosString(target, ['.id']);
    if (!id) return { success: false, error: `Lease for ${mac} has no .id — cannot remove it.` };
    try {
      await ctx.client.delete(`/ip/dhcp-server/lease/${id}`);
    } catch (e) {
      return { success: false, error: `Removing static lease ${mac} failed: ${e instanceof Error ? e.message : String(e)}` };
    }

    const after = (await ctx.client.get<Row[]>('/ip/dhcp-server/lease').catch(() => [] as Row[])).find((l) => (rosString(l, ['mac-address']) ?? '').toLowerCase() === mac);
    if (after) return { success: false, error: `Verification failed — static lease ${mac} still present.` };
    return { success: true, applied: true, details: { deleted: mac } };
  },
};

// --- DNS -------------------------------------------------------------------------------------------------

export const dnsServersSetAction: ActionDescriptor = {
  id: 'dns.servers.set',
  label: 'Set DNS servers',
  description: "Sets the router's own upstream DNS servers (/ip/dns singleton, via POST /ip/dns/set). Idempotent — an identical list is a no-op.",
  module: 'Network',
  riskLevel: 'write',
  deviceCount: 1,
  inputSchema: {
    servers: { type: 'array', required: true, items: { type: 'string' }, description: "Upstream DNS server addresses (e.g. ['1.1.1.1','9.9.9.9'])" },
  },
  execute: async (ctx, input) => {
    const servers = Array.isArray(input.servers) ? (input.servers as unknown[]).map((s) => String(s).trim()).filter(Boolean) : [];
    if (servers.length === 0) return { success: false, error: 'Provide at least one DNS server.' };

    const raw = await ctx.client.get<unknown>('/ip/dns').catch(() => null);
    const row = Array.isArray(raw) ? (raw[0] as Row | undefined) : (raw as Row | undefined);
    const current = rosString(row ?? {}, ['servers']) ?? '';
    if (current === servers.join(',')) {
      return { success: true, applied: false, details: { skipped: `DNS servers already ${current}` } };
    }

    try {
      await ctx.client.post('/ip/dns/set', { servers: servers.join(',') });
    } catch (e) {
      return { success: false, error: `Setting DNS servers failed: ${e instanceof Error ? e.message : String(e)}` };
    }

    const afterRaw = await ctx.client.get<unknown>('/ip/dns').catch(() => null);
    const afterRow = Array.isArray(afterRaw) ? (afterRaw[0] as Row | undefined) : (afterRaw as Row | undefined);
    if ((rosString(afterRow ?? {}, ['servers']) ?? '') !== servers.join(',')) {
      return { success: false, error: `Verification failed — DNS servers are "${rosString(afterRow ?? {}, ['servers'])}" after set.` };
    }
    return { success: true, applied: true, details: { before: current || null, after: servers.join(',') } };
  },
};

export const dnsHostsReadAction: ActionDescriptor = {
  id: 'dns.hosts.read',
  label: 'Read DNS static hosts',
  description: "Lists the router's local DNS host records (/ip/dns/static) — name → address.",
  module: 'Network',
  riskLevel: 'read',
  deviceCount: 1,
  inputSchema: {},
  execute: async (ctx) => {
    const rows = await ctx.client.get<Row[]>('/ip/dns/static').catch(() => [] as Row[]);
    return {
      success: true,
      details: { hosts: rows.map((h) => ({ name: rosString(h, ['name']) ?? null, address: rosString(h, ['address']) ?? null, type: rosString(h, ['type']) ?? 'A', ttl: rosString(h, ['ttl']) ?? null })) },
    };
  },
};

export const dnsHostAddAction: ActionDescriptor = {
  id: 'dns.host.add',
  label: 'Add a DNS static host',
  description: "Adds a local DNS record (/ip/dns/static) — A or AAAA by address shape. Idempotent — an identical name+address is left untouched.",
  module: 'Network',
  riskLevel: 'write',
  deviceCount: 1,
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, maxLength: 253, description: 'Hostname (e.g. nas.local)' },
    address: { type: 'string', required: true, description: 'IPv4 or IPv6 address' },
  },
  execute: async (ctx, input) => {
    const name = String(input.name ?? '').trim();
    const address = String(input.address ?? '').trim();
    const isV6 = address.includes(':');

    const rows = await ctx.client.get<Row[]>('/ip/dns/static').catch(() => [] as Row[]);
    const existing = rows.find((h) => rosString(h, ['name']) === name && rosString(h, ['address']) === address);
    if (existing) return { success: true, applied: false, details: { skipped: `host ${name} → ${address} already exists` } };

    try {
      await ctx.client.put('/ip/dns/static', { name, address });
    } catch (e) {
      return { success: false, error: `Adding DNS host ${name} failed: ${e instanceof Error ? e.message : String(e)}` };
    }

    const after = (await ctx.client.get<Row[]>('/ip/dns/static').catch(() => [] as Row[])).find((h) => rosString(h, ['name']) === name && rosString(h, ['address']) === address);
    if (!after) return { success: false, error: `Verification failed — DNS host ${name} → ${address} not present.` };
    return { success: true, applied: true, details: { created: `${name} → ${address}`, type: isV6 ? 'AAAA' : 'A' } };
  },
};

export const dnsHostDeleteAction: ActionDescriptor = {
  id: 'dns.host.delete',
  label: 'Remove a DNS static host',
  description: "Removes local DNS records by name (all addresses, or only the given one). Idempotent — nothing matching is a no-op.",
  module: 'Network',
  riskLevel: 'write',
  deviceCount: 1,
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, maxLength: 253, description: 'Hostname to remove' },
    address: { type: 'string', description: 'Only remove this specific record (omit = all records for the name)' },
  },
  execute: async (ctx, input) => {
    const name = String(input.name ?? '').trim();
    const address = typeof input.address === 'string' && input.address.trim() ? input.address.trim() : null;

    const rows = await ctx.client.get<Row[]>('/ip/dns/static').catch(() => [] as Row[]);
    const mine = rows.filter((h) => rosString(h, ['name']) === name && (!address || rosString(h, ['address']) === address));
    if (mine.length === 0) return { success: true, applied: false, details: { skipped: `no DNS host "${name}"${address ? ` → ${address}` : ''}` } };

    let removed = 0;
    for (const h of mine) {
      const id = rosString(h, ['.id']);
      if (!id) continue;
      await ctx.client.delete(`/ip/dns/static/${id}`).catch(() => undefined);
      removed += 1;
    }

    const after = (await ctx.client.get<Row[]>('/ip/dns/static').catch(() => [] as Row[])).filter((h) => rosString(h, ['name']) === name && (!address || rosString(h, ['address']) === address));
    if (after.length > 0) return { success: false, error: `Verification failed — ${after.length} record(s) for "${name}" still present.` };
    return { success: true, applied: true, details: { removed } };
  },
};

export const networkActions: ActionDescriptor[] = [
  interfacesReadAction,
  interfaceSettingsSetAction,
  vlanAddAction,
  vlanDeleteAction,
  routesReadAction,
  routeAddAction,
  routeDeleteAction,
  gatewaysReadAction,
  gatewayAddAction,
  gatewayDeleteAction,
  dhcpReconfigureAction,
  dhcpStaticMappingsReadAction,
  dhcpStaticMappingAddAction,
  dhcpStaticMappingDeleteAction,
  dnsServersSetAction,
  dnsHostsReadAction,
  dnsHostAddAction,
  dnsHostDeleteAction,
];
