import * as dhcp from '../client/dhcp';
import { post } from '../client/http';
import { ActionDescriptor } from './types';

/**
 * DHCP actions — DUAL BACKEND. Each action dispatches to the appliance's active
 * backend (dnsmasq on older installs, Kea on newer ones) via ctx.dhcpBackend,
 * which the planner resolves by auto-detection or the `dhcpBackend` option.
 */

function dataOf(res: { ok: boolean; status: number; data: unknown }): Record<string, unknown> | undefined {
  return res.ok && res.data !== null && typeof res.data === 'object' ? (res.data as Record<string, unknown>) : undefined;
}

/**
 * OPNsense endpoints answer HTTP 200 with `{"result":"failed"}` (model
 * mutations — validation error or ACL denial such as user-config-readonly) or
 * `{"status":"failed"}` (service actions like reconfigure) when the appliance
 * rejects a change — an HTTP-only check would mark those steps succeeded.
 * Treat any non-successful result/status value as failure and surface it in details.
 */
function withResultCheck(res: { ok: boolean; status: number; data: unknown }): {
  success: boolean;
  applied: false;
  details: Record<string, unknown>;
} {
  const d = (res.data !== null && typeof res.data === 'object' ? res.data : {}) as Record<string, unknown>;
  if (!res.ok) return { success: false, applied: false, details: d };
  for (const key of ['result', 'status']) {
    const v = d[key];
    if (typeof v === 'string' && !['ok', 'saved', 'deleted'].includes(v)) {
      return { success: false, applied: false, details: { ...d, error: `appliance rejected the change (${key}=${v})` } };
    }
  }
  return { success: true, applied: false, details: d };
}

export const dhcpActions: ActionDescriptor[] = [
  {
    id: 'dhcp.staticMapping.add',
    label: 'Add DHCP static mapping/reservation (staged)',
    module: 'DHCP',
    riskLevel: 'write',
    staged: true,
    deviceCount: 1,
    inputSchema: {
      // Required only for the dnsmasq backend — Kea reservations bind to a subnet
      // (resolved from the IP), not an interface. The client enforces it per backend.
      interface: { type: 'string', description: 'Serving interface (dnsmasq backend; ignored by Kea)' },
      mac: { type: 'string', required: true, pattern: '^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$' },
      ip: { type: 'string', required: true },
      hostname: { type: 'string' },
    },
    execute: async (ctx, input) => {
      const iface = typeof input.interface === 'string' && input.interface.trim() !== '' ? input.interface : undefined;
      if (!iface && ctx.dhcpBackend === 'dnsmasq') {
        return { success: false, applied: false, details: { error: 'interface is required for the dnsmasq backend' } };
      }
      const res = await dhcp.addStaticMapping(ctx.client, ctx.dhcpBackend, {
        interface: iface ?? '',
        mac: String(input.mac),
        ip: String(input.ip),
        hostname: typeof input.hostname === 'string' ? input.hostname : undefined,
      });
      return withResultCheck(res);
    },
  },
  {
    id: 'dhcp.staticMapping.set',
    label: 'Edit DHCP static mapping/reservation (staged)',
    module: 'DHCP',
    riskLevel: 'write',
    staged: true,
    deviceCount: 1,
    inputSchema: {
      uuid: { type: 'string', required: true, description: 'Reservation/mapping uuid as reported by the dhcpReservations inventory' },
      mac: { type: 'string', required: true, pattern: '^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$' },
      ip: { type: 'string', required: true },
      hostname: { type: 'string' },
    },
    execute: async (ctx, input) => {
      const res = await dhcp.setStaticMapping(ctx.client, ctx.dhcpBackend, String(input.uuid), {
        interface: '',
        mac: String(input.mac),
        ip: String(input.ip),
        hostname: typeof input.hostname === 'string' ? input.hostname : undefined,
      });
      return withResultCheck(res);
    },
  },
  {
    id: 'dhcp.staticMapping.delete',
    label: 'Delete DHCP static mapping/reservation (staged)',
    module: 'DHCP',
    riskLevel: 'write',
    staged: true,
    deviceCount: 1,
    inputSchema: { uuid: { type: 'string', required: true } },
    execute: async (ctx, input) => {
      const res = await dhcp.deleteStaticMapping(ctx.client, ctx.dhcpBackend, String(input.uuid));
      return withResultCheck(res);
    },
  },
  {
    id: 'dhcp.staticMappings.read',
    label: 'Read DHCP static mappings/reservations',
    module: 'DHCP',
    riskLevel: 'read',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const res = await dhcp.searchStaticMappings(ctx.client, ctx.dhcpBackend);
      return { success: res.ok, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'dhcp.network.create',
    label: 'Create DHCP network/range (staged)',
    module: 'DHCP',
    riskLevel: 'write',
    staged: true,
    deviceCount: 1,
    inputSchema: {
      interface: { type: 'string', required: true, description: 'Interface identifier to serve (dnsmasq backend; ignored by Kea)' },
      cidr: { type: 'string', pattern: '^\\d{1,3}(\\.\\d{1,3}){3}/\\d{1,2}$', description: 'Subnet CIDR the range lives in' },
      rangeStart: { type: 'string', required: true, pattern: '^\\d{1,3}(\\.\\d{1,3}){3}$', description: 'First address of the lease range' },
      rangeEnd: { type: 'string', required: true, pattern: '^\\d{1,3}(\\.\\d{1,3}){3}$', description: 'Last address of the lease range' },
    },
    execute: async (ctx, input) => {
      const start = String(input.rangeStart);
      const end = String(input.rangeEnd);
      if (ctx.dhcpBackend === 'dnsmasq') {
        // Same endpoint networkIntents.ts uses for the optional dhcpPool step.
        const res = await post(ctx.client, '/api/dnsmasq/settings/add_range', { item: { interface: String(input.interface), start_addr: start, end_addr: end } });
        return withResultCheck(res);
      }
      // Kea backend — standard Kea subnet shape (subnet + pools). Staged; the plan's
      // dhcp.reconfigure step activates it. Field names follow the OPNsense Kea
      // controller's config blob; a rejected item fails the step with the appliance's error.
      const res = await dhcp.addKeaSubnet(ctx.client, { subnet: String(input.cidr), pools: [{ pool: `${start}-${end}` }] });
      return withResultCheck(res);
    },
  },
  {
    id: 'dhcp.network.delete',
    label: 'Delete DHCP network/range (staged)',
    module: 'DHCP',
    riskLevel: 'write',
    staged: true,
    deviceCount: 1,
    inputSchema: {
      refId: { type: 'string', required: true, description: 'Range/subnet uuid as reported by the dhcpNetworks inventory (dnsmasq range uuid or Kea subnet id)' },
    },
    execute: async (ctx, input) => {
      const ref = String(input.refId);
      if (ctx.dhcpBackend === 'dnsmasq') {
        const res = await post(ctx.client, `/api/dnsmasq/settings/del_range/${encodeURIComponent(ref)}`, {});
        return withResultCheck(res);
      }
      const res = await dhcp.deleteKeaSubnet(ctx.client, ref);
      return withResultCheck(res);
    },
  },
  {
    id: 'dhcp.reconfigure',
    label: 'Apply staged DHCP changes (active backend)',
    module: 'DHCP',
    riskLevel: 'write',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const res = await dhcp.reconfigureDhcp(ctx.client, ctx.dhcpBackend);
      const checked = withResultCheck(res);
      return { ...checked, applied: checked.success };
    },
  },
];
