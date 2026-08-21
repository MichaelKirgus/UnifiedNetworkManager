import * as dhcp from '../client/dhcp';
import { ActionDescriptor } from './types';

/**
 * DHCP actions — DUAL BACKEND. Each action dispatches to the appliance's active
 * backend (dnsmasq on older installs, Kea on newer ones) via ctx.dhcpBackend,
 * which the planner resolves by auto-detection or the `dhcpBackend` option.
 */

function dataOf(res: { ok: boolean; status: number; data: unknown }): Record<string, unknown> | undefined {
  return res.ok && res.data !== null && typeof res.data === 'object' ? (res.data as Record<string, unknown>) : undefined;
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
      interface: { type: 'string', required: true },
      mac: { type: 'string', required: true, pattern: '^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$' },
      ip: { type: 'string', required: true },
      hostname: { type: 'string' },
    },
    execute: async (ctx, input) => {
      const res = await dhcp.addStaticMapping(ctx.client, ctx.dhcpBackend, {
        interface: String(input.interface),
        mac: String(input.mac),
        ip: String(input.ip),
        hostname: typeof input.hostname === 'string' ? input.hostname : undefined,
      });
      return { success: res.ok, applied: false, details: dataOf(res) ?? {} };
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
      return { success: res.ok, applied: false, details: dataOf(res) ?? {} };
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
    id: 'dhcp.reconfigure',
    label: 'Apply staged DHCP changes (active backend)',
    module: 'DHCP',
    riskLevel: 'write',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const res = await dhcp.reconfigureDhcp(ctx.client, ctx.dhcpBackend);
      return { success: res.ok, applied: res.ok, details: dataOf(res) ?? {} };
    },
  },
];
