import * as dns from '../client/dns';
import { ActionDescriptor } from './types';

/**
 * DNS actions — DUAL BACKEND. Each action dispatches to the appliance's active
 * backend (dnsmasq on older installs, Unbound on newer ones) via ctx.dnsBackend,
 * which the planner resolves by auto-detection or the `dnsBackend` option.
 */

function dataOf(res: { ok: boolean; status: number; data: unknown }): Record<string, unknown> | undefined {
  return res.ok && res.data !== null && typeof res.data === 'object' ? (res.data as Record<string, unknown>) : undefined;
}

export const dnsActions: ActionDescriptor[] = [
  {
    id: 'dns.host.add',
    label: 'Add DNS host record (staged)',
    module: 'DNS',
    riskLevel: 'write',
    staged: true,
    deviceCount: 1,
    inputSchema: { name: { type: 'string', required: true }, ip: { type: 'string', required: true } },
    execute: async (ctx, input) => {
      const res = await dns.addHostRecord(ctx.client, ctx.dnsBackend, { name: String(input.name), ip: String(input.ip) });
      return { success: res.ok, applied: false, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'dns.host.delete',
    label: 'Delete DNS host record (staged)',
    module: 'DNS',
    riskLevel: 'write',
    staged: true,
    deviceCount: 1,
    inputSchema: { uuid: { type: 'string', required: true } },
    execute: async (ctx, input) => {
      const res = await dns.deleteHostRecord(ctx.client, ctx.dnsBackend, String(input.uuid));
      return { success: res.ok, applied: false, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'dns.hosts.read',
    label: 'Read DNS host records',
    module: 'DNS',
    riskLevel: 'read',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const res = await dns.searchHostRecords(ctx.client, ctx.dnsBackend);
      return { success: res.ok, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'dns.reconfigure',
    label: 'Apply staged DNS changes (active backend)',
    module: 'DNS',
    riskLevel: 'write',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const res = await dns.reconfigureDns(ctx.client, ctx.dnsBackend);
      return { success: res.ok, applied: res.ok, details: dataOf(res) ?? {} };
    },
  },
];
