import * as ifaces from '../client/interfaces';
import { ActionDescriptor } from './types';

/**
 * Interface actions: settings + logical interfaces (VLAN, LAGG, bridge, loopback, VIP).
 */

function dataOf(res: { ok: boolean; status: number; data: unknown }): Record<string, unknown> | undefined {
  return res.ok && res.data !== null && typeof res.data === 'object' ? (res.data as Record<string, unknown>) : undefined;
}

export const interfaceActions: ActionDescriptor[] = [
  {
    id: 'interfaces.read',
    label: 'Read interfaces + details',
    module: 'Interfaces',
    riskLevel: 'read',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const res = await ifaces.getInterfacesInfo(ctx.client);
      return { success: res.ok, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'interface.settings.set',
    label: 'Update interface settings (staged)',
    module: 'Interfaces',
    riskLevel: 'write',
    staged: true,
    deviceCount: 1,
    inputSchema: { settings: { type: 'object', required: true, description: 'Interface settings object' } },
    execute: async (ctx, input) => {
      const res = await ifaces.setInterfaceSettings(ctx.client, (input.settings as Record<string, unknown>) ?? {});
      return { success: res.ok, applied: false, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'interfaces.reconfigure',
    label: 'Apply staged interface changes',
    module: 'Interfaces',
    riskLevel: 'write',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const res = await ifaces.reconfigureInterfaces(ctx.client);
      return { success: res.ok, applied: res.ok, details: dataOf(res) ?? {} };
    },
  },

  // --- VLANs -------------------------------------------------------------------

  {
    id: 'vlan.add',
    label: 'Add VLAN (staged)',
    module: 'Interfaces',
    riskLevel: 'write',
    staged: true,
    deviceCount: 1,
    inputSchema: { item: { type: 'object', required: true, description: 'VLAN object (interface, tag, description)' } },
    execute: async (ctx, input) => {
      const res = await ifaces.vlans.add(ctx.client, (input.item as Record<string, unknown>) ?? {});
      return { success: res.ok, applied: false, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'vlan.delete',
    label: 'Delete VLAN (staged)',
    module: 'Interfaces',
    riskLevel: 'write',
    staged: true,
    deviceCount: 1,
    inputSchema: { uuid: { type: 'string', required: true } },
    execute: async (ctx, input) => {
      const res = await ifaces.vlans.del(ctx.client, String(input.uuid));
      return { success: res.ok, applied: false, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'vlans.reconfigure',
    label: 'Apply staged VLAN changes',
    module: 'Interfaces',
    riskLevel: 'write',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const res = await ifaces.vlans.reconfigure(ctx.client);
      return { success: res.ok, applied: res.ok, details: dataOf(res) ?? {} };
    },
  },

  // --- LAGG ----------------------------------------------------------------------

  {
    id: 'lagg.add',
    label: 'Add LAGG interface (staged)',
    module: 'Interfaces',
    riskLevel: 'write',
    staged: true,
    deviceCount: 1,
    inputSchema: { item: { type: 'object', required: true, description: 'LAGG object (members, protocol)' } },
    execute: async (ctx, input) => {
      const res = await ifaces.laggs.add(ctx.client, (input.item as Record<string, unknown>) ?? {});
      return { success: res.ok, applied: false, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'lagg.delete',
    label: 'Delete LAGG interface (staged)',
    module: 'Interfaces',
    riskLevel: 'write',
    staged: true,
    deviceCount: 1,
    inputSchema: { uuid: { type: 'string', required: true } },
    execute: async (ctx, input) => {
      const res = await ifaces.laggs.del(ctx.client, String(input.uuid));
      return { success: res.ok, applied: false, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'laggs.reconfigure',
    label: 'Apply staged LAGG changes',
    module: 'Interfaces',
    riskLevel: 'write',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const res = await ifaces.laggs.reconfigure(ctx.client);
      return { success: res.ok, applied: res.ok, details: dataOf(res) ?? {} };
    },
  },
];
