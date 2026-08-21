import * as routes from '../client/routes';
import { ActionDescriptor } from './types';

/**
 * Routing actions: gateways (routing/settings) + static routes (routes/routes).
 * The SD-LAN/WAN back-route use case is expressed with these: a forward route on
 * firewall A toward the remote subnet via a new gateway, plus a BACK-ROUTE on
 * firewall B toward the origin LAN — both are plain gateway+route steps.
 */

function dataOf(res: { ok: boolean; data: unknown }): Record<string, unknown> | undefined {
  return res.ok && res.data !== null && typeof res.data === 'object' ? (res.data as Record<string, unknown>) : undefined;
}

function rowsOf(res: { ok: boolean; data: unknown }): Record<string, unknown>[] {
  const d = dataOf(res);
  return Array.isArray(d?.['rows']) ? (d!['rows'] as Record<string, unknown>[]) : [];
}

export const routeActions: ActionDescriptor[] = [
  // --- Reads -----------------------------------------------------------------

  {
    id: 'routes.read',
    label: 'Read static routes',
    module: 'Routing',
    riskLevel: 'read',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const res = await routes.searchRoutes(ctx.client);
      return { success: res.ok, details: { rows: rowsOf(res as { ok: boolean; data: unknown }) } };
    },
  },
  {
    id: 'gateways.read',
    label: 'Read gateways',
    module: 'Routing',
    riskLevel: 'read',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const res = await routes.searchGateways(ctx.client);
      return { success: res.ok, details: { rows: rowsOf(res as { ok: boolean; data: unknown }) } };
    },
  },

  // --- Gateways ------------------------------------------------------------------

  {
    id: 'gateway.add',
    label: 'Add gateway (staged)',
    module: 'Routing',
    riskLevel: 'write',
    staged: true,
    deviceCount: 1,
    inputSchema: {
      name: { type: 'string', required: true, description: 'Gateway identifier' },
      interface: { type: 'string', required: true, description: 'Interface (e.g. lan, wan)' },
      gatewayIp: { type: 'string', required: true, description: 'Next-hop IP on that interface' },
    },
    execute: async (ctx, input) => {
      const gw: Record<string, unknown> = {
        name: String(input.name),
        interface: String(input.interface),
        gateway: String(input.gatewayIp),
      };
      const res = await routes.addGateway(ctx.client, gw);
      return { success: res.ok, applied: false, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'gateway.delete',
    label: 'Delete gateway (staged)',
    module: 'Routing',
    riskLevel: 'write',
    staged: true,
    deviceCount: 1,
    inputSchema: { uuid: { type: 'string', required: true } },
    execute: async (ctx, input) => {
      const res = await routes.deleteGateway(ctx.client, String(input.uuid));
      return { success: res.ok, applied: false, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'gateways.reconfigure',
    label: 'Apply staged gateway changes',
    module: 'Routing',
    riskLevel: 'write',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const res = await routes.reconfigureGateways(ctx.client);
      return { success: res.ok, applied: res.ok, details: dataOf(res) ?? {} };
    },
  },

  // --- Static routes -----------------------------------------------------------------

  {
    id: 'route.add',
    label: 'Add static route (staged)',
    module: 'Routing',
    riskLevel: 'write',
    staged: true,
    deviceCount: 1,
    inputSchema: {
      network: { type: 'string', required: true, description: 'Destination CIDR, e.g. 10.255.0.0/24' },
      gatewayName: { type: 'string', required: true, description: 'Gateway to route through (by name)' },
    },
    execute: async (ctx, input) => {
      const r: Record<string, unknown> = {
        network: String(input.network),
        gateway: String(input.gatewayName),
      };
      const res = await routes.addRoute(ctx.client, r);
      return { success: res.ok, applied: false, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'route.delete',
    label: 'Delete static route (staged)',
    module: 'Routing',
    riskLevel: 'write',
    staged: true,
    deviceCount: 1,
    inputSchema: { uuid: { type: 'string', required: true } },
    execute: async (ctx, input) => {
      const res = await routes.deleteRoute(ctx.client, String(input.uuid));
      return { success: res.ok, applied: false, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'routes.reconfigure',
    label: 'Apply staged static-route changes',
    module: 'Routing',
    riskLevel: 'write',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const res = await routes.reconfigureRoutes(ctx.client);
      return { success: res.ok, applied: res.ok, details: dataOf(res) ?? {} };
    },
  },
];
