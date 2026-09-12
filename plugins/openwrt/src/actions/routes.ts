/**
 * Routing actions — gateways + static routes over uci (network package).
 */

import type { ActionDescriptor } from './types';
import { sshAvailable, noSshResult } from './types';
import { okResult, failResult, runCommands, readUciPackage } from './helpers';
import { uciSetCmd, uciDelCmd, uciCommitCmd, uciAddSectionCmds, uciSectionCount } from '../client/sshBackend';

export const ROUTES_ACTIONS: ActionDescriptor[] = [
  {
    id: 'routes.read',
    label: 'Read routes',
    description: 'Live routing table (ip route) + configured gateways.',
    module: 'Routing',
    riskLevel: 'read',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const routes = await ctx.backend.routes().catch(() => []);
      return okResult({ count: routes.length, routes });
    },
  },
  {
    id: 'gateways.read',
    label: 'Read gateways',
    description: 'Configured gateway options per interface (uci network).',
    module: 'Routing',
    riskLevel: 'read',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      if (!sshAvailable(ctx)) return noSshResult();
      const tree = await readUciPackage(ctx.backend.ssh!, 'network');
      const gateways: Record<string, unknown>[] = [];
      for (const [key, options] of Object.entries(tree['network'] ?? {})) {
        if (!key.startsWith('@interface[')) continue;
        const gw = options['gateway'];
        if (gw) gateways.push({ key, name: options['name'], gateway: gw });
      }
      return okResult({ gateways });
    },
  },
  {
    id: 'gateway.add',
    label: 'Set interface gateway',
    description: 'Sets the default gateway for an interface (uci network .gateway). Staged — reload applies it.',
    module: 'Routing',
    riskLevel: 'write',
    deviceCount: 1,
    staged: true,
    inputSchema: {
      name: { type: 'string', required: true, description: 'Interface section name (e.g. wan)' },
      gatewayIp: { type: 'string', required: true, description: 'Gateway IPv4 address' },
    },
    execute: async (ctx, input) => {
      if (!sshAvailable(ctx)) return noSshResult();
      const ssh = ctx.backend.ssh!;
      const tree = await readUciPackage(ssh, 'network');
      const section = Object.entries(tree['network'] ?? {}).find(([, o]) => o['name'] === String(input.name));
      if (!section) return failResult(`No interface named "${input.name}" found.`);
      const r = await runCommands(ssh, [
        uciSetCmd('network', section[0], 'gateway', String(input.gatewayIp)),
        uciCommitCmd(),
        '/etc/init.d/network reload >/dev/null 2>&1 || true',
      ]);
      return r.ok ? okResult({ interface: input.name, gateway: input.gatewayIp }) : failResult(`gateway.add failed: ${r.stderr.slice(0, 300)}`);
    },
  },
  {
    id: 'route.add',
    label: 'Add static route',
    description: 'Adds a static route via an interface gateway (uci network .ip4route list). Staged.',
    module: 'Routing',
    riskLevel: 'write',
    deviceCount: 1,
    staged: true,
    inputSchema: {
      name: { type: 'string', required: true, description: 'Interface section name the route is bound to' },
      network: { type: 'string', required: true, description: 'Destination CIDR (e.g. 10.28.0.0/16)' },
    },
    execute: async (ctx, input) => {
      if (!sshAvailable(ctx)) return noSshResult();
      const ssh = ctx.backend.ssh!;
      const tree = await readUciPackage(ssh, 'network');
      const section = Object.entries(tree['network'] ?? {}).find(([, o]) => o['name'] === String(input.name));
      if (!section) return failResult(`No interface named "${input.name}" found.`);
      // ip4route entries are "dest/gw" pairs; the gateway is the interface's own.
      const gw = section[1]['gateway'];
      if (!gw) return failResult(`Interface "${input.name}" has no gateway configured — set one first (gateway.add).`);
      const r = await runCommands(ssh, [
        `uci add_list network.${section[0]}.ip4route='${String(input.network)}/${gw}'`,
        uciCommitCmd(),
        '/etc/init.d/network reload >/dev/null 2>&1 || true',
      ]);
      return r.ok ? okResult({ interface: input.name, network: input.network, gateway: gw }) : failResult(`route.add failed: ${r.stderr.slice(0, 300)}`);
    },
  },
  {
    id: 'routes.reconfigure',
    label: 'Reload routing',
    description: 'Reloads the network service so pending route/gateway changes take effect.',
    module: 'Routing',
    riskLevel: 'write',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      if (!sshAvailable(ctx)) return noSshResult();
      const r = await runCommands(ctx.backend.ssh!, ['/etc/init.d/network reload >/dev/null 2>&1 || true']);
      return r.ok ? okResult() : failResult(`routes.reconfigure failed: ${r.stderr.slice(0, 300)}`);
    },
  },
];
