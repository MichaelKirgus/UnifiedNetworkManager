/**
 * System actions — status/info reads, service control, reboot/halt.
 */

import type { ActionDescriptor } from './types';
import { sshAvailable, noSshResult } from './types';
import { okResult, failResult, runCommands } from './helpers';

export const SYSTEM_ACTIONS: ActionDescriptor[] = [
  {
    id: 'system.status.read',
    label: 'Read system status',
    description: 'Board identity (hostname/model/release), uptime and running services.',
    module: 'System',
    riskLevel: 'read',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const [board, services] = await Promise.all([
        ctx.backend.boardInfo().catch(() => null),
        ctx.backend.services().catch(() => [] as Awaited<ReturnType<typeof ctx.backend.services>>),
      ]);
      if (!board && services.length === 0) return failResult('Could not read system status (no transport available).');
      return okResult({ board, serviceCount: services.length });
    },
  },
  {
    id: 'system.info.read',
    label: 'Read system information',
    description: 'Hostname, hardware model and OpenWrt release string.',
    module: 'System',
    riskLevel: 'read',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const board = await ctx.backend.boardInfo().catch(() => null);
      if (!board) return failResult('Could not read system information.');
      return okResult({ hostname: board.hostname, model: board.model, release: board.release, uptimeSeconds: board.uptimeSeconds });
    },
  },
  {
    id: 'system.services.read',
    label: 'List services',
    description: 'All procd init scripts with enabled/running state.',
    module: 'System',
    riskLevel: 'read',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const services = await ctx.backend.services().catch(() => []);
      return okResult({ services });
    },
  },
  {
    id: 'system.service.restart',
    label: 'Restart a service',
    description: 'Restarts one procd service (e.g. dnsmasq, firewall, network).',
    module: 'System',
    riskLevel: 'write',
    deviceCount: 1,
    inputSchema: {
      name: { type: 'string', required: true, description: 'Init script name (/etc/init.d/<name>)' },
    },
    execute: async (ctx, input) => {
      if (!sshAvailable(ctx)) return noSshResult();
      const name = String(input.name).replace(/[^a-zA-Z0-9_-]/g, ''); // init script names are safe alnum
      if (!name) return failResult('Invalid service name.');
      const r = await runCommands(ctx.backend.ssh!, [`/etc/init.d/${name} restart`]);
      return r.ok ? okResult({ service: name }) : failResult(`Restart of ${name} failed: ${r.stderr.slice(0, 300)}`);
    },
  },
  {
    id: 'system.reboot',
    label: 'Reboot device',
    description: 'Schedules an immediate reboot. DANGEROUS — the device is unreachable for ~1 minute.',
    module: 'System',
    riskLevel: 'dangerous',
    deviceCount: 1,
    timeoutMs: 30_000,
    inputSchema: {},
    execute: async (ctx) => {
      if (!sshAvailable(ctx)) return noSshResult();
      // Fire-and-forget: the reboot kills our own session mid-command.
      await ctx.backend.ssh!.exec('reboot', 5_000).catch(() => undefined);
      return okResult({ note: 'Reboot initiated — device will be unreachable briefly.' });
    },
  },
  {
    id: 'system.halt',
    label: 'Halt device',
    description: 'Powers the device off. DANGEROUS.',
    module: 'System',
    riskLevel: 'dangerous',
    deviceCount: 1,
    timeoutMs: 30_000,
    inputSchema: {},
    execute: async (ctx) => {
      if (!sshAvailable(ctx)) return noSshResult();
      await ctx.backend.ssh!.exec('poweroff', 5_000).catch(() => undefined);
      return okResult({ note: 'Power-off initiated.' });
    },
  },
];
