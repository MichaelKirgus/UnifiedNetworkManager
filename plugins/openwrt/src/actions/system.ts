/**
 * System actions — status/info reads, service control, reboot/halt.
 */

import type { ActionDescriptor } from './types';
import { sshAvailable, noSshResult } from './types';
import { okResult, failResult, runCommands } from './helpers';
import { uciSetCmd, uciCommitCmd } from '../client/sshBackend';

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
  // --- Unified service lifecycle (Services page — catalog-driven buttons) -----

  {
    id: 'services.start',
    label: 'Start a service',
    description: 'Starts one procd init script (/etc/init.d/<name> start).',
    module: 'Services',
    riskLevel: 'write',
    deviceCount: 1,
    inputSchema: {
      name: { type: 'string', required: true, description: 'Init script name (/etc/init.d/<name>)' },
    },
    execute: async (ctx, input) => {
      if (!sshAvailable(ctx)) return noSshResult();
      const name = String(input.name).replace(/[^a-zA-Z0-9_-]/g, ''); // init script names are safe alnum
      if (!name) return failResult('Invalid service name.');
      const r = await runCommands(ctx.backend.ssh!, [`/etc/init.d/${name} start`]);
      return r.ok ? okResult({ service: name }) : failResult(`Start of ${name} failed: ${r.stderr.slice(0, 300)}`);
    },
  },
  {
    id: 'services.stop',
    label: 'Stop a service',
    description: 'Stops one procd init script (/etc/init.d/<name> stop).',
    module: 'Services',
    riskLevel: 'write',
    deviceCount: 1,
    inputSchema: {
      name: { type: 'string', required: true, description: 'Init script name (/etc/init.d/<name>)' },
    },
    execute: async (ctx, input) => {
      if (!sshAvailable(ctx)) return noSshResult();
      const name = String(input.name).replace(/[^a-zA-Z0-9_-]/g, ''); // init script names are safe alnum
      if (!name) return failResult('Invalid service name.');
      const r = await runCommands(ctx.backend.ssh!, [`/etc/init.d/${name} stop`]);
      return r.ok ? okResult({ service: name }) : failResult(`Stop of ${name} failed: ${r.stderr.slice(0, 300)}`);
    },
  },
  {
    id: 'services.restart',
    label: 'Restart a service',
    description: 'Restarts one procd init script (/etc/init.d/<name> restart).',
    module: 'Services',
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
    id: 'system.timezone.set',
    label: 'Set device timezone',
    description:
      'Sets the system IANA timezone via uci (e.g. "Europe/Berlin") and restarts the system service to apply it. Reversible — sets whatever zone you choose, never forces UTC.',
    module: 'System',
    riskLevel: 'write',
    deviceCount: 1,
    timeoutMs: 30_000,
    inputSchema: {
      timezone: { type: 'string', required: true, minLength: 2, maxLength: 64, description: 'IANA timezone identifier (e.g. "Europe/Berlin", "UTC")' },
    },
    execute: async (ctx, input) => {
      if (!sshAvailable(ctx)) return noSshResult();
      const tz = String(input.timezone).trim();
      // IANA identifiers are [A-Za-z0-9_+-/]; reject anything else before it hits the shell.
      if (!/^[A-Za-z0-9_+\-/]+$/.test(tz)) return failResult('Invalid timezone identifier.');
      const r = await runCommands(ctx.backend.ssh!, [
        uciSetCmd('system', '@system[0]', 'timezone', tz),
        uciCommitCmd(),
        '/etc/init.d/system restart >/dev/null 2>&1 || true',
      ]);
      return r.ok ? okResult({ timezone: tz }) : failResult(`Setting timezone failed: ${r.stderr.slice(0, 300)}`);
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
