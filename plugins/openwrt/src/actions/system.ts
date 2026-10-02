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
  // --- Fleet clock re-sync (Time page "Re-sync devices") ----------------------
  // Canonical action id shared across plugins — deviceCount 'N' fans out one step
  // per device via plan.ts; the API treats non-1 counts as multi-device intents.
  {
    id: 'system.clock.sync',
    label: 'Sync or set device clock',
    description:
      "Re-syncs the router to its configured NTP source (mode='sync') and/or sets a specific wall-clock time and/or IANA timezone (mode='set'). Fleet-wide intent — fans out one step per device. 'sync' restarts the system/ntpd procd service so OpenWrt re-polls its uci-configured NTP servers. 'set' writes the clock with `date -s` and/or the timezone via uci.",
    module: 'System',
    riskLevel: 'write',
    deviceCount: 'N',
    timeoutMs: 60_000,
    inputSchema: {
      mode: { type: 'string', required: true, enum: ['sync', 'set'], description: "'sync' = re-trigger native NTP; 'set' = manual wall-clock and/or timezone" },
      timeUtc: { type: 'string', description: "ISO-8601 UTC instant for mode='set' (e.g. 2026-10-02T14:30:00Z)" },
      timezone: { type: 'string', description: "IANA zone for mode='set' (e.g. Europe/Berlin); independent of timeUtc" },
    },
    execute: async (ctx, input) => {
      if (!sshAvailable(ctx)) return noSshResult();
      const ssh = ctx.backend.ssh!;
      const mode = String(input.mode ?? '').trim();
      if (!['sync', 'set'].includes(mode)) return failResult("mode must be 'sync' or 'set'.");

      // --- sync: re-trigger native NTP ---------------------------------------
      if (mode === 'sync') {
        // Newer OpenWrt runs ntpd as its own procd service; older versions fold it
        // into the system service. Restart whichever exists — both are harmless no-ops otherwise.
        const r = await runCommands(ssh, [
          'if [ -x /etc/init.d/ntpd ]; then /etc/init.d/ntpd restart >/dev/null 2>&1 && { echo "restarted ntpd"; exit 0; }; fi',
          '/etc/init.d/system restart >/dev/null 2>&1 && { echo "restarted system"; exit 0; }',
          'echo "No NTP-capable service found (tried ntpd, system)" >&2; exit 1',
        ], 30_000);
        if (!r.ok) return failResult(`NTP re-sync failed: ${(r.stderr || r.stdout).slice(0, 300)}`);
        const status = await ssh.exec('date -u +%Y-%m-%dT%H:%M:%SZ; uci get system.@system[0].ntp_server 2>/dev/null || true').catch(() => null);
        return okResult({ mode: 'sync', restarted: (r.stdout ?? '').trim(), clockUtc: status?.stdout?.split('\n')[0] });
      }

      // --- set: manual wall-clock and/or timezone ----------------------------
      const timeUtc = typeof input.timeUtc === 'string' && input.timeUtc.trim() ? input.timeUtc.trim() : undefined;
      const tz = typeof input.timezone === 'string' && input.timezone.trim() ? input.timezone.trim() : undefined;
      if (!timeUtc && !tz) return failResult("mode 'set' requires at least one of timeUtc or timezone.");

      const cmds: string[] = [];
      // Timezone first, so the wall-clock set is applied under the final zone.
      if (tz) {
        // IANA identifiers are [A-Za-z0-9_+-/]; reject anything else before it hits the shell.
        if (!/^[A-Za-z][A-Za-z0-9_+-]*(\/[A-Za-z0-9_+-]+)*$/.test(tz)) return failResult('Invalid timezone identifier.');
        cmds.push(uciSetCmd('system', '@system[0]', 'timezone', tz));
      }
      if (timeUtc) {
        // Strict ISO-8601 shape — reject anything that could inject shell.
        if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?(Z|[+-]\d{2}:?\d{2})?$/.test(timeUtc)) return failResult('timeUtc must be an ISO-8601 instant (e.g. 2026-10-02T14:30:00Z).');
        cmds.push(`date -s '${timeUtc}'`);
      }
      if (tz) cmds.push(uciCommitCmd());
      // Apply: restart the service that owns time handling.
      cmds.push('if [ -x /etc/init.d/ntpd ]; then /etc/init.d/ntpd restart >/dev/null 2>&1 || true; fi');
      cmds.push('/etc/init.d/system restart >/dev/null 2>&1 || true');

      const r = await runCommands(ssh, cmds, 30_000);
      if (!r.ok) return failResult(`Setting clock failed: ${r.stderr.slice(0, 300)}`);

      // Verify by re-reading the wall clock + zone.
      const check = await ssh.exec('date -u +%Y-%m-%dT%H:%M:%SZ; date +%Z').catch(() => null);
      const lines = (check?.stdout ?? '').trim().split('\n');
      return okResult({ mode: 'set', timeUtc: timeUtc ?? undefined, timezone: tz ?? undefined, reportedUtc: lines[0] || undefined, reportedZone: lines[1] || undefined });
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
    // Flapping guard — a failed reboot must never be re-dispatched (it would
    // power-cycle the router again).
    retryOnDispatchFailure: false,
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
    // Flapping guard — a failed halt must never be re-dispatched.
    retryOnDispatchFailure: false,
    inputSchema: {},
    execute: async (ctx) => {
      if (!sshAvailable(ctx)) return noSshResult();
      await ctx.backend.ssh!.exec('poweroff', 5_000).catch(() => undefined);
      return okResult({ note: 'Power-off initiated.' });
    },
  },
];
