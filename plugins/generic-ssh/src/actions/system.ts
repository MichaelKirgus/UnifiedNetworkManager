/**
 * System actions — identity reads, service control, timezone.
 *
 * Deliberately NO reboot/halt: the user's standing instruction is that this
 * plugin must never interrupt a production system's availability. Service
 * restarts are 'write' (scoped to one unit); everything else here is read-only.
 */

import type { ActionDescriptor } from './types';
import { okResult, failResult, runCommands, serviceCmd, shq, isSafeName } from './types';

export const SYSTEM_ACTIONS: ActionDescriptor[] = [
  {
    id: 'system.info.read',
    label: 'Read system information',
    description: 'Hostname, OS release and uptime — the same identity data the Devices page shows.',
    module: 'System',
    riskLevel: 'read',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const r = await ctx.backend.runSections([
        { name: 'hostname', cmd: "hostname 2>/dev/null" },
        { name: 'release', cmd: "grep -E '^PRETTY_NAME=' /etc/os-release 2>/dev/null | head -1 || true; uname -sr 2>/dev/null" },
        { name: 'uptime', cmd: "awk '{print int($1)}' /proc/uptime 2>/dev/null" },
      ]).catch(() => new Map<string, string>());

      const hostname = (r.get('hostname') ?? '').trim().split('\n')[0]?.trim() ?? '';
      let release = '';
      for (const line of (r.get('release') ?? '').split('\n')) {
        const m = line.match(/^(?:PRETTY_NAME|NAME)=(.*)$/);
        if (m) { release = m[1].replace(/^["']|["']$/g, '').trim(); break; }
      }
      if (!release) {
        const lines = (r.get('release') ?? '').split('\n').map((l) => l.trim()).filter(Boolean);
        release = lines[lines.length - 1] ?? '';
      }
      const uptime = Number((r.get('uptime') ?? '0').trim());
      if (!hostname && !release) return failResult('Could not read system information.');
      return okResult({ hostname: hostname || ctx.host, release, uptimeSeconds: Number.isFinite(uptime) ? uptime : null });
    },
  },
  {
    id: 'system.services.read',
    label: 'List services',
    description: 'All systemd units with their load/active state (sysvinit init.d scripts on non-systemd boxes).',
    module: 'System',
    riskLevel: 'read',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const r = await ctx.backend.exec(
        "if command -v systemctl >/dev/null 2>&1; then systemctl list-units --type=service --all --no-legend --plain 2>/dev/null | head -300; else ls /etc/init.d/ 2>/dev/null; fi",
      ).catch(() => null);
      if (!r) return failResult('Could not read service list.');
      const services: Array<{ name: string; state: string }> = [];
      for (const line of r.stdout.split('\n')) {
        // systemd: "name.service loaded active running Description"
        const m = line.trim().match(/^([a-zA-Z0-9._@:-]+\.service)\s+(\S+)\s+(\S+)\s+(\S+)/);
        if (m) { services.push({ name: m[1], state: `${m[3]} (${m[4]})` }); continue; }
        const plain = line.trim();
        if (/^[a-zA-Z0-9._@:-]+$/.test(plain)) services.push({ name: plain, state: 'init.d' });
      }
      return okResult({ count: services.length, services });
    },
  },
  {
    id: 'system.service.restart',
    label: 'Restart a service',
    description:
      'Restarts ONE named unit (e.g. "sshd", "postfix"). Scoped to that single service — it does NOT touch networking or the SSH session itself unless you name sshd. Verify the unit exists on the target first (system.services.read).',
    module: 'System',
    riskLevel: 'write',
    deviceCount: 1,
    timeoutMs: 60_000,
    inputSchema: {
      name: { type: 'string', required: true, description: 'Unit or init script name (e.g. "postfix", "sshd")' },
    },
    execute: async (ctx, input) => {
      const name = String(input.name).trim();
      if (!isSafeName(name)) return failResult('Invalid service name.');
      // Never let a plan restart the SSH daemon itself — that would kill the
      // session mid-command and leave the device in an unknown state.
      if (/^sshd?$/.test(name) || /^ssh$/i.test(name)) {
        return failResult('Restarting the SSH service is not allowed through UNM (it would terminate the management session).');
      }
      const r = await runCommands(ctx.backend, [serviceCmd('restart', name)], 60_000);
      if (!r.ok) return failResult(`Restart of ${name} failed: ${(r.stderr || r.stdout).slice(0, 300)}`);
      // Verify the unit is active afterwards (best-effort — some units report differently).
      const check = await ctx.backend.exec(serviceCmd('status', name)).catch(() => null);
      const active = /active|running/i.test(check?.stdout ?? '');
      return okResult({ service: name, active });
    },
  },
  {
    id: 'system.timezone.set',
    label: 'Set device timezone',
    description:
      'Sets the system IANA timezone (e.g. "Europe/Berlin"). Reversible — sets whatever zone you choose. On systemd boxes uses timedatectl; otherwise writes /etc/timezone + links /etc/localtime.',
    module: 'System',
    riskLevel: 'write',
    deviceCount: 1,
    timeoutMs: 30_000,
    inputSchema: {
      timezone: { type: 'string', required: true, minLength: 2, maxLength: 64, description: 'IANA timezone identifier (e.g. "Europe/Berlin", "UTC")' },
    },
    execute: async (ctx, input) => {
      const tz = String(input.timezone).trim();
      // IANA identifiers are [A-Za-z0-9_+-/]; reject anything else before it hits the shell.
      if (!/^[A-Za-z][A-Za-z0-9_+-]*(\/[A-Za-z0-9_+-]+)*$/.test(tz)) return failResult('Invalid timezone identifier.');

      const cmds: string[] = [];
      // Detect available zoneinfo path (Debian vs Alpine differ).
      cmds.push(`ZONEFILE=$(ls /usr/share/zoneinfo/${shq(tz)} 2>/dev/null || ls /etc/zoneinfo/${shq(tz)} 2>/dev/null); [ -n "$ZONEFILE" ] || { echo "timezone ${tz} not found in zoneinfo"; exit 1; }`);
      cmds.push(`if command -v timedatectl >/dev/null 2>&1; then timedatectl set-timezone ${shq(tz)}; else ln -sf $ZONEFILE /etc/localtime && echo ${shq(tz)} > /etc/timezone; fi`);
      const r = await runCommands(ctx.backend, cmds, 30_000);
      if (!r.ok) return failResult(`Setting timezone failed: ${(r.stderr || r.stdout).slice(0, 300)}`);

      // Verify the clock now reports the new zone.
      const check = await ctx.backend.exec('date +%Z; cat /etc/timezone 2>/dev/null || readlink -f /etc/localtime 2>/dev/null').catch(() => null);
      return okResult({ timezone: tz, reported: (check?.stdout ?? '').trim().split('\n')[0] ?? null });
    },
  },
];
