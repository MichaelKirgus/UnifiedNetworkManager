/**
 * DNS + DHCP actions over uci (dhcp package = dnsmasq on stock OpenWrt).
 */

import type { ActionDescriptor } from './types';
import { sshAvailable, noSshResult } from './types';
import { okResult, failResult, runCommands, readUciPackage } from './helpers';
import { uciSetCmd, uciDelCmd, uciCommitCmd, uciAddSectionCmds, uciSectionCount } from '../client/sshBackend';

export const DNS_ACTIONS: ActionDescriptor[] = [
  {
    id: 'dns.hosts.read',
    label: 'Read static DNS hosts',
    description: 'Configured dnsmasq host records (name → IP).',
    module: 'DNS',
    riskLevel: 'read',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      if (!sshAvailable(ctx)) return noSshResult();
      const tree = await readUciPackage(ctx.backend.ssh!, 'dhcp');
      const hosts: Record<string, unknown>[] = [];
      for (const [key, options] of Object.entries(tree['dhcp'] ?? {})) {
        if (!key.startsWith('@host[') && !key.startsWith('@map[')) continue;
        hosts.push({ key, name: options['name'], ip: options['ip'], mac: options['mac'] });
      }
      return okResult({ count: hosts.length, hosts });
    },
  },
  {
    id: 'dns.host.add',
    label: 'Add static DNS host',
    description: 'Adds a dnsmasq host record (name → IP). Staged — reconfigure applies it.',
    module: 'DNS',
    riskLevel: 'write',
    deviceCount: 1,
    staged: true,
    inputSchema: {
      name: { type: 'string', required: true, description: 'Hostname' },
      ip: { type: 'string', required: true, description: 'IPv4 address' },
    },
    execute: async (ctx, input) => {
      if (!sshAvailable(ctx)) return noSshResult();
      const ssh = ctx.backend.ssh!;
      const tree = await readUciPackage(ssh, 'dhcp');
      // Reuse an existing record with the same name when present.
      const existing = Object.entries(tree['dhcp'] ?? {}).find(([k, o]) => /^@(host|map)\[\d+\]$/.test(k) && (o['name'] === String(input.name) || o['hostname'] === String(input.name)));
      const idx = uciSectionCount(tree['dhcp'], 'host');
      const { sectionKey, cmds } = existing ? { sectionKey: existing[0], cmds: [] as string[] } : uciAddSectionCmds('dhcp', 'host', idx);
      cmds.push(uciSetCmd('dhcp', sectionKey, 'name', String(input.name)));
      cmds.push(uciSetCmd('dhcp', sectionKey, 'ip', String(input.ip)));
      cmds.push(uciCommitCmd());
      const r = await runCommands(ssh, [...cmds, '/etc/init.d/dnsmasq restart >/dev/null 2>&1 || true']);
      return r.ok ? okResult({ host: input.name, ip: input.ip }) : failResult(`dns.host.add failed: ${r.stderr.slice(0, 300)}`);
    },
  },
  {
    id: 'dns.host.delete',
    label: 'Delete static DNS host',
    description: 'Removes a dnsmasq host record by its uci key (from dns.hosts.read).',
    module: 'DNS',
    riskLevel: 'write',
    deviceCount: 1,
    staged: true,
    inputSchema: {
      hostKey: { type: 'string', required: true, description: 'uci key, e.g. @host[2]' },
    },
    execute: async (ctx, input) => {
      if (!sshAvailable(ctx)) return noSshResult();
      const ssh = ctx.backend.ssh!;
      const hostKey = String(input.hostKey);
      if (!/^@\w+\[\d+\]$/.test(hostKey)) return failResult('Invalid host key — expected form @host[N].');
      const r = await runCommands(ssh, [uciDelCmd('dhcp', hostKey), uciCommitCmd(), '/etc/init.d/dnsmasq restart >/dev/null 2>&1 || true']);
      return r.ok ? okResult({ deleted: hostKey }) : failResult(`dns.host.delete failed: ${r.stderr.slice(0, 300)}`);
    },
  },
  {
    id: 'dns.reconfigure',
    label: 'Reload DNS (dnsmasq)',
    description: 'Restarts dnsmasq so pending host records take effect.',
    module: 'DNS',
    riskLevel: 'write',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      if (!sshAvailable(ctx)) return noSshResult();
      const r = await runCommands(ctx.backend.ssh!, ['/etc/init.d/dnsmasq restart >/dev/null 2>&1 || true']);
      return r.ok ? okResult() : failResult(`dns.reconfigure failed: ${r.stderr.slice(0, 300)}`);
    },
  },
];

export const DHCP_ACTIONS: ActionDescriptor[] = [
  {
    id: 'dhcp.staticMappings.read',
    label: 'Read DHCP static mappings',
    description: 'Configured dnsmasq host reservations (MAC → IP).',
    module: 'DHCP',
    riskLevel: 'read',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      if (!sshAvailable(ctx)) return noSshResult();
      const tree = await readUciPackage(ctx.backend.ssh!, 'dhcp');
      const mappings: Record<string, unknown>[] = [];
      for (const [key, options] of Object.entries(tree['dhcp'] ?? {})) {
        if (!key.startsWith('@host[') && !key.startsWith('@map[')) continue;
        mappings.push({ key, name: options['name'], ip: options['ip'], mac: options['mac'] });
      }
      return okResult({ count: mappings.length, mappings });
    },
  },
  {
    id: 'dhcp.staticMapping.add',
    label: 'Add DHCP static mapping',
    description: 'Reserves an IP for a MAC address (dnsmasq host record). Staged.',
    module: 'DHCP',
    riskLevel: 'write',
    deviceCount: 1,
    staged: true,
    inputSchema: {
      mac: { type: 'string', required: true, pattern: '^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', description: 'MAC address (aa:bb:cc:dd:ee:ff)' },
      ip: { type: 'string', required: true, description: 'Reserved IPv4' },
      hostname: { type: 'string', description: 'Hostname to advertise' },
    },
    execute: async (ctx, input) => {
      if (!sshAvailable(ctx)) return noSshResult();
      const ssh = ctx.backend.ssh!;
      const tree = await readUciPackage(ssh, 'dhcp');
      const idx = uciSectionCount(tree['dhcp'], 'host');
      const { sectionKey, cmds } = uciAddSectionCmds('dhcp', 'host', idx);
      cmds.push(uciSetCmd('dhcp', sectionKey, 'mac', String(input.mac)));
      cmds.push(uciSetCmd('dhcp', sectionKey, 'ip', String(input.ip)));
      if (typeof input.hostname === 'string' && input.hostname) cmds.push(uciSetCmd('dhcp', sectionKey, 'name', input.hostname));
      cmds.push(uciCommitCmd());
      const r = await runCommands(ssh, [...cmds, '/etc/init.d/dnsmasq restart >/dev/null 2>&1 || true']);
      return r.ok ? okResult({ mac: input.mac, ip: input.ip }) : failResult(`dhcp.staticMapping.add failed: ${r.stderr.slice(0, 300)}`);
    },
  },
  {
    id: 'dhcp.staticMapping.delete',
    label: 'Delete DHCP static mapping',
    description: 'Removes a dnsmasq host reservation by its uci key.',
    module: 'DHCP',
    riskLevel: 'write',
    deviceCount: 1,
    staged: true,
    inputSchema: {
      hostKey: { type: 'string', required: true, description: 'uci key, e.g. @host[0]' },
    },
    execute: async (ctx, input) => {
      if (!sshAvailable(ctx)) return noSshResult();
      const ssh = ctx.backend.ssh!;
      const hostKey = String(input.hostKey);
      if (!/^@\w+\[\d+\]$/.test(hostKey)) return failResult('Invalid mapping key — expected form @host[N].');
      const r = await runCommands(ssh, [uciDelCmd('dhcp', hostKey), uciCommitCmd(), '/etc/init.d/dnsmasq restart >/dev/null 2>&1 || true']);
      return r.ok ? okResult({ deleted: hostKey }) : failResult(`dhcp.staticMapping.delete failed: ${r.stderr.slice(0, 300)}`);
    },
  },
  {
    id: 'dhcp.reconfigure',
    label: 'Reload DHCP (dnsmasq)',
    description: 'Restarts dnsmasq so pending reservations take effect.',
    module: 'DHCP',
    riskLevel: 'write',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      if (!sshAvailable(ctx)) return noSshResult();
      const r = await runCommands(ctx.backend.ssh!, ['/etc/init.d/dnsmasq restart >/dev/null 2>&1 || true']);
      return r.ok ? okResult() : failResult(`dhcp.reconfigure failed: ${r.stderr.slice(0, 300)}`);
    },
  },
];
