/**
 * Firewall actions (fw4 = nftables) — read + rule/alias CRUD over uci.
 */

import type { ActionDescriptor } from './types';
import { sshAvailable, noSshResult } from './types';
import { okResult, failResult, runCommands, readUciPackage } from './helpers';
import { parseFirewallUci } from '../client/backend';
import { uciSetCmd, uciAddListCmd, uciDelCmd, uciCommitCmd, uciAddSectionCmds, uciSectionCount, shq } from '../client/sshBackend';

export const FIREWALL_ACTIONS: ActionDescriptor[] = [
  {
    id: 'firewall.rules.read',
    label: 'Read firewall rules',
    description: 'All fw4 filter + NAT rules (unified cross-device shape).',
    module: 'Firewall',
    riskLevel: 'read',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const rows = await ctx.backend.firewallRules();
      if (!rows) return failResult('Could not read firewall rules.');
      return okResult({ count: rows.length, rules: rows });
    },
  },
  {
    id: 'firewall.zones.read',
    label: 'Read firewall zones',
    description: 'fw4 zone definitions (lan/wan/...) with default policies.',
    module: 'Firewall',
    riskLevel: 'read',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      if (!sshAvailable(ctx)) return noSshResult();
      const tree = await readUciPackage(ctx.backend.ssh!, 'firewall');
      const zones: Record<string, unknown>[] = [];
      for (const [key, options] of Object.entries(tree['firewall'] ?? {})) {
        if (!key.startsWith('@zone[')) continue;
        zones.push({ key, ...options });
      }
      return okResult({ zones });
    },
  },
  {
    id: 'firewall.rule.add',
    label: 'Add firewall rule',
    description: 'Adds a new fw4 filter rule (staged — commit + reload applied by the action).',
    module: 'Firewall',
    riskLevel: 'write',
    deviceCount: 1,
    staged: true,
    inputSchema: {
      name: { type: 'string', required: true, description: 'Rule name' },
      srcZone: { type: 'string', default: 'lan', description: 'Source zone (e.g. lan)' },
      destZone: { type: 'string', default: 'wan', description: 'Destination zone (e.g. wan)' },
      target: { type: 'string', enum: ['ACCEPT', 'DROP', 'REJECT'], default: 'ACCEPT' },
      proto: { type: 'string', default: 'all', description: 'Protocol (tcp/udp/all or numbers)' },
      destPort: { type: 'string', description: 'Destination port(s), e.g. 443 or 1000-2000' },
      srcIp: { type: 'string', description: 'Source IP/CIDR (default = whole zone)' },
    },
    execute: async (ctx, input) => {
      if (!sshAvailable(ctx)) return noSshResult();
      const ssh = ctx.backend.ssh!;
      const tree = await readUciPackage(ssh, 'firewall');
      const idx = uciSectionCount(tree['firewall'], 'rule');
      const { sectionKey, cmds } = uciAddSectionCmds('firewall', 'rule', idx);
      cmds.push(uciSetCmd('firewall', sectionKey, 'name', String(input.name)));
      cmds.push(uciSetCmd('firewall', sectionKey, 'src', String(input.srcZone ?? 'lan')));
      cmds.push(uciSetCmd('firewall', sectionKey, 'dest', String(input.destZone ?? 'wan')));
      cmds.push(uciSetCmd('firewall', sectionKey, 'target', String(input.target ?? 'ACCEPT')));
      if (input.proto && input.proto !== 'all') cmds.push(uciSetCmd('firewall', sectionKey, 'proto', String(input.proto)));
      if (typeof input.destPort === 'string' && input.destPort) cmds.push(uciSetCmd('firewall', sectionKey, 'dest_port', input.destPort));
      if (typeof input.srcIp === 'string' && input.srcIp) cmds.push(uciSetCmd('firewall', sectionKey, 'src_ip', input.srcIp));
      cmds.push(uciCommitCmd());
      const r = await runCommands(ssh, [...cmds, '/etc/init.d/firewall restart >/dev/null 2>&1 || true']);
      return r.ok ? okResult({ rule: sectionKey }) : failResult(`firewall.rule.add failed: ${r.stderr.slice(0, 300)}`);
    },
  },
  {
    id: 'firewall.rule.delete',
    label: 'Delete firewall rule',
    description: 'Deletes a fw4 filter rule by its uci key (from firewall.rules.read vendorRuleId).',
    module: 'Firewall',
    riskLevel: 'write',
    deviceCount: 1,
    staged: true,
    inputSchema: {
      ruleKey: { type: 'string', required: true, description: 'uci key, e.g. @rule[3]' },
    },
    execute: async (ctx, input) => {
      if (!sshAvailable(ctx)) return noSshResult();
      const ssh = ctx.backend.ssh!;
      const ruleKey = String(input.ruleKey);
      if (!/^@\w+\[\d+\]$/.test(ruleKey)) return failResult('Invalid rule key — expected form @rule[N].');
      const r = await runCommands(ssh, [uciDelCmd('firewall', ruleKey), uciCommitCmd(), '/etc/init.d/firewall restart >/dev/null 2>&1 || true']);
      return r.ok ? okResult({ deleted: ruleKey }) : failResult(`firewall.rule.delete failed: ${r.stderr.slice(0, 300)}`);
    },
  },
  {
    id: 'firewall.alias.add',
    label: 'Add firewall alias',
    description: 'Adds a named IP/network alias usable in rules.',
    module: 'Firewall',
    riskLevel: 'write',
    deviceCount: 1,
    staged: true,
    inputSchema: {
      name: { type: 'string', required: true },
      value: { type: 'string', required: true, description: 'IP or CIDR' },
    },
    execute: async (ctx, input) => {
      if (!sshAvailable(ctx)) return noSshResult();
      const ssh = ctx.backend.ssh!;
      const tree = await readUciPackage(ssh, 'firewall');
      const idx = uciSectionCount(tree['firewall'], 'alias');
      const { sectionKey, cmds } = uciAddSectionCmds('firewall', 'alias', idx);
      cmds.push(uciSetCmd('firewall', sectionKey, 'name', String(input.name)));
      cmds.push(uciSetCmd('firewall', sectionKey, 'value', String(input.value)));
      cmds.push(uciCommitCmd());
      const r = await runCommands(ssh, [...cmds, '/etc/init.d/firewall restart >/dev/null 2>&1 || true']);
      return r.ok ? okResult({ alias: sectionKey }) : failResult(`firewall.alias.add failed: ${r.stderr.slice(0, 300)}`);
    },
  },
  {
    id: 'firewall.reload',
    label: 'Reload firewall',
    description: 'Restarts the fw4 service (applies any pending changes).',
    module: 'Firewall',
    riskLevel: 'write',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      if (!sshAvailable(ctx)) return noSshResult();
      const r = await runCommands(ctx.backend.ssh!, ['/etc/init.d/firewall restart']);
      return r.ok ? okResult() : failResult(`firewall reload failed: ${r.stderr.slice(0, 300)}`);
    },
  },
];
