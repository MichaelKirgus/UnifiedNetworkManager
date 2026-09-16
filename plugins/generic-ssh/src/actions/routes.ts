/**
 * Route actions — read/add/delete static routes.
 *
 * Apply is immediate via `ip route` (works on every Linux box). Persistence is
 * best-effort: a small idempotent hook script in /etc/network/if-up.d/ re-adds
 * the route after interface up events on ifupdown-based systems; netplan-only
 * boxes get the live route plus an explicit note that it must be added to their
 * netplan YAML to survive a reboot (editing vendor YAML from shell is too
 * fragile to automate safely).
 */

import type { ActionDescriptor } from './types';
import { okResult, failResult, runCommands, shq, isV4Cidr, isV4Addr, isSafeName } from './types';

const HOOK_DIR = '/etc/network/if-up.d';

/** Stable hook filename for one route (destination + gateway). */
function hookFile(destination: string, gateway?: string): string {
  const slug = `${destination.replace(/[^0-9a-f.]+/gi, '-')}${gateway ? `-${gateway.replace(/[^0-9a-f.]+/gi, '-')}` : ''}`;
  return `${HOOK_DIR}/unm-route-${slug}`;
}

/** The idempotent hook script body for one route. */
function hookScript(destination: string, gateway?: string, iface?: string): string {
  const via = gateway ? `via ${gateway}` : '';
  const dev = iface ? `dev ${iface}` : '';
  return [
    '#!/bin/sh',
    `# UNM-managed static route (managed by the Generic SSH plugin)`,
    `[ "$IFACE" = "lo" ] && exit 0`,
    gateway && iface
      ? `ip route replace ${destination} via ${gateway} dev ${iface}`
      : gateway
        ? `ip route replace ${destination} via ${gateway}`
        : `ip route replace ${destination}${dev}`,
    'exit 0',
  ].filter(Boolean).join('\n');
}

export const ROUTES_ACTIONS: ActionDescriptor[] = [
  {
    id: 'routes.read',
    label: 'Read routing table',
    description: 'The live IPv4 routing table (default + connected + static routes) as reported by `ip route show`.',
    module: 'Routing',
    riskLevel: 'read',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const r = await ctx.backend.exec('ip -4 route show 2>/dev/null').catch(() => null);
      if (!r || r.code !== 0) return failResult('Could not read the routing table.');
      const routes: Array<{ destination: string; gateway?: string; interface?: string }> = [];
      for (const line of r.stdout.split('\n')) {
        const m = line.trim().match(/^(default|(\S+))\s+(?:via\s+(\S+)\s+)?dev\s+(\S+)/);
        if (!m) continue;
        routes.push({ destination: m[1] === 'default' ? '0.0.0.0/0' : m[2], gateway: m[3], interface: m[4] });
      }
      return okResult({ count: routes.length, routes });
    },
  },
  {
    id: 'route.add',
    label: 'Add static route',
    description:
      'Adds one IPv4 static route immediately (ip route) and persists it where possible (ifupdown hook). Re-adding an existing route is a no-op replace. Does NOT touch the default gateway unless you explicitly target 0.0.0.0/0 — prefer a specific CIDR.',
    module: 'Routing',
    riskLevel: 'write',
    deviceCount: 1,
    timeoutMs: 30_000,
    inputSchema: {
      destination: { type: 'string', required: true, description: 'Destination network (IPv4 CIDR, e.g. "10.255.0.0/24")' },
      gateway: { type: 'string', description: 'Next-hop IPv4 address (omit for a directly-connected route)' },
      interface: { type: 'string', description: 'Outgoing interface name (e.g. "ens3"); recommended when no gateway is given' },
    },
    execute: async (ctx, input) => {
      const destination = String(input.destination).trim();
      if (!isV4Cidr(destination)) return failResult('Invalid destination — expected an IPv4 CIDR like 10.255.0.0/24.');
      const gateway = typeof input.gateway === 'string' && input.gateway.trim() ? input.gateway.trim() : undefined;
      if (gateway && !isV4Addr(gateway)) return failResult('Invalid gateway — expected an IPv4 address.');
      const iface = typeof input.interface === 'string' && input.interface.trim() ? input.interface.trim() : undefined;
      if (iface && !isSafeName(iface)) return failResult('Invalid interface name.');

      // A default-route change is the single most disruptive routing edit there
      // is — require it to be explicit AND carry a gateway.
      const isDefault = destination === '0.0.0.0/0';
      if (isDefault && !gateway) return failResult('A default route requires an explicit gateway.');

      const via = gateway ? `via ${gateway}` : '';
      const dev = iface ? `dev ${iface}` : '';
      const applyCmd = `ip route replace ${destination} ${via} ${dev}`.replace(/\s+/g, ' ').trim();

      // 1) Apply immediately (idempotent — `replace` overwrites an existing entry).
      const r = await runCommands(ctx.backend, [applyCmd], 30_000);
      if (!r.ok) return failResult(`ip route failed: ${(r.stderr || r.stdout).slice(0, 300)}`);

      // 2) Persist best-effort via an ifupdown hook (idempotent re-add on iface up).
      let persisted = false;
      const hook = hookFile(destination, gateway);
      const persist = await runCommands(ctx.backend, [
        `[ -d ${HOOK_DIR} ] || exit 0`, // netplan-only box — no ifupdown hooks here
        `printf '%s' ${shq(hookScript(destination, gateway, iface))} > ${hook}`,
        'chmod +x ' + hook,
      ], 30_000);
      persisted = persist.ok;

      // 3) Verify the route is live.
      const check = await ctx.backend.exec(`ip -4 route show ${destination} 2>/dev/null || true`).catch(() => null);
      return okResult({
        destination, gateway: gateway ?? null, interface: iface ?? null,
        applied: true,
        persisted,
        persistenceNote: persisted
          ? 'ifupdown hook installed — route re-applies on interface up events.'
          : 'No ifupdown hooks on this system (netplan-only?) — the route is live now but add it to your netplan YAML for reboot survival.',
        liveEntry: (check?.stdout ?? '').trim().split('\n')[0] ?? null,
      });
    },
  },
  {
    id: 'route.delete',
    label: 'Delete static route',
    description:
      'Removes one IPv4 route from the live table and deletes its UNM ifupdown hook (if present). Deleting the default route will cut off remote management — use with care.',
    module: 'Routing',
    riskLevel: 'write',
    deviceCount: 1,
    timeoutMs: 30_000,
    inputSchema: {
      destination: { type: 'string', required: true, description: 'Destination network (IPv4 CIDR) to remove' },
      gateway: { type: 'string', description: 'Gateway the route was added with (used to locate its hook file)' },
    },
    execute: async (ctx, input) => {
      const destination = String(input.destination).trim();
      if (!isV4Cidr(destination)) return failResult('Invalid destination — expected an IPv4 CIDR.');
      const gateway = typeof input.gateway === 'string' && input.gateway.trim() ? input.gateway.trim() : undefined;

      // Refuse to delete the default route through UNM — that is a manual,
      // deliberate operation (it would sever this very management path).
      if (destination === '0.0.0.0/0') {
        return failResult('Deleting the default route is not allowed through UNM (it would sever remote management).');
      }

      const hook = hookFile(destination, gateway);
      const r = await runCommands(ctx.backend, [
        `ip route del ${destination} 2>/dev/null || true`, // absent route = already gone
        `rm -f ${hook}`,
      ], 30_000);
      if (!r.ok) return failResult(`Route deletion failed: ${(r.stderr || r.stdout).slice(0, 300)}`);

      const check = await ctx.backend.exec(`ip -4 route show ${destination} 2>/dev/null || true`).catch(() => null);
      const stillThere = (check?.stdout ?? '').trim().length > 0;
      return okResult({ destination, deleted: !stillThere, hookRemoved: true });
    },
  },
];
