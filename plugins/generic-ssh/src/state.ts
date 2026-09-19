/**
 * POST /state — dynamic device-state document for the UNM Config page.
 *
 * Read-only by design: sections of items with live states + context-aware action
 * references (the webapp opens the matching catalog dialog). Built from FRESH
 * reads so it always reflects current configuration; writes flow through actions.
 */

import type { DeviceStateResponse, StateSection } from '@unm/plugin-sdk';
import type { CommandRunner } from './client/privilege';
import { GenericSshCollector } from './monitoring';

function formatDuration(totalSeconds: number): string {
  const d = Math.floor(totalSeconds / 86400);
  const h = Math.floor((totalSeconds % 86400) / 3600);
  const m = Math.floor((totalSeconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

/** Builds the Config-page state document from one fresh collection pass. */
export async function buildGenericSshState(backend: CommandRunner): Promise<DeviceStateResponse> {
  const collector = new GenericSshCollector(backend);
  const [board, networks, neighborsRes, routes] = await Promise.all([
    collector.boardInfo().catch(() => null),
    collector.interfaces().catch(() => [] as Awaited<ReturnType<typeof collector.interfaces>>),
    collector.neighbors().catch(() => ({ arp: [], ndp: [] })),
    collector.routes().catch(() => [] as Awaited<ReturnType<typeof collector.routes>>),
  ]);

  const sections: StateSection[] = [];

  // --- System -----------------------------------------------------------------
  sections.push({
    id: 'system',
    label: 'System',
    description: 'Board identity + service management for this device.',
    items: [
      {
        key: 'board',
        title: board?.hostname || backend.host,
        subtitle: board?.release ?? null,
        status: 'ok',
        fields: {
          hostname: board?.hostname ?? '',
          release: board?.release ?? '',
          uptime: board?.uptimeSeconds != null ? formatDuration(board.uptimeSeconds) : '',
        },
      },
    ],
    actions: [
      { actionId: 'system.services.read' },
      { actionId: 'snapshot.create' },
      { actionId: 'snapshot.list' },
    ],
  });

  // --- Interfaces ---------------------------------------------------------------
  sections.push({
    id: 'interfaces',
    label: 'Interfaces',
    description: 'Configured network interfaces with live status (one row per address).',
    items: networks.map((n) => ({
      key: `${n.name}:${n.ip ?? '-'}`,
      title: n.name,
      subtitle: n.ip ? `${n.ip}${n.prefix != null ? `/${n.prefix}` : ''}` : null,
      status: (n.status ?? 'unknown').toLowerCase(),
      fields: {
        ip: n.ip ?? '',
        prefix: n.prefix != null ? String(n.prefix) : '',
        version: n.version ?? '',
        mac: n.mac ?? '',
        vlanId: n.vlanId != null ? String(n.vlanId) : '',
      },
    })),
  });

  // --- Routes ---------------------------------------------------------------------
  sections.push({
    id: 'routes',
    label: 'Routes',
    description: `${routes.length} live IPv4 routes (static + connected).`,
    items: routes.map((r, i) => ({
      key: `route-${i}`,
      title: r.destination === '0.0.0.0/0' ? 'default' : r.destination,
      subtitle: r.gateway ? `via ${r.gateway}` : null,
      status: (r.status ?? 'active').toLowerCase(),
      fields: {
        destination: r.destination,
        gateway: r.gateway ?? '',
        protocol: r.protocol ?? '',
        interface: (r.extra?.['interface'] as string | undefined) ?? '',
      },
      // Only UNM-managed static routes are deletable here — connected + default
      // rows would break the box if removed.
      ...(r.protocol === 'static' && r.destination !== '0.0.0.0/0'
        ? { actions: [{ actionId: 'route.delete', prefill: { destination: r.destination, gateway: r.gateway ?? undefined } }] }
        : {}),
    })),
    actions: [
      { actionId: 'routes.read' },
      { actionId: 'route.add' },
    ],
  });

  // --- WireGuard --------------------------------------------------------------------
  const wg = await backend.exec(
    `ls /etc/wireguard/*.conf 2>/dev/null; echo ---; for f in /etc/wireguard/*.conf; do [ -f "$f" ] || continue; echo "## $f"; grep -vE '^PrivateKey' "$f" | head -40; done; echo ---; wg show all 2>/dev/null || true`,
  ).catch(() => null);
  if (wg) {
    const parts = wg.stdout.split('---');
    const files: string[] = (parts[0] ?? '').split('\n').map((l) => l.trim()).filter(Boolean);
    sections.push({
      id: 'wireguard',
      label: 'WireGuard',
      description: files.length > 0 ? `${files.length} configured interface(s)` : 'No wg-quick interfaces configured.',
      items: files.map((f, i) => ({
        key: `wg-${i}`,
        title: f.split('/').pop() ?? f,
        subtitle: null,
        status: /up|online/i.test(parts[2] ?? '') ? 'ok' : 'unknown',
        fields: { config: f },
        actions: [{ actionId: 'wireguard.service.reconfigure', prefill: { name: (f.split('/').pop() ?? '').replace(/\.conf$/, '') } }],
      })),
      actions: [
        { actionId: 'wireguard.tunnels.read' },
        { actionId: 'wireguard.server.set' },
      ],
    });
  }

  // --- Neighbors (context for route planning) ----------------------------------------
  const arp = neighborsRes.arp;
  if (arp.length > 0) {
    sections.push({
      id: 'neighbors',
      label: 'Neighbors',
      description: `${arp.length} ARP entries — useful context when adding routes toward local networks.`,
      items: arp.slice(0, 50).map((h, i) => ({
        key: `arp-${i}`,
        title: h.ip ?? '',
        subtitle: h.mac ?? null,
        status: 'ok',
        fields: { ip: h.ip ?? '', mac: h.mac ?? '', interface: h.intf ?? '' },
      })),
    });
  }

  return { collectedAt: new Date().toISOString(), sections };
}
