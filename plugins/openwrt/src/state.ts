/**
 * GET /state — dynamic device-state document for the UNM Config page.
 *
 * Read-only by design (opnsense's actual write path is actions, not inline
 * forms): sections of items with live states + context-aware action references.
 * Built from a fresh inventory snapshot so it always reflects current config.
 */

import type { DeviceStateResponse, StateItem, StateSection } from '@unm/plugin-sdk';
import type { Backend } from './client/backend';
import { getInventory } from './monitoring';
import type { CertificateRow } from '@unm/plugin-sdk';

export async function buildOpenWrtState(backend: Backend, hostKey: string): Promise<DeviceStateResponse> {
  const snap = await getInventory(hostKey, backend, [] as CertificateRow[]);

  const sections: StateSection[] = [];

  // --- System -----------------------------------------------------------------
  const board = snap.board;
  sections.push({
    id: 'system',
    label: 'System',
    description: 'Board identity + transport negotiation for this device.',
    items: [
      {
        key: 'board',
        title: board?.hostname || hostKey,
        subtitle: board ? `${board.model} — ${board.release}` : null,
        status: 'ok',
        fields: {
          hostname: board?.hostname ?? '',
          model: board?.model ?? '',
          release: board?.release ?? '',
          uptime: board?.uptimeSeconds != null ? formatDuration(board.uptimeSeconds) : '',
        },
      },
      {
        key: 'transport',
        title: `Transport: ${backend.state.mode}`,
        subtitle: backend.state.luciBaseUrl ? `LuCI at ${backend.state.luciBaseUrl}` : 'LuCI not in use',
        status: backend.state.sshAvailable ? 'ok' : 'warning',
        fields: {
          mode: backend.state.mode,
          luci: backend.state.luciBaseUrl ?? 'unavailable',
          ssh: backend.state.sshAvailable ? `${backend.host}:${backend.state.report.find((r) => r.startsWith('ssh'))?.split(':').pop() ?? ''}` : 'no credential bound',
        },
      },
    ],
    actions: [
      { actionId: 'system.reboot' },
      { actionId: 'snapshot.create' },
    ],
  });

  // --- Interfaces ---------------------------------------------------------------
  sections.push({
    id: 'interfaces',
    label: 'Interfaces',
    description: 'Configured network interfaces with live status.',
    items: snap.networks.map((n) => ({
      key: n.name,
      title: n.name,
      subtitle: n.ip ? `${n.ip}${n.prefix ? `/${n.prefix}` : ''}` : null,
      status: (n.status ?? 'unknown').toLowerCase(),
      fields: {
        ip: n.ip ?? '',
        prefix: n.prefix != null ? String(n.prefix) : '',
        version: n.version ?? '',
        mac: n.mac ?? '',
        vlanId: n.vlanId != null ? String(n.vlanId) : '',
      },
      actions: [{ actionId: 'interface.settings.set', prefill: { name: n.name } }],
    })),
  });

  // --- Firewall -------------------------------------------------------------------
  const fw = snap.firewallRules ?? [];
  sections.push({
    id: 'firewall',
    label: 'Firewall',
    description: snap.firewallRules === null ? 'Rule collection failed — showing nothing (previous rows kept on the API side).' : `${fw.length} rules`,
    items: fw.slice(0, 100).map((r) => ({
      key: r.vendorRuleId,
      title: r.description || `${r.ruleType}: ${r.sourceIp || 'any'} → ${r.destIp || 'any'}`,
      subtitle: r.scope ? `scope: ${r.scope}` : null,
      status: r.enabled ? (r.action === 'allow' ? 'ok' : 'critical') : 'disabled',
      fields: {
        type: r.ruleType,
        protocol: r.protocol,
        source: r.sourceIp || '',
        destination: r.destIp || '',
        destPort: r.destPort ?? '',
        action: r.action,
      },
      actions: [{ actionId: 'firewall.rules.read' }],
    })),
  });

  // --- Wireless ---------------------------------------------------------------------
  if (snap.wifiSsids.length > 0) {
    sections.push({
      id: 'wireless',
      label: 'Wireless',
      description: `${snap.wifiSsids.length} SSID(s)`,
      items: snap.wifiSsids.map((w, i) => ({
        key: `ssid-${i}`,
        title: w.name,
        subtitle: w.ifc ? `on ${w.ifc}` : null,
        status: 'ok',
        fields: {
          band: w.band,
          channel: w.channel != null ? String(w.channel) : '',
          encryption: w.encryption ?? '',
        },
      })),
    });
  }

  // --- Tunnels ------------------------------------------------------------------------
  if (snap.tunnels.length > 0) {
    sections.push({
      id: 'tunnels',
      label: 'Tunnels',
      description: `${snap.tunnels.length} tunnel(s)`,
      items: snap.tunnels.map((t, i) => ({
        key: `tunnel-${i}`,
        title: t.name,
        subtitle: t.peerAddress ? `peer ${t.peerAddress}` : null,
        status: (t.status ?? 'unknown').toLowerCase(),
        fields: {
          type: t.type,
          subnet: t.subnet ?? '',
          interface: t.interfaceName ?? '',
          lastHandshake: t.lastHandshakeSeconds != null ? `${t.lastHandshakeSeconds}s ago` : '',
        },
      })),
    });
  }

  // --- Services ---------------------------------------------------------------------------
  sections.push({
    id: 'services',
    label: 'Services',
    description: `${snap.services.length} init script(s)`,
    items: snap.services.slice(0, 60).map((s) => ({
      key: s.name,
      title: s.name,
      status: s.running ? 'ok' : 'disabled',
      fields: { enabled: s.enabled ? 'yes' : 'no', running: s.running ? `pid ${s.pid ?? ''}`.trim() : 'stopped' },
      actions: [{ actionId: 'system.service.restart', prefill: { name: s.name } }],
    })),
  });

  return { collectedAt: new Date().toISOString(), sections };
}

function formatDuration(seconds: number): string {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}
