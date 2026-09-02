import { DeviceStateResponse, StateActionRef, StateItem, SwitchLayout } from '@unm/plugin-sdk';
import { SxSwitchSnapshot } from './sxClient';

/**
 * Builds the dynamic device-state document for the UNM Config page (GET /state)
 * from a slow-path inventory snapshot. Sections:
 *   - Ports  — one item per switch port with live link state, speed, VLAN mode/
 *              PVID and (when FDB enrichment is on) the MACs learned on it;
 *              actions = speed/shutdown, PoE, LACP, VLAN (variant-aware).
 *   - System — device summary + a read-only "read port states" action.
 * Action ids reference this plugin's catalog (validated by the API broker);
 * `prefill` seeds the dialog with the port number so the user only picks values.
 */

/** MACs learned on one port, from the neighbor cache (+ FDB enrichment). */
function macsForPort(snapshot: SxSwitchSnapshot, port: number): string[] {
  const out = new Set<string>();
  for (const n of snapshot.neighbors) {
    if (n.port === port && n.mac !== '') out.add(n.mac);
  }
  return Array.from(out).sort();
}

/** One PoE entry's human label ('' when the port has no PoE data). */
function poeLabel(snapshot: SxSwitchSnapshot, port: number): string {
  const e = snapshot.poePorts.find((p) => p.port === port);
  if (!e) return '';
  const watts = e.powerUsedWatts !== null ? `${e.powerUsedWatts} W` : e.pdClass || '—';
  return `${watts}${e.priorityLabel ? ` (${e.priorityLabel})` : ''}`;
}

/** LACP label for a port ('' when not an aggregation member). */
function lacpLabel(snapshot: SxSwitchSnapshot, port: number): string {
  const l = snapshot.lags.find((m) => m.port === port);
  if (!l || !l.lacpLabel || l.lacpLabel === 'No') return '';
  return `LACP ${l.aggrId !== '' && l.aggrId !== '—' ? l.aggrId : ''}${l.key !== '' && l.key !== '—' ? ` key ${l.key}` : ''}`.trim();
}

export function buildSxState(snapshot: SxSwitchSnapshot): DeviceStateResponse {
  const sx4 = snapshot.variant === 'sx4';

  // --- Ports -----------------------------------------------------------------
  const portItems: StateItem[] = snapshot.ports.map((p) => {
    const macs = macsForPort(snapshot, p.port);
    const fields: Record<string, string | number | null | unknown[]> = {
      speed: p.speedStatus || (p.media && p.media !== '' ? `${p.speedStatus} (${p.media})` : '') || null,
      'VLAN mode': p.vlanModeLabel || null,
      PVID: p.pvid !== null ? String(p.pvid) : null,
    };
    if (sx4) {
      fields['Allowed VLANs'] = p.allowedVlans || null;
      const poe = poeLabel(snapshot, p.port);
      if (poe) fields.PoE = poe;
      const lacp = lacpLabel(snapshot, p.port);
      if (lacp) fields.LACP = lacp;
    }
    if (macs.length > 0) fields.MACs = macs;

    // Per-port actions — variant-aware: PoE/LACP/VLAN objects only exist on 4.x.
    const portNum = p.port;
    const actions: StateActionRef[] = [
      { actionId: 'port.speedMode.set', prefill: { port: portNum } },
    ];
    if (sx4) {
      actions.push(
        { actionId: 'vlan.pvid.set', prefill: { port: portNum } },
        { actionId: 'vlan.mode.set', prefill: { port: portNum } },
        { actionId: 'lacp.port.set', prefill: { port: portNum, enabled: false } },
      );
      if (snapshot.poePorts.some((e) => e.port === portNum)) {
        actions.push(
          { actionId: 'poe.mode.set', prefill: { port: portNum } },
          { actionId: 'poe.priority.set', prefill: { port: portNum } },
        );
      }
    }

    return {
      key: `P${portNum}`,
      title: p.label,
      subtitle: `Port ${portNum}`,
      status: p.linkUp === null ? 'unknown' : p.linkUp ? 'up' : 'down',
      fields,
      actions,
    };
  });

  // Switch-face layout — SX models are compact all-RJ45 switches, so one
  // unlabeled band in panel order (the webapp's generic fallback matches this).
  const portsLayout: SwitchLayout = { groups: [{ id: 'row-1', portKeys: portItems.map((i) => i.key) }] };

  // --- System ------------------------------------------------------------------
  const sys = snapshot.system;
  const systemItem: StateItem = {
    key: 'system',
    title: sys.name || 'Switch',
    subtitle: [sys.model, sys.firmwareVersion].filter(Boolean).join(' · ') || null,
    status: 'ok',
    fields: {
      Serial: sys.serialNumber || null,
      Uptime: sys.uptimeText || null,
      CPU: sys.cpuLoadPct !== null ? `${sys.cpuLoadPct}%` : null,
      Memory:
        sys.memoryTotalMb !== null && sys.memoryFreeMb !== null && sys.memoryTotalMb > 0
          ? `${Math.round(((sys.memoryTotalMb - sys.memoryFreeMb) / sys.memoryTotalMb) * 100)}% used`
          : null,
    },
    actions: [{ actionId: 'ports.state.read' }],
  };

  return {
    collectedAt: new Date().toISOString(),
    sections: [
      {
        id: 'ports',
        label: 'Ports',
        description: `Switch ports with live link state${sx4 ? ', VLAN, PoE and LACP' : ''}. MACs appear when FDB enrichment is enabled. Click ports to select them for bulk actions.`,
        kind: 'switch',
        layout: portsLayout,
        items: portItems,
      },
      {
        id: 'system',
        label: 'System',
        description: 'Device summary.',
        items: [systemItem],
      },
    ],
  };
}
