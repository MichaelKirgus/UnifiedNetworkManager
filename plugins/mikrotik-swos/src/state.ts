/**
 * Builds the dynamic device-state document for the UNM Config page (POST /state)
 * from a collected SwOS snapshot. Sections:
 *   - Ports    — one item per physical port with live link state, speed/duplex,
 *                PoE mode + draw, LAG/LACP membership, per-port VLAN settings
 *                and the MACs learned on that port; per-item actions prefill
 *                the port number (port.config.set / poe.config.set /
 *                lag.config.set / vlan.port.set).
 *   - VLANs    — the configured VLAN table (read-only display; changes go
 *                through vlans.table.set, a DANGEROUS catalog entry).
 *   - System   — identity/model/firmware/uptime summary + read actions.
 * Action ids reference this plugin's catalog (validated by the API broker);
 * executing any of them always flows through the plan workflow.
 */

import { DeviceStateResponse, StateActionRef, StateItem, SwitchLayout } from '@unm/plugin-sdk';
import { LagPort, PoePort, PortInfo, SwosSnapshot, VlanRow } from './monitoring';

/**
 * Switch-face layout for the virtual switch view. Ports with SFP diagnostics
 * (sfpRows carry a 'port' number per populated slot) form an "SFP+" band; all
 * other ports form the "RJ45" band — mirroring how real SwOS front panels are
 * laid out (e.g. CRS309-1G-8S+ = 8× RJ45 + 8× SFP+). No SFP data → one band.
 */
function buildSwosLayout(snapshot: SwosSnapshot): SwitchLayout {
  const sfpPorts = new Set<number>();
  for (const row of snapshot.sfpRows) {
    const p = Number(row['port']);
    if (Number.isFinite(p)) sfpPorts.add(p);
  }
  const keysOf = (pred: (p: PortInfo) => boolean) =>
    snapshot.ports.filter(pred).map((p) => String(p.port));

  if (sfpPorts.size === 0) {
    return { groups: [{ id: 'row-1', label: 'RJ45', portKeys: keysOf(() => true) }] };
  }
  const groups: SwitchLayout['groups'] = [];
  const rj45 = keysOf((p) => !sfpPorts.has(p.port));
  if (rj45.length > 0) groups.push({ id: 'row-rj45', label: 'RJ45', portKeys: rj45 });
  const sfp = keysOf((p) => sfpPorts.has(p.port));
  if (sfp.length > 0) groups.push({ id: 'row-sfp', label: 'SFP+', portKeys: sfp });
  return { groups };
}

/** MACs learned on one physical port (the mac table's `intf` is 'port N' or 'port 1+8'). */
function macsForPort(snapshot: SwosSnapshot, port: number): string[] {
  const out = new Set<string>();
  for (const m of snapshot.macs) {
    if (!m.intf.startsWith('port ')) continue;
    const parts = m.intf.slice('port '.length).split('+');
    if (parts.some((p) => Number(p.trim()) === port)) out.add(m.mac);
  }
  return Array.from(out).sort();
}

/** The per-port VLAN row for one port, or null when the endpoint reported none. */
function vlanForPort(snapshot: SwosSnapshot, port: number): { mode: string; receive: string; defaultVlanId: number | null; forceVlanId: boolean } | null {
  const row = snapshot.portVlans.find((v) => v.port === port);
  if (!row) return null;
  return { mode: row.mode, receive: row.receive, defaultVlanId: row.defaultVlanId, forceVlanId: row.forceVlanId };
}

/** Builds the per-port action refs — only actions the hardware actually supports. */
function portActions(snapshot: SwosSnapshot, port: number): StateActionRef[] {
  const actions: StateActionRef[] = [
    // Rename / enable-disable / auto-negotiation (enabled:false = shutdown).
    { actionId: 'port.config.set', prefill: { port } },
  ];
  if (snapshot.poe && snapshot.poe.some((p) => p.port === port)) {
    actions.push({ actionId: 'poe.config.set', prefill: { port, mode: snapshot.poe.find((p) => p.port === port)?.mode ?? 'off' } });
  }
  if (snapshot.lag && snapshot.lag.some((l) => l.port === port)) {
    actions.push({ actionId: 'lag.config.set', prefill: { port, mode: snapshot.lag.find((l) => l.port === port)?.mode ?? 'passive' } });
  }
  if (snapshot.portVlans.some((v) => v.port === port)) {
    actions.push({ actionId: 'vlan.port.set', prefill: { port, vlanMode: snapshot.portVlans.find((v) => v.port === port)?.mode ?? 'Disabled' } });
  }
  return actions;
}

export function buildSwosState(snapshot: SwosSnapshot): DeviceStateResponse {
  // --- Ports ---------------------------------------------------------------------
  const poeByPort = new Map<number, PoePort>();
  for (const p of snapshot.poe ?? []) poeByPort.set(p.port, p);
  const lagByPort = new Map<number, LagPort>();
  for (const l of snapshot.lag ?? []) lagByPort.set(l.port, l);

  const portItems: StateItem[] = [];
  for (const p of snapshot.ports) {
    const poe = poeByPort.get(p.port);
    const lag = lagByPort.get(p.port);
    const vlan = vlanForPort(snapshot, p.port);
    const macs = macsForPort(snapshot, p.port);

    const fields: Record<string, string | number | null | unknown[]> = {};
    if (p.speedLabel && p.speedLabel !== 'unknown') fields.Speed = p.linkUp ? p.speedLabel : `down (${p.speedLabel})`;
    if (p.duplex !== 'unknown' && p.linkUp) fields.Duplex = p.duplex;
    fields.AutoNegotiation = p.autoNegotiation ? 'on' : 'off';
    if (vlan) {
      fields['VLAN mode'] = vlan.mode;
      if (vlan.defaultVlanId !== null) fields.PVID = vlan.defaultVlanId;
      if (vlan.forceVlanId) fields['Force VLAN'] = 'yes';
    }
    if (poe) {
      fields['PoE mode'] = poe.mode;
      if (poe.powerW !== null) fields['PoE draw'] = `${poe.powerW} W`;
      else if (poe.status && poe.status !== 'unknown') fields['PoE status'] = poe.status;
    }
    if (lag && (lag.mode !== 'passive' || lag.group > 0)) {
      fields.LAG = `group ${lag.group} (${lag.mode})`;
      if (lag.partnerMac) fields['Partner MAC'] = lag.partnerMac;
    }
    if (macs.length > 0) fields.MACs = macs;

    portItems.push({
      key: String(p.port),
      title: p.name,
      subtitle: `port ${p.port}`,
      status: !p.enabled ? 'disabled' : p.linkUp ? 'up' : 'down',
      fields,
      actions: portActions(snapshot, p.port),
    });
  }

  // --- VLANs -----------------------------------------------------------------------
  const vlanItems: StateItem[] = snapshot.vlans.map((v: VlanRow) => ({
    key: String(v.id),
    title: v.name || `VLAN ${v.id}`,
    subtitle: `id ${v.id}`,
    status: 'ok',
    fields: {
      Members: v.members.length > 0 ? v.members.join(', ') : null,
      IGMPsnooping: v.igmpSnooping ? 'on' : 'off',
    },
  }));

  // --- System ------------------------------------------------------------------------
  const systemItem: StateItem = {
    key: 'system',
    title: snapshot.identity || snapshot.model || 'SwOS switch',
    subtitle: [snapshot.platformName, snapshot.firmwareVersion].filter(Boolean).join(' · ') || null,
    status: 'ok',
    fields: {
      Model: snapshot.model || null,
      Firmware: snapshot.firmwareVersion || null,
      MAC: snapshot.macAddress || null,
      Serial: snapshot.serialNumber || null,
      Uptime: snapshot.uptimeSeconds !== null ? `${Math.floor(snapshot.uptimeSeconds / 3600)}h ${Math.floor((snapshot.uptimeSeconds % 3600) / 60)}m` : null,
      'Management IP': snapshot.currentIp || null,
    },
    actions: [
      { actionId: 'swos.system.info' },
      { actionId: 'swos.backup.download' },
      // File-based maintenance (files ride along as base64 in the step input —
      // a future Files page will manage them): firmware flash, config restore, reboot.
      { actionId: 'firmware.update' },
      { actionId: 'swos.config.restore' },
      { actionId: 'system.reboot' },
    ],
  };

  return {
    collectedAt: new Date().toISOString(),
    sections: [
      {
        id: 'ports',
        label: 'Ports',
        description: 'Physical ports with live link state, PoE, LAG and per-port VLANs. Learned MACs show which devices are on each port. Click ports to select them for bulk actions.',
        kind: 'switch',
        layout: buildSwosLayout(snapshot),
        items: portItems,
      },
      ...(vlanItems.length > 0
        ? [{ id: 'vlans', label: 'VLANs', description: 'Configured VLAN table (changes via the dangerous "Replace the VLAN table" action).', items: vlanItems }]
        : []),
      {
        id: 'system',
        label: 'System',
        description: 'Switch identity and management summary.',
        items: [systemItem],
      },
    ],
  };
}
