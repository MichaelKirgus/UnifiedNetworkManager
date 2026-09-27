/**
 * Builds the dynamic device-state document for the UNM Config page from a
 * parsed LCOS GetConfig dump (see webapi.ts) plus optional LIVE status data
 * (port link state, LACP bundle state, counters — OIDs that are NOT in the
 * config text). Every section maps to one of the plugin's catalog actions —
 * item `actions` carry prefill so the webapp's ActionDialog opens with the
 * right values.
 */

import { DeviceStateResponse, StateSection } from '@unm/plugin-sdk';
import { tableCell, type ParsedLcosConfig } from './webapi';

/** Live status rows fetched via getTable (13.1.x OIDs — not in GetConfig text). */
export interface LxLiveStatus {
  /** 13.1.5.99 Ports: cells 1 Port, 2 Link-Active, 3 Connector, 4 MAC. */
  ports: { indexPath: string; cells: Map<string, string> }[] | null;
  /** 13.1.5.44 LACP status: cells 1 Bundle, 2 State, 3 Speed, 6 Local-MAC, 8 Partner-MAC, 10 Local-Ports, 11 Bundle-State. */
  lacpStatus: { indexPath: string; cells: Map<string, string> }[] | null;
  /** 13.1.5.52 ByteTransport: cells 1 Port, 2 Tx-Bytes, 3 Rx-Bytes, 4 Rx-CRC-Errors. */
  counters: { indexPath: string; cells: Map<string, string> }[] | null;
  /** 13.1.47.42.1 — the PoE input type of this (PoE-powered) device. */
  poeInputType: string | null;
}

/** Human-readable byte counter (KB/MB/GB). */
function formatBytes(n: number): string {
  if (!Number.isFinite(n)) return '—';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let v = n;
  let u = 0;
  while (v >= 1024 && u < units.length - 1) { v /= 1024; u++; }
  return `${v.toFixed(v >= 100 || u === 0 ? 0 : 1)} ${units[u]}`;
}

/** The row-index path of the i-th parsed row of a table (from its cell keys). */
function rowIndexPath(parsed: ParsedLcosConfig, tableOid: string, i: number): string {
  const rows = parsed.tables.get(tableOid);
  const row = rows?.[i];
  if (!row) return '0';
  for (const k of row.keys()) {
    if (k.startsWith(`${tableOid}.`)) {
      // Cell key = <table>.<idx…>.<col> — the index path is everything but the last segment.
      const rest = k.slice(tableOid.length + 1).split('.');
      return rest.slice(0, -1).join('.') || '0';
    }
  }
  return '0';
}

export function buildLxState(parsed: ParsedLcosConfig, live?: LxLiveStatus | null): DeviceStateResponse {
  const sections: StateSection[] = [];

  // --- System -----------------------------------------------------------------
  const name = parsed.scalars.get('13.2.1') ?? '';
  const comment = parsed.scalars.get('13.2.11.1');
  const location = parsed.scalars.get('13.2.11.9');
  sections.push({
    id: 'system',
    label: 'System',
    description: 'Device identity and free-text metadata.',
    items: [
      {
        key: 'identity',
        title: name || '(unnamed)',
        subtitle: location ?? null,
        status: 'ok',
        fields: {
          Name: name || '—',
          Comment: comment && comment.length > 0 ? comment : '—',
          Location: location && location.length > 0 ? location : '—',
        },
        actions: [
          { actionId: 'system.name.set', prefill: { name } },
          { actionId: 'system.comment.set', prefill: { comment: comment ?? '' } },
          // Backup/restore — the GetConfig text document is the full config;
          // backups land in UNM's central file repo (Files page).
          { actionId: 'config.backup.download' },
          { actionId: 'config.restore' },
        ],
      },
    ],
  });

  // --- WLAN networks (SSIDs) ----------------------------------------------------
  const netRows = parsed.tables.get('13.2.20.1') ?? [];
  sections.push({
    id: 'wlan-networks',
    label: 'WLAN Networks',
    description: 'Configured SSIDs — encryption profile, VLAN and visibility.',
    items: netRows.map((_, i) => {
      const idx = rowIndexPath(parsed, '13.2.20.1', i);
      return {
        key: `net-${idx}`,
        title: tableCell(parsed, '13.2.20.1', '2', idx) || '(no SSID)',
        subtitle: tableCell(parsed, '13.2.20.1', '1', idx) ?? null,
        status: (tableCell(parsed, '13.2.20.1', '4', idx) === 'Yes' ? 'disabled' : 'enabled') as string,
        fields: {
          Network: tableCell(parsed, '13.2.20.1', '1', idx) ?? '—',
          SSID: tableCell(parsed, '13.2.20.1', '2', idx) ?? '—',
          Encryption: tableCell(parsed, '13.2.20.1', '102', idx) || '—',
          VLAN: (tableCell(parsed, '13.2.20.1', '200', idx) === '0' ? 'untagged' : `VLAN ${tableCell(parsed, '13.2.20.1', '200', idx)}`),
          Hidden: tableCell(parsed, '13.2.20.1', '4', idx) || 'No',
        },
        actions: [
          { actionId: 'ssid.vlan.set', prefill: { network: tableCell(parsed, '13.2.20.1', '1', idx) ?? '', vlanId: Number(tableCell(parsed, '13.2.20.1', '200', idx) ?? 0) } },
        ],
      };
    }),
    actions: [
      { actionId: 'wlan.network.add' },
    ],
  });

  // --- Radios -------------------------------------------------------------------
  const radioRows = parsed.tables.get('13.2.20.8') ?? [];
  sections.push({
    id: 'radios',
    label: 'Radios',
    description: 'Per-radio band, channel and transmit power.',
    items: radioRows.map((_, i) => {
      const idx = rowIndexPath(parsed, '13.2.20.8', i);
      const chanRaw = tableCell(parsed, '13.2.20.8', '8', idx);
      return {
        key: `radio-${idx}`,
        title: tableCell(parsed, '13.2.20.8', '1', idx) ?? `Radio ${i + 1}`,
        subtitle: tableCell(parsed, '13.2.20.8', '6', idx) || null,
        status: 'ok',
        fields: {
          Band: tableCell(parsed, '13.2.20.8', '6', idx) || '—',
          Channel: chanRaw === '0' ? 'auto' : (chanRaw ?? 'auto'),
          Mode: [tableCell(parsed, '13.2.20.8', '9', idx), tableCell(parsed, '13.2.20.8', '3', idx)].filter((x) => x && x !== '').join(' / ') || 'Auto',
          Bandwidth: tableCell(parsed, '13.2.20.8', '24', idx) || 'Auto',
          Power: `${tableCell(parsed, '13.2.20.8', '33', idx) || 'Automatic'}${(tableCell(parsed, '13.2.20.8', '33', idx) === 'Manual' && tableCell(parsed, '13.2.20.8', '34', idx)) ? ` (${tableCell(parsed, '13.2.20.8', '34', idx)} dBm)` : ''}`,
        },
        actions: [
          { actionId: 'radio.channel.set', prefill: { ifc: tableCell(parsed, '13.2.20.8', '1', idx) ?? '', channel: chanRaw === '0' ? 0 : Number(chanRaw ?? 0) } },
          { actionId: 'radio.power.set', prefill: { ifc: tableCell(parsed, '13.2.20.8', '1', idx) ?? '', mode: tableCell(parsed, '13.2.20.8', '33', idx) === 'Manual' ? 'Manual' : 'Automatic' } },
        ],
      };
    }),
  });

  // --- Encryption profiles ---------------------------------------------------------
  const profRows = parsed.tables.get('13.2.20.3') ?? [];
  sections.push({
    id: 'encryption',
    label: 'Encryption Profiles',
    description: 'WLAN encryption profiles referenced by the networks above.',
    items: profRows.map((_, i) => {
      const idx = rowIndexPath(parsed, '13.2.20.3', i);
      return {
        key: `prof-${idx}`,
        title: tableCell(parsed, '13.2.20.3', '1', idx) ?? `Profile ${i + 1}`,
        status: 'ok',
        fields: {
          Encryption: tableCell(parsed, '13.2.20.3', '2', idx) || '—',
          Method: tableCell(parsed, '13.2.20.3', '4', idx) || '—',
          WPA: tableCell(parsed, '13.2.20.3', '9', idx) || '—',
          RADIUS: tableCell(parsed, '13.2.20.3', '21', idx) || null,
        },
      };
    }),
  });

  // --- Interfaces & VLANs -------------------------------------------------------------
  const ifRows = parsed.tables.get('13.2.70.6') ?? [];
  sections.push({
    id: 'interfaces',
    label: 'Interfaces & VLANs',
    description: 'LAN interfaces with their VLAN assignment and addressing.',
    items: ifRows.map((_, i) => {
      const idx = rowIndexPath(parsed, '13.2.70.6', i);
      const vlanRaw = tableCell(parsed, '13.2.70.6', '3', idx);
      return {
        key: `ifc-${idx}`,
        title: tableCell(parsed, '13.2.70.6', '1', idx) ?? `Interface ${i + 1}`,
        subtitle: tableCell(parsed, '13.2.70.6', '2', idx) || null,
        status: 'ok',
        fields: {
          Interface: tableCell(parsed, '13.2.70.6', '2', idx) ?? '—',
          VLAN: vlanRaw === '0' ? 'untagged' : `VLAN ${vlanRaw}`,
          IPv4: `${tableCell(parsed, '13.2.70.6', '4', idx) || 'DHCP'}${(tableCell(parsed, '13.2.70.6', '6', idx) ?? '') !== '' ? ` (${tableCell(parsed, '13.2.70.6', '6', idx)})` : ''}`,
          Comment: tableCell(parsed, '13.2.70.6', '9', idx) || null,
        },
      };
    }),
  });

  // --- Switch ports (virtual switch face) -------------------------------------------------
  // Live link state comes from the status OIDs (live?.ports); when unavailable
  // (e.g. a read-only probe without getTable access) fall back to the config-side
  // port lists so the section still renders.
  const livePorts = live?.ports ?? null;
  const lacpStatusRows = live?.lacpStatus ?? [];
  const counterRows = live?.counters ?? [];

  // LACP membership: bundle → member ports (status col 10 "ETH2, ETH1").
  const portBundle = new Map<string, { bundle: string; state: string; bundleState: string }>();
  for (const r of lacpStatusRows) {
    const members = (r.cells.get('10') ?? '').split(',').map((s) => s.trim()).filter(Boolean);
    for (const m of members) portBundle.set(m, { bundle: r.cells.get('1') ?? '', state: r.cells.get('2') || 'down', bundleState: r.cells.get('11') ?? '' });
  }

  // Config-side per-port facts.
  const untaggedByPort = new Map<string, number[]>();
  for (let i = 0; i < (parsed.tables.get('13.2.70.8')?.length ?? 0); i++) {
    const idx = rowIndexPath(parsed, '13.2.70.8', i);
    const port = tableCell(parsed, '13.2.70.8', '1', idx) ?? '';
    if (!untaggedByPort.has(port)) untaggedByPort.set(port, []);
    untaggedByPort.get(port)!.push(Number(tableCell(parsed, '13.2.70.8', '2', idx) ?? 0));
  }
  const l2mPorts = new Set<string>();
  for (let i = 0; i < (parsed.tables.get('13.2.11.50.2')?.length ?? 0); i++) {
    const idx = rowIndexPath(parsed, '13.2.11.50.2', i);
    if ((tableCell(parsed, '13.2.11.50.2', '2', idx) ?? '0') === '1') l2mPorts.add(tableCell(parsed, '13.2.11.50.2', '1', idx) ?? '');
  }

  const portNames: string[] = livePorts && livePorts.length > 0
    ? livePorts.map((r) => r.cells.get('1') ?? '').filter(Boolean)
    : [...new Set([...l2mPorts, ...(parsed.tables.get('13.2.62.2') ?? []).map((_, i) => tableCell(parsed, '13.2.62.2', '1', rowIndexPath(parsed, '13.2.62.2', i)) ?? '')])].filter(Boolean);

  const poeInputType = live?.poeInputType ?? null;
  const poeNote = poeInputType ? ` PoE input (device power feed): ${poeInputType}.` : '';
  sections.push({
    id: 'switch-ports',
    label: 'Switch Ports',
    description: `Physical ethernet ports with live link state, LACP membership and VLAN assignments.${poeNote} LLDP is not configurable on LX devices.`,
    kind: 'switch',
    layout: { groups: [{ id: 'row-1', label: null, portKeys: portNames.map((n) => `port-${n}`) }] },
    items: portNames.map((name) => {
      const liveRow = livePorts?.find((r) => r.cells.get('1') === name);
      const counter = counterRows.find((r) => r.cells.get('1') === name);
      const bundle = portBundle.get(name);
      const linkActive = liveRow ? liveRow.cells.get('2') === '1' : null;
      const untagged = (untaggedByPort.get(name) ?? []).filter((v) => v > 0);
      const lacpLabel = bundle
        ? `${bundle.bundle}${bundle.state !== 'up' ? ' (' + bundle.state + ')' : ''}`
        : l2mPorts.has(name)
          ? 'LAN bridge (L2M)'
          : '—';
      return {
        key: `port-${name}`,
        title: name,
        subtitle: bundle ? `${bundle.bundle} (${bundle.state})` : l2mPorts.has(name) ? 'LAN bridge' : null,
        status: (linkActive == null ? 'ok' : linkActive ? (bundle && bundle.bundleState === 'Degraded' ? 'degraded' : 'up') : 'down') as string,
        fields: {
          Link: liveRow ? (linkActive ? 'active' : 'inactive') : '—',
          Connector: liveRow?.cells.get('3') || null, // numeric enum index — vendor does not publish the label mapping
          MAC: ((liveRow?.cells.get('4') ?? '').replace(/^0+$/, '') || null) as string | null,
          LACP: lacpLabel,
          'Untagged VLANs': untagged.length > 0 ? untagged.map((v) => String(v)) : null,
          'Tx / Rx': counter ? `${formatBytes(Number(counter.cells.get('2') ?? 0))} / ${formatBytes(Number(counter.cells.get('3') ?? 0))}` : null,
        },
        actions: [
          { actionId: 'vlan.untagged.set', prefill: { port: name } },
          { actionId: 'l2m.port.set', prefill: { port: name } },
          { actionId: 'stp.port.set', prefill: { port: name } },
          { actionId: 'lacp.port.set', prefill: { port: name } },
        ],
      };
    }),
    actions: [
      { actionId: 'ports.read' },
      { actionId: 'poe.passthrough.set' },
    ],
  });

  // --- NTP -----------------------------------------------------------------------------
  const ntpRows = parsed.tables.get('13.2.14.21.3') ?? [];
  sections.push({
    id: 'ntp',
    label: 'NTP',
    description: 'Time synchronization — operating state and configured servers.',
    items: [
      {
        key: 'ntp-agent',
        title: `NTP agent (${(parsed.scalars.get('13.2.14.21.1') ?? '0') === '1' ? 'enabled' : 'disabled'})`,
        status: ((parsed.scalars.get('13.2.14.21.1') ?? '0') === '1' ? 'enabled' : 'disabled') as string,
        fields: { Servers: ntpRows.length > 0 ? `${ntpRows.length} configured` : 'none' },
        actions: [
          { actionId: 'ntp.operating.set', prefill: { operating: (parsed.scalars.get('13.2.14.21.1') ?? '0') === '1' } },
          { actionId: 'ntp.server.add' },
        ],
      },
      ...ntpRows.map((_, i) => {
        const idx = rowIndexPath(parsed, '13.2.14.21.3', i);
        const server = tableCell(parsed, '13.2.14.21.3', '1', idx) ?? '';
        const active = (tableCell(parsed, '13.2.14.21.3', '2', idx) ?? '0') === '1';
        return {
          key: `ntp-${idx}`,
          title: server || '(unnamed)',
          status: (active ? 'enabled' : 'disabled') as string,
          fields: { Active: active ? 'yes' : 'no' },
          actions: [
            { actionId: 'ntp.server.set-active', prefill: { server, active } },
            { actionId: 'ntp.server.remove', prefill: { server } },
          ],
        };
      }),
    ],
  });

  // --- SNMP -----------------------------------------------------------------------------
  const snmpCommunities = parsed.tables.get('13.2.9.27') ?? [];
  sections.push({
    id: 'snmp',
    label: 'SNMP',
    description: 'SNMP agent — operating state, traps and communities (v3 user passwords are never shown).',
    items: [
      {
        key: 'snmp-agent',
        title: `SNMP agent (${(parsed.scalars.get('13.2.9.41') ?? '0') === '1' ? 'enabled' : 'disabled'})`,
        status: ((parsed.scalars.get('13.2.9.41') ?? '0') === '1' ? 'enabled' : 'disabled') as string,
        fields: {
          Port: parsed.scalars.get('13.2.9.21') ?? '—',
          Traps: (parsed.scalars.get('13.2.9.1') ?? '0') === '1' ? 'on' : 'off',
          'Admitted protocols': parsed.scalars.get('13.2.9.37') ?? '—', // bitmask: 0=v1, 1=v2c, 2=v3 (observed)
        },
        actions: [
          { actionId: 'snmp.settings.set', prefill: { operating: (parsed.scalars.get('13.2.9.41') ?? '0') === '1' } },
          { actionId: 'snmp.community.add' },
        ],
      },
      ...snmpCommunities.map((_, i) => {
        const idx = rowIndexPath(parsed, '13.2.9.27', i);
        return {
          key: `snmp-comm-${idx}`,
          title: tableCell(parsed, '13.2.9.27', '1', idx) ?? '(unnamed)',
          subtitle: tableCell(parsed, '13.2.9.27', '3', idx) || null,
          status: ((tableCell(parsed, '13.2.9.27', '8', idx) ?? '0') === '1' ? 'enabled' : 'disabled') as string,
          fields: { 'Security name': tableCell(parsed, '13.2.9.27', '3', idx) ?? '—' },
        };
      }),
    ],
  });

  // --- STP -----------------------------------------------------------------------------
  const stpPortRows = parsed.tables.get('13.2.62.3.2') ?? [];
  sections.push({
    id: 'stp',
    label: 'Spanning Tree (STP)',
    description: 'Bridge settings and per-port STP data.',
    items: [
      {
        key: 'stp-bridge',
        title: `STP bridge (${(parsed.scalars.get('13.2.62.3.1') ?? '0') === '1' ? 'enabled' : 'disabled'})`,
        status: ((parsed.scalars.get('13.2.62.3.1') ?? '0') === '1' ? 'enabled' : 'disabled') as string,
        fields: {
          'Bridge priority': parsed.scalars.get('13.2.62.3.3') ?? '—',
          'Protocol version': `${parsed.scalars.get('13.2.62.3.4') ?? '—'} (enum index)`,
          Timers: `fd ${parsed.scalars.get('13.2.62.3.5') ?? '—'} / hello ${parsed.scalars.get('13.2.62.3.6') ?? '—'} / max-age ${parsed.scalars.get('13.2.62.3.7') ?? '—'}`,
        },
        actions: [
          {
            actionId: 'stp.settings.set',
            prefill: {
              operating: (parsed.scalars.get('13.2.62.3.1') ?? '0') === '1',
              bridgePriority: Number(parsed.scalars.get('13.2.62.3.3') ?? 8),
              protocolVersionIndex: parsed.scalars.get('13.2.62.3.4') != null ? Number(parsed.scalars.get('13.2.62.3.4')) : undefined,
            },
          },
        ],
      },
      ...stpPortRows.map((_, i) => {
        const idx = rowIndexPath(parsed, '13.2.62.3.2', i);
        return {
          key: `stp-port-${idx}`,
          title: tableCell(parsed, '13.2.62.3.2', '1', idx) ?? '(port)',
          status: 'ok' as string,
          fields: {
            Priority: tableCell(parsed, '13.2.62.3.2', '2', idx) ?? '—',
            'Edge port': (tableCell(parsed, '13.2.62.3.2', '3', idx) ?? '0') === '1' ? 'yes' : 'no',
          },
          actions: [
            { actionId: 'stp.port.set', prefill: { port: tableCell(parsed, '13.2.62.3.2', '1', idx) ?? '' } },
          ],
        };
      }),
    ],
  });

  // --- LACP -----------------------------------------------------------------------------
  const lacpBundleRows = parsed.tables.get('13.2.62.1') ?? [];
  sections.push({
    id: 'lacp',
    label: 'LACP Bundles',
    description: 'Link aggregation — configured bundles and their live state.',
    items: lacpBundleRows.length > 0 ? lacpBundleRows.map((_, i) => {
      const idx = rowIndexPath(parsed, '13.2.62.1', i);
      const name = tableCell(parsed, '13.2.62.1', '1', idx) ?? '';
      const statusRow = lacpStatusRows.find((r) => r.cells.get('1') === name);
      const members = (statusRow?.cells.get('10') ?? '').split(',').map((s) => s.trim()).filter(Boolean);
      const memberNote = members.length > 0 ? ` — ${members.join(', ')}` : '';
      return {
        key: `lacp-${idx}`,
        title: name,
        subtitle: statusRow ? `${statusRow.cells.get('2') || 'down'}${memberNote}` : null,
        status: (statusRow?.cells.get('11') === 'Degraded' ? 'degraded' : ((tableCell(parsed, '13.2.62.1', '2', idx) ?? '0') === '1' ? 'enabled' : 'disabled')) as string,
        fields: {
          Priority: tableCell(parsed, '13.2.62.1', '3', idx) ?? '—',
          Members: members.length > 0 ? members : null,
          'Bundle state': statusRow?.cells.get('11') || null,
        },
        actions: [
          { actionId: 'lacp.bundle.set', prefill: { bundle: name, operating: (tableCell(parsed, '13.2.62.1', '2', idx) ?? '0') === '1' } },
        ],
      };
    }) : [{ key: 'lacp-none', title: 'No LACP bundles configured', status: 'disabled' as string, fields: {} }],
  });

  // --- WLC / CAPWAP ---------------------------------------------------------------------
  const wlcRows = parsed.tables.get('13.2.59.1') ?? [];
  const operating = parsed.scalars.get('13.2.59.2') ?? 'No';
  sections.push({
    id: 'wlc',
    label: 'WLAN Controller (CAPWAP)',
    description: 'Central WLC management — the target of the UNM migration.',
    items: wlcRows.length > 0
      ? wlcRows.map((_, i) => {
          const idx = rowIndexPath(parsed, '13.2.59.1', i);
          return {
            key: `wlc-${idx}`,
            title: tableCell(parsed, '13.2.59.1', '1', idx) ?? 'Controller',
            status: (operating === 'Yes' ? 'enabled' : 'disabled') as string,
            fields: {
              Address: tableCell(parsed, '13.2.59.1', '1', idx) ?? '—',
              Port: tableCell(parsed, '13.2.59.1', '2', idx) || '—',
              Operating: operating,
            },
            actions: [
              { actionId: 'wlc.address.set', prefill: { address: tableCell(parsed, '13.2.59.1', '1', idx) ?? '', port: Number(tableCell(parsed, '13.2.59.1', '2', idx) ?? 0), operating } },
            ],
          };
        })
      : [{ key: 'wlc-none', title: 'No controller configured', status: 'disabled' as string, fields: { Operating: operating } }],
    actions: [
      { actionId: 'config.persist' },
    ],
  });

  return { collectedAt: new Date().toISOString(), sections };
}
