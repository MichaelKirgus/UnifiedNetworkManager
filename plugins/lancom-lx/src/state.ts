/**
 * Builds the dynamic device-state document for the UNM Config page from a
 * parsed LCOS GetConfig dump (see webapi.ts). Every section maps to one of the
 * plugin's catalog actions — item `actions` carry prefill so the webapp's
 * ActionDialog opens with the right values.
 */

import { DeviceStateResponse, StateSection } from '@unm/plugin-sdk';
import { tableCell, type ParsedLcosConfig } from './webapi';

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

export function buildLxState(parsed: ParsedLcosConfig): DeviceStateResponse {
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
