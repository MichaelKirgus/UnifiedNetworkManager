import { DeviceStateResponse, StateItem } from '@unm/plugin-sdk';
import { InventorySnapshot } from './inventoryTypes';

/**
 * Builds the dynamic device-state document for the UNM Config page (GET /state)
 * from the cached inventory snapshot. Sections:
 *   - Interfaces — one item per configured interface with MAC, IPs and live
 *              status; section actions = read interfaces + apply staged changes.
 *   - System   — hostname/version summary + power actions (reboot/halt are
 *                DANGEROUS catalog entries) + service restart.
 * Action ids reference this plugin's catalog (validated by the API broker).
 */

/** Normalizes an OPNsense interface status string to a badge value. */
function normalizeStatus(raw: unknown): string {
  const s = typeof raw === 'string' ? raw.trim().toLowerCase() : '';
  if (!s) return 'unknown';
  if (/(up|active|online)/.test(s)) return 'up';
  if (/(down|inactive|offline|disabled)/.test(s)) return 'down';
  return s;
}

/** Collects the IP addresses of one interface entry.
 *  The inventory snapshot's network rows are ALREADY normalized by parseNetworkRows
 *  into flat `{ ip, prefix, version }` fields — read those first; fall back to the
 *  raw recordset/legacy shapes (nested ipv4/ipv6) for defensive completeness. */
function ipsOf(entry: Record<string, unknown>): string[] {
  const out = new Set<string>();
  // Normalized row shape (one per IP address).
  const flatIp = typeof entry['ip'] === 'string' ? (entry['ip'] as string).trim() : '';
  if (flatIp) out.add(flatIp);
  for (const versionKey of ['ipv4', 'ipv6'] as const) {
    const v = entry[versionKey];
    if (!v || typeof v !== 'object') continue;
    const entries: Record<string, unknown>[] = [];
    if (Array.isArray(v)) {
      for (const item of v) if (item && typeof item === 'object') entries.push(item as Record<string, unknown>);
    } else {
      const obj = v as Record<string, unknown>;
      if (Array.isArray(obj['addresses'])) {
        for (const item of obj['addresses'] as unknown[]) if (item && typeof item === 'object') entries.push(item as Record<string, unknown>);
      } else if (obj['address'] !== undefined || obj['ip'] !== undefined) {
        entries.push(obj);
      }
    }
    for (const e of entries) {
      const cidr = typeof e['ipaddr'] === 'string' ? (e['ipaddr'] as string).trim() : '';
      if (cidr) out.add(cidr.split('/')[0].trim());
      else {
        const ip = typeof e['ip'] === 'string' ? (e['ip'] as string).trim() : typeof e['address'] === 'string' ? (e['address'] as string).trim() : '';
        if (ip) out.add(ip);
      }
    }
  }
  return Array.from(out);
}

export function buildOpnsenseState(
  snapshot: InventorySnapshot,
  interfaceMacs: { name: string; mac: string }[]
): DeviceStateResponse {
  const macByName = new Map(interfaceMacs.map((m) => [m.name.toLowerCase(), m.mac]));

  // --- Interfaces --------------------------------------------------------------
  // One item per configured interface (deduped by name — the networks rows are
  // one-per-IP, so several rows share an interface). The first row supplies the
  // display fields; ALL rows contribute their IPs to a union.
  const byName = new Map<string, Record<string, unknown>>();
  const ipsByInterface = new Map<string, Set<string>>();
  for (const row of snapshot.networks) {
    const name = typeof row['name'] === 'string' ? (row['name'] as string).trim() : '';
    if (!name) continue;
    if (!byName.has(name)) byName.set(name, row);
    const ips = ipsByInterface.get(name) ?? new Set<string>();
    for (const ip of ipsOf(row)) ips.add(ip);
    ipsByInterface.set(name, ips);
  }

  const interfaceItems: StateItem[] = [];
  for (const [name, row] of byName) {
    const mac = (typeof row['mac'] === 'string' && (row['mac'] as string)) || macByName.get(name.toLowerCase()) || null;
    const ips = Array.from(ipsByInterface.get(name) ?? []);
    const vlanId = typeof row['vlanId'] === 'number' ? (row['vlanId'] as number) : null;

    const fields: Record<string, string | number | null | unknown[]> = {};
    if (mac) fields.MAC = mac;
    if (ips.length > 0) fields.IPs = ips.sort();
    if (vlanId !== null) fields.VLAN = vlanId;

    interfaceItems.push({
      key: name,
      title: name,
      status: normalizeStatus(row['status']),
      fields,
    });
  }
  // Stable ordering — OPNsense identifiers are lan/wan/optN.
  interfaceItems.sort((a, b) => a.key.localeCompare(b.key));

  // --- System --------------------------------------------------------------------
  const systemItem: StateItem = {
    key: 'system',
    title: snapshot.hostname || 'OPNsense',
    subtitle: snapshot.version ? `OPNsense ${snapshot.version}` : null,
    status: 'ok',
    fields: {},
    actions: [
      { actionId: 'system.reboot' },
      { actionId: 'system.halt' },
      { actionId: 'system.service.restart' },
    ],
  };

  return {
    collectedAt: new Date().toISOString(),
    sections: [
      {
        id: 'interfaces',
        label: 'Interfaces',
        description: 'Configured interfaces with MAC, IPs and live status.',
        items: interfaceItems,
        actions: [{ actionId: 'interfaces.read' }],
      },
      {
        id: 'system',
        label: 'System',
        description: 'Appliance summary + power actions (dangerous).',
        items: [systemItem],
      },
    ],
  };
}
