/**
 * Builds the dynamic device-state document for the UNM Config page (POST /state)
 * from live TrueNAS API calls. Sections:
 *   - Pools      — one item per ZFS pool with status, size/used/free and scrub
 *                  state (read-only in v1; pool management is a later release).
 *   - Interfaces — one item per network interface with link state, MAC, IP
 *                  aliases and VLAN tag.
 *   - System     — hostname/version/model/uptime summary + the DANGEROUS power
 *                  actions (system.reboot / system.shutdown) which always flow
 *                  through the plan workflow.
 */

import { DeviceStateResponse, StateItem, StateSection } from '@unm/plugin-sdk';
import { pickNumber, pickString } from '@unm/plugin-sdk';

/** Human-readable byte size ("8.0 TB") for state fields. */
export function formatBytes(bytes: number | undefined): string | null {
  if (typeof bytes !== 'number' || !Number.isFinite(bytes) || bytes < 0) return null;
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  let v = bytes;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${i === 0 ? v.toFixed(0) : v.toFixed(1)} ${units[i]}`;
}

/** Seconds → "15d 4h" / "3h 12m". */
export function formatUptime(totalSeconds: number | undefined): string | null {
  if (typeof totalSeconds !== 'number' || !Number.isFinite(totalSeconds) || totalSeconds < 0) return null;
  const d = Math.floor(totalSeconds / 86400);
  const h = Math.floor((totalSeconds % 86400) / 3600);
  const m = Math.floor((totalSeconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m`;
  return `${Math.floor(totalSeconds)}s`;
}

/** Normalizes a pool status string to a badge value. */
function poolStatus(status: string): string {
  const s = status.toUpperCase();
  if (s === 'ONLINE' || s === 'DEGRADED') return 'ok'; // DEGRADED still serves data — but flagged below
  if (s === 'FAULTED' || s === 'OFFLINE' || s === 'UNAVAIL') return 'critical';
  if (s === 'MAINTENANCE') return 'degraded';
  return 'unknown';
}

/** One state item per ZFS pool. */
function poolItems(pools: Record<string, unknown>[]): StateItem[] {
  const items: StateItem[] = [];
  for (const p of pools) {
    const name = pickString(p, ['name']) ?? 'unknown';
    const statusRaw = pickString(p, ['status', 'state']) ?? 'UNKNOWN';
    const sizeBytes = pickNumber(p, ['size', 'size_bytes']);
    const allocBytes = pickNumber(p, ['allocated', 'alloc', 'used', 'used_bytes']);
    const freeBytes = pickNumber(p, ['free', 'available', 'free_bytes']);

    let scrub: string | null = null;
    const scan = p['scan'];
    if (scan && typeof scan === 'object') {
      const s = pickString(scan as Record<string, unknown>, ['state']);
      const fn = pickString(scan as Record<string, unknown>, ['function']);
      scrub = s ? `${fn ?? ''} ${s}`.trim().toLowerCase() : null;
    } else if (typeof p['scrub_state'] === 'string') {
      scrub = (p['scrub_state'] as string).toLowerCase();
    }

    const fields: Record<string, string | number | null | unknown[]> = {};
    const size = formatBytes(sizeBytes);
    const used = formatBytes(allocBytes ?? (sizeBytes !== undefined && freeBytes !== undefined ? sizeBytes - freeBytes : undefined));
    if (size) fields.Size = size;
    if (used) fields.Used = used;
    const free = formatBytes(freeBytes);
    if (free) fields.Free = free;
    if (scrub && scrub !== '—') fields.Scrub = scrub;

    items.push({
      key: name,
      title: name,
      status: poolStatus(statusRaw),
      subtitle: statusRaw.toLowerCase(),
      fields,
    });
  }
  return items;
}

/** One state item per network interface (deduped by description/name). */
function interfaceItems(ifaces: Record<string, unknown>[]): StateItem[] {
  const items: StateItem[] = [];
  for (const i of ifaces) {
    const name = pickString(i, ['description']) || pickString(i, ['name']);
    if (!name) continue;
    const state = (i['state'] ?? {}) as Record<string, unknown>;
    const macRaw = typeof state['link_address'] === 'string' ? (state['link_address'] as string).toLowerCase() : null;
    const linkUp = state['link_state'] === 'LINK_STATE_UP';

    // IP aliases: v26 encodes each alias as a JSON STRING inside `aliases`;
    // older releases used plain objects — both are handled.
    const ips = new Set<string>();
    const aliasesRaw = i['aliases'];
    if (Array.isArray(aliasesRaw)) {
      for (const a of aliasesRaw) {
        let alias: Record<string, unknown> | undefined;
        if (typeof a === 'string') {
          try { alias = JSON.parse(a) as Record<string, unknown>; } catch { continue; }
        } else if (a && typeof a === 'object') {
          alias = a as Record<string, unknown>;
        }
        const ip = pickString(alias ?? {}, ['address']);
        if (ip) ips.add(ip);
      }
    }

    const fields: Record<string, string | number | null | unknown[]> = {};
    if (macRaw) fields.MAC = macRaw;
    if (ips.size > 0) fields.IPs = Array.from(ips).sort();
    const vlanId = pickNumber(i, ['vlan_tag']);
    if (vlanId !== undefined && vlanId > 0) fields.VLAN = vlanId;

    items.push({
      key: name,
      title: name,
      status: linkUp ? 'up' : 'down',
      fields,
    });
  }
  return items.sort((a, b) => a.key.localeCompare(b.key));
}

/**
 * Builds the full state document. All inputs are raw API results (already
 * fetched by the /state handler with fresh credentials).
 */
export function buildTruenasState(args: {
  sysInfo?: Record<string, unknown>;
  pools?: Record<string, unknown>[];
  ifaces?: Record<string, unknown>[];
}): DeviceStateResponse {
  const { sysInfo, pools = [], ifaces = [] } = args;

  // --- System ------------------------------------------------------------------
  const hostname = pickString(sysInfo ?? {}, ['hostname']);
  const version = pickString(sysInfo ?? {}, ['version']);
  const model = pickString(sysInfo ?? {}, ['model', 'cpu_model']);
  const serial = pickString(sysInfo ?? {}, ['system_serial', 'serial', 'serial_number']);
  const up = pickNumber(sysInfo ?? {}, ['uptime_seconds', 'uptime']);
  const cores = pickNumber(sysInfo ?? {}, ['cores', 'core_count']);
  const loadavg = Array.isArray((sysInfo ?? {})['loadavg']) ? ((sysInfo ?? {})['loadavg'] as unknown[])[0] : undefined;
  const memTotal = pickNumber(sysInfo ?? {}, ['physmem', 'mem_total']);

  const fields: Record<string, string | number | null | unknown[]> = {};
  if (version) fields.Version = version;
  if (model && !/to be filled/i.test(model)) fields.Model = model;
  if (serial && !/to be filled/i.test(serial)) fields.Serial = serial;
  const uptime = formatUptime(up);
  if (uptime) fields.Uptime = uptime;
  if (typeof loadavg === 'number' && typeof cores === 'number' && cores > 0) {
    fields['CPU load'] = `${Math.max(0, Math.min(100, Math.round((loadavg / cores) * 1000) / 10))}%`;
  }
  const mem = formatBytes(memTotal);
  if (mem) fields.Memory = mem;

  // Interfaces render as a virtual switch face — one band in item order
  // (name-based keys like 'em0'/'bridge0' keep their full label).
  const ifaceItems = interfaceItems(ifaces);
  const interfacesSection: StateSection | null =
    ifaceItems.length > 0
      ? {
          id: 'interfaces',
          label: 'Interfaces',
          description: 'Network interfaces with link state, MACs and IP aliases. Click interfaces to select them for bulk actions.',
          kind: 'switch',
          layout: { groups: [{ id: 'row-1', portKeys: ifaceItems.map((i) => i.key) }] },
          items: ifaceItems,
        }
      : null;

  return {
    collectedAt: new Date().toISOString(),
    sections: [
      ...(pools.length > 0
        ? [{ id: 'pools', label: 'ZFS Pools', description: 'Storage pools with capacity and scrub state.', items: poolItems(pools) }]
        : []),
      ...(interfacesSection ? [interfacesSection] : []),
      {
        id: 'system',
        label: 'System',
        description: 'Appliance summary + power actions (dangerous — executed via the plan workflow).',
        items: [
          {
            key: 'system',
            title: hostname || 'TrueNAS',
            subtitle: version ? `TrueNAS ${version}` : null,
            status: 'ok',
            fields,
            actions: [{ actionId: 'system.reboot' }, { actionId: 'system.shutdown' }],
          },
        ],
      },
    ],
  };
}
