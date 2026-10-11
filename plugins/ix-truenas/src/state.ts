/**
 * Builds the dynamic device-state document for the UNM Config page (POST /state)
 * from live TrueNAS API calls. Sections:
 *   - Pools      — one item per ZFS pool with status, size/used/free and scrub
 *                  state (read-only in v1; pool management is a later release).
 *   - Drive Bays — one item per enclosure slot from enclosure2.query (iX
 *                  hardware) rendered as a disk-tray face, with identify /
 *                  replace / offline actions; on hosts WITHOUT native enclosure
 *                  management the section falls back to a virtual view of every
 *                  disk.query row grouped by pool (external JBODs included).
 *   - Interfaces — one item per network interface with link state, MAC, IP
 *                  aliases and VLAN tag.
 *   - System     — hostname/version/model/uptime summary + configuration
 *                  backup/restore (config.backup.download / config.restore) and
 *                  the DANGEROUS power actions (system.reboot / system.shutdown),
 *                  which always flow through the plan workflow.
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

/** Pool membership + live vdev status for one bare disk name. */
interface DiskPoolEntry { pool: string; status: string | null }

/** Maps a pool topology tree to bare disk name → {pool, vdevStatus}. Walks every
 *  vdev category (data/log/cache/spares) recursively; leaf DISK entries carry
 *  `disk` (bare name), `path` (/dev/...) and the live vdev `status`. */
function diskPoolInfo(pools: Record<string, unknown>[]): Map<string, DiskPoolEntry> {
  const byDev = new Map<string, DiskPoolEntry>();
  const walk = (vdevs: unknown, poolName: string): void => {
    if (!Array.isArray(vdevs)) return;
    for (const v of vdevs) {
      if (!v || typeof v !== 'object') continue;
      const vd = v as Record<string, unknown>;
      const type = pickString(vd, ['type'])?.toUpperCase();
      if (type === 'DISK' || Array.isArray(vd['children'])) {
        const disk = pickString(vd, ['disk']);
        const path = pickString(vd, ['path']);
        const bare = disk ?? (path ? path.replace(/^\/dev\//, '') : null);
        if (bare && !byDev.has(bare)) byDev.set(bare, { pool: poolName, status: pickString(vd, ['status']) ?? null });
      }
      walk(vd['children'], poolName);
    }
  };
  for (const p of pools) {
    const name = pickString(p, ['name']);
    const topo = p['topology'];
    if (!name || !topo || typeof topo !== 'object') continue;
    for (const cat of Object.values(topo as Record<string, unknown>)) walk(cat, name);
  }
  return byDev;
}

/** Normalizes an enclosure element status to a badge value. */
function bayStatus(status: string | null | undefined): string {
  const s = (status ?? '').toUpperCase();
  if (s === 'OK' || s === 'INFO') return 'ok';
  if (s === 'CRIT' || s === 'UNRECOV') return 'critical';
  if (s === 'NON-CRIT' || s === 'INVOP') return 'degraded';
  return 'unknown';
}

/** One state item per drive bay across all enclosures. `enclosures` is the raw
 *  `enclosure2.query` result — empty on non-iX hardware (the virtual fallback
 *  then takes over; see buildTruenasState). */
function enclosureItems(enclosures: Record<string, unknown>[], byDev: Map<string, DiskPoolEntry>): StateItem[] {
  const items: StateItem[] = [];
  for (const enc of enclosures) {
    const encId = pickString(enc, ['id']);
    if (!encId) continue;
    const elements = enc['elements'];
    const slots = elements && typeof elements === 'object' ? ((elements as Record<string, unknown>)['Array Device Slot'] ?? {}) : {};
    for (const [slotRaw, el] of Object.entries(slots as Record<string, unknown>)) {
      if (!el || typeof el !== 'object') continue;
      const e = el as Record<string, unknown>;
      const slot = Number(slotRaw);
      if (!Number.isFinite(slot) || slot <= 0) continue;

      const dev = pickString(e, ['dev']);
      const model = pickString(e, ['model']);
      const serial = pickString(e, ['serial']);
      const sizeBytes = pickNumber(e, ['size']);
      const supportsIdentify = e['supports_identify_light'] === true;
      const pool = dev ? (byDev.get(dev)?.pool ?? null) : null;

      const fields: Record<string, string | number | null | unknown[]> = {};
      if (model && !/to be filled/i.test(model)) fields.Model = model;
      if (serial) fields.Serial = serial;
      const size = formatBytes(sizeBytes);
      if (size) fields.Size = size;
      if (pool) fields.Pool = pool;

      const actions: StateItem['actions'] = [];
      if (supportsIdentify) {
        // Lights the bay LED — the physical "which drive is this" helper.
        actions.push({ actionId: 'enclosure.identify', prefill: { enclosureId: encId, slot, status: 'ON' } });
      }
      if (dev && pool) {
        // Disk-level operations target the vdev by device name (the appliance
        // resolves it against the pool topology).
        actions.push({ actionId: 'storage.disk-replace', prefill: { pool, label: dev } });
        actions.push({ actionId: 'storage.disk-offline', prefill: { pool, label: dev } });
        actions.push({ actionId: 'storage.disk-online', prefill: { pool, label: dev } });
      }

      items.push({
        key: `${encId}:${slot}`,
        title: `Slot ${slot}`,
        subtitle: dev ? dev : 'empty bay',
        status: dev ? bayStatus(pickString(e, ['status'])) : 'disabled',
        fields,
        ...(actions.length > 0 ? { actions } : {}),
      });
    }
  }
  return items;
}

/** One layout band per physical enclosure (controller first — the query is
 *  already sorted that way); bays within a band in ascending slot order. */
function enclosureLayout(enclosures: Record<string, unknown>[]): { groups: { id: string; label?: string | null; portKeys: string[] }[] } {
  const groups = enclosures.map((enc) => {
    const encId = pickString(enc, ['id']) ?? 'unknown';
    const elements = enc['elements'];
    const slots = elements && typeof elements === 'object' ? ((elements as Record<string, unknown>)['Array Device Slot'] ?? {}) : {};
    const portKeys = Object.keys(slots)
      .map(Number)
      .filter((n) => Number.isFinite(n) && n > 0)
      .sort((a, b) => a - b)
      .map((n) => `${encId}:${n}`);
    const label = pickString(enc, ['label']) || pickString(enc, ['name']);
    return { id: `enc-${encId}`, label: label ?? null, portKeys };
  });
  return { groups };
}

/** Natural order for bare disk names (da2 before da10). */
function diskNameOrder(a: string, b: string): number {
  const ma = /^([a-z]+)(\d+)$/i.exec(a);
  const mb = /^([a-z]+)(\d+)$/i.exec(b);
  if (ma && mb) {
    if (ma[1].toLowerCase() !== mb[1].toLowerCase()) return ma[1].localeCompare(mb[1]);
    return Number(ma[2]) - Number(mb[2]);
  }
  return a.localeCompare(b);
}

/** Media type from a raw disk.query row — modern `type` ('HDD'|'SSD'), legacy
 *  integer `rotationrate` (0/null = SSD) or boolean `rotation_rate`. */
function diskMediaType(d: Record<string, unknown>): string | null {
  const t = pickString(d, ['type']);
  if (t === 'HDD' || t === 'SSD') return t.toLowerCase();
  const rr = d['rotationrate'];
  if (typeof rr === 'number') return rr > 0 ? 'hdd' : 'ssd';
  if (rr === null) return 'ssd';
  if (typeof d['rotation_rate'] === 'boolean') return d['rotation_rate'] ? 'hdd' : 'ssd';
  return null;
}

/** Live vdev status → bay LED badge for the virtual tray. */
function vdevBayStatus(status: string | null): string {
  const s = (status ?? '').toUpperCase();
  if (s === 'ONLINE') return 'ok';
  if (s === 'DEGRADED' || s === 'MAINTENANCE') return 'degraded';
  if (s === 'FAULTED' || s === 'UNAVAIL') return 'critical';
  if (s === 'OFFLINE') return 'offline';
  return 'unknown';
}

/** Virtual drive-bay view for hosts WITHOUT native enclosure management: one bay
 *  per disk.query row (external JBOD disks included), LED from the pool's vdev
 *  status, replace/offline/online actions for pooled disks. No identify action —
 *  there is no LED hardware to light. */
function virtualBayItems(disks: Record<string, unknown>[], byDev: Map<string, DiskPoolEntry>): StateItem[] {
  const items: StateItem[] = [];
  for (const d of disks) {
    const name = pickString(d, ['name', 'identifier']);
    if (!name) continue;
    const model = pickString(d, ['model', 'description']);
    const serial = pickString(d, ['serial', 'serial_number']);
    const sizeBytes = pickNumber(d, ['size', 'capacity_bytes']);
    const media = diskMediaType(d);
    const info = byDev.get(name);

    const fields: Record<string, string | number | null | unknown[]> = {};
    if (model && !/to be filled/i.test(model)) fields.Model = model;
    if (serial) fields.Serial = serial;
    const size = formatBytes(sizeBytes);
    if (size) fields.Size = size;
    if (media) fields.Media = media.toUpperCase();
    if (info?.pool) fields.Pool = info.pool;

    const actions: StateItem['actions'] = [];
    if (info?.pool) {
      // Disk-level operations target the vdev by device name — same contract as
      // the native tray, so the plan workflow is identical either way.
      actions.push({ actionId: 'storage.disk-replace', prefill: { pool: info.pool, label: name } });
      actions.push({ actionId: 'storage.disk-offline', prefill: { pool: info.pool, label: name } });
      actions.push({ actionId: 'storage.disk-online', prefill: { pool: info.pool, label: name } });
    }

    items.push({
      key: `vdisk:${name}`,
      title: name,
      subtitle: model && !/to be filled/i.test(model) ? model : (media ? media.toUpperCase() : null),
      status: info ? vdevBayStatus(info.status) : 'unknown',
      fields,
      ...(actions.length > 0 ? { actions } : {}),
    });
  }
  return items.sort((a, b) => diskNameOrder(a.key.replace(/^vdisk:/, ''), b.key.replace(/^vdisk:/, '')));
}

/** One layout band per pool for the virtual tray; disks outside any pool fall
 *  into the tray's automatic "Unassigned" band. */
function virtualBayLayout(items: StateItem[], byDev: Map<string, DiskPoolEntry>): { groups: { id: string; label?: string | null; portKeys: string[] }[] } {
  const byPool = new Map<string, string[]>();
  for (const it of items) {
    const name = it.key.replace(/^vdisk:/, '');
    const pool = byDev.get(name)?.pool;
    if (!pool) continue; // orphan → the tray's automatic "Unassigned" band
    const keys = byPool.get(pool);
    if (keys) keys.push(it.key); else byPool.set(pool, [it.key]);
  }
  const groups = Array.from(byPool.entries())
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([pool, portKeys]) => ({ id: `vpool-${pool}`, label: pool, portKeys }));
  return { groups };
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
  /** `update.config` result — the configured update branch/profile (best-effort). */
  updateConfig?: Record<string, unknown>;
  /** `enclosure2.query` result — empty on non-iX hardware → virtual fallback. */
  enclosures?: Record<string, unknown>[];
  /** `disk.query` result — the virtual drive-bay view when no native enclosure
   *  data exists (bare-metal builds, external JBODs). */
  disks?: Record<string, unknown>[];
}): DeviceStateResponse {
  const { sysInfo, pools = [], ifaces = [], updateConfig, enclosures = [], disks = [] } = args;

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
  // The configured update branch/profile (update.config) — the same value the
  // Updates page shows in its Branch column; switchable via update.profile.set.
  const profile = pickString(updateConfig ?? {}, ['profile']);
  if (profile) fields.Branch = profile;

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

  // Drive bays render as a disk-tray face. Native enclosure data (iX hardware)
  // ALWAYS wins; when enclosure2.query returns [] the section falls back to a
  // virtual view of every disk.query row — one band per pool, unpooled disks in
  // the tray's automatic "Unassigned" band.
  const byDev = diskPoolInfo(pools);
  let bayItems = enclosureItems(enclosures, byDev);
  let encLayout: { groups: { id: string; label?: string | null; portKeys: string[] }[] };
  let encDescription = 'Installed disks per enclosure. Click bays to select them for identify / replace / offline actions.';
  if (bayItems.length === 0 && disks.length > 0) {
    bayItems = virtualBayItems(disks, byDev);
    encLayout = virtualBayLayout(bayItems, byDev);
    encDescription = 'No native enclosure management detected — all physical disks grouped by pool. Click bays to select them for replace / offline actions.';
  } else {
    encLayout = enclosureLayout(enclosures);
  }
  const enclosuresSection: StateSection | null =
    bayItems.length > 0
      ? {
          id: 'enclosures',
          label: 'Drive Bays',
          description: encDescription,
          kind: 'enclosure',
          layout: encLayout,
          items: bayItems,
        }
      : null;

  return {
    collectedAt: new Date().toISOString(),
    sections: [
      ...(pools.length > 0
        ? [{ id: 'pools', label: 'ZFS Pools', description: 'Storage pools with capacity and scrub state.', items: poolItems(pools) }]
        : []),
      ...(enclosuresSection ? [enclosuresSection] : []),
      ...(interfacesSection ? [interfacesSection] : []),
      {
        id: 'system',
        label: 'System',
        description: 'Appliance summary + configuration backup/restore and power actions (dangerous — executed via the plan workflow).',
        items: [
          {
            key: 'system',
            title: hostname || 'TrueNAS',
            subtitle: version ? `TrueNAS ${version}` : null,
            status: 'ok',
            fields,
            actions: [
              { actionId: 'config.backup.download' },
              { actionId: 'config.restore' },
              { actionId: 'update.profile.read' },
              { actionId: 'update.profile.set' },
              { actionId: 'system.firmware.update-file' },
              { actionId: 'system.reboot' },
              { actionId: 'system.shutdown' },
            ],
          },
        ],
      },
    ],
  };
}
