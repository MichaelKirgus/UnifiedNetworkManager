import { Router, Response } from 'express';
import { and, asc, eq, inArray } from 'drizzle-orm';
import { db } from '../db';
import * as schema from '../db/schema';
import { requireAuth } from '../auth/middleware';

const router = Router();

/**
 * Cross-device inventory views (Networks + Hosts pages). The rows live in the
 * normalized `networks` / `hosts` tables, populated by the telemetry worker
 * from each plugin's /monitoring metrics. Every response row is joined with
 * the device it was collected on and the plugin instance that produced it —
 * plugins.name carries multi-instance suffixes ("OPNsense Plugin (site-a)").
 */

interface DeviceView {
  id: string;
  name: string;
  managementAddress: string;
  siteName: string | null;
}

/**
 * Batch-loads device + site display data for the given ids. Returns a map of
 * deviceId -> view (missing devices are simply absent — stale rows are swept
 * by the worker, but a delete race must not break the response).
 */
async function loadDeviceViews(deviceIds: string[]): Promise<Map<string, DeviceView>> {
  const map = new Map<string, DeviceView>();
  if (deviceIds.length === 0) return map;
  const devices = await db.query.devices.findMany({ where: inArray(schema.devices.id, deviceIds) });
  const siteIds = Array.from(new Set(devices.map((d) => d.siteId).filter((s): s is string => !!s)));
  const sites = siteIds.length > 0 ? await db.query.sites.findMany({ where: inArray(schema.sites.id, siteIds) }) : [];
  const siteNameById = new Map(sites.map((s) => [s.id, s.name] as const));
  for (const d of devices) {
    map.set(d.id, {
      id: d.id,
      name: d.name,
      managementAddress: d.managementAddress,
      siteName: d.siteId ? (siteNameById.get(d.siteId) ?? null) : null,
    });
  }
  return map;
}

/** Batch-loads plugin display names for the given ids. */
async function loadPluginNames(pluginIds: string[]): Promise<Map<string, string>> {
  const map = new Map<string, string>();
  if (pluginIds.length === 0) return map;
  const plugins = await db.query.plugins.findMany({ where: inArray(schema.plugins.id, pluginIds) });
  for (const p of plugins) map.set(p.id, p.name);
  return map;
}

/** One host as presented by GET /hosts — possibly merged from several stored rows. */
interface MergedHost {
  deviceId: string;
  pluginId: string;
  mac: string;
  /** All addresses of this host, IPv4 first (a dual-stack device has both). */
  ips: string[];
  /** Discovery sources that reported this MAC (e.g. arp + ndp for a dual-stack host). */
  sources: string[];
  hostname: string | null;
  manufacturer: string | null;
  intf: string | null;
  expiry: string | null;
  lastSeenAt: string;
}

/** Canonical display order for discovery sources. */
const SOURCE_ORDER: Record<string, number> = { arp: 0, ndp: 1, dhcp: 2, wlan: 3 };

/**
 * Merges stored host rows into one row per physical host: the same MAC seen
 * via several sources (e.g. its IPv4 in ARP + its IPv6 in NDP) is almost
 * certainly a single dual-stack device. Storage keeps the per-source
 * granularity (needed for topology detection); this merge only shapes the
 * GET /hosts response.
 */
function mergeHostRows(rows: typeof schema.hosts.$inferSelect[]): MergedHost[] {
  const groups = new Map<string, typeof rows>();
  for (const r of rows) {
    // Same MAC on the same device + plugin instance = one physical host.
    const key = `${r.deviceId}|${r.pluginId}|${r.mac}`;
    const list = groups.get(key);
    if (list) list.push(r);
    else groups.set(key, [r]);
  }

  return Array.from(groups.values()).map((group) => {
    // IPv4 first, then IPv6 — the usual reading order for a dual-stack host.
    const ips = Array.from(new Set(group.map((r) => r.ip))).sort((a, b) => {
      const av = a.includes(':') ? 1 : 0;
      const bv = b.includes(':') ? 1 : 0;
      return av !== bv ? av - bv : a.localeCompare(b);
    });
    const sources = Array.from(new Set(group.map((r) => r.source))).sort(
      (a, b) => (SOURCE_ORDER[a] ?? 9) - (SOURCE_ORDER[b] ?? 9)
    );
    // DHCP rows carry the richest metadata — prefer their hostname/expiry.
    const dhcp = group.find((r) => r.source === 'dhcp');
    return {
      deviceId: group[0].deviceId,
      pluginId: group[0].pluginId,
      mac: group[0].mac,
      ips,
      sources,
      hostname: dhcp?.hostname ?? group.find((r) => r.hostname)?.hostname ?? null,
      manufacturer: group.find((r) => r.manufacturer)?.manufacturer ?? null,
      intf:
        Array.from(new Set(group.map((r) => r.intf).filter((v): v is string => !!v))).join(', ') ||
        null,
      expiry: dhcp?.expiry ?? null,
      // Latest observation across all sources (ISO strings compare lexicographically).
      lastSeenAt: group.reduce((max, r) => (r.lastSeenAt > max ? r.lastSeenAt : max), group[0].lastSeenAt),
    };
  });
}

/** One network as presented by GET /networks — possibly merged from several stored rows. */
interface MergedNetwork {
  deviceId: string;
  pluginId: string;
  name: string;
  /** All addresses of this interface, IPv4 first (a dual-stack interface has both). */
  cidrs: string[];
  /** Address families present on the interface (e.g. ["v4","v6"] for dual-stack). */
  versions: ('v4' | 'v6')[];
  vlanId: number | null;
  mac: string | null;
  status: string | null;
  collectedAt: string;
}

/**
 * Merges stored network rows into one row per interface: an interface with a
 * dual-stack assignment (IPv4 + IPv6) is stored as two rows (the PK includes
 * the IP — topology detection needs that granularity), but it is ONE network.
 * This merge only shapes the GET /networks response, mirroring mergeHostRows.
 */
function mergeNetworkRows(rows: typeof schema.networks.$inferSelect[]): MergedNetwork[] {
  const groups = new Map<string, typeof rows>();
  for (const r of rows) {
    // Same interface on the same device + plugin instance = one network.
    const key = `${r.deviceId}|${r.pluginId}|${r.name}`;
    const list = groups.get(key);
    if (list) list.push(r);
    else groups.set(key, [r]);
  }

  return Array.from(groups.values()).map((group) => {
    // IPv4 first, then IPv6 — the usual reading order for a dual-stack interface.
    const cidrs = group
      .filter((r) => r.ip !== '')
      .map((r) => (r.prefix !== null ? `${r.ip}/${r.prefix}` : r.ip))
      .sort((a, b) => {
        const av = a.includes(':') ? 1 : 0;
        const bv = b.includes(':') ? 1 : 0;
        return av !== bv ? av - bv : a.localeCompare(b);
      });
    const versions: ('v4' | 'v6')[] = [];
    for (const v of group.map((r) => r.version)) {
      if ((v === 'v4' || v === 'v6') && !versions.includes(v)) versions.push(v);
    }
    return {
      deviceId: group[0].deviceId,
      pluginId: group[0].pluginId,
      name: group[0].name,
      cidrs,
      versions,
      vlanId: group.find((r) => r.vlanId !== null)?.vlanId ?? null,
      mac: group.find((r) => r.mac)?.mac ?? null,
      status: group.find((r) => r.status)?.status ?? null,
      // Latest observation across the interface's rows (ISO strings compare lexicographically).
      collectedAt: group.reduce((max, r) => (r.collectedAt > max ? r.collectedAt : max), group[0].collectedAt),
    };
  });
}

// GET /networks - All configured networks across devices.
// Query params: deviceId (exact), siteId (filter by device's site).
router.get('/networks', requireAuth, async (_req, res: Response) => {
  try {
    const { deviceId, siteId } = _req.query as Record<string, string | undefined>;

    let where;
    if (deviceId && siteId) {
      // Both filters: verify the device belongs to the site first.
      const device = await db.query.devices.findFirst({ where: eq(schema.devices.id, deviceId) });
      if (!device || device.siteId !== siteId) {
        res.status(200).json([]);
        return;
      }
      where = eq(schema.networks.deviceId, deviceId);
    } else if (deviceId) {
      where = eq(schema.networks.deviceId, deviceId);
    } else if (siteId) {
      // Subquery: devices belonging to the site.
      const deviceIds = (await db.query.devices.findMany({ where: eq(schema.devices.siteId, siteId) })).map((d) => d.id);
      if (deviceIds.length === 0) {
        res.status(200).json([]);
        return;
      }
      where = inArray(schema.networks.deviceId, deviceIds);
    }

    const rows = await db.query.networks.findMany({
      ...(where ? { where } : {}),
      orderBy: [asc(schema.networks.deviceId), asc(schema.networks.name)],
    });

    // Merge per-address rows into one row per interface (dual-stack appears once).
    const merged = mergeNetworkRows(rows);

    const [deviceViews, pluginNames] = await Promise.all([
      loadDeviceViews(Array.from(new Set(merged.map((m) => m.deviceId)))),
      loadPluginNames(Array.from(new Set(merged.map((m) => m.pluginId)))),
    ]);

    res.status(200).json(
      merged.map((m) => {
        const device = deviceViews.get(m.deviceId);
        return {
          ...m,
          deviceName: device?.name ?? null,
          managementAddress: device?.managementAddress ?? null,
          siteName: device?.siteName ?? null,
          pluginName: pluginNames.get(m.pluginId) ?? null,
        };
      })
    );
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// GET /hosts - All discovered hosts across devices (ARP/NDP neighbors + DHCP leases).
// Query params: deviceId, siteId, source ('arp'|'ndp'|'dhcp'|'wlan').
router.get('/hosts', requireAuth, async (_req, res: Response) => {
  try {
    const { deviceId, siteId, source } = _req.query as Record<string, string | undefined>;

    if (source && !['arp', 'ndp', 'dhcp', 'wlan'].includes(source)) {
      res.status(400).json({ error: '"source" must be one of: arp, ndp, dhcp, wlan' });
      return;
    }

    let where;
    const sourceClause = source ? eq(schema.hosts.source, source) : undefined;
    if (deviceId && siteId) {
      // Both filters: verify the device belongs to the site first.
      const device = await db.query.devices.findFirst({ where: eq(schema.devices.id, deviceId) });
      if (!device || device.siteId !== siteId) {
        res.status(200).json([]);
        return;
      }
      where = sourceClause ? and(eq(schema.hosts.deviceId, deviceId), sourceClause) : eq(schema.hosts.deviceId, deviceId);
    } else if (deviceId) {
      where = sourceClause ? and(eq(schema.hosts.deviceId, deviceId), sourceClause) : eq(schema.hosts.deviceId, deviceId);
    } else if (siteId) {
      const deviceIds = (await db.query.devices.findMany({ where: eq(schema.devices.siteId, siteId) })).map((d) => d.id);
      if (deviceIds.length === 0) {
        res.status(200).json([]);
        return;
      }
      const deviceClause = inArray(schema.hosts.deviceId, deviceIds);
      where = sourceClause ? and(deviceClause, sourceClause) : deviceClause;
    } else if (sourceClause) {
      where = sourceClause;
    }

    const rows = await db.query.hosts.findMany({
      ...(where ? { where } : {}),
      orderBy: [asc(schema.hosts.deviceId), asc(schema.hosts.ip)],
    });

    // Merge per-source rows into one row per physical host (same MAC).
    const merged = mergeHostRows(rows);

    const [deviceViews, pluginNames] = await Promise.all([
      loadDeviceViews(Array.from(new Set(merged.map((m) => m.deviceId)))),
      loadPluginNames(Array.from(new Set(merged.map((m) => m.pluginId)))),
    ]);

    res.status(200).json(
      merged.map((m) => {
        const device = deviceViews.get(m.deviceId);
        return {
          ...m,
          deviceName: device?.name ?? null,
          managementAddress: device?.managementAddress ?? null,
          siteName: device?.siteName ?? null,
          pluginName: pluginNames.get(m.pluginId) ?? null,
        };
      })
    );
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

export default router;
