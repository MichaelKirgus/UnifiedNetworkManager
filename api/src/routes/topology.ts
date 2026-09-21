import { Router, Response } from 'express';
import { and, asc, desc, eq, inArray } from 'drizzle-orm';
import { db } from '../db';
import * as schema from '../db/schema';
import { requireAuth, requirePermission } from '../auth/middleware';
import { allowedDeviceIds } from '../deviceAccess';
import { buildTopologyGraph, TopologyResult } from '../utils/topology';

const router = Router();

/**
 * GET /topology — the physical + logical network graph for the Topology page.
 *
 * The graph is computed SERVER-SIDE (the webapp never does cross-device joins):
 * normalized inventory tables provide device↔VLAN membership, MAC-table/ARP
 * rows provide inferred physical links, tunnels provide overlay links, and the
 * latest telemetry snapshot per assignment provides port detail (trunk VLANs,
 * LACP partners). All computation is hash-map based — O(devices + mac entries)
 * — so it stays fast at 100+ devices. A short in-memory TTL cache absorbs
 * repeated page loads between poll cycles.
 */

const CACHE_TTL_MS = 30_000; // matches the telemetry poll cadence
// Keyed per (user scope, site, hosts) — a scoped user's graph must never be
// served from another caller's cache entry.
const cache = new Map<string, { at: number; payload: TopologyResult }>();

/**
 * Plugin-suggested default layer per device — for each assignment, look up the
 * device's selected model in that plugin's catalog (plugins.deviceModels JSON)
 * and take its `defaultLayerId`. A suggestion is only honored when it names an
 * existing layer. Shared by GET /topology and the documented-hosts inventory
 * import (which applies a known device's placement to matching hosts).
 */
export async function loadSuggestedLayers(
  devices: Array<{ id: string; vendor: string; model: string | null }>,
  assignments: Array<{ deviceId: string; pluginId: string }>,
  validLayerIds: Set<string>
): Promise<Map<string, string>> {
  const suggestedByDevice = new Map<string, string>();
  if (assignments.length === 0) return suggestedByDevice;
  const deviceById = new Map(devices.map((d) => [d.id, d] as const));
  const pluginRows = await db.query.plugins.findMany({
    where: inArray(schema.plugins.id, Array.from(new Set(assignments.map((a) => a.pluginId)))),
  });
  const modelsByPlugin = new Map<string, Array<{ vendor: string; model: string; defaultLayerId?: string }>>();
  for (const p of pluginRows) {
    if (!p.deviceModels) continue;
    try {
      const parsed = JSON.parse(p.deviceModels);
      if (Array.isArray(parsed)) modelsByPlugin.set(p.id, parsed);
    } catch {
      /* corrupt catalog — no suggestion from this plugin */
    }
  }
  for (const a of assignments) {
    const dev = deviceById.get(a.deviceId);
    if (!dev || !dev.model) continue;
    const models = modelsByPlugin.get(a.pluginId);
    if (!models) continue;
    const entry = models.find(
      (m) => m && typeof m.vendor === 'string' && typeof m.model === 'string'
        && m.vendor.toLowerCase() === dev.vendor.toLowerCase()
        && m.model === dev.model
    );
    if (entry?.defaultLayerId && validLayerIds.has(entry.defaultLayerId)) {
      suggestedByDevice.set(dev.id, entry.defaultLayerId);
    }
  }
  return suggestedByDevice;
}

router.get('/topology', requireAuth, requirePermission('topology:read'), async (req, res: Response) => {
  try {
    // The OpenAPI validator coerces `includeHosts` to a real boolean (the spec
    // declares type: boolean), so accept both the coerced value and raw strings.
    const { siteId, includeHosts } = req.query as Record<string, string | boolean | undefined>;
    const wantHosts = includeHosts === true || includeHosts === 'true' || includeHosts === '1';

    // Device-level access control — the graph only contains the caller's devices.
    const allowed = await allowedDeviceIds(req);
    if (allowed !== null && allowed.size === 0) {
      res.status(200).json({ nodes: [], edges: [] });
      return;
    }
    const key = `${allowed !== null ? req.user!.sub : 'all'}|${siteId ?? ''}|${wantHosts ? 1 : 0}`;

    const hit = cache.get(key);
    if (hit && Date.now() - hit.at < CACHE_TTL_MS) {
      res.status(200).json(hit.payload);
      return;
    }

    // Devices (optionally scoped to one site), name-sorted for stable layout.
    let deviceRows = await db.query.devices.findMany({ orderBy: [asc(schema.devices.name)] });
    if (allowed !== null) deviceRows = deviceRows.filter((d) => allowed.has(d.id));
    if (siteId) deviceRows = deviceRows.filter((d) => d.siteId === siteId);
    const deviceIds = deviceRows.map((d) => d.id);
    if (deviceIds.length === 0) {
      res.status(200).json({ nodes: [], edges: [] });
      return;
    }

    // All current-state inventory rows for these devices + the assignments we
    // need latest snapshots for. The tables hold only fresh data (24h sweep),
    // so this is a small working set even at large scale.
    const [networks, hosts, tunnels, deviceIps, assignments, layerRows] = await Promise.all([
      db.query.networks.findMany({ where: inArray(schema.networks.deviceId, deviceIds) }),
      db.query.hosts.findMany({ where: inArray(schema.hosts.deviceId, deviceIds) }),
      db.query.tunnels.findMany({ where: inArray(schema.tunnels.deviceId, deviceIds) }),
      db.query.deviceIps.findMany({ where: inArray(schema.deviceIps.deviceId, deviceIds) }),
      db.query.devicePlugins.findMany({ where: inArray(schema.devicePlugins.deviceId, deviceIds) }),
      db.query.networkLayers.findMany(),
    ]);

    // Layer ids that actually exist — an override or plugin suggestion pointing
    // at a deleted/unknown layer falls through to the heuristic instead of
    // producing a dangling band.
    const validLayerIds = new Set(layerRows.map((l) => l.id));

    // Plugin-suggested default layers — see loadSuggestedLayers().
    const suggestedByDevice = await loadSuggestedLayers(
      deviceRows.map((d) => ({ id: d.id, vendor: d.vendor, model: d.model })),
      assignments,
      validLayerIds
    );

    // ONE latest snapshot per assignment (index-backed findFirst each; the set
    // of assignments is small — a few dozen at most). Port-level detail lives
    // only in these blobs until Phase 2 normalizes it.
    const snapshots = await Promise.all(
      assignments.map(async (a) => {
        const t = await db.query.telemetry.findFirst({
          where: and(eq(schema.telemetry.deviceId, a.deviceId), eq(schema.telemetry.pluginId, a.pluginId)),
          orderBy: [desc(schema.telemetry.collectedAt)],
        });
        if (!t) return null;
        try {
          const metrics = typeof t.metrics === 'string' ? JSON.parse(t.metrics) : (t.metrics as Record<string, unknown>);
          return { deviceId: a.deviceId, pluginId: a.pluginId, metrics };
        } catch {
          return null; // corrupt blob — the graph simply lacks that device's ports
        }
      })
    );

    const payload = buildTopologyGraph({
      devices: deviceRows.map((d) => {
        let types: string[] = [];
        try {
          const parsed = JSON.parse(d.deviceTypes);
          if (Array.isArray(parsed)) types = parsed.filter((t): t is string => typeof t === 'string');
        } catch {
          /* malformed array — heuristic simply sees no types */
        }
        return {
          id: d.id,
          name: d.name,
          status: d.status,
          siteId: d.siteId,
          managementAddress: d.managementAddress,
          deviceTypes: types,
          vendor: d.vendor,
          model: d.model ?? null,
          layerOverride: d.layerOverride && validLayerIds.has(d.layerOverride) ? d.layerOverride : null,
          suggestedLayerId: suggestedByDevice.get(d.id) ?? null,
        };
      }),
      networks,
      hosts,
      tunnels,
      deviceIps,
      snapshots: snapshots.filter((s): s is NonNullable<typeof s> => !!s),
      includeHosts: wantHosts,
    });

    cache.set(key, { at: Date.now(), payload });
    if (cache.size > 64) { // unbounded-growth guard — drop the oldest entries
      const oldest = [...cache.entries()].sort((a, b) => a[1].at - b[1].at)[0];
      if (oldest && oldest[0] !== key) cache.delete(oldest[0]);
    }
    res.status(200).json(payload);
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

export default router;
