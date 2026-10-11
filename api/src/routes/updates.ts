/**
 * GET /updates — cross-device update center (Updates page).
 *
 * One endpoint, two payloads:
 *   rows[]  — available updates from the `device_updates` table (populated by
 *             the telemetry worker from each plugin's `updates` metric; plugins
 *             opt in via capability 'updates'). Joined with device + plugin names.
 *   stack   — "UNM itself" card: running API version, discovered plugin versions,
 *             and a feed-based latest-version check when updateFeedUrl is set.
 *
 * Query params: deviceId (exact), siteId (filter by device's site), kind
 * ('firmware'|'os-package'|'docker-image'|'app'). Device-level access control
 * applies exactly like the other inventory views — scoped callers get 200 []
 * for out-of-scope devices, never a leak.
 */

import { Router, Response } from 'express';
import { and, asc, eq, inArray } from 'drizzle-orm';
import { db } from '../db';
import * as schema from '../db/schema';
import { requireAuth, requirePermission } from '../auth/middleware';
import { allowedDeviceIds } from '../deviceAccess';
import { getStackUpdateInfo } from '../stackUpdates';
import { loadDeviceViews, loadPluginNames } from '../utils/deviceViews';

const router = Router();

// DeviceView / loadDeviceViews / loadPluginNames come from utils/deviceViews (shared).

function safeParseJson<T>(raw: string): T {
  try {
    return JSON.parse(raw) as T;
  } catch {
    return {} as T;
  }
}

router.get('/updates', requireAuth, requirePermission('updates:read'), async (req, res: Response) => {
  try {
    const { deviceId, siteId, kind } = req.query as Record<string, string | undefined>;

    if (kind && !['firmware', 'os-package', 'docker-image', 'app', 'stack'].includes(kind)) {
      res.status(400).json({ error: '"kind" must be one of: firmware, os-package, docker-image, app, stack' });
      return;
    }

    // "UNM itself" card — computed once and reused by every response path (the
    // feed check is short-cached, so this stays cheap even on early returns).
    const stack = await getStackUpdateInfo();

    // Device-level access control — scoped callers only see rows of their devices.
    const allowed = await allowedDeviceIds(req);
    if (allowed !== null && allowed.size === 0) {
      res.status(200).json({ rows: [], stack });
      return;
    }
    if (deviceId && allowed !== null && !allowed.has(deviceId)) {
      res.status(200).json({ rows: [], stack });
      return;
    }

    let where;
    const kindClause = kind ? eq(schema.deviceUpdates.kind, kind) : undefined;
    if (deviceId && siteId) {
      const device = await db.query.devices.findFirst({ where: eq(schema.devices.id, deviceId) });
      if (!device || device.siteId !== siteId) {
        res.status(200).json({ rows: [], stack });
        return;
      }
      where = kindClause ? and(eq(schema.deviceUpdates.deviceId, deviceId), kindClause) : eq(schema.deviceUpdates.deviceId, deviceId);
    } else if (deviceId) {
      where = kindClause ? and(eq(schema.deviceUpdates.deviceId, deviceId), kindClause) : eq(schema.deviceUpdates.deviceId, deviceId);
    } else if (siteId) {
      let deviceIds = (await db.query.devices.findMany({ where: eq(schema.devices.siteId, siteId) })).map((d) => d.id);
      if (allowed !== null) deviceIds = deviceIds.filter((id) => allowed.has(id));
      if (deviceIds.length === 0) {
        res.status(200).json({ rows: [], stack });
        return;
      }
      const deviceClause = inArray(schema.deviceUpdates.deviceId, deviceIds);
      where = kindClause ? and(deviceClause, kindClause) : deviceClause;
    } else if (kindClause) {
      where = allowed !== null ? and(kindClause, inArray(schema.deviceUpdates.deviceId, [...allowed])) : kindClause;
    } else if (allowed !== null) {
      where = inArray(schema.deviceUpdates.deviceId, [...allowed]);
    }

    const rows = await db.query.deviceUpdates.findMany({
      ...(where ? { where } : {}),
      orderBy: [asc(schema.deviceUpdates.deviceId), asc(schema.deviceUpdates.kind), asc(schema.deviceUpdates.name)],
    });

    const [deviceViews, pluginNames] = await Promise.all([
      loadDeviceViews(Array.from(new Set(rows.map((r) => r.deviceId)))),
      loadPluginNames(Array.from(new Set(rows.map((r) => r.pluginId)))),
    ]);

    const mappedRows = rows.map((r) => {
      const device = deviceViews.get(r.deviceId);
      return {
        ...r,
        applyInput: safeParseJson<Record<string, unknown>>(r.applyInput),
        extra: safeParseJson<Record<string, unknown>>(r.extra),
        deviceName: device?.name ?? null,
        managementAddress: device?.managementAddress ?? null,
        siteName: device?.siteName ?? null,
        pluginName: pluginNames.get(r.pluginId) ?? null,
      };
    });

    // Append a synthetic "UNM itself" row when a newer version is available so it
    // renders in the SAME table (its own device-like node) with a manual apply
    // path — consistent with how every other update appears. Only shown for the
    // unfiltered view: it belongs to no device/site and has kind 'stack'.
    if (stack.available && stack.latestApiVersion && !deviceId && !siteId && (!kind || kind === 'stack')) {
      mappedRows.push({
        deviceId: 'unm-stack',
        pluginId: '',
        kind: 'stack',
        name: 'UnifiedNetworkManager',
        currentVersion: stack.apiVersion,
        latestVersion: stack.latestApiVersion,
        rebootRequired: null,
        sizeBytes: null,
        releaseNotesUrl: stack.releaseUrl ?? stack.notesUrl ?? null,
        releaseNotes: null,
        branch: null,
        applyActionId: null,
        applyInput: {},
        extra: { synthetic: true },
        collectedAt: new Date().toISOString(),
        deviceName: 'UnifiedNetworkManager (this instance)',
        managementAddress: null,
        siteName: null,
        pluginName: null,
      });
    }

    res.status(200).json({ rows: mappedRows, stack });
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

export default router;
