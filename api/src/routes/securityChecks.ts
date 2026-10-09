/**
 * GET /security-checks — cross-device security findings (Security page).
 *
 * One endpoint: rows[] = actionable security findings from the
 * `device_security_checks` table (populated by the telemetry worker from each
 * plugin's `securityChecks` metric; plugins opt in via capability
 * 'securityChecks'). Only warning/critical rows are ever persisted — a clean
 * device simply has no rows. Joined with device + plugin names, exactly like
 * the other inventory views. Device-level access control applies: scoped
 * callers get 200 [] for out-of-scope devices, never a leak.
 *
 * Query params: deviceId (exact), siteId (filter by device's site), kind
 * ('auth-failures'|'file-integrity'|'rate-limiting'|'account'|'service-exposure'|'other'),
 * status ('warning'|'critical').
 */

import { Router, Response } from 'express';
import { and, asc, eq, inArray, sql } from 'drizzle-orm';
import { db } from '../db';
import * as schema from '../db/schema';
import { requireAuth, requirePermission } from '../auth/middleware';
import { allowedDeviceIds } from '../deviceAccess';
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

const KNOWN_KINDS = ['auth-failures', 'file-integrity', 'rate-limiting', 'account', 'service-exposure', 'other'];

router.get('/security-checks', requireAuth, requirePermission('security:read'), async (req, res: Response) => {
  try {
    const { deviceId, siteId, kind, status } = req.query as Record<string, string | undefined>;

    if (kind && !KNOWN_KINDS.includes(kind)) {
      res.status(400).json({ error: `"kind" must be one of: ${KNOWN_KINDS.join(', ')}` });
      return;
    }
    if (status && !['info', 'warning', 'critical'].includes(status)) {
      res.status(400).json({ error: '"status" must be one of: info, warning, critical' });
      return;
    }

    // Device-level access control — scoped callers only see rows of their devices.
    const allowed = await allowedDeviceIds(req);
    if (allowed !== null && allowed.size === 0) {
      res.status(200).json({ rows: [] });
      return;
    }
    if (deviceId && allowed !== null && !allowed.has(deviceId)) {
      res.status(200).json({ rows: [] });
      return;
    }

    const kindClause = kind ? eq(schema.deviceSecurityChecks.kind, kind) : undefined;
    const statusClause = status ? eq(schema.deviceSecurityChecks.status, status) : undefined;
    let where;
    if (deviceId && siteId) {
      const device = await db.query.devices.findFirst({ where: eq(schema.devices.id, deviceId) });
      if (!device || device.siteId !== siteId) {
        res.status(200).json({ rows: [] });
        return;
      }
      where = and(eq(schema.deviceSecurityChecks.deviceId, deviceId), kindClause, statusClause);
    } else if (deviceId) {
      where = and(eq(schema.deviceSecurityChecks.deviceId, deviceId), kindClause, statusClause);
    } else if (siteId) {
      let deviceIds = (await db.query.devices.findMany({ where: eq(schema.devices.siteId, siteId) })).map((d) => d.id);
      if (allowed !== null) deviceIds = deviceIds.filter((id) => allowed.has(id));
      if (deviceIds.length === 0) {
        res.status(200).json({ rows: [] });
        return;
      }
      where = and(inArray(schema.deviceSecurityChecks.deviceId, deviceIds), kindClause, statusClause);
    } else {
      const clauses = [kindClause, statusClause].filter(Boolean);
      if (allowed !== null) clauses.push(inArray(schema.deviceSecurityChecks.deviceId, [...allowed]));
      where = clauses.length > 0 ? and(...clauses) : undefined;
    }

    // Severity rank (critical first) — plain alphabetical would put 'info' before 'warning'.
    const severityRank = sql`CASE "status" WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END`;
    const rows = await db.query.deviceSecurityChecks.findMany({
      ...(where ? { where } : {}),
      orderBy: [severityRank, asc(schema.deviceSecurityChecks.deviceId), asc(schema.deviceSecurityChecks.kind), asc(schema.deviceSecurityChecks.name)],
    });

    const [deviceViews, pluginNames] = await Promise.all([
      loadDeviceViews(Array.from(new Set(rows.map((r) => r.deviceId)))),
      loadPluginNames(Array.from(new Set(rows.map((r) => r.pluginId)))),
    ]);

    res.status(200).json({
      rows: rows.map((r) => {
        const device = deviceViews.get(r.deviceId);
        return {
          ...r,
          extra: safeParseJson<Record<string, unknown>>(r.extra),
          deviceName: device?.name ?? null,
          managementAddress: device?.managementAddress ?? null,
          siteName: device?.siteName ?? null,
          pluginName: pluginNames.get(r.pluginId) ?? null,
        };
      }),
    });
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

export default router;
