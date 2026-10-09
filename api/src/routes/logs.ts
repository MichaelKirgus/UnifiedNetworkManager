import { Router, Response } from 'express';
import { and, desc, eq, gte, inArray, ilike, lt, or } from 'drizzle-orm';
import { db } from '../db';
import * as schema from '../db/schema';
import { requireAuth, requirePermission } from '../auth/middleware';
import { allowedDeviceIds } from '../deviceAccess';

/**
 * Public read side of the plugin log pipeline (ingest lives in routes/internal.ts).
 * Powers two webapp views: the global Logs page and the per-device Logs section
 * in DeviceDetail. Gated by `logs:read` — logs can carry critical details
 * (endpoints, error payloads), so they do not ride on devices:read.
 */

const router = Router();

const LOG_LEVELS = ['debug', 'info', 'warn', 'error'];
const DEFAULT_LIMIT = 500;
const MAX_LIMIT = 2000;

// GET /logs - plugin log entries, newest first.
// Query params: deviceId?, pluginId?, level? (comma list), search? (ILIKE on
// message + context), from?/to? (ISO timestamps), limit (default 500, max 2000).
router.get(
  '/logs',
  requireAuth,
  requirePermission('logs:read'),
  async (_req, res: Response) => {
    try {
      const q = _req.query as Record<string, string | undefined>;

      const levels = (q.level ?? '')
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
      for (const l of levels) {
        if (!LOG_LEVELS.includes(l)) {
          res.status(400).json({ error: `"level" must be a comma list of: ${LOG_LEVELS.join(', ')}` });
          return;
        }
      }

      const limit = Math.min(MAX_LIMIT, Math.max(1, Number(q.limit ?? DEFAULT_LIMIT) || DEFAULT_LIMIT));

      const clauses = [];
      if (q.deviceId) clauses.push(eq(schema.pluginLogs.deviceId, q.deviceId));
      if (q.pluginId) clauses.push(eq(schema.pluginLogs.pluginId, q.pluginId));
      if (levels.length === 1) {
        clauses.push(eq(schema.pluginLogs.level, levels[0]));
      } else if (levels.length > 1) {
        clauses.push(inArray(schema.pluginLogs.level, levels));
      }
      if (q.search) {
        const pattern = `%${q.search}%`;
        clauses.push(or(ilike(schema.pluginLogs.message, pattern), ilike(schema.pluginLogs.context, pattern)));
      }
      if (q.from) clauses.push(gte(schema.pluginLogs.emittedAt, q.from));
      if (q.to) clauses.push(lt(schema.pluginLogs.emittedAt, q.to));

      // Device-level access control — scoped callers only see logs of their own
      // devices. Device-less plugin logs are excluded for them too (they may
      // reference any device); unrestricted callers keep the full view.
      const allowed = await allowedDeviceIds(_req);
      if (allowed !== null) {
        if (q.deviceId && !allowed.has(q.deviceId)) {
          res.status(200).json([]);
          return;
        }
        clauses.push(inArray(schema.pluginLogs.deviceId, [...allowed]));
      }

      const rows = await db.query.pluginLogs.findMany({
        ...(clauses.length > 0 ? { where: and(...clauses) } : {}),
        orderBy: [desc(schema.pluginLogs.emittedAt)],
        limit,
      });

      // Batch-load display names so the webapp can render plugin/device chips
      // without extra round-trips (same pattern as routes/networks.ts).
      const deviceIds = Array.from(new Set(rows.map((r) => r.deviceId).filter((d): d is string => !!d)));
      const pluginIds = Array.from(new Set(rows.map((r) => r.pluginId)));
      const [devices, plugins] = await Promise.all([
        deviceIds.length > 0 ? db.query.devices.findMany({ where: inArray(schema.devices.id, deviceIds) }) : [],
        pluginIds.length > 0 ? db.query.plugins.findMany({ where: inArray(schema.plugins.id, pluginIds) }) : [],
      ]);
      const deviceNameById = new Map(devices.map((d) => [d.id, d.name] as const));
      const pluginNameById = new Map(plugins.map((p) => [p.id, p.name] as const));

      res.status(200).json(
        rows.map((r) => ({
          id: r.id,
          pluginId: r.pluginId,
          pluginName: pluginNameById.get(r.pluginId) ?? null,
          deviceId: r.deviceId,
          deviceName: r.deviceId ? (deviceNameById.get(r.deviceId) ?? null) : null,
          level: r.level,
          message: r.message,
          context: r.context ? safeParseJson(r.context) : null,
          emittedAt: r.emittedAt,
        }))
      );
    } catch (err) {
      const e = err as { status?: number; message?: string };
      res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
    }
  }
);

function safeParseJson(s: string): unknown {
  try {
    return JSON.parse(s);
  } catch {
    return s; // truncated context may be invalid JSON — surface the raw text
  }
}

export default router;
