import { Router, Response } from 'express';
import { requireAuth, requirePermission } from '../auth/middleware';
import { getWorkerRuntimes, getEvents, telemetryStats, getPostgresStats } from '../workers/stats';
import {
  getSystemSettings,
  saveSystemSettings,
  validateSettingsUpdate,
  SETTINGS_LIMITS,
} from '../systemSettings';

/**
 * System/HA observability + runtime tuning (Workers page). Gated by
 * `system:read` — the status view exposes internal topology (worker roles,
 * leadership, DB internals) that regular operators should not see.
 *
 *   GET /system/status    -> this instance's worker runtimes, telemetry cycle
 *                            stats, recent events, and a Postgres snapshot
 *   GET /system/settings  -> effective HA/worker settings + allowed limits
 *   PUT /system/settings  -> persist new values (validated; live effect)
 */

const router = Router();

// GET /system/status - worker infrastructure + database health.
router.get(
  '/system/status',
  requireAuth,
  requirePermission('system:read'),
  async (_req, res: Response) => {
    try {
      const [postgres] = await Promise.all([getPostgresStats()]);
      res.status(200).json({
        instance: {
          hostname: process.env.HOSTNAME ?? 'api',
          pid: process.pid,
          uptimeSeconds: Math.round(process.uptime()),
          nodeVersion: process.version,
        },
        workers: getWorkerRuntimes(),
        telemetry: telemetryStats,
        events: getEvents(50),
        postgres,
      });
    } catch (err) {
      const e = err as { status?: number; message?: string };
      res.status(e.status ?? 500).json({ error: e.message ?? 'Failed to collect system status' });
    }
  }
);

// GET /system/settings - effective values + the allowed ranges (for form UIs).
router.get(
  '/system/settings',
  requireAuth,
  requirePermission('system:read'),
  async (_req, res: Response) => {
    try {
      const settings = await getSystemSettings();
      res.status(200).json({ ...settings, limits: SETTINGS_LIMITS });
    } catch (err) {
      const e = err as { status?: number; message?: string };
      res.status(e.status ?? 500).json({ error: e.message ?? 'Failed to load system settings' });
    }
  }
);

// PUT /system/settings - persist new values. All-or-nothing, validated +
// clamped server-side. Takes effect on the next worker beat (no restart).
router.put(
  '/system/settings',
  requireAuth,
  requirePermission('system:write'),
  async (req, res: Response) => {
    try {
      const body = (req.body ?? {}) as Record<string, unknown>;
      // Unsent fields keep their current effective value — a one-field PUT must
      // not reset the other knob to its env default.
      const base = await getSystemSettings();
      const values = validateSettingsUpdate(body, base);
      await saveSystemSettings(values);
      res.status(200).json({ ...values, limits: SETTINGS_LIMITS });
    } catch (err) {
      const e = err as { status?: number; message?: string };
      // Validation errors are client errors — the route maps them to 400.
      res.status(e.status ?? 400).json({ error: e.message ?? 'Invalid settings' });
    }
  }
);

export default router;
