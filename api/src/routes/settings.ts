import { Router, Response } from 'express';
import { requireAuth, requirePermission } from '../auth/middleware';
import { listAllSettings, updateSetting, resetSetting } from '../systemSettings';

/**
 * Central system settings (the Settings page). These are the app-wide knobs that
 * are NOT plugin- or device-specific — data retention windows, session/timeout
 * behaviour, worker cadence and execution budgets. The registry in
 * `systemSettings.ts` is the single source of truth for labels, help text, types
 * and allowed ranges; this router only exposes it over HTTP.
 *
 *   GET    /settings      -> every setting with its effective value + metadata
 *   PUT    /settings/:key -> update one (validated + clamped server-side)
 *   DELETE /settings/:key -> reset one to its env/default baseline
 *
 * Reading requires `system:read`; writing requires `system:write`. Changes take
 * effect on the next worker beat — no restart.
 */

const router = Router();

// GET /settings - all settings with effective values + metadata for the UI.
router.get(
  '/settings',
  requireAuth,
  requirePermission('system:read'),
  async (_req, res: Response) => {
    try {
      const settings = await listAllSettings();
      res.status(200).json({ settings });
    } catch (err) {
      const e = err as { status?: number; message?: string };
      res.status(e.status ?? 500).json({ error: e.message ?? 'Failed to load settings' });
    }
  }
);

// PUT /settings/:key - update one setting. Body carries the raw value under `value`.
router.put(
  '/settings/:key',
  requireAuth,
  requirePermission('system:write'),
  async (req, res: Response) => {
    try {
      const body = (req.body ?? {}) as Record<string, unknown>;
      const view = await updateSetting(String(req.params.key ?? ''), body.value);
      res.status(200).json({ setting: view });
    } catch (err) {
      const e = err as { status?: number; message?: string };
      // Validation errors are client errors — the route maps them to 400.
      res.status(e.status ?? 400).json({ error: e.message ?? 'Invalid setting value' });
    }
  }
);

// DELETE /settings/:key - reset one setting to its env/default baseline.
router.delete(
  '/settings/:key',
  requireAuth,
  requirePermission('system:write'),
  async (req, res: Response) => {
    try {
      const view = await resetSetting(String(req.params.key ?? ''));
      res.status(200).json({ setting: view });
    } catch (err) {
      const e = err as { status?: number; message?: string };
      res.status(e.status ?? 400).json({ error: e.message ?? 'Failed to reset setting' });
    }
  }
);

export default router;
