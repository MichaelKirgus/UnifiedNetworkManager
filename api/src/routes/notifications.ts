import { Router, Response } from 'express';
import { db } from '../db';
import * as schema from '../db/schema';
import { eq, inArray } from 'drizzle-orm';
import { requireAuth, requirePermission } from '../auth/middleware';
import { dispatchPluginAction } from '../utils/pluginDispatch';
import {
  acknowledgeAllOpen,
  acknowledgeNotifications,
  closeNotifications,
  countOpenForUser,
  getVisibilityPrefs,
  listNotifications,
  resolveNotification,
  resolveNotifications,
  setVisibilityPrefs,
} from '../notifications';

/**
 * Notification center — public read + user-scoped actions.
 *
 *   GET    /notifications            list (filters: status/severity/source/deviceId/pluginId/search/limit)
 *   GET    /notifications/count      open count visible to the caller (bell badge)
 *   POST   /notifications/ack        acknowledge {ids} | all:true
 *   POST   /notifications/close      close/dismiss {ids, propagate?}
 *   POST   /notifications/resolve    resolve {ids} — bulk "condition fixed"
 *   DELETE /notifications/:id        resolve one (condition fixed/cleared)
 *   GET    /notifications/prefs      the caller's visibility prefs
 *   PUT    /notifications/prefs      update them (notifications:write)
 *
 * Gated by `notifications:read`; only the prefs PUT needs `notifications:write`.
 */

/**
 * Propagate a close to the appliance for TrueNAS alert notifications.
 *
 * UNM notification rows are normally LOCAL state — closing one never touches
 * the device. But plugin-source rows that mirror appliance alerts (TrueNAS
 * `alert.list`) carry a dedupe key of the form `plugin:<pluginId>:<key>`; when
 * the user closes such a row we also dismiss the underlying alert on the box
 * (`alerts.dismiss` action) so the acknowledgment is end-to-end. Dismissed
 * alerts stop driving health and are skipped by the plugin's mirroring, so the
 * closed state stays consistent across re-polls.
 *
 * Best-effort: runs AFTER the local close has already succeeded (the response
 * is sent first), groups rows per device+plugin, and never throws — a failed
 * dispatch only logs. Returns nothing; callers fire-and-forget it.
 */
async function propagateCloseToAppliances(ids: string[]): Promise<void> {
  try {
    const rows = await db.query.notifications.findMany({ where: inArray(schema.notifications.id, ids) });
    // Group by device+plugin — one dispatch per appliance, keys batched.
    const groups = new Map<string, { deviceId: string; pluginId: string; keys: Set<string> }>();
    for (const row of rows) {
      if (row.source !== 'plugin' || !row.deviceId || !row.pluginId || !row.dedupeKey) continue;
      const m = /^plugin:([^:]+):(.+)$/.exec(row.dedupeKey);
      if (!m || m[1] !== row.pluginId) continue; // only rows this plugin produced
      const key = m[2];
      let g = groups.get(`${row.deviceId}|${row.pluginId}`);
      if (!g) {
        g = { deviceId: row.deviceId, pluginId: row.pluginId, keys: new Set() };
        groups.set(`${row.deviceId}|${row.pluginId}`, g);
      }
      g.keys.add(key);
    }

    for (const g of groups.values()) {
      const res = await dispatchPluginAction(g.deviceId, g.pluginId, 'alerts.dismiss', { keys: [...g.keys] });
      if (!res.ok) {
        console.warn(`[notifications] appliance dismiss failed for ${g.deviceId}/${g.pluginId}: ${res.error}`);
      } else {
        const d = res.result?.details as Record<string, unknown> | undefined;
        console.info(
          `[notifications] dismissed ${String(d?.dismissed ?? 0)} alert(s) on appliance for device ${g.deviceId} (${[...g.keys].length} key(s))`
        );
      }
    }
  } catch (err) {
    // Propagation is strictly best-effort — the local close already succeeded.
    console.warn('[notifications] appliance propagation error:', err);
  }
}

const router = Router();

// GET /notifications — newest first, filtered.
router.get(
  '/notifications',
  requireAuth,
  requirePermission('notifications:read'),
  async (req, res: Response) => {
    try {
      const q = req.query as Record<string, string | boolean | undefined>;
      // The OpenAPI validator COERCES query params to the spec-declared type —
      // `all` is declared boolean and arrives as a real JS boolean, so accept
      // BOTH forms (see topology.ts for the same pattern).
      const all = q.all === true || q.all === 'true';
      const rows = await listNotifications(
        {
          status: typeof q.status === 'string' ? q.status : undefined,
          severity: typeof q.severity === 'string' ? q.severity : undefined,
          source: typeof q.source === 'string' ? q.source : undefined,
          deviceId: typeof q.deviceId === 'string' ? q.deviceId : undefined,
          pluginId: typeof q.pluginId === 'string' ? q.pluginId : undefined,
          search: typeof q.search === 'string' ? q.search : undefined,
          limit: typeof q.limit === 'string' && q.limit ? Number(q.limit) : undefined,
          // The bell/dropdown want the user's filtered view; the full page passes
          // `all=true` to see everything regardless of personal prefs.
          respectPrefs: !all,
        },
        req.user?.sub
      );
      res.json(rows);
    } catch (err) {
      const e = err as { status?: number; message?: string };
      res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
    }
  }
);

// GET /notifications/count — the bell badge.
router.get(
  '/notifications/count',
  requireAuth,
  requirePermission('notifications:read'),
  async (req, res: Response) => {
    try {
      const count = await countOpenForUser(req.user!.sub);
      res.json({ count });
    } catch (err) {
      const e = err as { status?: number; message?: string };
      res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
    }
  }
);

// POST /notifications/ack — acknowledge one or all.
router.post(
  '/notifications/ack',
  requireAuth,
  requirePermission('notifications:read'),
  async (req, res: Response) => {
    try {
      const body = req.body as { ids?: string[]; all?: boolean };
      if (body?.all === true) {
        const n = await acknowledgeAllOpen(req.user!.sub);
        return res.json({ acknowledged: n });
      }
      const ids = Array.isArray(body?.ids) ? body.ids.filter((x): x is string => typeof x === 'string') : [];
      if (ids.length === 0) {
        return res.status(400).json({ error: '"ids" (array) or "all": true is required' });
      }
      const n = await acknowledgeNotifications(ids.slice(0, 500), req.user!.sub);
      res.json({ acknowledged: n });
    } catch (err) {
      const e = err as { status?: number; message?: string };
      res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
    }
  }
);

// POST /notifications/close — dismiss from view. With `propagate: true`,
// plugin-source rows that mirror appliance alerts (TrueNAS alert.list) also
// dismiss the underlying alert on the box (best-effort, after responding).
router.post(
  '/notifications/close',
  requireAuth,
  requirePermission('notifications:read'),
  async (req, res: Response) => {
    try {
      const body = req.body as { ids?: string[]; propagate?: boolean };
      const ids = Array.isArray(body?.ids) ? body.ids.filter((x): x is string => typeof x === 'string') : [];
      if (ids.length === 0) {
        return res.status(400).json({ error: '"ids" array is required' });
      }
      const capped = ids.slice(0, 500);
      const n = await closeNotifications(capped);
      // Fire-and-forget AFTER the response — appliance round-trips must not
      // delay or fail the local close.
      if (body?.propagate === true) void propagateCloseToAppliances(capped);
      res.json({ closed: n });
    } catch (err) {
      const e = err as { status?: number; message?: string };
      res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
    }
  }
);

// DELETE /notifications/:id — resolve one.
router.delete(
  '/notifications/:id',
  requireAuth,
  requirePermission('notifications:read'),
  async (req, res: Response) => {
    try {
      await resolveNotification(req.params.id);
      res.json({ ok: true });
    } catch (err) {
      const e = err as { status?: number; message?: string };
      res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
    }
  }
);

// POST /notifications/resolve — bulk "condition fixed" (same transition as DELETE :id).
router.post(
  '/notifications/resolve',
  requireAuth,
  requirePermission('notifications:read'),
  async (req, res: Response) => {
    try {
      const body = req.body as { ids?: string[] };
      const ids = Array.isArray(body?.ids) ? body.ids.filter((x): x is string => typeof x === 'string') : [];
      if (ids.length === 0) {
        return res.status(400).json({ error: '"ids" array is required' });
      }
      const n = await resolveNotifications(ids.slice(0, 500));
      res.json({ resolved: n });
    } catch (err) {
      const e = err as { status?: number; message?: string };
      res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
    }
  }
);

// GET /notifications/prefs — the caller's visibility prefs.
router.get(
  '/notifications/prefs',
  requireAuth,
  requirePermission('notifications:read'),
  async (req, res: Response) => {
    try {
      const visibility = await getVisibilityPrefs(req.user!.sub);
      res.json({ userId: req.user!.sub, visibility });
    } catch (err) {
      const e = err as { status?: number; message?: string };
      res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
    }
  }
);

// PUT /notifications/prefs — update the caller's visibility prefs.
router.put(
  '/notifications/prefs',
  requireAuth,
  requirePermission('notifications:write'),
  async (req, res: Response) => {
    try {
      const body = req.body as { visibility?: Record<string, unknown> };
      if (!body || typeof body !== 'object' || !body.visibility || typeof body.visibility !== 'object') {
        return res.status(400).json({ error: '"visibility" object is required' });
      }
      const visibility = await setVisibilityPrefs(req.user!.sub, body.visibility);
      res.json({ userId: req.user!.sub, visibility });
    } catch (err) {
      const e = err as { status?: number; message?: string };
      res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
    }
  }
);

export default router;
