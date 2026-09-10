import { Router } from 'express';
import { sql, inArray } from 'drizzle-orm';
import { db } from '../db';
import * as schema from '../db/schema';
import { requireAuth } from '../auth/middleware';
import { countOpenForUser } from '../notifications';

const router = Router();

/**
 * Aggregated nav-badge counts for the sidebar. One round-trip returns every
 * actionable count a page can show; each key is present ONLY when the caller
 * holds that page's read permission (so restricted users never learn about data
 * they cannot open). Add a new badge by appending one entry to COUNTS below —
 * the webapp maps its nav items onto these keys.
 */
interface CountSpec {
  /** Response key + the permission required to see it. */
  key: 'notifications' | 'configJobs' | 'plans';
  permission: string;
  compute: (userId: string) => Promise<number>;
}

const COUNTS: CountSpec[] = [
  {
    // Open notifications visible under the user's own visibility prefs.
    key: 'notifications',
    permission: 'notifications:read',
    compute: (userId) => countOpenForUser(userId),
  },
  {
    // Config jobs still in flight or waiting for a worker.
    key: 'configJobs',
    permission: 'config-jobs:read',
    compute: async () => {
      const [row] = await db
        .select({ n: sql<number>`count(*)::int` })
        .from(schema.configJobs)
        .where(inArray(schema.configJobs.status, ['queued', 'running']));
      return row?.n ?? 0;
    },
  },
  {
    // Plans that are active (same set the top-bar plans icon highlights).
    key: 'plans',
    permission: 'plans:read',
    compute: async () => {
      const [row] = await db
        .select({ n: sql<number>`count(*)::int` })
        .from(schema.plans)
        .where(inArray(schema.plans.status, ['executing', 'ready', 'draft']));
      return row?.n ?? 0;
    },
  },
];

router.get('/counts', requireAuth, async (req, res) => {
  const permissions: string[] = req.user?.permissions ?? [];
  const userId = req.user!.sub;
  const out: Record<string, number> = {};
  await Promise.all(
    COUNTS.filter((c) => permissions.includes(c.permission)).map(async (c) => {
      try {
        out[c.key] = await c.compute(userId);
      } catch {
        // A failing count must not break the whole badge — omit it.
      }
    })
  );
  res.status(200).json(out);
});

export default router;
