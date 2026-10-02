import { Router, Request } from 'express';
import { and, asc, desc, eq, exists, not, notInArray, or, sql, inArray } from 'drizzle-orm';
import { db } from '../db';
import * as schema from '../db/schema';
import { requireAuth } from '../auth/middleware';
import { allowedDeviceIds } from '../deviceAccess';
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
  key: 'notifications' | 'configJobs' | 'plans' | 'certificates' | 'updates' | 'securityChecks';
  permission: string;
  compute: (req: Request, userId: string) => Promise<number>;
}

const COUNTS: CountSpec[] = [
  {
    // Open notifications visible under the user's own visibility prefs.
    key: 'notifications',
    permission: 'notifications:read',
    compute: (_req, userId) => countOpenForUser(userId),
  },
  {
    // Config jobs still in flight or waiting for a worker — scoped to the
    // caller's devices (device-level access control).
    key: 'configJobs',
    permission: 'config-jobs:read',
    compute: async (req) => {
      const allowed = await allowedDeviceIds(req);
      if (allowed !== null && allowed.size === 0) return 0;
      const [row] = await db
        .select({ n: sql<number>`count(*)::int` })
        .from(schema.configJobs)
        .where(
          and(
            inArray(schema.configJobs.status, ['queued', 'running']),
            allowed !== null ? inArray(schema.configJobs.deviceId, [...allowed]) : undefined
          )
        );
      return row?.n ?? 0;
    },
  },
  {
    // Certificate endpoints that are NOT healthy right now: expired leaf or
    // issuer, chain-invalid, or presenting a DIFFERENT key than trusted (a live
    // pinning mismatch). PLUS UNM's own mTLS leaves that are revoked or past
    // their expiry. Surfaced as the red badge on the Certificates nav item.
    key: 'certificates',
    permission: 'certificates:read',
    compute: async (req) => {
      const allowed = await allowedDeviceIds(req);
      let n = 0;
      if (!(allowed !== null && allowed.size === 0)) {
        const [row] = await db
          .select({ n: sql<number>`count(*)::int` })
          .from(schema.certificates)
          .where(
            and(
              or(
                sql`"daysToExpiry" < 0`,
                sql`"chainDaysToExpiry" < 0`,
                eq(schema.certificates.valid, false),
                // fingerprint set AND differs from the trusted pin (both non-null).
                sql`"fingerprint" IS NOT NULL AND "trustedFingerprint" IS NOT NULL AND "fingerprint" <> "trustedFingerprint"`
              ),
              allowed !== null ? inArray(schema.certificates.deviceId, [...allowed]) : undefined
            )
          );
        n = row?.n ?? 0;
      }
      // Fleet-infra mTLS leaves (no device scope — visible to every caller).
      // Only the CURRENT leaf per subject counts (newest notAfter) — the
      // registry keeps superseded rows as an audit trail.
      const allLeaves = await db.query.caCertificates.findMany({
        orderBy: [asc(schema.caCertificates.subject), desc(schema.caCertificates.notAfter)],
      });
      const currentBySubject = new Map<string, (typeof allLeaves)[number]>();
      for (const r of allLeaves) if (!currentBySubject.has(r.subject)) currentBySubject.set(r.subject, r);
      const mtlsBad = [...currentBySubject.values()].filter(
        (r) => r.status === 'revoked' || new Date(r.notAfter).getTime() < Date.now()
      ).length;
      return n + mtlsBad;
    },
  },
  {
    // Plans that are active (same set the top-bar plans icon highlights) — a
    // plan only counts when EVERY device its steps reference is in scope.
    key: 'plans',
    permission: 'plans:read',
    compute: async (req) => {
      const allowed = await allowedDeviceIds(req);
      if (allowed !== null && allowed.size === 0) return 0;
      const [row] = await db
        .select({ n: sql<number>`count(*)::int` })
        .from(schema.plans)
        .where(
          and(
            // Scheduled plans count as active too (queued for a later run).
            inArray(schema.plans.status, ['executing', 'ready', 'draft', 'scheduled']),
            allowed !== null
              ? not(exists(
                  db.select({ id: schema.planSteps.id }).from(schema.planSteps).where(
                    and(eq(schema.planSteps.planId, sql`${schema.plans.id}`), notInArray(schema.planSteps.deviceId, [...allowed]))
                  )
                ))
              : undefined
          )
        );
      return row?.n ?? 0;
    },
  },
  {
    // Available updates across the caller's devices. Only rows with available=
    // true are ever persisted in device_updates, so a plain count is the badge.
    key: 'updates',
    permission: 'updates:read',
    compute: async (req) => {
      const allowed = await allowedDeviceIds(req);
      if (allowed !== null && allowed.size === 0) return 0;
      const [row] = await db
        .select({ n: sql<number>`count(*)::int` })
        .from(schema.deviceUpdates)
        .where(allowed !== null ? inArray(schema.deviceUpdates.deviceId, [...allowed]) : undefined);
      return row?.n ?? 0;
    },
  },
  {
    // Actionable security findings across the caller's devices. Only warning/
    // critical rows are ever persisted (status 'ok' is dropped at ingest), so a
    // plain count IS the number of open issues — the badge lights up only when
    // something actually needs attention.
    key: 'securityChecks',
    permission: 'security:read',
    compute: async (req) => {
      const allowed = await allowedDeviceIds(req);
      if (allowed !== null && allowed.size === 0) return 0;
      const [row] = await db
        .select({ n: sql<number>`count(*)::int` })
        .from(schema.deviceSecurityChecks)
        .where(allowed !== null ? inArray(schema.deviceSecurityChecks.deviceId, [...allowed]) : undefined);
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
        out[c.key] = await c.compute(req, userId);
      } catch {
        // A failing count must not break the whole badge — omit it.
      }
    })
  );
  res.status(200).json(out);
});

export default router;
