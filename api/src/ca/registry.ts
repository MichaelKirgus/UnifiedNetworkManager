/**
 * caRegistry — UNM's operational mirror of step-ca's issued leaves.
 *
 * step-ca keeps its authoritative issuance state in its own embedded DB; this
 * registry (the `ca_certificates` table) is what the webapp + notification
 * worker read. Three writers feed it:
 *   - plugins: their SDK reports the leaf descriptor via GET /metrics
 *     (`tlsCert`) — ingested by the plugin-metrics worker on every poll;
 *   - api: its own enrollment (apiMtls) registers after each swap;
 *   - mcp: self-registers through POST /plugin/ca/register (it has no
 *     x-plugin-api-key, so it uses its API token like any other client).
 *
 * Rows are keyed by SERIAL — a re-enrolled service gets a new serial and the
 * old row is kept as history until `pruneStale()` removes superseded leaves.
 * Revocation (POST /ca/revoke) marks rows revoked; the CA then refuses
 * renewals for that serial, so the leaf dies at its expiry.
 */

import { db } from '../db';
import * as schema from '../db/schema';
import { and, eq, sql } from 'drizzle-orm';
import type { TlsCertInfo } from '@unm/plugin-sdk';

/** One leaf to register (or refresh) in the registry. */
export interface RegistryLeaf extends TlsCertInfo {
  /** Identity label — the plugin name / 'api' / 'mcp'. */
  subject: string;
  /** Which UNM service holds the leaf ('plugin' | 'api' | 'mcp'). */
  source?: 'plugin' | 'api' | 'mcp';
}

/**
 * Upserts one issued leaf by serial. Existing rows are refreshed (validity
 * window + SANs can shift on renewal); revocation state is NEVER clobbered —
 * a revoked serial stays revoked even if the same material reappears.
 */
export async function registerLeaf(leaf: RegistryLeaf): Promise<void> {
  const now = new Date().toISOString();
  await db
    .insert(schema.caCertificates)
    .values({
      id: leaf.serial,
      serial: leaf.serial,
      subject: leaf.subject,
      dnsNames: JSON.stringify(leaf.sans),
      source: leaf.source ?? 'plugin',
      issuer: leaf.issuer,
      notBefore: leaf.notBefore,
      notAfter: leaf.notAfter,
      status: 'issued',
      createdAt: now,
    })
    .onConflictDoUpdate({
      target: schema.caCertificates.serial,
      set: {
        subject: leaf.subject,
        dnsNames: JSON.stringify(leaf.sans),
        source: leaf.source ?? 'plugin',
        issuer: leaf.issuer,
        notBefore: leaf.notBefore,
        notAfter: leaf.notAfter,
        // Keep an explicit revocation — the CA refuses renewals for a revoked
        // serial anyway, so resurrecting it here would only confuse the UI.
        status: sql`CASE WHEN ${schema.caCertificates.status} = 'revoked' THEN 'revoked' ELSE 'issued' END`,
      },
    });
}

/**
 * Removes registry rows that can no longer be live leaves:
 *   - superseded: another row for the SAME subject has a later notAfter;
 *   - expired: notBefore is older than `maxAgeDays` (default 400 — well past
 *     any leaf lifetime + renewal window, so a long-offline plugin's old leaf
 *     eventually disappears instead of accumulating forever).
 * Revoked rows are kept (audit trail) unless superseded.
 */
export async function pruneStale(maxAgeDays = 400): Promise<number> {
  const cutoff = new Date(Date.now() - maxAgeDays * 86_400_000).toISOString();

  // Superseded: a newer leaf exists for the same subject.
  const superseded = await db
    .delete(schema.caCertificates)
    .where(
      sql`EXISTS (
        SELECT 1 FROM ca_certificates other
        WHERE other.subject = ${schema.caCertificates.subject}
          AND other.serial <> ${schema.caCertificates.serial}
          AND other."notAfter" > ${schema.caCertificates.notAfter}
      )`
    )
    .returning({ id: schema.caCertificates.id });

  // Expired beyond the retention window.
  const expired = await db
    .delete(schema.caCertificates)
    .where(sql`${schema.caCertificates.notBefore} < ${cutoff}`)
    .returning({ id: schema.caCertificates.id });

  return (superseded?.length ?? 0) + (expired?.length ?? 0);
}

/** All registry rows, newest first — the backing data for GET /ca/certificates. */
export async function listLeaves(): Promise<typeof schema.caCertificates.$inferSelect[]> {
  return db.query.caCertificates.findMany({ orderBy: [sql`${schema.caCertificates.notAfter} DESC`] });
}

/** True when a subject currently has at least one non-revoked, unexpired leaf. */
export async function subjectHasLiveLeaf(subject: string): Promise<boolean> {
  const now = new Date().toISOString();
  const rows = await db.query.caCertificates.findMany({ where: eq(schema.caCertificates.subject, subject) });
  return rows.some((r) => r.status !== 'revoked' && r.notAfter > now);
}

/** Serials of all currently-live (non-revoked, unexpired) leaves. */
export async function liveSerials(): Promise<string[]> {
  const now = new Date().toISOString();
  const rows = await db.query.caCertificates.findMany({ where: eq(schema.caCertificates.status, 'issued') });
  return rows.filter((r) => r.notAfter > now).map((r) => r.serial);
}

/** Revokes a serial in the registry (the CA-side revocation is separate). */
export async function markRevoked(serial: string): Promise<number> {
  const res = await db
    .update(schema.caCertificates)
    .set({ status: 'revoked', revokedAt: new Date().toISOString() })
    .where(and(eq(schema.caCertificates.serial, serial), eq(schema.caCertificates.status, 'issued')))
    .returning({ id: schema.caCertificates.id });
  return res.length ?? 0;
}

/** Convenience for the API's own enrollment — registers its leaf as source 'api'. */
export function registerApiLeaf(leaf: TlsCertInfo): Promise<void> {
  return registerLeaf({ ...leaf, subject: 'api', source: 'api' });
}
