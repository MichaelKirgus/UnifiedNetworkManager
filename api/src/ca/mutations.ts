/**
 * ca mutations — the single implementation of WiFi (EAP-TLS) client-cert
 * enrollment and revocation.
 *
 * These functions are the ONLY place wifi_client_certs rows are created or
 * revoked. They are called by the plan executor's local-mutation branch
 * (api/src/plans/systemActions.ts) so that certificate changes flow through the
 * plan workflow (2FA-gated execution, full audit trail, retryable, automatable).
 *
 * Enrollment: keygen + sign via the CA, store the encrypted private key in
 * wifi_client_certs, mirror into the unified leaf registry. The private key is
 * NEVER returned here — it stays encrypted at rest and is only decrypted by the
 * download route. Revocation is CA-first (step-ca marks it revoked in its own
 * DB), then mirrored into both registries + the per-auth enforcement list.
 */

import * as crypto from 'crypto';
import { eq } from 'drizzle-orm';
import { db, pgErrorCode, pool } from '../db';
import { caCertificates, wifiClientCerts } from '../db/schema';
import { revokeCertificate } from './stepCaAdmin';
import { enrollEapTlsClient, EnrollValidationError } from './enroll';
import { encryptKeyPem } from './keyVault';
import { registerLeaf } from './registry';

/** Mirrors a successful CA revocation into revoked_serials (per-auth enforcement). */
export async function recordRevokedSerial(serial: string, subject = ''): Promise<void> {
  try {
    await pool.query(
      `INSERT INTO revoked_serials (serial, subject, "revokedAt") VALUES ($1, $2, $3)
       ON CONFLICT (serial) DO UPDATE SET subject = EXCLUDED.subject`,
      [serial.toLowerCase(), subject, new Date().toISOString()]
    );
  } catch (err) {
    console.warn(`[ca] failed to record revoked serial ${serial} in revoked_serials:`, (err as Error).message);
  }
}

/**
 * Enrolls ONE WiFi (EAP-TLS) client certificate. Throws on validation failure,
 * duplicate name, or CA/DB error. Returns the issued metadata (the private key
 * is stored encrypted and never returned).
 */
export async function enrollWifiCert(input: Record<string, unknown>): Promise<{
  serial: string;
  cn: string;
  notBefore: string;
  notAfter: string;
  clamped?: boolean;
  clampReason?: string;
}> {
  const name = typeof input.name === 'string' ? input.name : '';

  // Duplicate-name check BEFORE signing — otherwise a duplicate request would
  // burn a CA signature and leave an untracked leaf in the CA's own DB.
  try {
    const existing = await db.query.wifiClientCerts.findMany({ where: eq(wifiClientCerts.name, name) });
    if (existing.length > 0) throw new Error(`A WiFi client certificate named "${name}" already exists`);
  } catch (e) {
    if (e instanceof EnrollValidationError || /already exists/.test((e as Error).message)) throw e;
    const err = e as { message?: string };
    console.warn('[ca] duplicate-name precheck failed:', err.message);
    throw new Error('Failed to check for an existing certificate with that name');
  }

  let enrolled: Awaited<ReturnType<typeof enrollEapTlsClient>>;
  try {
    enrolled = await enrollEapTlsClient({
      name,
      cn: typeof input.cn === 'string' ? input.cn : undefined,
      organization: typeof input.organization === 'string' ? input.organization : undefined,
      organizationalUnit: typeof input.organizationalUnit === 'string' ? input.organizationalUnit : undefined,
      sans: Array.isArray(input.sans) ? (input.sans as string[]) : undefined,
      keyType: typeof input.keyType === 'string' ? (input.keyType as never) : undefined,
      days: typeof input.days === 'number' ? input.days : undefined,
    });
  } catch (err) {
    if (err instanceof EnrollValidationError) throw err;
    const e = err as { message?: string };
    // Only CA HTTP errors ("CA /1.0/…") are safe to surface verbatim — DB and
    // internal errors embed SQL parameters (key material) in their messages.
    const detail = /^CA \//.test(e.message ?? '') ? `: ${e.message}` : '';
    throw new Error(`Certificate authority sign request failed${detail}`);
  }

  try {
    await db.insert(wifiClientCerts).values({
      id: crypto.randomUUID(),
      name, // unique enrollment label (CN defaults to it but may differ)
      cn: enrolled.subject,
      organization: typeof input.organization === 'string' ? input.organization.trim() : '',
      organizationalUnit: typeof input.organizationalUnit === 'string' ? input.organizationalUnit.trim() : '',
      sansJson: JSON.stringify(Array.isArray(input.sans) ? (input.sans as string[]) : []),
      keyType: typeof input.keyType === 'string' ? input.keyType : 'ec-p256',
      serial: enrolled.serial,
      issuer: 'UNM CA Intermediate CA',
      notBefore: enrolled.notBefore,
      notAfter: enrolled.notAfter,
      status: 'issued',
      keyEncrypted: encryptKeyPem(enrolled.keyPem),
      certPem: enrolled.chainPem,
      createdAt: new Date().toISOString(),
    });
  } catch (e) {
    const err = e as { message?: string };
    if (pgErrorCode(e) === '23505') {
      // Lost a race with a concurrent enrollment of the same name — the CA
      // already signed a leaf we cannot track. Revoke it so nothing untracked
      // stays valid, then report the conflict.
      console.warn(`[ca] duplicate-name race for "${name}" (serial ${enrolled.serial}) — revoking the orphaned leaf`);
      try { await revokeCertificate(enrolled.serial); } catch { /* CA may be unreachable; log only */ }
      throw new Error(`A WiFi client certificate named "${name}" already exists`);
    }
    // Never echo the raw DB error — drizzle-orm ≥0.45 wraps it in a
    // DrizzleQueryError whose message embeds every SQL parameter, i.e. the
    // encrypted private key and the full cert chain. Log only the CAUSE's
    // message (the plain pg error text).
    const cause = (e as { cause?: { message?: string } }).cause;
    console.error('[ca] failed to store the enrolled WiFi certificate:', cause?.message ?? err.message);
    throw new Error('The certificate was issued but could not be stored — check the API logs');
  }

  // Mirror into the unified leaf registry (kind='wifi') so revocation + expiry
  // tooling see it alongside mTLS leaves.
  await registerLeaf({
    serial: enrolled.serial,
    sans: [enrolled.subject],
    issuer: 'UNM CA Intermediate CA',
    notBefore: enrolled.notBefore,
    notAfter: enrolled.notAfter,
    subject: enrolled.subject,
    source: 'plugin',
    kind: 'wifi',
  });

  return {
    serial: enrolled.serial,
    cn: enrolled.subject,
    notBefore: enrolled.notBefore,
    notAfter: enrolled.notAfter,
    ...(enrolled.clamped !== undefined ? { clamped: enrolled.clamped } : {}),
    ...(enrolled.clampReason !== undefined ? { clampReason: enrolled.clampReason } : {}),
  };
}

/**
 * Revokes ONE WiFi client cert by serial. CA-first (idempotent in step-ca),
 * then mirrored into both registries + the per-auth enforcement list. Throws on
 * unknown serial or CA failure (NOT applied). Returns whether it was already
 * revoked plus the CA's HTTP status for the revocation call.
 */
export async function revokeWifiCert(serial: string): Promise<{ alreadyRevoked: boolean; caStatus: number }> {
  const s = serial.trim().toLowerCase();
  if (!/^[0-9a-fA-F]{1,64}$/.test(s)) throw new Error('serial must be a hex string');

  // Serials are stored in the case step-ca returned them (usually UPPERCASE) —
  // match case-insensitively.
  const rows = (await pool.query(
    `SELECT * FROM wifi_client_certs WHERE lower(serial) = $1`,
    [s],
  )) as { rows: Array<(typeof wifiClientCerts.$inferSelect)> };
  if (rows.rows.length === 0) throw new Error(`No WiFi client certificate with serial ${s}`);

  const alreadyRevoked = rows.rows.every((r) => r.status === 'revoked');

  let caStatus = 200;
  try {
    const result = await revokeCertificate(s);
    caStatus = result.status;
  } catch (err) {
    const e = err as { message?: string };
    throw new Error(`CA unreachable — revocation NOT applied: ${e.message ?? 'unknown error'}`);
  }

  const now = new Date().toISOString();
  for (const row of rows.rows) {
    if (row.status !== 'revoked') {
      await db.update(wifiClientCerts).set({ status: 'revoked', revokedAt: now }).where(eq(wifiClientCerts.id, row.id));
    }
  }
  const regRes = (await pool.query(
    `SELECT * FROM ca_certificates WHERE lower(serial) = $1`,
    [s],
  )) as { rows: Array<(typeof caCertificates.$inferSelect)> };
  for (const row of regRes.rows) {
    if (row.status !== 'revoked') {
      await db.update(caCertificates).set({ status: 'revoked', revokedAt: now }).where(eq(caCertificates.id, row.id));
    }
  }

  // Per-auth enforcement: FreeRADIUS rejects this serial on the next EAP-TLS auth.
  const subject = rows.rows.length > 0 ? `CN=${rows.rows[0].cn}` : '';
  await recordRevokedSerial(s, subject);

  return { alreadyRevoked, caStatus };
}

/**
 * Revokes many WiFi client certs by serial in one call (one CA round-trip per
 * serial). Unknown serials are reported in `missing` (never fatal); a per-serial
 * CA failure lands in `failed` without mirroring. Throws only when the CA is
 * unreachable for EVERY serial (nothing applied) — otherwise returns the summary.
 */
export async function revokeWifiCerts(serials: string[]): Promise<{
  revoked: number;
  alreadyRevoked: number;
  failed: Array<{ serial: string; error: string }>;
  missing: string[];
}> {
  const unique = Array.from(new Set(serials.map((s) => s.trim().toLowerCase()).filter(Boolean)));
  if (unique.length === 0) throw new Error('"serials" must be a non-empty array of hex certificate serials');

  // Serials are stored in the case step-ca returned them (usually UPPERCASE) —
  // match case-insensitively.
  const rowsRes = (await pool.query(
    `SELECT * FROM wifi_client_certs WHERE lower(serial) = ANY($1::text[])`,
    [unique],
  )) as { rows: Array<(typeof wifiClientCerts.$inferSelect)> };
  const bySerial = new Map(rowsRes.rows.map((r) => [r.serial.toLowerCase(), r]));
  const missing = serials.filter((s) => !bySerial.has(s.trim().toLowerCase()));

  const now = new Date().toISOString();
  let revoked = 0;
  let alreadyRevoked = 0;
  const failed: Array<{ serial: string; error: string }> = [];

  for (const serial of unique) {
    const row = bySerial.get(serial);
    if (!row) continue; // reported in `missing`
    if (row.status === 'revoked') {
      alreadyRevoked++;
      continue;
    }
    try {
      await revokeCertificate(serial);
    } catch (err) {
      failed.push({ serial, error: (err as Error).message ?? 'CA unreachable' });
      continue; // CA-first: NOT mirrored into the registries
    }

    await db.update(wifiClientCerts).set({ status: 'revoked', revokedAt: now }).where(eq(wifiClientCerts.id, row.id));
    const regRes = (await pool.query(
      `SELECT * FROM ca_certificates WHERE lower(serial) = $1`,
      [serial],
    )) as { rows: Array<(typeof caCertificates.$inferSelect)> };
    for (const r of regRes.rows) {
      if (r.status !== 'revoked') {
        await db.update(caCertificates).set({ status: 'revoked', revokedAt: now }).where(eq(caCertificates.id, r.id));
      }
    }
    // Per-auth enforcement: FreeRADIUS rejects this serial on the next EAP-TLS auth.
    await recordRevokedSerial(serial, `CN=${row.cn}`);
    revoked++;
  }

  if (revoked === 0 && alreadyRevoked === 0 && failed.length > 0) {
    throw new Error('CA unreachable — revocation NOT applied');
  }
  return { revoked, alreadyRevoked, failed, missing };
}
