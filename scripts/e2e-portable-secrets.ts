/**
 * End-to-end verification of portable device credentials (the `secrets` backup
 * section — passphrase-encrypted envelope, cross-instance import).
 *
 * Runs against the LIVE dev stack (auth: UNM_API_TOKEN from .env, else admin login):
 *   1. creates a throwaway apiKey secret and reads its decrypted fields
 *   2. POST /backups with sections=[devices,secrets] + passphrase → asserts the
 *      manifest flags secretsEncrypted and carries an envelope
 *   4. downloads the archive, unwraps it locally: WRONG passphrase must fail,
 *      the correct one must yield the exact decrypted fields
 *   5. POST /backups/restore/apply (stored backupId): wrong passphrase → section
 *      error; correct passphrase → safe merge skips every existing id
 *   6. cross-instance simulation: deletes the secret and re-imports it from the
 *      archive — asserts the ORIGINAL id is preserved and the value decrypts
 *      under THIS instance's provider key (the actual portability guarantee)
 *   7. cleans up (secret + backup row)
 *
 * Usage (from the repo root):
 *   ./node_modules/.bin/tsx scripts/e2e-portable-secrets.ts
 */

import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { createRequire } from 'node:module';
import { unwrapSecrets, SecretEnvelope, EnvelopeSecret } from '../api/src/secretEnvelope';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const PASSPHRASE = 'e2e-portable-secrets-passphrase-42';
const WRONG_PASSPHRASE = 'definitely-the-wrong-passphrase';
const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));

let failures = 0;
function check(label: string, cond: boolean, extra?: unknown): void {
  if (cond) console.log(`  PASS ${label}`);
  else {
    failures++;
    console.error(`  FAIL ${label}`, extra !== undefined ? JSON.stringify(extra).slice(0, 400) : '');
  }
}

async function main(): Promise<void> {
  const { Pool } = apiRequire('pg');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm' });

  // --- Auth — prefer the long-lived API token (bypasses TOTP), else admin login -
  let token = process.env.UNM_API_TOKEN ?? null;
  if (!token) {
    try {
      const envText = fs.readFileSync(path.resolve(process.cwd(), '.env'), 'utf8');
      const m = /^UNM_API_TOKEN=(.+)$/m.exec(envText);
      if (m && m[1].trim().length > 0) token = m[1].trim();
    } catch { /* no .env */ }
  }
  if (!token) {
    const r = await fetch(`${API}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: 'admin' }) });
    token = ((await r.json()) as { accessToken?: string }).accessToken ?? null;
  }
  check('authenticated', Boolean(token));
  if (!token) throw new Error('login failed');

  const authed = async (method: string, p: string, body?: unknown): Promise<Response> =>
    fetch(`${API}${p}`, { method, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });

  // --- 1. Throwaway secret ------------------------------------------------------
  const createRes = await authed('POST', '/secrets', { type: 'apiKey', label: 'e2e-portable-secret', fields: { key: `portable-${Date.now()}` } });
  const createdBody = (await createRes.json().catch(() => null)) as { id?: string; error?: string } | null;
  check('test secret created (201)', createRes.status === 201, createdBody);
  const testSecretId = createdBody?.id;
  if (!testSecretId) throw new Error('no secret id');

  const fieldsRes = await authed('GET', `/secrets/${testSecretId}`);
  check('decrypted fields readable (200)', fieldsRes.status === 200, fieldsRes.status);
  const expectedFields = ((await fieldsRes.json()) as { fields?: Record<string, string> }).fields ?? {};
  check('secret has a key field', typeof expectedFields.key === 'string' && expectedFields.key.length > 0, Object.keys(expectedFields));

  // --- 2. Backup with the secrets section ---------------------------------------
  const backupRes = await authed('POST', '/backups', { name: 'e2e-portable-secrets', sections: ['devices', 'secrets'], destination: 'local', passphrase: PASSPHRASE });
  const backupBody = (await backupRes.json().catch(() => null)) as { backup?: { id?: string }; error?: string } | null;
  check('backup created (201)', backupRes.status === 201, backupBody);
  const backupId = backupBody?.backup?.id;
  if (!backupId) throw new Error('no backup id');

  // Missing-passphrase guard: the API must refuse a secrets section without one.
  const noPassRes = await authed('POST', '/backups', { name: 'e2e-no-pass', sections: ['secrets'], destination: 'local' });
  check('secrets section WITHOUT passphrase is rejected (400)', noPassRes.status === 400, noPassRes.status);

  // --- 3. Download + inspect the archive ----------------------------------------
  const dl = await authed('GET', `/backups/${backupId}/download`);
  check('archive download (200)', dl.status === 200, dl.status);
  if (dl.status !== 200) throw new Error('download failed');
  const archive = JSON.parse(zlib.gunzipSync(Buffer.from(await dl.arrayBuffer())).toString('utf8')) as {
    manifest: { secretsEncrypted?: boolean; sections: Record<string, { rowCount: number }> };
    data: Record<string, any>;
  };

  check('manifest.secretsEncrypted is true', archive.manifest.secretsEncrypted === true);
  check('manifest carries the secrets section with a row count', (archive.manifest.sections.secrets?.rowCount ?? 0) >= 1, archive.manifest.sections.secrets);
  const envelope: SecretEnvelope | undefined = archive.data.secrets?.envelope?.[0];
  check('data.secrets.envelope present + well-formed', Boolean(envelope && envelope.format === 'unm-secret-envelope' && envelope.kdf === 'scrypt' && envelope.ciphertext.length > 0), { format: envelope?.format, kdf: envelope?.kdf });

  // --- 4. Local unwrap — wrong passphrase fails, correct one round-trips --------
  let wrongFailed = false;
  try {
    unwrapSecrets(envelope!, WRONG_PASSPHRASE);
  } catch (err) {
    wrongFailed = /wrong passphrase|corrupt/i.test((err as Error).message);
  }
  check('WRONG passphrase fails to unwrap', wrongFailed);

  let unwrapped: EnvelopeSecret[] = [];
  try {
    unwrapped = unwrapSecrets(envelope!, PASSPHRASE);
  } catch (err) {
    console.error('  FAIL correct passphrase unwrap threw:', (err as Error).message);
    failures++;
  }
  check('correct passphrase unwraps the envelope', unwrapped.length >= 1, { count: unwrapped.length });
  const inEnvelope = unwrapped.find((s) => s.id === testSecretId);
  check('test secret is inside the envelope with its original id', Boolean(inEnvelope), { ids: unwrapped.map((s) => s.id).slice(0, 5) });
  check('envelope fields match the decrypted source values', inEnvelope ? JSON.stringify(inEnvelope.fields) === JSON.stringify(expectedFields) : false);

  // --- 5. Restore-apply against THIS instance (safe merge + passphrase gate) ----
  const wrongApply = await authed('POST', '/backups/restore/apply', { backupId, sections: ['secrets'], passphrase: WRONG_PASSPHRASE });
  check('apply with WRONG passphrase → 200 with section error (continueOnSectionError)', wrongApply.status === 200, wrongApply.status);
  const wrongReport = ((await wrongApply.json()) as { report?: Array<{ section: string; error?: string }> }).report ?? [];
  check('secrets section reported an unlock failure', Boolean(wrongReport.find((r) => r.section === 'secrets' && r.error)), wrongReport);

  const applyRes = await authed('POST', '/backups/restore/apply', { backupId, sections: ['secrets'], passphrase: PASSPHRASE });
  check('apply with correct passphrase → 200', applyRes.status === 200, applyRes.status);
  const report = ((await applyRes.json()) as { report?: Array<{ section: string; tables: Array<{ table: string; created: number; skipped?: number }>; error?: string }> }).report ?? [];
  const secretsReport = report.find((r) => r.section === 'secrets');
  check('secrets section applied without error', Boolean(secretsReport && !secretsReport.error), secretsReport);
  const t = secretsReport?.tables?.[0];
  check('safe merge: existing ids skipped, nothing created (same instance)', Boolean(t) && t.created === 0 && (t.skipped ?? 0) >= 1, t);

  // --- 6. Cross-instance simulation — delete + re-import from the archive -------
  const delRes = await authed('DELETE', `/secrets/${testSecretId}`);
  check('test secret deleted for re-import test (204)', delRes.status === 204, delRes.status);

  const reimportRes = await authed('POST', '/backups/restore/apply', { backupId, sections: ['secrets'], passphrase: PASSPHRASE });
  check('re-import apply → 200', reimportRes.status === 200, reimportRes.status);
  const reReport = ((await reimportRes.json()) as { report?: Array<{ section: string; tables: Array<{ table: string; created: number; skipped?: number }>; error?: string }> }).report ?? [];
  const rt = reReport.find((r) => r.section === 'secrets')?.tables?.[0];
  check('re-import CREATED the deleted secret (portable round-trip)', Boolean(rt) && rt.created >= 1, rt);

  // The row must exist under its ORIGINAL id and decrypt under THIS instance's key.
  const recheck = await authed('GET', `/secrets/${testSecretId}`);
  check('re-imported secret readable at the SAME id (200)', recheck.status === 200, recheck.status);
  if (recheck.status === 200) {
    const reFields = ((await recheck.json()) as { fields?: Record<string, string> }).fields ?? {};
    check('re-imported value decrypts to the ORIGINAL fields', JSON.stringify(reFields) === JSON.stringify(expectedFields), Object.keys(reFields));
  }

  // --- 7. Cleanup -----------------------------------------------------------------
  const cleanupSecret = await authed('DELETE', `/secrets/${testSecretId}`);
  check('cleanup: test secret deleted (204)', cleanupSecret.status === 204, cleanupSecret.status);
  const cleanupBackup = await authed('DELETE', `/backups/${backupId}`);
  check('cleanup: backup row deleted (200/204)', cleanupBackup.status === 200 || cleanupBackup.status === 204, cleanupBackup.status);

  await pool.end();
  console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error('FATAL', err);
  process.exit(1);
});
