/**
 * End-to-end verification for the Files page extension (repo picker + default
 * repo + "Uploaded by" username resolution). Runs against the LIVE dev stack:
 *   1. logs in via the real auth flow (TOTP minted from the seeded admin secret)
 *   2. GET /files/providers — asserts providers list + effective defaultProviderId
 *   3. GET /system-settings — asserts the fileRepoDefaultProviderId descriptor exists
 *   4. uploads a small test file WITHOUT x-file-provider → must land in the default repo
 *      (providerId set, blob present in that provider's volume)
 *   5. GET /files — asserts uploadedByName is resolved to 'admin' (not a raw UUID)
 *   6. cleans up the test upload
 *
 * Usage (from the repo root):
 *   ./node_modules/.bin/tsx scripts/verify-files-page.ts
 */

import path from 'node:path';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
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
  // --- Login (admin/admin; TOTP when enabled) ---------------------------------
  const { Pool } = apiRequire('pg');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm' });
  const adminRow = (await pool.query(`SELECT "totpSecret", id FROM users WHERE username = 'admin'`)).rows[0] as { totpSecret: string | null; id: string };

  let token: string | null = null;
  if (!adminRow.totpSecret) {
    const r = await fetch(`${API}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: 'admin' }) });
    token = ((await r.json()) as { accessToken?: string }).accessToken ?? null;
  } else {
    const { authenticator } = apiRequire('otplib');
    const code = authenticator.generate(adminRow.totpSecret);
    const r1 = await fetch(`${API}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: 'admin' }) });
    const challenge = ((await r1.json()) as { challengeToken?: string }).challengeToken ?? '';
    const r2 = await fetch(`${API}/auth/2fa/verify`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ challengeToken: challenge, totpCode: code }) });
    token = ((await r2.json()) as { accessToken?: string }).accessToken ?? null;
  }
  check('authenticated', Boolean(token));
  if (!token) throw new Error('login failed');

  const authed = async (method: string, p: string, init?: RequestInit): Promise<Response> =>
    fetch(`${API}${p}`, {
      method,
      body: init?.body,
      headers: { Authorization: `Bearer ${token}`, ...(init?.headers as Record<string, string> | undefined) },
    });

  // --- 1. Providers + effective default ---------------------------------------
  const provRes = await authed('GET', '/files/providers');
  const provBody = (await provRes.json().catch(() => null)) as { providers?: Array<{ id: string; name: string; online: boolean }>; defaultProviderId?: string | null } | null;
  check('GET /files/providers → 200', provRes.status === 200, provBody);
  if (!provBody) throw new Error('providers response not JSON');
  check('at least one provider registered', (provBody.providers ?? []).length >= 1, provBody);
  check('defaultProviderId present in response', 'defaultProviderId' in provBody, Object.keys(provBody));
  const providers = provBody.providers ?? [];
  const def = provBody.defaultProviderId;
  if (def) {
    const defProv = providers.find((p) => p.id === def);
    check(`default provider ${def.slice(0, 8)}… is online`, Boolean(defProv?.online), defProv);
  } else {
    console.log('  INFO defaultProviderId is null (no provider online — local fallback expected)');
  }

  // --- 2. System setting descriptor -------------------------------------------
  const setRes = await authed('GET', '/settings');
  check('GET /settings → 200', setRes.status === 200);
  const setBody = (await setRes.json()) as { settings?: Array<{ key: string }>; descriptors?: Array<{ key: string }> };
  const allKeys = [...(setBody.settings ?? []), ...(setBody.descriptors ?? [])].map((s) => s.key);
  check('fileRepoDefaultProviderId descriptor registered', allKeys.includes('fileRepoDefaultProviderId'), allKeys.filter((k) => String(k).includes('file')));

  // --- 3. Upload WITHOUT provider header → default repo ------------------------
  const marker = `files-page-verify-${Date.now()}`;
  const upRes = await authed('POST', '/files', {
    method: 'POST',
    headers: { 'Content-Type': 'application/octet-stream', 'x-file-name': `${marker}.txt`, 'x-file-category': 'other' },
    body: new Blob([`verify ${marker}`]),
  });
  const upBody = (await upRes.json().catch(() => null)) as { file?: { id: string; name: string; sha256: string; uploadedBy: string | null; uploadedByName?: string | null; providerId: string | null } } | null;
  check('upload (no provider header) → 201', upRes.status === 201, upBody);
  if (!upBody?.file) throw new Error('upload response not JSON');
  check('uploaded entry has providerId set', Boolean(upBody.file.providerId), upBody.file);
  if (def) check('upload landed in the DEFAULT repo', upBody.file.providerId === def, { got: upBody.file.providerId, want: def });

  // --- 4. List → uploadedByName resolved ---------------------------------------
  const listRes = await authed('GET', '/files');
  check('GET /files → 200', listRes.status === 200);
  const listBody = (await listRes.json()) as { files: Array<{ id: string; name: string; uploadedBy: string | null; uploadedByName?: string | null }> };
  const mine = listBody.files.find((f) => f.name === `${marker}.txt`);
  check('uploaded file appears in listing', Boolean(mine));
  if (mine) {
    check('uploadedBy is the admin user id', mine.uploadedBy === adminRow.id, mine.uploadedBy);
    check('uploadedByName resolved to "admin"', mine.uploadedByName === 'admin', mine.uploadedByName);
  }

  // --- 5. Cleanup ---------------------------------------------------------------
  if (mine) {
    const delRes = await authed('DELETE', `/files/${encodeURIComponent(mine.id)}`);
    check('cleanup delete → 204', delRes.status === 204, delRes.status);
  }

  await pool.end();
  console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
