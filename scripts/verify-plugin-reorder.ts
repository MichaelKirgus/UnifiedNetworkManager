/**
 * End-to-end check of PUT /v1/devices/:id/plugins/order using a THROWAWAY
 * device (created and deleted by this script — no production data touched).
 *
 * 1. Creates "ZZ-REORDER-TEST" with two plugins (ICMP first → primary, FBox second).
 * 2. Reads the stored order back.
 * 3. Reorders them via PUT .../plugins/order (FBox first).
 * 4. Verifies dense re-numbering + primary flag moved to position 0.
 * 5. Deletes the throwaway device.
 *
 * Usage (from repo root):
 *   ./node_modules/.bin/tsx scripts/verify-plugin-reorder.ts
 */

import path from 'node:path';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));

interface Assignment {
  id: string;
  pluginId: string;
  isPrimary: boolean;
  order: number;
}

async function main(): Promise<void> {
  // --- Login (admin/admin; TOTP from seeded secret when enabled) -----------
  const { Pool } = apiRequire('pg');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm' });
  const adminRow = (await pool.query(`SELECT "totpSecret" FROM users WHERE username = 'admin'`)).rows[0] as { totpSecret: string | null };
  await pool.end();

  let token: string | null = null;
  if (!adminRow) {
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
  if (!token) throw new Error('login failed');

  const H = { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` };
  const j = async (r: Response) => (await r.json()) as Record<string, unknown>;

  // --- Plugin ids -----------------------------------------------------------
  const icmpId = 'c9d5e7f8-2a3b-4c5d-8e6f-0a1b2c3d4e5f'; // ICMP Plugin (no creds)
  const fboxId = '00000000-0000-4000-8000-000000000008'; // FBox Plugin

  // --- Create throwaway device ----------------------------------------------
  let deviceId: string | null = null;
  try {
    const created = await fetch(`${API}/devices`, { method: 'POST', headers: H, body: JSON.stringify({
      name: 'ZZ-REORDER-TEST', vendor: 'generic', deviceTypes: ['server'],
      managementAddress: '192.0.2.254', // TEST-NET-3 — never routed
      plugins: [{ pluginId: icmpId }, { pluginId: fboxId }],
    }) });
    if (created.status !== 200 && created.status !== 201) throw new Error(`create → HTTP ${created.status}: ${(await created.text()).slice(0, 300)}`);
    const body = await j(created);
    deviceId = String(body.id ?? '');
    console.log(`✓ created throwaway device ${deviceId}`);

    // --- Initial order -------------------------------------------------------
    let list = await fetch(`${API}/devices/${deviceId}/plugins`, { headers: H });
    if (list.status !== 200) throw new Error(`GET plugins → HTTP ${list.status}`);
    let rows = ((await j(list)) as { plugins: Assignment[] }).plugins;
    console.log('initial:', rows.map((r) => `${r.pluginId.slice(0, 8)}… order=${r.order} primary=${r.isPrimary}`).join(' | '));
    if (rows.length !== 2 || rows[0].pluginId !== icmpId || !rows[0].isPrimary) throw new Error('unexpected initial state');

    // --- Reorder: FBox first --------------------------------------------------
    const rev = await fetch(`${API}/devices/${deviceId}/plugins/order`, { method: 'PUT', headers: H, body: JSON.stringify({ order: [fboxId, icmpId] }) });
    if (rev.status !== 200) throw new Error(`reorder → HTTP ${rev.status}: ${(await rev.text()).slice(0, 300)}`);
    const revBody = await j(rev);
    console.log('PUT response plugins:', ((revBody.plugins as Assignment[]) ?? []).map((r) => `${r.pluginId.slice(0, 8)}… order=${r.order} primary=${r.isPrimary}`).join(' | '));

    // --- Verify persisted state -------------------------------------------------
    list = await fetch(`${API}/devices/${deviceId}/plugins`, { headers: H });
    rows = ((await j(list)) as { plugins: Assignment[] }).plugins;
    console.log('after  :', rows.map((r) => `${r.pluginId.slice(0, 8)}… order=${r.order} primary=${r.isPrimary}`).join(' | '));

    const ok =
      rows.length === 2 &&
      rows[0].pluginId === fboxId && rows[0].order === 0 && rows[0].isPrimary === true &&
      rows[1].pluginId === icmpId && rows[1].order === 1 && rows[1].isPrimary === false;
    if (!ok) throw new Error('reorder did not persist as expected');

    // --- Idempotency: same order again → still fine ------------------------------
    const again = await fetch(`${API}/devices/${deviceId}/plugins/order`, { method: 'PUT', headers: H, body: JSON.stringify({ order: [fboxId, icmpId] }) });
    if (again.status !== 200) throw new Error(`re-apply → HTTP ${again.status}`);

    console.log('\nPASS — reorder endpoint works end-to-end (dense re-numbering + primary swap).');
  } finally {
    // --- Cleanup: delete the throwaway device -----------------------------------
    if (deviceId) {
      const del = await fetch(`${API}/devices/${deviceId}`, { method: 'DELETE', headers: H });
      console.log(del.status === 200 || del.status === 204 ? `✓ deleted ${deviceId}` : `cleanup FAILED → HTTP ${del.status}: ${(await del.text()).slice(0, 200)}`);
    }
  }
}

main().catch((err) => {
  console.error('FAIL:', err instanceof Error ? err.message : err);
  process.exitCode = 1;
});
