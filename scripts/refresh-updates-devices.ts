/**
 * Forces an immediate read-only re-poll (collectInventory: true) of the given
 * devices via POST /v1/devices/refresh, then prints GET /v1/updates.
 * No device state is modified — refresh only triggers normal /monitoring polls.
 *
 * Usage (from repo root):
 *   ./node_modules/.bin/tsx scripts/refresh-updates-devices.ts [deviceName ...]
 */

import path from 'node:path';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));

async function main(): Promise<void> {
  const names = process.argv.slice(2);
  if (names.length === 0) throw new Error('pass at least one device name');

  // --- Login (admin/admin; TOTP from seeded secret when enabled) -----------
  const { Pool } = apiRequire('pg');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm' });
  const rows = (await pool.query(`SELECT id, name FROM devices WHERE name = ANY($1)`, [names])).rows as { id: string; name: string }[];
  await pool.end();
  if (rows.length === 0) throw new Error(`no devices matching ${names.join(', ')}`);

  const adminRow = (await (async () => {
    const p2 = new Pool({ connectionString: process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm' });
    try { return (await p2.query(`SELECT "totpSecret" FROM users WHERE username = 'admin'`)).rows[0] as { totpSecret: string | null }; } finally { await p2.end(); }
  })()).totpSecret;

  let token: string | null = null;
  if (!adminRow) {
    const r = await fetch(`${API}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: 'admin' }) });
    token = ((await r.json()) as { accessToken?: string }).accessToken ?? null;
  } else {
    const { authenticator } = apiRequire('otplib');
    const code = authenticator.generate(adminRow);
    const r1 = await fetch(`${API}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: 'admin' }) });
    const challenge = ((await r1.json()) as { challengeToken?: string }).challengeToken ?? '';
    const r2 = await fetch(`${API}/auth/2fa/verify`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ challengeToken: challenge, totpCode: code }) });
    token = ((await r2.json()) as { accessToken?: string }).accessToken ?? null;
  }
  if (!token) throw new Error('login failed');

  // --- Force refresh (read-only re-poll with inventory collection) ---------
  const res = await fetch(`${API}/devices/refresh`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, body: JSON.stringify({ deviceIds: rows.map((r) => r.id) }) });
  if (res.status !== 200) throw new Error(`refresh → HTTP ${res.status}: ${(await res.text()).slice(0, 400)}`);
  const refreshBody = (await res.json()) as { results: Array<{ name: string; ok: boolean; error?: string }> };
  for (const r of refreshBody.results) console.log(`  refresh ${r.name}: ${r.ok ? 'ok' : `FAILED (${r.error ?? '?'})`}`);

  // --- Show resulting updates ----------------------------------------------
  const up = await fetch(`${API}/updates`, { headers: { Authorization: `Bearer ${token}` } });
  if (up.status !== 200) throw new Error(`/v1/updates → HTTP ${up.status}`);
  const body = (await up.json()) as { rows: Array<{ deviceName: string; pluginName: string; kind: string; name: string; currentVersion?: string | null; latestVersion?: string | null; applyActionId?: string | null }> };
  console.log(`\n=== /v1/updates — ${body.rows.length} row(s) ===`);
  for (const r of body.rows) {
    const apply = r.applyActionId ? ` [apply: ${r.applyActionId}]` : ' [no-apply]';
    console.log(`  • ${r.deviceName} · ${r.pluginName}: kind=${r.kind} "${r.name}" ${r.currentVersion ?? '?'} → ${r.latestVersion ?? '?'}${apply}`);
  }
}

main().catch((err) => { console.error('ERROR', err.message ?? err); process.exit(1); });
