/**
 * End-to-end check of the Generic HTTP(S) plugin using a THROWAWAY device
 * (created and deleted by this script — no production data touched).
 *
 * 1. Creates "ZZ-HTTP-E2E" with management address example.com + the generic-http plugin.
 * 2. Forces an immediate full poll via POST /v1/devices/refresh (bypasses the
 *    staggered scheduler AND guarantees collectInventory=true, so the TLS
 *    certificate probe runs and `metrics['certificates']` is ingested).
 * 3. Verifies rows landed in the `certificates` table — exactly what the
 *    Certificates page renders (issuer, expiry, chain verdict) — plus the live
 *    response-time/status metrics in telemetry.
 * 4. Deletes the throwaway device (its cert rows are deleted with it).
 *
 * Usage (from repo root):
 *   ./node_modules/.bin/tsx scripts/verify-generic-http.ts
 */

import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const PLUGIN_ID = '00000000-0000-4000-8000-00000000000d'; // Generic HTTP(S) Plugin
const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));

function psql(sql: string): string {
  return execFileSync('docker', ['exec', '-i', 'unifiednetworkmanager-postgres-1', 'psql', '-U', 'unm', '-d', 'unm', '-t', '-A', '-F', '|'], { input: sql, encoding: 'utf8' }).trim();
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
    const code = authenticator.generate(adminRow.totpSecret); // secret STRING, not the row
    const r1 = await fetch(`${API}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: 'admin' }) });
    const challenge = ((await r1.json()) as { challengeToken?: string }).challengeToken ?? '';
    const r2 = await fetch(`${API}/auth/2fa/verify`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ challengeToken: challenge, totpCode: code }) });
    token = ((await r2.json()) as { accessToken?: string }).accessToken ?? null;
  }
  if (!token) throw new Error('login failed');

  const H = { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` };

  // --- Create throwaway device ----------------------------------------------
  let deviceId: string | null = null;
  try {
    const created = await fetch(`${API}/devices`, { method: 'POST', headers: H, body: JSON.stringify({
      name: 'ZZ-HTTP-E2E', vendor: 'generic', deviceTypes: ['server'],
      managementAddress: 'example.com', // real public host — exercises HTTP + TLS cert probe
      plugins: [{ pluginId: PLUGIN_ID }],
    }) });
    if (created.status !== 200 && created.status !== 201) throw new Error(`create → HTTP ${created.status}: ${(await created.text()).slice(0, 300)}`);
    const body = (await created.json()) as { id?: string };
    deviceId = String(body.id ?? '');
    console.log(`✓ created throwaway device ${deviceId} (example.com + Generic HTTP(S) Plugin)`);

    // --- Force an immediate FULL poll (collectInventory=true) -----------------
    const ref = await fetch(`${API}/devices/refresh`, { method: 'POST', headers: H, body: JSON.stringify({ deviceIds: [deviceId] }) });
    if (ref.status !== 200) throw new Error(`refresh → HTTP ${ref.status}: ${(await ref.text()).slice(0, 300)}`);
    const refBody = (await ref.json()) as { results?: Array<{ ok: boolean }> };
    const result = refBody.results?.[0];
    if (!result?.ok) throw new Error(`forced poll not ok: ${JSON.stringify(refBody).slice(0, 300)}`);
    console.log('✓ forced full poll succeeded');

    // --- Certificates table (what the Certificates page renders) --------------
    const rows = psql(`SELECT name || ' | ' || "commonName" || ' | issuer=' || issuer || ' | valid=' || valid || ' | daysToExpiry=' || COALESCE("daysToExpiry", -1) FROM certificates WHERE "deviceId" = '${deviceId}' ORDER BY name`).split('\n').filter(Boolean);
    if (rows.length === 0) throw new Error('FAIL — no certificate rows ingested');
    console.log('✓ certificates table:');
    for (const row of rows) console.log(`   ${row}`);

    // --- Telemetry health + live metrics --------------------------------------
    const tele = psql(`SELECT "health" || ' | ' || COALESCE((metrics::json)->>'http.responseTimeMs', '?') || ' ms | status=' || COALESCE((metrics::json)->>'http.status', '?') FROM telemetry WHERE "deviceId" = '${deviceId}' ORDER BY "collectedAt" DESC LIMIT 1`);
    console.log(`✓ latest telemetry: ${tele}`);
    if (!tele.startsWith('ok')) throw new Error('FAIL — device not healthy in telemetry');

    // --- Certificates page API view (what the webapp fetches) ------------------
    const certApi = await fetch(`${API}/certificates?deviceId=${deviceId}`, { headers: H });
    if (certApi.status !== 200) throw new Error(`GET /certificates → HTTP ${certApi.status}`);
    // The endpoint returns a BARE array of certificate rows.
    const apiRows = ((await certApi.json()) as unknown[]) as Record<string, unknown>[];
    if (!Array.isArray(apiRows) || apiRows.length === 0) throw new Error('FAIL — GET /certificates returned no rows');
    console.log(`✓ GET /v1/certificates returned ${apiRows.length} row(s)`);

    console.log('\nPASS — Generic HTTP(S) plugin works end-to-end: reachability + response-time metrics, TLS cert ingested into the Certificates page.');
  } finally {
    if (deviceId) {
      const del = await fetch(`${API}/devices/${deviceId}`, { method: 'DELETE', headers: H });
      console.log(del.ok ? `✓ deleted throwaway device ${deviceId}` : `! delete → HTTP ${del.status} (clean up manually)`);
    }
  }
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
