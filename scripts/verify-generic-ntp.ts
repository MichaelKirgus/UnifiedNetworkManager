/**
 * End-to-end check of the Generic (S)NTP plugin using a THROWAWAY device
 * (created and deleted by this script — no production data touched).
 *
 * 1. Creates "ZZ-NTP-E2E" with management address `mock-ntp` (the compose mock
 *    NTP server service name — bare hostname, no scheme/port) + the generic-ntp plugin.
 * 2. Forces an immediate full poll via POST /v1/devices/refresh → the plugin sends
 *    one SNTP request to udp://mock-ntp:123 and ingests `system.ntpServed`.
 * 3. Verifies: telemetry health ok + ntp.* metrics; the `device_times` table has
 *    the NTP-served columns populated for this (device, plugin); GET /device-time
 *    returns the row with ntpAvailable=true; and the short-cycle probe endpoint
 *    answers keys=ntpServed.
 * 4. Deletes the throwaway device (its clock rows are deleted with it).
 *
 * Prereq: `docker compose up -d mock-ntp` (this host blocks outbound UDP/123, so
 * the in-network mock is the deterministic target — same pattern as mock-appliance).
 *
 * Usage (from repo root):
 *   ./node_modules/.bin/tsx scripts/verify-generic-ntp.ts
 */

import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const PLUGIN_ID = '00000000-0000-4000-8000-00000000000e'; // Generic (S)NTP Plugin
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
      name: 'ZZ-NTP-E2E', vendor: 'generic', deviceTypes: ['server'],
      managementAddress: 'mock-ntp', // compose mock NTP server (bare hostname → default port 123)
      plugins: [{ pluginId: PLUGIN_ID }],
    }) });
    if (created.status !== 200 && created.status !== 201) throw new Error(`create → HTTP ${created.status}: ${(await created.text()).slice(0, 300)}`);
    const body = (await created.json()) as { id?: string };
    deviceId = String(body.id ?? '');
    console.log(`✓ created throwaway device ${deviceId} (mock-ntp + Generic (S)NTP Plugin)`);

    // --- Force an immediate FULL poll ----------------------------------------
    const ref = await fetch(`${API}/devices/refresh`, { method: 'POST', headers: H, body: JSON.stringify({ deviceIds: [deviceId] }) });
    if (ref.status !== 200) throw new Error(`refresh → HTTP ${ref.status}: ${(await ref.text()).slice(0, 300)}`);
    const refBody = (await ref.json()) as { results?: Array<{ ok: boolean; error?: string }> };
    const result = refBody.results?.[0];
    if (!result?.ok) throw new Error(`forced poll not ok: ${JSON.stringify(refBody).slice(0, 300)}`);
    console.log('✓ forced full poll succeeded');

    // --- Telemetry health + NTP metrics --------------------------------------
    const tele = psql(`SELECT "health" || ' | reachable=' || COALESCE((metrics::json)->>'ntp.reachable', '?') || ' | rtt=' || COALESCE((metrics::json)->>'ntp.responseTimeMs', '?') || ' ms | timeUtc=' || COALESCE((metrics::json)->>'ntp.timeUtc', '?') || ' | stratum=' || COALESCE((metrics::json)->>'ntp.stratum', '?') FROM telemetry WHERE "deviceId" = '${deviceId}' ORDER BY "collectedAt" DESC LIMIT 1`);
    console.log(`✓ latest telemetry: ${tele}`);
    if (!tele.startsWith('ok')) throw new Error('FAIL — device not healthy in telemetry');

    // --- device_times table (what the Time page reads) ------------------------
    // ingestDeviceTime() is fire-and-forget async inside pollAssignment, so the
    // row lands a few ms after refresh returns — retry briefly rather than race it.
    let dt = '';
    for (let i = 0; i < 20 && !dt.includes('ntpTimeUtc=20'); i++) {
      await new Promise((r) => setTimeout(r, 300));
      // NOTE: single quotes around the '<null>' placeholders — double quotes would
      // make Postgres treat them as column identifiers and error out.
      dt = psql(`SELECT COALESCE("localIso", '') || ' | ntpTimeUtc=' || COALESCE("ntpTimeUtc", '<null>') || ' | ntpEpochMs=' || COALESCE("ntpEpochMs", -1) || ' | stratum=' || COALESCE("ntpStratum", -1) || ' | ref=' || COALESCE("ntpReferenceId", '<null>') FROM device_times WHERE "deviceId" = '${deviceId}' AND "pluginId" = '${PLUGIN_ID}'`);
    }
    console.log(`✓ device_times row: ${dt}`);
    if (!dt.includes('ntpTimeUtc=20')) throw new Error('FAIL — ntpTimeUtc not populated in device_times');

    // --- GET /device-time (what the Time page fetches) ------------------------
    const timeApi = await fetch(`${API}/device-time?deviceId=${deviceId}`, { headers: H });
    if (timeApi.status !== 200) throw new Error(`GET /device-time → HTTP ${timeApi.status}`);
    const timeBody = (await timeApi.json()) as { devices?: Array<Record<string, unknown>> };
    const row = timeBody.devices?.[0];
    if (!row) throw new Error('FAIL — GET /device-time returned no device');
    console.log(`✓ GET /v1/device-time: ntpAvailable=${String(row['ntpAvailable'])} ntpTimeUtc=${String(row['ntpTimeUtc'])} stratum=${String(row['ntpStratum'])} ref=${String(row['ntpReferenceId'])} ntpDriftMs=${String(row['ntpDriftMs'])}`);
    if (row['ntpAvailable'] !== true) throw new Error('FAIL — /device-time did not report ntpAvailable=true');

    // --- Short-cycle probe endpoint (live NTP-served refresh) -----------------
    const probe = await fetch(`${API}/devices/${deviceId}/probe?keys=ntpServed&pluginId=${PLUGIN_ID}`, { headers: H });
    if (probe.status !== 200) throw new Error(`GET /probe → HTTP ${probe.status}: ${(await probe.text()).slice(0, 300)}`);
    const probeBody = (await probe.json()) as { probe?: { metrics?: Record<string, unknown> } };
    const served = probeBody.probe?.metrics?.['system.ntpServed'] as Record<string, unknown> | undefined;
    if (!served || typeof served.timeUtc !== 'string') throw new Error('FAIL — probe did not return system.ntpServed');
    console.log(`✓ GET /probe keys=ntpServed: timeUtc=${String(served.timeUtc)} stratum=${String(served.stratum)}`);

    console.log('\nPASS — Generic (S)NTP plugin works end-to-end: NTP reachability + served-time metrics, ingested into the Time page (device_times + /device-time), and live via the probe endpoint.');
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
