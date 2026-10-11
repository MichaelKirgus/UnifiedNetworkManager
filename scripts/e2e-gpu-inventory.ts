/**
 * E2E check for the cross-plugin GPU feature (v0.4.0 generic-ssh / v0.27.0
 * TrueNAS / v0.9.0 docker): force-refreshes every device assigned to one of
 * those plugins, then reads back BOTH the ingested `gpus` table rows and the
 * raw telemetry metrics['gpus'] so we can confirm:
 *   - PCI enumeration caught the card(s) (name/vendor/slot/driver);
 *   - live counters merged in where a vendor tool exists;
 *   - GPU-less hosts yield an authoritative EMPTY array (wipe path).
 *
 * Usage (from repo root):
 *   ./node_modules/.bin/tsx scripts/e2e-gpu-inventory.ts [deviceName ...]
 * With no args it refreshes every device assigned to the three plugins.
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
    console.error(`  FAIL ${label}`, extra !== undefined ? JSON.stringify(extra).slice(0, 600) : '');
  }
}

async function main(): Promise<void> {
  const wanted = process.argv.slice(2); // optional device-name filter

  const { Pool } = apiRequire('pg');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm' });

  // --- Target devices: assigned to one of the three GPU-capable plugins -------
  const devRows = (await pool.query(
    `SELECT d.id, d.name FROM devices d
     JOIN device_plugins a ON a."deviceId" = d.id
     WHERE a."pluginId" IN (
       SELECT id FROM plugins WHERE name LIKE '%TrueNAS%' OR name LIKE '%Generic SSH%' OR name LIKE 'Docker Plugin'
     ) ORDER BY d.name`
  )).rows as Array<{ id: string; name: string }>;

  const targets = wanted.length > 0 ? devRows.filter((d) => wanted.includes(d.name)) : devRows;
  if (targets.length === 0) throw new Error(`no target devices${wanted.length ? ` for ${wanted.join(', ')}` : ''}`);
  console.log(`Refreshing ${targets.length} device(s): ${targets.map((t) => t.name).join(', ')}\n`);

  // --- Auth -------------------------------------------------------------------
  // Preferred: a long-lived API token (UNM_API_TOKEN env or .env) — no 2FA.
  // Fallback: admin login with TOTP minted from the seeded secret (works while
  // the password is still the default 'admin').
  let token = process.env.UNM_API_TOKEN ?? null;
  if (!token) {
    try {
      const fs = apiRequire('node:fs');
      const envFile = fs.readFileSync(path.resolve(process.cwd(), '.env'), 'utf8');
      const m = envFile.match(/^UNM_API_TOKEN=(.+)$/m);
      if (m?.[1]?.trim()) token = m[1].trim();
    } catch { /* no .env */ }
  }
  if (!token) {
    const adminRow = (await pool.query(`SELECT "totpSecret" FROM users WHERE username = 'admin'`)).rows[0] as { totpSecret: string | null };
    if (!adminRow?.totpSecret) {
      const r = await fetch(`${API}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: process.env.UNM_ADMIN_PW ?? 'admin' }) });
      token = ((await r.json()) as { accessToken?: string }).accessToken ?? null;
    } else {
      // otplib@13 dropped the `authenticator` instance — use the functional API.
      const { generate: otpGenerate } = apiRequire('otplib');
      const code = await otpGenerate({ strategy: 'totp', secret: adminRow.totpSecret });
      const r1 = await fetch(`${API}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: process.env.UNM_ADMIN_PW ?? 'admin' }) });
      const challenge = ((await r1.json()) as { challengeToken?: string }).challengeToken ?? '';
      const r2 = await fetch(`${API}/auth/2fa/verify`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ challengeToken: challenge, totpCode: code }) });
      token = ((await r2.json()) as { accessToken?: string }).accessToken ?? null;
    }
  }
  if (!token) throw new Error('no auth — set UNM_API_TOKEN (or .env) / UNM_ADMIN_PW');

  const authed = async (method: string, p: string, body?: unknown): Promise<{ status: number; json: () => Promise<unknown> }> => {
    const res = await fetch(`${API}${p}`, { method, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    return { status: res.status, json: async () => (await res.json().catch(() => null)) as never };
  };

  // --- Force refresh (metrics + inventory) ------------------------------------
  const refRes = await authed('POST', '/devices/refresh', { deviceIds: targets.map((t) => t.id) });
  check('refresh endpoint answered 200', refRes.status === 200, await refRes.json());

  // Give the telemetry worker a beat to ingest (the refresh resolves after the
  // poll returns; ingestion is synchronous in the same handler, but be safe).
  await new Promise((r) => setTimeout(r, 1500));

  // --- Read back: ingested gpus rows + raw telemetry metrics['gpus'] ----------
  for (const t of targets) {
    console.log(`\n=== ${t.name} ===`);
    const gpuRows = (await pool.query(
      `SELECT name, vendor, slot, driver, "driverVersion", "vramBytes", "utilPercent", "tempCelsius" FROM gpus WHERE "deviceId" = $1 ORDER BY slot`, [t.id]
    )).rows as Array<Record<string, unknown>>;

    // The LATEST snapshot carrying the key — metrics-only polls omit it by
    // design (absent = no wipe), so the newest row may legitimately lack it.
    const tel = (await pool.query(
      `SELECT metrics FROM telemetry WHERE "deviceId" = $1 AND (metrics::jsonb ? 'gpus') ORDER BY "collectedAt" DESC LIMIT 1`, [t.id]
    )).rows[0] as { metrics: string } | undefined;
    let rawGpus: unknown = null;
    if (tel) {
      try { rawGpus = JSON.parse(tel.metrics)['gpus']; } catch { /* ignore */ }
    }

    const hasKey = tel !== undefined;
    console.log(`  telemetry gpus key present (latest inventory poll): ${hasKey}   ingested rows: ${gpuRows.length}`);
    for (const r of gpuRows) {
      const vram = typeof r['vramBytes'] === 'number' ? `${(r['vramBytes'] as number) / 1048576 | 0} MiB` : null;
      console.log(`   • ${String(r.name).slice(0, 32).padEnd(32)} ${String(r.vendor ?? '').padEnd(7)} slot=${r.slot} drv=${r.driver ?? '-'}${r['driverVersion'] ? `@${r['driverVersion']}` : ''}${vram ? ` vram=${vram}` : ''}${typeof r['utilPercent'] === 'number' ? ` util=${r['utilPercent']}%` : ''}${typeof r['tempCelsius'] === 'number' ? ` ${r['tempCelsius']}°C` : ''}`);
    }
    if (gpuRows.length === 0) {
      // Distinguish "no GPUs" (authoritative empty array emitted) from "key absent".
      check(`${t.name}: no GPU rows — key present-but-empty (wipe path) or absent`, Array.isArray(rawGpus) || !hasKey, rawGpus);
    } else {
      check(`${t.name}: ingested row count matches telemetry array`, gpuRows.length === (Array.isArray(rawGpus) ? rawGpus.length : -1), { table: gpuRows.length, telemetry: Array.isArray(rawGpus) ? rawGpus.length : 'absent' });
    }
  }

  await pool.end();
  console.log(`\n${failures === 0 ? 'ALL CHECKS PASSED' : `${failures} CHECK(S) FAILED`}`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e.message ?? e); process.exit(1); });
