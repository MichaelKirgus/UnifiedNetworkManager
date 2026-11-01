/**
 * Live verification for the netcup-scp CPU probe (VMs page CPU column).
 * Runs against the LIVE dev stack:
 *   1. logs in via the real auth flow (TOTP minted from the seeded admin secret)
 *   2. GET /devices/:id/probe?keys=vmStats,vmStates → asserts vmStates is an
 *      object and every ingested VM has a cpuPct in [0,100] + vcpus ≥ 1
 *   3. cross-checks one VM's value against the raw SCP metrics/cpu series
 *      (latest point mean ÷ 1e9 × 100) via the netcup CLI
 *
 * Usage (from the repo root):
 *   ./node_modules/.bin/tsx scripts/verify-netcup-cpu-probe.ts [deviceId]
 */

import path from 'node:path';
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const DEVICE_ID = process.argv[2] ?? 'f23b7164-e948-41f6-a41e-089757f3a97c';
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
  // --- Auth (UNM_API_TOKEN from .env first, else admin login + TOTP) -----------
  const { Pool } = apiRequire('pg');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm' });

  let token: string | null = process.env.UNM_API_TOKEN ?? null;
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
  check('authenticated', Boolean(token));
  if (!token) throw new Error('login failed');

  const authed = async (method: string, p: string): Promise<Response> =>
    fetch(`${API}${p}`, { method, headers: { Authorization: `Bearer ${token}` } });

  // --- Ingested VMs (the set the webapp would poll for) ------------------------
  const vmsRes = await authed('GET', '/vms');
  const vmsBody = (await vmsRes.json()) as { vms?: Array<{ name: string; deviceId: string; pluginId: string }> };
  const netcupVms = (vmsBody.vms ?? []).filter((v) => v.deviceId === DEVICE_ID);
  check('GET /vms → ingested netcup VMs present', netcupVms.length > 0, `count=${netcupVms.length}`);

  // --- The probe itself ---------------------------------------------------------
  // URLSearchParams percent-encodes the comma — the API's OpenAPI validator
  // rejects raw reserved characters in query values (400).
  const probeQs = new URLSearchParams({ keys: 'vmStats,vmStates' }).toString();
  const probeRes = await authed('GET', `/devices/${DEVICE_ID}/probe?${probeQs}`);
  check('GET /devices/:id/probe → 200', probeRes.status === 200, `status=${probeRes.status}`);
  if (probeRes.status !== 200) throw new Error(`probe failed: ${await probeRes.text().catch(() => '')}`.slice(0, 300));

  const body = (await probeRes.json()) as { collectedAt?: string; probe?: { collectedAt?: string; metrics?: Record<string, unknown> } };
  const metrics = body.probe?.metrics ?? {};
  check('probe has collectedAt', typeof body.probe?.collectedAt === 'string' || typeof body.collectedAt === 'string', JSON.stringify(body).slice(0, 200));

  const vmStates = metrics['vmStates'];
  check('vmStates present as object (webapp early-return guard)', vmStates !== null && typeof vmStates === 'object', `vmStates=${JSON.stringify(vmStates ?? null)}`);

  const vmStats = metrics['vmStats'] as Record<string, { cpuPct?: number; vcpus?: number }> | undefined;
  check('vmStats present as object', vmStats !== null && typeof vmStats === 'object' && !Array.isArray(vmStats), `keys=${JSON.stringify(Object.keys(vmStats ?? {}))}`);

  const stats = vmStats ?? {};
  let allInRange = true;
  for (const [name, s] of Object.entries(stats)) {
    if (typeof s?.cpuPct !== 'number' || !Number.isFinite(s.cpuPct) || s.cpuPct < 0 || s.cpuPct > 100) allInRange = false;
    if (typeof s?.vcpus !== 'number' || s.vcpus < 1) allInRange = false;
  }
  check('every vmStats entry has cpuPct in [0,100] + vcpus ≥ 1', Object.keys(stats).length > 0 && allInRange, JSON.stringify(stats));

  // Every ingested VM should have a stat (RUNNING ones at least; stopped VMs may
  // still carry their last series point — accept either but report coverage).
  const missing = netcupVms.filter((v) => !(v.name in stats)).map((v) => v.name);
  check('all ingested VMs covered by vmStats', missing.length === 0, `missing=${JSON.stringify(missing)} (ingested=${netcupVms.map((v) => v.name).join(', ')})`);

  // --- Cross-check one VM against the raw SCP series via the netcup CLI --------
  const sample = Object.entries(stats)[0];
  if (sample && process.env.SKIP_CLI !== '1') {
    const [name, s] = sample;
    try {
      const listRaw = execFileSync('netcup', ['servers', 'list'], { encoding: 'utf8' });
      const servers = JSON.parse(listRaw) as Array<{ id: number; name: string }>;
      const srv = servers.find((x) => x.name === name);
      if (srv) {
        const raw = execFileSync('netcup', ['servers', 'metrics', 'cpu', String(srv.id), '--hours', '1'], { encoding: 'utf8' });
        const series = JSON.parse(raw) as Record<string, Record<string, number>>;
        const points = Object.entries(series).filter(([, v]) => v && typeof v === 'object').sort(([a], [b]) => a.localeCompare(b));
        const latest = points[points.length - 1]?.[1] ?? {};
        const values = Object.values(latest).filter((v): v is number => typeof v === 'number' && Number.isFinite(v));
        const expected = Math.min(100, Math.max(0, (values.reduce((a, b) => a + b, 0) / values.length / 1e9) * 100));
        // The probe's snapshot can be minutes older than this CLI read (cache TTL
        // + script runtime), and busy VMs drift several points per minute — allow
        // ±10pp. Still catches unit errors (×60, ÷1e9 mistakes) by orders of magnitude.
        const tol = Math.max(10, expected * 0.2);
        check(`cross-check ${name}: plugin cpuPct=${s.cpuPct} vs raw latest=${expected.toFixed(1)} (tolerance ±${tol.toFixed(1)})`, typeof s.cpuPct === 'number' && Math.abs(s.cpuPct - expected) <= tol, { name, plugin: s.cpuPct, raw: expected });
      } else {
        console.log(`  INFO no server named ${name} in CLI list — skipping cross-check`);
      }
    } catch (e) {
      console.log('  INFO netcup CLI unavailable — skipping cross-check', String(e).slice(0, 120));
    }
  }

  await pool.end();
  if (failures > 0) throw new Error(`${failures} check(s) failed`);
  console.log('\nAll checks passed.');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
