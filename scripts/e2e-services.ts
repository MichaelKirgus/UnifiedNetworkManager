/**
 * End-to-end verification for the cross-device Services page.
 *
 * Validates against the deployed stack (API on :3000):
 *   1. GET /services — 200 + array, every row carries a valid shape
 *      (deviceId/name/type/status enum). Works with an EMPTY table too.
 *   2. Filter validation — bogus type/status values are rejected with 400.
 *   3. Live ingestion — force-refreshes one real device that has an
 *      OPNsense / TrueNAS / generic-SSH plugin assigned and asserts its
 *      services land in the cross-device view within a bounded wait.
 *
 * The table is worker-managed inventory (like tunnels/routes) — this script
 * creates NO rows of its own, so there is nothing to clean up: it only reads
 * and triggers refreshes of devices that already exist.
 *
 * Usage (from the repo root, with the stack up):
 *   ./node_modules/.bin/tsx scripts/e2e-services.ts
 */

import path from 'node:path';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
// pg/otplib live in the API package's node_modules — resolve them from there.
const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));

let failures = 0;
function check(label: string, cond: boolean, extra?: unknown) {
  if (cond) console.log(`  PASS ${label}`);
  else {
    failures++;
    console.error(`  FAIL ${label}`, extra !== undefined ? JSON.stringify(extra).slice(0, 400) : '');
  }
}

async function main(): Promise<void> {
  // --- Login (admin/admin; TOTP minted from the seeded secret when enabled) --
  const { Pool } = apiRequire('pg');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm' });

  const health = await fetch('http://localhost:3000/healthz').then((r) => r.json()).catch(() => null);
  check('API healthy', (health as { status?: string })?.status === 'ok', health);

  const adminRow = (await pool.query(`SELECT "totpSecret" FROM users WHERE username = 'admin'`)).rows[0] as { totpSecret: string | null };
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
  check('authenticated (login flow)', Boolean(token));
  if (!token) throw new Error('login failed');

  const authed = async (method: string, p: string, body?: unknown): Promise<{ status: number; json: () => Promise<unknown> }> => {
    const res = await fetch(`${API}${p}`, { method, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    return { status: res.status, json: async () => (await res.json().catch(() => null)) as never };
  };

  // ---------------------------------------------------------------------------
  // 1. GET /services — shape + enum validation on whatever is stored
  // ---------------------------------------------------------------------------
  console.log('\n— Services listing —');

  const list = await authed('GET', '/services');
  check('GET /services returns 200', list.status === 200, { status: list.status });
  const rows = (await list.json()) as Array<Record<string, unknown>>;
  check('response is an array', Array.isArray(rows), typeof rows);

  const VALID_TYPES = new Set(['systemd', 'openrc', 'runit', 'sysvinit', 'freebsd-rc', 'truenas', 'openwrt']);
  const VALID_STATUS = new Set(['running', 'stopped', 'failed', 'unknown']);
  if (Array.isArray(rows)) {
    const badShape = rows.filter(
      (r) => typeof r['deviceId'] !== 'string' || typeof r['name'] !== 'string' || !VALID_TYPES.has(String(r['type'])) || !VALID_STATUS.has(String(r['status']))
    );
    check('every row carries deviceId/name + valid type/status enums', badShape.length === 0, badShape.slice(0, 3));
    const withDevice = rows.filter((r) => typeof r['deviceName'] === 'string' && (r['deviceName'] as string).length > 0);
    check('rows are joined with device display data', withDevice.length === rows.length || rows.length === 0, { total: rows.length, joined: withDevice.length });
    console.log(`  (info) ${rows.length} service row(s) currently stored`);
  }

  // ---------------------------------------------------------------------------
  // 2. Filter validation — bogus enum values are rejected before any query
  // ---------------------------------------------------------------------------
  const badType = await authed('GET', '/services?type=bogus');
  check('"type" filter rejects unknown values with 400', badType.status === 400, { status: badType.status });
  const badStatus = await authed('GET', '/services?status=bogus');
  check('"status" filter rejects unknown values with 400', badStatus.status === 400, { status: badStatus.status });

  // A valid enum filter must at least succeed (may be empty).
  const okFilter = await authed('GET', '/services?type=systemd&status=running');
  check('valid type+status filters return 200 array', okFilter.status === 200 && Array.isArray(await okFilter.json()), { status: okFilter.status });

  // ---------------------------------------------------------------------------
  // 3. Live ingestion — refresh a real device with a services-reporting plugin
  // ---------------------------------------------------------------------------
  console.log('\n— Live ingestion (forced refresh) —');

  const devRes = await pool.query(
    `SELECT d.id AS "deviceId", d.name AS "deviceName", p.name AS "pluginName"
       FROM devices d
       JOIN device_plugins dp ON dp."deviceId" = d.id
       JOIN plugins p ON p.id = dp."pluginId"
      WHERE (p.name ILIKE '%opnsense%' OR p.name ILIKE '%truenas%' OR p.name ILIKE '%generic ssh%')
        AND d.enabled = TRUE
      ORDER BY d.name LIMIT 1`
  );
  const target = devRes.rows[0] as { deviceId: string; deviceName: string; pluginName: string } | undefined;

  if (!target) {
    console.log('  SKIP no enabled OPNsense/TrueNAS/generic-SSH device registered — ingestion check needs one');
  } else {
    console.log(`  (info) refreshing ${target.deviceName} (${target.pluginName})`);
    const before = ((await authed('GET', `/services?deviceId=${target.deviceId}`).then((r) => r.json())) as Array<Record<string, unknown>>).length;

    const refresh = await authed('POST', '/devices/refresh', { deviceIds: [target.deviceId] });
    check('forced refresh accepted', refresh.status === 200 || refresh.status === 202, { status: refresh.status, body: await refresh.json() });

    // The poll + inventory ingest is async — wait for the rows to appear.
    let after = before;
    let sawRows = false;
    const deadline = Date.now() + 90_000;
    while (Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 5_000));
      const cur = ((await authed('GET', `/services?deviceId=${target.deviceId}`).then((r) => r.json())) as Array<Record<string, unknown>>);
      after = cur.length;
      if (cur.length > before || cur.length > 0) {
        sawRows = true;
        break;
      }
    }
    check(`device ${target.deviceName} reports services after refresh`, sawRows && after > 0, { before, after });

    // The rows must carry the device's identity + a sane type label.
    const cur = (await authed('GET', `/services?deviceId=${target.deviceId}`).then((r) => r.json())) as Array<Record<string, unknown>>;
    if (cur.length > 0) {
      check('ingested rows carry deviceName join', cur.every((r) => r['deviceName'] === target.deviceName), cur.slice(0, 2));
      const types = new Set(cur.map((r) => String(r['type'])));
      check('ingested rows use a known init-system label', [...types].every((t) => VALID_TYPES.has(t)), [...types]);
    }
  }

  // ---------------------------------------------------------------------------
  // 4. Action catalogs — every service-reporting plugin advertises the unified
  //    services.start / services.stop / services.restart intents (the Services
  //    page's Actions column renders them catalog-driven).
  // ---------------------------------------------------------------------------
  console.log('\n— Service action catalogs —');

  const catRes = await pool.query(
    `SELECT DISTINCT dp."pluginId" AS "pluginId", p.name AS "pluginName"
       FROM device_plugins dp
       JOIN plugins p ON p.id = dp."pluginId"
      WHERE (p.name ILIKE '%opnsense%' OR p.name ILIKE '%truenas%' OR p.name ILIKE '%generic ssh%' OR p.name ILIKE '%openwrt%')`
  );
  const catalogPlugins = catRes.rows as Array<{ pluginId: string; pluginName: string }>;

  if (catalogPlugins.length === 0) {
    console.log('  SKIP no service-reporting plugins registered — catalog check needs one');
  } else {
    for (const cp of catalogPlugins) {
      const r = await authed('GET', `/plugins/${cp.pluginId}/actions`);
      if (r.status !== 200) {
        check(`catalog fetch ${cp.pluginName}`, false, { status: r.status });
        continue;
      }
      const body = (await r.json()) as { actions?: Array<{ id: string }> };
      const ids = new Set((body.actions ?? []).map((a) => a.id));
      for (const intent of ['services.start', 'services.stop', 'services.restart']) {
        check(`${cp.pluginName} advertises ${intent}`, ids.has(intent), [...ids].filter((i) => i.startsWith('services.')));
      }
    }
  }

  await pool.end();

  console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error('E2E crashed:', err);
  process.exit(1);
});
