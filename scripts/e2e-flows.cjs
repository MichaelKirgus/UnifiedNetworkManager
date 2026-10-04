#!/usr/bin/env node
/**
 * E2E test for the sFlow collector pipeline:
 *   1. login (admin/admin, TOTP-aware)
 *   2. send a burst of mock sFlow datagrams to the collector (host udp/6343)
 *   3. wait for ingest into flow_micro
 *   4. exercise all five /v1/flows routes
 * Usage: node scripts/e2e-flows.cjs [collectorHost] [collectorPort]
 */
const path = require('path');
const { spawnSync } = require('child_process');

const API = process.env.API_URL || 'http://localhost:3000/v1';
const HOST = process.argv[2] || '127.0.0.1';
const PORT = Number(process.argv[3]) || 6343;
const BURST_MS = Number(process.env.FLOWS_E2E_BURST_MS) || 8000;
// When set, wait for the next completed 5-minute bucket to roll up before
// checking the aggregate-backed routes (adds up to ~5.5 min).
const WAIT_ROLLUP = process.env.FLOWS_E2E_WAIT_ROLLUP === '1';
// When set, TRUNCATE all three flow tables first (clean-slate verification run).
const TRUNCATE = process.env.FLOWS_E2E_TRUNCATE === '1';

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

async function waitForRollup() {
  const nowMs = Date.now();
  const bucketEndMs = (Math.floor(nowMs / 300_000) + 1) * 300_000; // next boundary
  const waitMs = bucketEndMs - nowMs + 25_000; // boundary + rollup tick margin
  console.log(`\n[rollup] waiting ${Math.round(waitMs / 1000)}s for the 5-minute rollup…`);
  await sleep(waitMs);
}

let failures = 0;
function check(name, ok, extra = '') {
  console.log(`  ${ok ? 'ok  ' : 'FAIL'} ${name}${extra ? ` — ${extra}` : ''}`);
  if (!ok) failures += 1;
}

async function login() {
  const apiDir = path.join(__dirname, '..', 'api');
  const { Pool } = require(path.join(apiDir, 'node_modules', 'pg'));
  const pool = new Pool({ connectionString: process.env.DATABASE_URL || 'postgresql://unm:unm@localhost:5432/unm' });
  try {
    const adminRow = (await pool.query(`SELECT "totpSecret" FROM users WHERE username = 'admin'`)).rows[0];
    if (!adminRow.totpSecret) {
      const r = await fetch(`${API}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: 'admin' }) });
      return ((await r.json()).accessToken ?? null);
    }
    const { authenticator } = require(path.join(apiDir, 'node_modules', 'otplib'));
    const code = authenticator.generate(adminRow.totpSecret);
    const r1 = await fetch(`${API}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: 'admin' }) });
    const challengeToken = ((await r1.json()).challengeToken ?? '');
    const r2 = await fetch(`${API}/auth/2fa/verify`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ challengeToken, totpCode: code }) });
    return ((await r2.json()).accessToken ?? null);
  } finally {
    await pool.end();
  }
}

async function main() {
  const token = await login();
  check('authenticated', Boolean(token));
  if (!token) process.exit(1);

  const authed = async (p, opts = {}) => {
    const res = await fetch(`${API}${p}`, { ...opts, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` } });
    return { status: res.status, json: () => res.json().catch(() => null) };
  };

  const { Pool } = require(path.join(__dirname, '..', 'api', 'node_modules', 'pg'));
  const pool = new Pool({ connectionString: process.env.DATABASE_URL || 'postgresql://unm:unm@localhost:5432/unm' });

  // ── 0. optional clean slate (restart the API AFTER truncating so its
  //      rollup cursor starts fresh and covers this run's data) ───────────
  if (TRUNCATE) {
    console.log('\n[setup] truncating flow tables…');
    await pool.query('TRUNCATE flow_micro, flow_agg_5m, flow_agg_1h');
    const { execSync } = require('child_process');
    execSync('docker compose up -d api', { cwd: path.join(__dirname, '..'), stdio: 'inherit' });
    await new Promise((r) => setTimeout(r, 8000)); // wait for API boot + leadership
  }

  // ── 1. mock burst ────────────────────────────────────────────────
  console.log(`\n[mock] sending sFlow datagrams to udp://${HOST}:${PORT} for ${BURST_MS / 1000}s`);
  const env = { ...process.env, SFLOW_SEND_INTERVAL_MS: '2000' };
  spawnSync('node', [path.join(__dirname, 'mock-sflow.cjs'), HOST, String(PORT)], { stdio: 'inherit', env, timeout: BURST_MS });

  // ── 2. wait for ingest (drain loop runs every 1s) ───────────────
  let microRows = 0;
  for (let i = 0; i < 15 && microRows === 0; i++) {
    await new Promise((r) => setTimeout(r, 2000));
    const r = await pool.query('SELECT count(*)::int AS n FROM flow_micro');
    microRows = r.rows[0].n;
  }
  check('flow_micro has rows after burst', microRows > 0, `rows=${microRows}`);

  const agg = await pool.query(
    'SELECT "srcIp"::text s, "dstIp"::text d, proto, sum(bytes)::bigint b FROM flow_micro GROUP BY 1,2,3 ORDER BY 4 DESC'
  );
  console.log('  flow_micro tuples:');
  for (const r of agg.rows) console.log(`    ${r.s} → ${r.d} proto=${r.proto} bytes=${r.b}`);

  const v6 = await pool.query("SELECT count(*)::int n FROM flow_micro WHERE family(\"srcIp\") = 6");
  check('IPv6 flows ingested', v6.rows[0].n > 0, `rows=${v6.rows[0].n}`);

  if (WAIT_ROLLUP) await waitForRollup();

  // ── 3. routes ────────────────────────────────────────────────────
  const now = Date.now();
  const from = new Date(now - 15 * 60_000).toISOString();
  const to = new Date(now + 60_000).toISOString();

  const talkers = await authed(`/flows/top-talkers?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`);
  check('GET /flows/top-talkers → 200', talkers.status === 200, `status=${talkers.status}`);
  if (talkers.status === 200) {
    const j = await talkers.json();
    check('top-talkers has sources', Array.isArray(j.sources) && j.sources.length > 0, `sources=${j.sources?.length}`);
    console.log(`    top source: ${JSON.stringify(j.sources?.[0] ?? null)}`);
  }

  const internet = await authed(`/flows/internet?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`);
  check('GET /flows/internet → 200', internet.status === 200, `status=${internet.status}`);
  if (internet.status === 200) {
    const j = await internet.json();
    check('internet egress > 0 (8.8.8.8 mock)', (j.total?.estBytes ?? 0) > 0, `estBytes=${j.total?.estBytes}`);
  }

  const pairs = await authed(`/flows/pairs?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`);
  check('GET /flows/pairs → 200', pairs.status === 200, `status=${pairs.status}`);
  if (pairs.status === 200) {
    const j = await pairs.json();
    check('pairs non-empty', Array.isArray(j.pairs) && j.pairs.length > 0, `pairs=${j.pairs?.length}`);
  }

  const series = await authed(`/flows/timeseries?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}&bucket=5m`);
  check('GET /flows/timeseries → 200', series.status === 200, `status=${series.status}`);
  if (series.status === 200) {
    const j = await series.json();
    check('timeseries has points', Array.isArray(j.points) && j.points.length > 0, `points=${j.points?.length}`);
  }

  const collectors = await authed('/flow-collectors');
  check('GET /flows/flow-collectors → 200', collectors.status === 200, `status=${collectors.status}`);
  if (collectors.status === 200) {
    const j = await collectors.json();
    check('ingest stats present', Boolean(j.ingest?.queueDepth !== undefined), JSON.stringify(j.ingest ?? null));
    check('collector listed + reachable', Array.isArray(j.collectors) && j.collectors.length > 0 && j.collectors[0].reachable, `collectors=${j.collectors?.length}`);
    if (j.collectors?.[0]) console.log(`    collector: ${JSON.stringify(j.collectors[0])}`);
  }

  await pool.end();
  console.log(failures === 0 ? '\nALL PASS' : `\n${failures} FAILURE(S)`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
