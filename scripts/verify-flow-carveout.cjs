#!/usr/bin/env node
/**
 * Live verification of configurable flow ranges (feature 2) — needs a running stack.
 *
 *   1. PUT /settings/flowExternalRanges = '192.168.1.20/32' (carve-out inside RFC1918)
 *   2. insert two flow_micro rows directly: src 192.168.1.200 → dst 192.168.1.20
 *      (carved out) and → dst 192.168.1.10 (exact inventory hit — must stay internal)
 *   3. wait for the 5-minute rollup to consume them, then assert:
 *        - carved-out tuple has dstClass = 'internet'
 *        - exact-hit tuple has dstClass = 'internal' (precedence over carve-outs)
 *   4. reset the setting + clean up the test rows
 *
 * Usage: node scripts/verify-flow-carveout.cjs
 */

const path = require('path');

const API = process.env.API_URL || 'http://localhost:3000/v1';
const DB = process.env.DATABASE_URL || 'postgresql://unm:unm@localhost:5432/unm';
const CARVE_OUT_IP = '192.168.1.20'; // not a known device IP — only reachable via the carve-out
const EXACT_HIT_IP = '192.168.1.10'; // seeded e2e device management address (exact inventory hit)
const SRC_IP = '192.168.1.200';      // unknown RFC1918 source — internal by default

let failures = 0;
function check(name, ok, extra = '') {
  console.log(`  ${ok ? 'ok  ' : 'FAIL'} ${name}${extra ? ` — ${extra}` : ''}`);
  if (!ok) failures += 1;
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function login() {
  const apiDir = path.join(__dirname, '..', 'api');
  const { Pool } = require(path.join(apiDir, 'node_modules', 'pg'));
  const pool = new Pool({ connectionString: DB });
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
  const pool = new Pool({ connectionString: DB });

  try {
    // ── 1. set the carve-out ────────────────────────────────────────
    console.log('\n[setup] carving out', CARVE_OUT_IP, 'as external');
    const put = await authed('/settings/flowExternalRanges', { method: 'PUT', body: JSON.stringify({ value: `${CARVE_OUT_IP}/32` }) });
    check('PUT flowExternalRanges → 200', put.status === 200, `status=${put.status}`);

    // ── 2. seed two tuples directly into flow_micro (current bucket) ─
    const nowIso = new Date().toISOString();
    await pool.query(
      `INSERT INTO flow_micro (ts, "collectorId", "srcIp", "dstIp", proto, bytes, packets, "sampleCount", "sampleRate")
       VALUES ($1,'e2e-carveout',$2::inet,$3::inet,6,1000,10,1,1),
              ($1,'e2e-carveout',$2::inet,$4::inet,6,500,5,1,1)`,
      [nowIso, SRC_IP, CARVE_OUT_IP, EXACT_HIT_IP]
    );
    // Log the exact ts + which 5-min bucket it lands in — on a failure this is
    // what correlates the rows with the worker's tick windows (ticks fire ~4-5
    // min AFTER their covered boundary).
    const bucketStartMs = Math.floor(Date.parse(nowIso) / 300_000) * 300_000;
    console.log(`[setup] inserted 2 flow_micro rows at ts=${nowIso} (bucket [${new Date(bucketStartMs).toISOString()}, ${new Date(bucketStartMs + 300_000).toISOString()}))`);

    // ── 3. wait for the rollup to consume them ───────────────────────
    // The rollup timer is aligned to API start, so the tick covering this
    // bucket can fire up to ~5 min AFTER its boundary — and under real traffic
    // the chunked INSERT of tens of thousands of tuples adds more. Give it
    // boundary + 15 min; in practice rows appear within ~6–8 min.
    const bucketEndMs = (Math.floor(Date.now() / 300_000) + 1) * 300_000;
    const deadline = bucketEndMs + 900_000; // boundary + 15 min margin
    console.log(`[rollup] waiting for flow_agg_5m rows (polling until ${new Date(deadline).toISOString()})…`);
    let carvedRow = null;
    let exactRow = null;
    while (Date.now() < deadline) {
      await sleep(10_000);
      // host() strips the "/32" that INET::text would append — a plain ::text
      // cast makes the string comparison below fail for every /32 address.
      const r = await pool.query(
        `SELECT host("dstIp") AS d, "dstClass", "srcClass" FROM flow_agg_5m WHERE "srcIp" = $1::inet`,
        [SRC_IP]
      );
      for (const row of r.rows) {
        if (row.d === CARVE_OUT_IP) carvedRow = row;
        if (row.d === EXACT_HIT_IP) exactRow = row;
      }
      if (carvedRow && exactRow) break;
    }

    check('carved-out tuple rolled up', Boolean(carvedRow));
    check('exact-hit tuple rolled up', Boolean(exactRow));
    if (carvedRow) {
      check(`dst ${CARVE_OUT_IP} classified INTERNET via carve-out`, carvedRow.dstClass === 'internet', `dstClass=${carvedRow.dstClass}`);
      check('src 192.168.1.200 still internal (RFC1918 default)', carvedRow.srcClass === 'internal', `srcClass=${carvedRow.srcClass}`);
    }
    if (exactRow) {
      check(`dst ${EXACT_HIT_IP} stays INTERNAL despite carve-out scope`, exactRow.dstClass === 'internal', `dstClass=${exactRow.dstClass}`);
    }

    // ── 4. reset + cleanup ───────────────────────────────────────────
    const del = await authed('/settings/flowExternalRanges', { method: 'DELETE' });
    check('reset flowExternalRanges → 200', del.status === 200);
    await pool.query(`DELETE FROM flow_agg_5m WHERE "srcIp" = $1::inet`, [SRC_IP]);
    await pool.query(`DELETE FROM flow_micro WHERE "collectorId" = 'e2e-carveout'`);
    console.log('[cleanup] removed test rows');
  } finally {
    // Safety: never leave the carve-out set.
    try { await authed('/settings/flowExternalRanges', { method: 'DELETE' }); } catch { /* best effort */ }
    await pool.end();
  }

  console.log(`\n${failures === 0 ? 'ALL PASS' : `${failures} FAILED`}`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
