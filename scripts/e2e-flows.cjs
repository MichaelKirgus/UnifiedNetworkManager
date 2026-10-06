#!/usr/bin/env node
/**
 * E2E test for the flow collector pipeline (sFlow + NetFlow v5/v9):
 *   1. login (admin/admin, TOTP-aware)
 *   2. send a burst of mock sFlow AND NetFlow v5/v9 datagrams to the shared
 *      collector port (host udp/6343) — all three protocols on one socket
 *   3. wait for ingest into flow_micro (verifies per-protocol tuples)
 *   4. exercise all five /v1/flows routes (+ estBytes single-multiplication check)
 Usage: node scripts/e2e-flows.cjs [collectorHost] [collectorPort]
 */
const path = require('path');
const { spawn } = require('child_process');

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

async function waitForRollup(pool, sinceMs) {
  // Wait until THIS burst's data is rolled up: the first completed 5-minute
  // bucket at/after the burst start must have landed in flow_agg_5m. (A plain
  // "table non-empty" check returns instantly on a long-running system where
  // older buckets already exist — and an API restart resets the rollup cursor
  // to "now", so pre-existing rows say nothing about this run's data.) The
  // rollup tick is a setInterval aligned to API START, not wall-clock
  // boundaries — after the bucket closes we may wait up to one full interval.
  const firstBucket = new Date(Math.floor(sinceMs / 300_000) * 300_000).toISOString();
  const deadline = Date.now() + 9 * 60_000; // bucket close (≤5 min) + one tick (5 min) − margin
  console.log(`\n[rollup] waiting for flow_agg_5m rows with bucket >= ${firstBucket}…`);
  while (Date.now() < deadline) {
    await sleep(10_000);
    const r = await pool.query('SELECT count(*)::int AS n FROM flow_agg_5m WHERE bucket >= $1', [firstBucket]);
    if (r.rows[0].n > 0) { console.log(`[rollup] rolled up — ${r.rows[0].n} row(s)`); return; }
  }
  console.warn('[rollup] timed out waiting for rollup rows — continuing anyway');
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
  const E2E_DEVICES = [
    { id: 'e2e-flows-dev-a', name: 'E2E Test A', mgmt: '192.168.1.50', extra: ['192.168.1.75'] },
    { id: 'e2e-flows-dev-b', name: 'E2E Test B', mgmt: '192.168.1.10', extra: [] },
  ];

  async function seedTestDevices() {
    const now = new Date().toISOString();
    for (const d of E2E_DEVICES) {
      await pool.query(
        `INSERT INTO devices (id, name, vendor, "managementAddress", status, "createdAt", enabled, "deviceTypes", tags)
         VALUES ($1,$2,'generic',$3,'unknown',$4,TRUE,'[]','[]')
         ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name`,
        [d.id, d.name, d.mgmt, now]
      );
      for (const ip of d.extra) {
        await pool.query(
          `INSERT INTO device_ips (id, "deviceId", address, "createdAt") VALUES ($1,$2,$3,$4)
           ON CONFLICT DO NOTHING`,
          [`e2e-flows-ip-${d.id}-${ip}`, d.id, ip, now]
        );
      }
    }
  }

  async function cleanupTestDevices() {
    const ids = E2E_DEVICES.map((d) => d.id);
    await pool.query('DELETE FROM device_ips WHERE "deviceId" = ANY($1)', [ids]);
    await pool.query('DELETE FROM devices WHERE id = ANY($1)', [ids]);
  }

  if (TRUNCATE) {
    console.log('\n[setup] truncating flow tables…');
    await pool.query('TRUNCATE flow_micro, flow_agg_5m, flow_agg_1h');
    const { execSync } = require('child_process');
    execSync('docker compose up -d api', { cwd: path.join(__dirname, '..'), stdio: 'inherit' });
    await new Promise((r) => setTimeout(r, 8000)); // wait for API boot + leadership
    // Seed two devices matching the mock IPs so IP→device enrichment and the
    // pairs route are exercised (enrichment map rebuilds on the first rollup).
    await seedTestDevices();
    const desc = E2E_DEVICES.map((d) => d.name + ' (' + d.mgmt + (d.extra.length ? ' + ' + d.extra.join(', ') : '') + ')');
    console.log('[setup] seeded test devices:', desc.join('; '));
  }

  // ── 1. mock burst (sFlow + NetFlow v5/v9 in parallel on the same port) ───
  const burstStartMs = Date.now();
  console.log(`\n[mock] sending sFlow + NetFlow v5/v9 datagrams to udp://${HOST}:${PORT} for ${BURST_MS / 1000}s`);
  const env = { ...process.env, SFLOW_SEND_INTERVAL_MS: '2000', NF_SEND_INTERVAL_MS: '2000' };
  // Second sFlow exporter (agent 192.168.1.2) sends ONLY the internal→internal
  // record — it duplicates exactly one tuple so we can verify multi-exporter
  // dedup (best observation kept, agentCount = 2). Same SAMPLE_RATE as the
  // first agent keeps the estBytes invariant check valid.
  const envSecondAgent = { ...env, AGENT_IP: '192.168.1.2', ONLY_INTERNAL: '1' };
  const procs = [
    spawn('node', [path.join(__dirname, 'mock-sflow.cjs'), HOST, String(PORT)], { stdio: 'inherit', env }),
    spawn('node', [path.join(__dirname, 'mock-sflow.cjs'), HOST, String(PORT)], { stdio: 'inherit', env: envSecondAgent }),
    spawn('node', [path.join(__dirname, 'mock-netflow.cjs'), HOST, String(PORT)], { stdio: 'inherit', env }),
  ];
  await sleep(BURST_MS);
  for (const p of procs) p.kill();

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

  // NetFlow-specific tuples (distinct from the sFlow mock's):
  const nf9 = await pool.query("SELECT count(*)::int n FROM flow_micro WHERE \"srcIp\" = '192.168.1.75'");
  check('NetFlow v9 flows ingested (template cache across datagrams)', nf9.rows[0].n > 0, `rows=${nf9.rows[0].n}`);
  const nf5 = await pool.query("SELECT count(*)::int n FROM flow_micro WHERE \"dstIp\" = '192.168.1.20'");
  check('NetFlow v5 flows ingested', nf5.rows[0].n > 0, `rows=${nf5.rows[0].n}`);

  // ── Multi-exporter dedup ────────────────────────────────────────
  // The internal→internal TCP tuple (192.168.1.50 → .10) is observed by THREE
  // exporters: sFlow agent 192.168.1.1, the second sFlow agent 192.168.1.2
  // (ONLY_INTERNAL), and NetFlow v5 (agent = UDP source address). Dedup keeps
  // ONE best observation per window — agentCount records how many agents saw it.
  const dedup = await pool.query(
    `SELECT MAX("agentCount")::int AS "maxAgents", SUM(bytes)::bigint AS "totalBytes", count(*)::int AS rows
     FROM flow_micro WHERE "srcIp" = '192.168.1.50' AND "dstIp" = '192.168.1.10' AND proto = 6`
  );
  console.log(`    dedup tuple .50→.10/6: rows=${dedup.rows[0].rows} maxAgentCount=${dedup.rows[0].maxAgents} totalBytes=${dedup.rows[0].totalBytes}`);
  check('dedup: shared tuple observed by >= 2 exporters (agentCount)', dedup.rows[0].maxAgents >= 2, `agentCount=${dedup.rows[0].maxAgents}`);

  // Tuples seen by exactly ONE exporter must NOT be flagged multi-observed.
  const single = await pool.query(
    'SELECT MAX("agentCount")::int AS "maxAgents" FROM flow_micro WHERE "srcIp" = \'192.168.1.75\''
  );
  check('dedup: single-exporter tuple has agentCount = 1', single.rows[0].maxAgents === 1, `agentCount=${single.rows[0].maxAgents}`);

  if (WAIT_ROLLUP) await waitForRollup(pool, burstStartMs);

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
    // The shared tuple's endpoints must surface ALL THREE exporters: the two
    // sFlow agents + NetFlow v5. observedBy >= 3 proves the rollup carries the
    // plugin's per-window union count (an agent that never won best-observation
    // in any window would be invisible to a distinct-winners-only count). Only
    // meaningful on a clean slate — on a live system the mock's tiny flows never
    // rank into the top-N talkers among real traffic.
    const multi = [...(j.sources ?? []), ...(j.destinations ?? [])].filter((t) => t.ip === '192.168.1.50' || t.ip === '192.168.1.10');
    if (TRUNCATE) check('top-talkers: shared-tuple IPs report observedBy >= 3 (all exporters)', multi.length > 0 && multi.every((t) => (t.observedBy ?? 0) >= 3), JSON.stringify(multi));
    else console.log(`    top-talkers observedBy check skipped (live system — mock flows not in top-N)`);
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
    // Requires BOTH endpoints enriched to known devices — only meaningful when
    // the test devices were seeded (TRUNCATE run).
    if (TRUNCATE) check('pairs non-empty (seeded devices enrich both ends)', Array.isArray(j.pairs) && j.pairs.length > 0, `pairs=${j.pairs?.length}`);
    else console.log(`    pairs: ${j.pairs?.length ?? 0} (no seeded inventory — skipped)`);
  }

  const series = await authed(`/flows/timeseries?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}&bucket=5m`);
  check('GET /flows/timeseries → 200', series.status === 200, `status=${series.status}`);
  if (series.status === 200) {
    const j = await series.json();
    check('timeseries has points', Array.isArray(j.points) && j.points.length > 0, `points=${j.points?.length}`);
  }

  // estBytes invariant: the sampling rate is applied EXACTLY ONCE (in the
  // rollup). Every flow_agg_5m row must satisfy estBytes = bytes × rate —
  // a pre-multiplied parser would show estBytes = bytes × rate².
  if (WAIT_ROLLUP) {
    const inv = await pool.query(
      `SELECT count(*) FILTER (WHERE a."estBytes" <> a.bytes * m.rate)::int AS bad,
              count(*)::int AS total
       FROM flow_agg_5m a
       JOIN (SELECT \"srcIp\", \"dstIp\", proto, MAX(\"sampleRate\") AS rate
             FROM flow_micro GROUP BY 1,2,3) m
         ON m.\"srcIp\" = a.\"srcIp\" AND m.\"dstIp\" = a.\"dstIp\" AND m.proto = a.proto`
    );
    check('estBytes = bytes × rate exactly once (no double-multiplication)', inv.rows[0].bad === 0, `bad=${inv.rows[0].bad}/${inv.rows[0].total}`);
  }

  const collectors = await authed('/flow-collectors');
  check('GET /flows/flow-collectors → 200', collectors.status === 200, `status=${collectors.status}`);
  if (collectors.status === 200) {
    const j = await collectors.json();
    check('ingest stats present', Boolean(j.ingest?.queueDepth !== undefined), JSON.stringify(j.ingest ?? null));
    check('collector listed + reachable', Array.isArray(j.collectors) && j.collectors.length > 0 && j.collectors[0].reachable, `collectors=${j.collectors?.length}`);
    if (j.collectors?.[0]) console.log(`    collector: ${JSON.stringify(j.collectors[0])}`);
  }

  // ── /flows/inventory — traffic keyed for the Hosts/Networks pages ────────
  // Window spans at least one COMPLETED 5-minute bucket (agg tables only hold
  // rolled-up data; a +60 s `to` covers the current partial window harmlessly).
  const invFrom = new Date(now - 10 * 60_000).toISOString();
  const invTo = new Date(now + 60_000).toISOString();
  const inventory = await authed(`/flows/inventory?from=${encodeURIComponent(invFrom)}&to=${encodeURIComponent(invTo)}`);
  check('GET /flows/inventory → 200', inventory.status === 200, `status=${inventory.status}`);
  if (inventory.status === 200) {
    const j = await inventory.json();
    check('perIp is an array of {ip, srcEstBytes, dstEstBytes}', Array.isArray(j.perIp) && j.perIp.every((r) => typeof r.ip === 'string' && Number.isFinite(Number(r.srcEstBytes)) && Number.isFinite(Number(r.dstEstBytes))), `rows=${j.perIp?.length}`);
    check('perNetwork is an array of {key, srcEstBytes, dstEstBytes}', Array.isArray(j.perNetwork) && j.perNetwork.every((r) => typeof r.key === 'string' && Number.isFinite(Number(r.srcEstBytes)) && Number.isFinite(Number(r.dstEstBytes))), `rows=${j.perNetwork?.length}`);
    // The mock's internal endpoints must surface with traffic in BOTH roles:
    // 192.168.1.50 is a source (internal→internal + egress), .10/.75 sources,
    // and .10/.20 are destinations.
    const ipRow = (ip) => (j.perIp ?? []).find((r) => r.ip === ip);
    check('perIp: internal source 192.168.1.50 has sent > 0', (ipRow('192.168.1.50')?.srcEstBytes ?? 0) > 0, JSON.stringify(ipRow('192.168.1.50')));
    check('perIp: internal destination 192.168.1.10 has received > 0', (ipRow('192.168.1.10')?.dstEstBytes ?? 0) > 0, JSON.stringify(ipRow('192.168.1.10')));
    check('perIp: internet destination 8.8.8.8 has received > 0', (ipRow('8.8.8.8')?.dstEstBytes ?? 0) > 0, JSON.stringify(ipRow('8.8.8.8')));
    // perNetwork keys must be canonical identities (subnet:/vlan:/name:) and no
    // internet-classified endpoint may map into an inventoried network — the
    // mock's only external IP is 8.8.8.8, so it must not fall in any subnet.
    const badKeys = (j.perNetwork ?? []).filter((r) => !/^(subnet:|vlan:|name:)/.test(r.key));
    check('perNetwork keys are canonical identities', badKeys.length === 0, JSON.stringify(badKeys.slice(0, 3)));
    if ((j.perIp ?? []).length > 0) console.log(`    perIp top: ${JSON.stringify(j.perIp.slice(0, 3))}`);
    if ((j.perNetwork ?? []).length > 0) console.log(`    perNetwork top: ${JSON.stringify(j.perNetwork.slice(0, 3))}`);
  }

  if (TRUNCATE) {
    await cleanupTestDevices();
    console.log('\n[cleanup] removed E2E test devices');
  }

  await pool.end();
  console.log(failures === 0 ? '\nALL PASS' : `\n${failures} FAILURE(S)`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
