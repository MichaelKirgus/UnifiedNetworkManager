#!/usr/bin/env node
/**
 * E2E test for the GeoIP feature (web-fetch plugin + geoip worker + lookup engine):
 *   1. login (admin/admin, TOTP-aware)
 *   2. wait until a webFetch-capable plugin is registered/online
 *   3. start the kit's geoip web fixture (packages/plugin-test-kit/src/fixtures/geoipWebserver.cjs)
 *      on :9199 (+ a --proxy instance on :9198)
 *   4. point the geoip worker at the mock (source=custom, interval=1h, deleteOld=true)
 *   5. POST /geoip/refresh with each fixture in turn and assert:
 *        - MMDB direct      → active file + top-talkers US/AU enrichment
 *        - dp-ip CSV        → old file pruned (repo count stays 1), DE row appears
 *        - LITE zip         → extracted member becomes the active .csv, range lookup works
 *        - tar.gz archive   → extracted .mmdb is served again
 *        - via proxy (:9198)→ same MMDB through the forward-proxy path
 *        - 404 URL          → refresh fails (502), previous good file kept serving
 * Usage: node scripts/e2e-geoip.cjs
 */
const path = require('path');
const { spawn } = require('child_process');

const API = process.env.API_URL || 'http://localhost:3000/v1';
const MOCK_PORT = Number(process.env.GEOIP_E2E_MOCK_PORT) || 9199;
const PROXY_PORT = Number(process.env.GEOIP_E2E_PROXY_PORT) || 9198;
const HOST_BASE = `http://host.docker.internal:${MOCK_PORT}`; // as seen from the web-fetch plugin container

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

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

  const authed = async (method, p, body) => {
    const res = await fetch(`${API}${p}`, {
      method,
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: body ? JSON.stringify(body) : undefined,
    });
    return { status: res.status, data: await res.json().catch(() => null) };
  };

  const { Pool } = require(path.join(__dirname, '..', 'api', 'node_modules', 'pg'));
  const pool = new Pool({ connectionString: process.env.DATABASE_URL || 'postgresql://unm:unm@localhost:5432/unm' });

  // ── 1. wait for a webFetch-capable plugin to be online ────────────────────
  console.log('\n[1] waiting for the web-fetch plugin…');
  let wf = null;
  const deadline = Date.now() + 90_000;
  while (Date.now() < deadline && !wf) {
    const r = await authed('GET', '/plugins');
    if (r.status === 200) {
      const now = Date.now();
      wf = (r.data ?? []).find((p) =>
        Array.isArray(p.capabilities) && p.capabilities.includes('webFetch') &&
        p.lastSeenAt && now - Date.parse(p.lastSeenAt) < 5 * 60_000);
    }
    if (!wf) await sleep(3_000);
  }
  check('web-fetch plugin registered + online', Boolean(wf), wf ? `${wf.name} @ ${wf.endpoint}` : 'not found within 90s');
  if (!wf) { pool.end(); process.exit(1); }

  // ── 2. start the mock servers (direct + proxy mode) ───────────────────────
  const FIX = path.join(__dirname, '..', 'packages', 'plugin-test-kit', 'src', 'fixtures');
  console.log(`\n[2] starting geoip web fixture on :${MOCK_PORT} and :${PROXY_PORT} (--proxy)…`);
  const mocks = [
    spawn('node', [path.join(FIX, 'geoipWebserver.cjs'), String(MOCK_PORT)], { stdio: 'inherit' }),
    spawn('node', [path.join(FIX, 'geoipWebserver.cjs'), String(PROXY_PORT), '--proxy'], { stdio: 'inherit' }),
  ];
  const health = async (port) => {
    try { return (await fetch(`http://127.0.0.1:${port}/health`)).status === 200; } catch { return false; }
  };
  for (let i = 0; i < 50 && !(await health(MOCK_PORT) && await health(PROXY_PORT)); i++) await sleep(300);
  check('mock servers healthy', await health(MOCK_PORT) && await health(PROXY_PORT));

  // ── 3. clean slate: drop old geoip repo files + reset the settings we touch ─
  console.log('\n[3] resetting state…');
  const oldFiles = (await pool.query(`SELECT id, name FROM repo_files WHERE category = 'geoip'`)).rows;
  for (const f of oldFiles) {
    const d = await authed('DELETE', `/files/${f.id}`);
    check(`deleted stale geoip file ${f.name}`, [200, 204].includes(d.status));
  }
  for (const key of ['geoipActiveFileId', 'geoipCustomUrl', 'geoipSource', 'geoipFetchIntervalHours', 'geoipDeleteOldFiles', 'webFetchProxyUrl']) {
    await authed('DELETE', `/settings/${key}`); // back to defaults
  }

  const setSetting = async (key, value) => {
    const r = await authed('PUT', `/settings/${key}`, { value });
    check(`set ${key}=${JSON.stringify(value)}`, r.status === 200, r.data?.error ?? '');
    return r;
  };

  // ── 4. configure the worker for this run ───────────────────────────────────
  console.log('\n[4] configuring geoip settings…');
  await setSetting('geoipEnabled', true);
  await setSetting('geoipSource', 'custom');
  await setSetting('geoipFetchIntervalHours', 1); // min — keeps the worker from re-firing mid-test (first beat already ran at boot)
  await setSetting('geoipDeleteOldFiles', true);

  const refresh = async () => authed('POST', '/geoip/refresh');
  const status = async () => (await authed('GET', '/geoip/status')).data;
  // A failed cycle with a previously-good file still answers HTTP 200 — the
  // failure only shows up in lastError. Assert it explicitly after each refresh.
  const checkCycleOk = (st, label) => {
    check(`${label}: no cycle error`, !st.lastError, String(st.lastError).slice(0, 160));
  };

  // Seed flow rows so the top-talkers route has external talkers to enrich.
  // estBytes is deliberately DOMINANT (TB-scale) — live traffic on this box
  // easily fills a plain top-100, and the assertions need these IPs ranked in.
  console.log('\n[5] seeding flow_agg_5m rows for external talkers…');
  const SEED_IPS = ['8.8.8.8', '1.1.1.1', '93.184.216.34'];
  for (const ip of SEED_IPS) {
    await pool.query(
      `INSERT INTO flow_agg_5m (bucket, "srcIp", "dstIp", proto, bytes, packets, "estBytes", "srcClass", "dstClass")
       VALUES (to_timestamp((EXTRACT(EPOCH FROM now()) / 300)::bigint * 300), $2::inet, $1::inet, 6, 1000, 10, 999999999999, 'internal', 'internet')
       ON CONFLICT (bucket, "srcIp", "dstIp", proto) DO UPDATE SET "estBytes" = EXCLUDED."estBytes"`,
      [ip, '192.168.1.50']
    );
  }
  // Verify the seed actually landed with its dominant estBytes (diagnostic).
  const seedCheck = await pool.query(
    `SELECT "dstIp", bucket, "estBytes" FROM flow_agg_5m WHERE "srcIp" = '192.168.1.50' AND "dstIp" = ANY($1::inet[]) ORDER BY "dstIp"`,
    [SEED_IPS]
  );
  console.log(`  seeded rows: ${seedCheck.rows.map((r) => `${String(r.dstIp)}@${r.bucket}=${Number(r.estBytes)}`).join(' | ')}`);

  // Re-assert the seed rows before every attempt — each time with a FRESH proto
  // value so the statement is an APPEND (a new PK tuple), never an in-place
  // UPDATE. WHY: flow_agg_5m carries a BRIN index on `bucket`, and its page
  // summaries go stale for rows that are UPDATEd in place — the route's windowed
  // query (`bucket >= now() - 1h`) then intermittently prunes them even though
  // unfiltered point queries (seq scan) still see them. A fresh append lands on
  // the partition's active page, whose BRIN summary IS maintained, so the row is
  // reliably visible to the windowed query regardless of where we are in the
  // 5-minute bucket cycle. (Observed: ON CONFLICT DO UPDATE reseeds were only
  // reliable across a bucket rollover; proto-appends are deterministic.)
  let seedProto = 100; // well clear of the initial seed's proto=6 rows
  const reseed = async () => {
    for (const ip of SEED_IPS) {
      await pool.query(
        `INSERT INTO flow_agg_5m (bucket, "srcIp", "dstIp", proto, bytes, packets, "estBytes", "srcClass", "dstClass")
         VALUES (to_timestamp((EXTRACT(EPOCH FROM now()) / 300)::bigint * 300), $2::inet, $1::inet, $3, 1000, 10, 999999999999, 'internal', 'internet')
         ON CONFLICT (bucket, "srcIp", "dstIp", proto) DO NOTHING`,
        [ip, '192.168.1.50', seedProto]
      );
    }
    seedProto += 1; // next reseed appends a different tuple
  };

  // Retries: right after an API restart the first few requests can hit a still-
  // warming worker pool (5xx/timeout). A missing row is retried too — reseed
  // first (see BRIN note above); if it persists across retries it's a real
  // assertion failure.
  const talkerRow = async (ip) => {
    for (let attempt = 1; attempt <= 4; attempt++) {
      await reseed();
      const r = await authed('GET', '/flows/top-talkers?limit=100');
      if (r.status !== 200) {
        console.log(`  (top-talkers ${r.status} on attempt ${attempt}, retrying…)`);
        await sleep(2500);
        continue;
      }
      const all = [...(r.data.sources ?? []), ...(r.data.destinations ?? [])];
      const row = all.find((t) => t.ip === ip);
      if (row) return row;
      const top3 = [...(r.data.destinations ?? [])].slice(0, 3).map((t) => `${t.ip}:${Number(t.estBytes)}`).join(' ');
      console.log(`  (row ${ip} absent — attempt ${attempt}: dsts=${(r.data.destinations ?? []).length} srcs=${(r.data.sources ?? []).length} top-dst=[${top3}])`);
      await sleep(2500);
    }
    return null;
  };

  // Poll until a RECENT flow_agg_5m internet row has a stored "dstCountryCode".
  // Scoped to the last 2 h so it is guaranteed to fall inside the /flows/internet
  // window below (self-consistent). Deliberately not scoped to the seed IPs: the
  // backfill fills pending rows in whatever order the partial index yields them,
  // and this box carries live traffic — continuous new internet rows mean a beat
  // has filled some recent ones by now. Unfiltered point query = no BRIN flakiness.
  const anyStoredCode = async () => {
    for (let i = 0; i < 30; i++) {
      const q = await pool.query(
        `SELECT "dstCountryCode" FROM flow_agg_5m WHERE "dstClass" = 'internet' AND "dstCountryCode" IS NOT NULL AND bucket >= now() - interval '2 hours' LIMIT 1`
      );
      if (q.rows[0]?.dstCountryCode) return String(q.rows[0].dstCountryCode);
      await sleep(3_000);
    }
    return null;
  };

  // GET /flows/internet — the per-country aggregation lives in this response.
  // Explicit 3 h window: wide enough to include anyStoredCode's 2 h scope, narrow
  // enough to stay fast over live traffic (and ?limit= is not a param of this route).
  const internet = async () => {
    const to = Date.now();
    const from = to - 3 * 3600_000;
    const r = await authed('GET', `/flows/internet?from=${from}&to=${to}`);
    if (r.status !== 200) { console.log(`  (/flows/internet answered ${r.status}: ${JSON.stringify(r.data?.error ?? '').slice(0, 160)})`); return null; }
    return r.data;
  };

  // ── 6. MMDB direct ─────────────────────────────────────────────────────────
  console.log('\n[6] refresh #1 — plain MMDB (direct)…');
  await setSetting('geoipCustomUrl', `${HOST_BASE}/sample.mmdb`);
  let r = await refresh();
  check('refresh returned 200', r.status === 200, JSON.stringify(r.data?.error ?? ''));
  let st = await status();
  checkCycleOk(st, 'MMDB');
  check('active file set', Boolean(st.activeFileId), `${st.activeFileName} (${st.activeFileSizeBytes} B)`);
  check('file name derived from URL', /geoip-sample\.mmdb-\d{4}-\d{2}-\d{2}$/.test(st.activeFileName ?? ''), st.activeFileName ?? '');
  const mmdbFileId = st.activeFileId;

  let t = await talkerRow('8.8.8.8');
  check('MMDB lookup 8.8.8.8 → US', t?.countryCode === 'US' && t?.countryName === 'United States' && t?.city === 'Mountain View', JSON.stringify({ cc: t?.countryCode, cn: t?.countryName, city: t?.city }));
  t = await talkerRow('1.1.1.1');
  check('MMDB lookup 1.1.1.1 → AU', t?.countryCode === 'AU' && t?.city === 'Sydney', JSON.stringify({ cc: t?.countryCode, city: t?.city }));

  // ── 7. dp-ip CSV (single-IP rows) + old-file pruning ───────────────────────
  console.log('\n[7] refresh #2 — dp-ip-style CSV…');
  await setSetting('geoipCustomUrl', `${HOST_BASE}/dpip.csv`);
  r = await refresh();
  check('refresh returned 200', r.status === 200, JSON.stringify(r.data?.error ?? ''));
  st = await status();
  checkCycleOk(st, 'CSV');
  check('active file switched to CSV', /geoip-dpip\.csv-\d{4}-\d{2}-\d{2}$/.test(st.activeFileName ?? ''), st.activeFileName ?? '');
  const csvCount = (await pool.query(`SELECT count(*)::int AS n FROM repo_files WHERE category = 'geoip'`)).rows[0].n;
  check('old MMDB file pruned (repo has exactly 1 geoip file)', csvCount === 1, `count=${csvCount}`);

  t = await talkerRow('8.8.8.8');
  check('CSV lookup 8.8.8.8 → US', t?.countryCode === 'US' && t?.city === 'Mountain View', JSON.stringify({ cc: t?.countryCode, city: t?.city }));
  t = await talkerRow('93.184.216.34');
  check('CSV lookup 93.184.216.34 → DE (only in CSV)', t?.countryCode === 'DE' && t?.city === 'Frankfurt am Main', JSON.stringify({ cc: t?.countryCode, city: t?.city }));

  // ── 8. IP2Location-LITE zip (range rows) ───────────────────────────────────
  console.log('\n[8] refresh #3 — LITE-style ZIP…');
  await setSetting('geoipCustomUrl', `${HOST_BASE}/lite.zip`);
  r = await refresh();
  check('refresh returned 200', r.status === 200, JSON.stringify(r.data?.error ?? ''));
  st = await status();
  checkCycleOk(st, 'ZIP');
  check('zip member extracted + active', /geoip-geoip-lite-ipv4\.csv-\d{4}-\d{2}-\d{2}$/.test(st.activeFileName ?? ''), st.activeFileName ?? '');
  const zipCount = (await pool.query(`SELECT count(*)::int AS n FROM repo_files WHERE category = 'geoip'`)).rows[0].n;
  check('CSV file pruned after zip fetch', zipCount === 1, `count=${zipCount}`);

  t = await talkerRow('8.8.8.8');
  check('LITE range lookup 8.8.8.8 → US/Mountain View (no name col)', t?.countryCode === 'US' && t?.city === 'Mountain View', JSON.stringify({ cc: t?.countryCode, cn: t?.countryName, city: t?.city }));
  t = await talkerRow('1.1.1.1');
  check('LITE range lookup 1.1.1.1 → AU/Sydney (1.0.0.0/8)', t?.countryCode === 'AU' && t?.city === 'Sydney', JSON.stringify({ cc: t?.countryCode, city: t?.city }));

  // ── 9. tar.gz archive (MaxMind-style) ─────────────────────────────────────
  console.log('\n[9] refresh #4 — tar.gz archive…');
  await setSetting('geoipCustomUrl', `${HOST_BASE}/archive.tar.gz`);
  r = await refresh();
  check('refresh returned 200', r.status === 200, JSON.stringify(r.data?.error ?? ''));
  st = await status();
  checkCycleOk(st, 'TAR.GZ');
  check('tar member extracted + active', /geoip-GeoLite2-City\.mmdb-\d{4}-\d{2}-\d{2}$/.test(st.activeFileName ?? ''), st.activeFileName ?? '');

  t = await talkerRow('8.8.8.8');
  check('extracted MMDB lookup 8.8.8.8 → US (with name)', t?.countryCode === 'US' && t?.countryName === 'United States', JSON.stringify({ cc: t?.countryCode, cn: t?.countryName }));

  // ── 10. same download THROUGH the forward proxy ───────────────────────────
  console.log('\n[10] refresh #5 — via forward proxy…');
  await setSetting('webFetchProxyUrl', `http://host.docker.internal:${PROXY_PORT}`);
  r = await refresh(); // same URL as step 9 → content dedupes to the existing file
  check('refresh through proxy returned 200', r.status === 200, JSON.stringify(r.data?.error ?? ''));
  st = await status();
  checkCycleOk(st, 'PROXY');
  check('active file unchanged (deduped content)', st.activeFileId === mmdbFileId || /GeoLite2-City\.mmdb/.test(st.activeFileName ?? ''), `${st.activeFileId} vs ${mmdbFileId}`);

  // ── 11. failure path — 404 keeps the last good file serving ───────────────
  console.log('\n[11] refresh #6 — failing URL…');
  await setSetting('geoipCustomUrl', `${HOST_BASE}/does-not-exist`);
  r = await refresh();
  check('failing refresh answers (200 — last good file still active)', [200, 502].includes(r.status), `status=${r.status} ${JSON.stringify(r.data?.error ?? '')}`);
  st = await status();
  check('lastError recorded', Boolean(st.lastError), String(st.lastError).slice(0, 120));
  t = await talkerRow('8.8.8.8');
  check('lookups still work off the last good file', t?.countryCode === 'US', JSON.stringify({ cc: t?.countryCode }));

  // ── 12. stored geo columns + /flows/internet country aggregation ───────────
  console.log('\n[12] stored dstCountryCode backfill + per-country egress…');
  await setSetting('geoipCustomUrl', `${HOST_BASE}/sample.mmdb`); // MMDB knows US + AU (not DE)
  r = await refresh();
  checkCycleOk((await status()), 'STORED-REFRESH');

  const code = await anyStoredCode();
  check('stored dstCountryCode backfilled on flow_agg_5m', Boolean(code), `code=${code}`);

  const net = await internet();
  check('/flows/internet returns perCountry array', Boolean(net) && Array.isArray(net.perCountry), JSON.stringify(net?.perCountry ?? null).slice(0, 200));
  const codedRow = (net?.perCountry ?? []).find((c) => c.countryCode != null);
  check('perCountry has a resolved-country row with egress', Boolean(codedRow) && Number(codedRow.estBytes) > 0, JSON.stringify(codedRow ?? net?.perCountry ?? null).slice(0, 200));

  // ── cleanup ────────────────────────────────────────────────────────────────
  console.log('\n[cleanup]…');
  await setSetting('webFetchProxyUrl', '');
  for (const key of ['geoipCustomUrl', 'geoipSource', 'geoipFetchIntervalHours', 'geoipDeleteOldFiles']) {
    await authed('DELETE', `/settings/${key}`);
  }
  const files = (await pool.query(`SELECT id FROM repo_files WHERE category = 'geoip'`)).rows;
  for (const f of files) await authed('DELETE', `/files/${f.id}`);
  await authed('DELETE', '/settings/geoipActiveFileId');
  await pool.query(
    `DELETE FROM flow_agg_5m WHERE "dstIp" = ANY($1::inet[]) AND "srcIp" = '192.168.1.50'::inet`,
    [SEED_IPS]
  );
  for (const m of mocks) m.kill();

  console.log(failures === 0 ? '\nALL PASS' : `\n${failures} FAILURE(S)`);
  await pool.end();
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
