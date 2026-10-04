#!/usr/bin/env node
/**
 * Live verification for the Phase D flow enrichment (needs a running stack):
 *   1. GET /flows/top-talkers rows carry networkName/vlanId fields
 *   2. GET /flows/ports returns source+destination port tables (port 0 allowed)
 *   3. GET /flows/ports?ip=… validates the drilldown param (400 on garbage)
 *   4. GET /flows/networks returns per-network rows with direction split
 *   5. ?siteId= filters work: valid site → 200, unknown id → 400
 * Usage: node scripts/verify-flows-enrichment.cjs
 */

const path = require('path');

const API = process.env.API_URL || 'http://localhost:3000/v1';

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

  // Widen the window to 24h so there is data even right after a deploy.
  // NOTE: the API's query validator rejects unencoded reserved chars — encode.
  const win = 'from=' + encodeURIComponent(new Date(Date.now() - 86_400_000).toISOString());

  console.log('\ntop-talkers enrichment fields');
  let res = await authed(`/flows/top-talkers?limit=10&${win}`);
  check('GET /flows/top-talkers → 200', res.status === 200, `status=${res.status}`);
  const talkers = (await res.json()) ?? {};
  const allTalkers = [...(talkers.sources ?? []), ...(talkers.destinations ?? [])];
  check('has rows in window', allTalkers.length > 0, `${allTalkers.length} rows`);
  if (allTalkers.length > 0) {
    const t = allTalkers[0];
    check('rows carry networkName field', 'networkName' in t, `row=${JSON.stringify(t.ip)} networkName=${t.networkName}`);
    check('rows carry vlanId field', 'vlanId' in t, `vlanId=${t.vlanId}`);
  }

  console.log('\nports');
  res = await authed(`/flows/ports?limit=10&${win}`);
  check('GET /flows/ports → 200', res.status === 200, `status=${res.status}`);
  const ports = (await res.json()) ?? {};
  check('sourcePorts is array', Array.isArray(ports.sourcePorts), `${ports.sourcePorts?.length} rows`);
  check('destinationPorts is array', Array.isArray(ports.destinationPorts), `${ports.destinationPorts?.length} rows`);
  if ((ports.destinationPorts?.length ?? 0) > 0) {
    const p = ports.destinationPorts[0];
    check('port row shape ok', typeof p.port === 'number' && typeof p.proto === 'number' && typeof p.estBytes === 'number', JSON.stringify(p));
  }
  res = await authed(`/flows/ports?ip=not-an-ip&${win}`);
  check('invalid ip → 400', res.status === 400, `status=${res.status}`);

  console.log('\nnetworks');
  res = await authed(`/flows/networks?limit=10&${win}`);
  check('GET /flows/networks → 200', res.status === 200, `status=${res.status}`);
  const nets = (await res.json()) ?? {};
  check('networks is array', Array.isArray(nets.networks), `${nets.networks?.length} rows`);
  if ((nets.networks?.length ?? 0) > 0) {
    const n = nets.networks[0];
    check('network row shape ok', typeof n.name === 'string' && typeof n.srcEstBytes === 'number' && typeof n.dstEstBytes === 'number' && n.estBytes === n.srcEstBytes + n.dstEstBytes, JSON.stringify(n));
  }

  console.log('\nsite filter');
  const sitesRes = await authed('/sites');
  const sites = ((await sitesRes.json()) ?? []).filter((s) => s.id);
  check('has at least one site', sites.length > 0, `${sites.length} sites`);
  if (sites.length > 0) {
    const sid = sites[0].id;
    for (const p of ['/flows/top-talkers', '/flows/ports', '/flows/networks']) {
      res = await authed(`${p}?siteId=${sid}&${win}`);
      check(`GET ${p}?siteId → 200`, res.status === 200, `status=${res.status} site=${sites[0].name}`);
    }
    res = await authed(`/flows/top-talkers?siteId=does-not-exist&${win}`);
    check('unknown siteId → 400', res.status === 400, `status=${res.status}`);
  }

  console.log(failures === 0 ? '\nALL PASS' : `\n${failures} FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
