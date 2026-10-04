#!/usr/bin/env node
/**
 * Live verification of flow hostname enrichment + the ports route — needs a running stack.
 *
 *   1. /flows/ports in all param shapes (no-ip, ip drilldown, siteId)
 *   2. /flows/top-talkers — internal IPs carry hosts-inventory hostnames
 *      (container/VM names like torserver01) + networkName/vlanId
 *   3. /flows/networks — real inventoried networks, not just "(unknown)"
 *   4. /flows/pairs — busiest host on each side of a device pair
 *
 * Usage: node scripts/verify-flow-hostnames.cjs
 */

const path = require('path');

const API = process.env.API_URL || 'http://localhost:3000/v1';
const DB = process.env.DATABASE_URL || 'postgresql://unm:unm@localhost:5432/unm';

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
  if (!token) process.exit(1);
  const from = encodeURIComponent(new Date(Date.now() - 3600_000).toISOString());
  const get = async (p) => {
    const r = await fetch(`${API}${p}`, { headers: { Authorization: `Bearer ${token}` } });
    return { status: r.status, json: () => r.json().catch(() => null) };
  };

  // 1. /flows/ports — all shapes (ip was the broken one).
  for (const c of ['', 'ip=10.100.2.1', 'siteId=x']) {
    const p = `/flows/ports?from=${from}&limit=5${c ? `&${c}` : ''}`;
    const r = await get(p);
    if (r.status === 400) { console.log(`[400 ok] ${p} → ${(await r.json()).error}`); continue; }
    const j = await r.json();
    const topSrc = j.sourcePorts?.slice(0, 3).map((x) => `${x.port}/${x.proto}`).join(', ');
    console.log(`[${r.status}] /flows/ports?${c || '(none)'} → srcTop: ${topSrc}`);
  }

  // 2. top-talkers — internal hostnames should now be inventory names.
  const tt = await get(`/flows/top-talkers?from=${from}&limit=8`);
  const j = (await tt.json()) ?? {};
  console.log(`\n[${tt.status}] /flows/top-talkers — sources:`);
  for (const s of j.sources ?? []) {
    console.log(`   ${s.ip}  dev=${s.deviceName ?? '-'}  host=${s.hostname ?? '-'}${s.hostnameSource ? ` (${s.hostnameSource})` : ''}  net=${s.networkName ?? '-'}`);
  }

  // 3. /flows/networks — should no longer be a single (unknown) row.
  const nw = await get(`/flows/networks?from=${from}&limit=6`);
  const nj = (await nw.json()) ?? {};
  console.log(`\n[${nw.status}] /flows/networks:`);
  for (const n of nj.networks ?? []) {
    console.log(`   ${n.name}  vlan=${n.vlanId ?? '-'}  total=${(n.estBytes / 1e6).toFixed(0)}MB`);
  }

  // 4. /flows/pairs — top-host identity.
  const pr = await get(`/flows/pairs?from=${from}&limit=3`);
  const pj = (await pr.json()) ?? {};
  console.log(`\n[${pr.status}] /flows/pairs:`);
  for (const p of pj.pairs ?? []) {
    console.log(`   ${p.srcName} [${p.srcTopHost ?? p.srcTopIp ?? '-'}] → ${p.dstName} [${p.dstTopHost ?? p.dstTopIp ?? '-'}]`);
  }
}

main().catch((err) => { console.error(err); process.exit(1); });
