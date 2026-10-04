#!/usr/bin/env node
/**
 * Live verification for the Phase C flow features (needs a running stack):
 *   1. GET /settings exposes flowInternalRanges + flowExternalRanges with defaults
 *   2. PUT rejects malformed CIDR lists (400) and accepts valid ones, then resets
 *   3. GET /flows/top-talkers rows carry the `hostname` field; external IPs get a
 *      best-effort reverse-DNS name when container DNS egress allows it (soft check)
 * Usage: node scripts/verify-flow-ranges.cjs
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

  console.log('\nsettings registry');
  const list = await authed('/settings');
  check('GET /settings → 200', list.status === 200);
  const byKey = new Map((await list.json()).settings.map((s) => [s.key, s]));
  const internal = byKey.get('flowInternalRanges');
  const external = byKey.get('flowExternalRanges');
  check('flowInternalRanges present', Boolean(internal));
  check('flowExternalRanges present', Boolean(external));
  if (internal) {
    check('default is RFC1918', internal.value === '10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16', `value=${JSON.stringify(internal.value)}`);
    check('category is Flows', internal.category === 'Flows');
  }

  console.log('\nvalidation');
  const bad = await authed('/settings/flowInternalRanges', { method: 'PUT', body: JSON.stringify({ value: 'not-a-cidr' }) });
  check('malformed CIDR → 400', bad.status === 400, `status=${bad.status}`);
  const okPut = await authed('/settings/flowExternalRanges', { method: 'PUT', body: JSON.stringify({ value: '8.8.8.8/32' }) });
  check('valid carve-out → 200', okPut.status === 200, `status=${okPut.status}`);
  const reset = await authed('/settings/flowExternalRanges', { method: 'DELETE' });
  check('reset → 200 (back to default)', reset.status === 200 && ((await reset.json()).setting?.value ?? '') === '');

  console.log('\ntop-talkers hostname');
  // Default window is the last hour — widen to 30 days if that's empty.
  let res = await authed('/flows/top-talkers?limit=50');
  check('GET /flows/top-talkers → 200', res.status === 200);
  let j = null;
  if (res.status === 200) {
    j = await res.json();
    if ((j.sources?.length ?? 0) + (j.destinations?.length ?? 0) === 0) {
      console.log('  info last hour empty — retrying with a 30-day window');
      const from = new Date(Date.now() - 30 * 86_400_000).toISOString();
      res = await authed(`/flows/top-talkers?limit=50&from=${encodeURIComponent(from)}`);
      j = res.status === 200 ? await res.json() : null;
    }
  }
  if (j) {
    const rows = [...(j.sources ?? []), ...(j.destinations ?? [])];
    check('rows present', rows.length > 0, `n=${rows.length}`);
    check('every row has a hostname field (string|null)', rows.every((r) => typeof r.hostname === 'string' || r.hostname === null));
    const external = rows.filter((r) => !r.internal && !r.deviceId);
    console.log(`  info ${external.length} external talker(s): ` + external.map((r) => `${r.ip}${r.hostname ? ` → ${r.hostname}` : ''}`).join(', '));
    // Soft: only meaningful when the container has DNS egress for PTR records —
    // never a hard failure.
    if (external.length > 0) {
      const resolved = external.filter((r) => r.hostname);
      console.log(`  info reverse-DNS resolved ${resolved.length}/${external.length} external IP(s)` + (resolved.length === 0 ? ' (no PTR egress — acceptable)' : ''));
    } else {
      console.log('  info no external talkers in window — skipping PTR soft-check');
    }
  }

  console.log(`\n${failures === 0 ? 'ALL PASS' : `${failures} FAILED`}`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
