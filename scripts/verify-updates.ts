/**
 * READ-ONLY verification for the Updates page (GET /v1/updates).
 *
 * Logs in via the real auth flow (admin/admin; TOTP minted from the seeded
 * secret when 2FA is enabled) and prints every available update row plus the
 * stack card. Performs NO writes — safe to run against the live dev stack.
 *
 * Usage (from the repo root):
 *   ./node_modules/.bin/tsx scripts/verify-updates.ts
 */

import path from 'node:path';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';

// pg + otplib live in api/node_modules; resolve through the API package.
const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));

interface UpdateRowView {
  name: string;
  kind: string;
  currentVersion?: string | null;
  latestVersion?: string | null;
  available: boolean;
  rebootRequired?: boolean;
  sizeBytes?: number | null;
  applyActionId?: string | null;
  deviceName: string;
  managementAddress: string;
  pluginName: string;
}

async function main(): Promise<void> {
  const { Pool } = apiRequire('pg');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm' });

  // --- Login (admin/admin; TOTP from seeded secret when enabled) -----------
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
  if (!token) {
    console.error('FAIL login failed');
    await pool.end();
    process.exit(1);
  }

  // --- GET /v1/updates ------------------------------------------------------
  const res = await fetch(`${API}/updates`, { headers: { Authorization: `Bearer ${token}` } });
  if (res.status !== 200) {
    console.error(`FAIL /v1/updates → HTTP ${res.status}: ${(await res.text()).slice(0, 400)}`);
    await pool.end();
    process.exit(1);
  }
  const body = (await res.json()) as { rows: UpdateRowView[]; stack?: Record<string, unknown> };

  console.log(`\n=== /v1/updates — ${body.rows.length} available update row(s) ===`);
  if (body.rows.length === 0) {
    console.log('  (none yet — telemetry worker populates rows on the next poll cycle after a plugin emits updates[])');
  }
  for (const r of body.rows) {
    const apply = r.applyActionId ? ` [apply: ${r.applyActionId}]` : ' [no-apply]';
    console.log(
      `  • ${r.deviceName} (${r.managementAddress}) · ${r.pluginName}\n` +
        `      kind=${r.kind} name="${r.name}" ${r.currentVersion ?? '?'} → ${r.latestVersion ?? '?'}${apply}`,
    );
  }

  // --- Stack card -----------------------------------------------------------
  if (body.stack) {
    console.log('\n=== stack ===');
    const s = body.stack as Record<string, unknown>;
    for (const [k, v] of Object.entries(s)) {
      if (typeof v !== 'object' || v === null) console.log(`  ${k}: ${JSON.stringify(v)}`);
    }
  }

  // --- Per-kind breakdown ---------------------------------------------------
  const byKind = new Map<string, number>();
  for (const r of body.rows) byKind.set(r.kind, (byKind.get(r.kind) ?? 0) + 1);
  console.log('\n=== by kind ===');
  if (byKind.size === 0) console.log('  (empty)');
  for (const [k, n] of [...byKind.entries()].sort()) console.log(`  ${k}: ${n}`);

  await pool.end();
}

main().catch((err) => {
  console.error('ERROR', err);
  process.exit(1);
});
