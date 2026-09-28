/**
 * Read-only probe of the LCOS router web UI (WLC01, 10.25.0.20).
 *
 * Purpose: reverse-engineer the saveconf/loadconf/backup/restore endpoints and
 * the SPA's API surface so the lancom-lcos plugin can implement config backup /
 * restore + setting writes over HTTP. NO writes are performed — only GETs of
 * form pages, option lists and static assets.
 *
 * Usage (from repo root): ./node_modules/.bin/tsx scripts/probe-lcos-web.ts [host]
 */
import path from 'node:path';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const HOST = process.argv[2] ?? '10.25.0.20';
const SECRET_ID = process.env.LCOS_WEB_SECRET_ID ?? '3352ee33-1577-4849-a7ae-9ecf4c67d104';

const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));
const OUT_DIR = '/tmp/lcos-web-probe';
fs.mkdirSync(OUT_DIR, { recursive: true });

function save(name: string, body: Buffer | string): void {
  const p = path.join(OUT_DIR, name);
  fs.writeFileSync(p, typeof body === 'string' ? body : body);
  console.log(`  saved ${p} (${typeof body === 'string' ? body.length : body.length} bytes)`);
}

async function main(): Promise<void> {
  // --- UNM API login (2FA) ----------------------------------------------------
  const { Pool } = apiRequire('pg');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm' });
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
  if (!token) throw new Error('UNM API login failed');
  console.log('authenticated against UNM API');

  // --- decrypted web credentials ----------------------------------------------
  const sr = await fetch(`${API}/secrets/${SECRET_ID}`, { headers: { Authorization: `Bearer ${token}` } });
  const sjson = (await sr.json()) as Record<string, any>;
  console.log('secret response keys:', Object.keys(sjson));
  const fields = (sjson.fields ?? sjson) as Record<string, string>;
  const username = String(fields.username ?? '');
  const password = String(fields.password ?? '');
  if (!username || !password) throw new Error(`unexpected secret shape: ${JSON.stringify(Object.keys(fields))}`);
  console.log(`credentials resolved (user="${username}", pw length=${password.length})`);

  // --- raw HTTP(S) GET against the router --------------------------------------
  const tokenB64 = Buffer.from(`${username}:${password}`, 'utf8').toString('base64');

  type ProbeResult = { status: number; headers: Record<string, string | string[] | undefined>; body: Buffer };
  function get(scheme: 'http' | 'https', port: number, urlPath: string): Promise<ProbeResult> {
    return new Promise((resolve, reject) => {
      const lib = scheme === 'https' ? https : http;
      const req = lib.get(
        { hostname: HOST, port, path: urlPath, method: 'GET', headers: { Authorization: `Basic ${tokenB64}`, Connection: 'close', Accept: '*/*' }, rejectUnauthorized: false, timeout: 15_000 },
        (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (c) => chunks.push(c));
          res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers as Record<string, string | string[] | undefined>, body: Buffer.concat(chunks) }));
        }
      );
      req.on('error', reject);
      req.setTimeout(15_000, () => req.destroy(new Error(`timeout ${scheme}://${HOST}:${port}${urlPath}`)));
    });
  }

  const paths = ['/', '/saveconf/options', '/loadconf/', '/backup', '/restore'];
  for (const scheme of ['http', 'https'] as const) {
    const port = scheme === 'http' ? 80 : 443;
    console.log(`\n=== ${scheme}://${HOST}:${port} ===`);
    for (const p of paths) {
      try {
        const r = await get(scheme, port, p);
        const ct = String(r.headers['content-type'] ?? '');
        console.log(`  GET ${p} → ${r.status} (${ct}, ${r.body.length} bytes)`);
        if (r.body.length > 0 && r.body.length < 2_000_000) {
          const safe = p.replace(/[^a-z0-9]+/gi, '_');
          save(`${scheme}-${safe}.bin`, r.body);
          // Show a snippet of text bodies.
          if (ct.includes('html') || ct.includes('json') || ct === '') {
            console.log(`    ${r.body.toString('utf8').slice(0, 400).replace(/\n/g, '\\n')}`);
          }
        }
      } catch (e) {
        console.log(`  GET ${p} → ERROR ${(e as Error).message}`);
      }
    }
  }

  // --- SPA discovery: fetch index + referenced JS bundles ------------------------
  for (const scheme of ['http', 'https'] as const) {
    const port = scheme === 'http' ? 80 : 443;
    try {
      const r = await get(scheme, port, '/');
      if (r.status !== 200 || !String(r.headers['content-type'] ?? '').includes('html')) continue;
      console.log(`\n=== SPA discovery via ${scheme} ===`);
      const html = r.body.toString('utf8');
      save(`${scheme}-index.html`, html);
      const refs = new Set<string>();
      for (const m of html.matchAll(/(?:src|href)="([^"]+\.(?:js|css))"/g)) refs.add(m[1]);
      console.log(`  referenced assets: ${[...refs].join(', ') || '(none)'}`);
      let i = 0;
      for (const ref of [...refs]) {
        if (!ref.startsWith('/') && !ref.startsWith('http')) continue;
        const urlPath = ref.startsWith('http') ? new URL(ref).pathname : ref;
        try {
          const br = await get(scheme, port, urlPath);
          i++;
          save(`${scheme}-asset-${i}${path.extname(urlPath) || '.js'}`, br.body);
          console.log(`  asset ${urlPath} → ${br.status} (${br.body.length} bytes)`);
        } catch (e) {
          console.log(`  asset ${urlPath} → ERROR ${(e as Error).message}`);
        }
      }
    } catch (e) {
      console.log(`SPA discovery via ${scheme}: ${(e as Error).message}`);
    }
  }

  await pool.end();
  console.log('\ndone — artifacts in', OUT_DIR);
}

main().catch((e) => {
  console.error('probe failed:', e);
  process.exit(1);
});
