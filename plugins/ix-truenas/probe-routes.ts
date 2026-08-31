/**
 * Live probe for static routes on a TrueNAS appliance.
 *   1. staticroute.query — the documented v26+ CRUD namespace (primary source)
 *   2. interface.query → per-interface `static_routes` (older-release fallback)
 * Usage: TRUENAS_HOST=... TRUENAS_API_KEY=... npx tsx probe-routes.ts
 */
import { TruenasClient, TruenasCredentials } from './src/client/truenasClient';

const host = process.env['TRUENAS_HOST'] ?? '10.25.0.10';
const transport = (process.env['TRUENAS_TRANSPORT'] as 'auto' | 'http' | 'https') || 'auto';
const timeoutMs = Number(process.env['TRUENAS_TIMEOUT_MS'] ?? 8000);

let creds: TruenasCredentials;
if (process.env['TRUENAS_API_KEY']) {
  const owner = process.env['TRUENAS_API_KEY_USERNAME'] || 'root';
  creds = { kind: 'apiKey', username: owner, apiKey: process.env['TRUENAS_API_KEY'] };
} else if (process.env['TRUENAS_USER'] && process.env['TRUENAS_PASSWORD']) {
  creds = { kind: 'password', username: process.env['TRUENAS_USER'], password: process.env['TRUENAS_PASSWORD'] };
} else {
  console.error('Set TRUENAS_HOST + (TRUENAS_USER+TRUENAS_PASSWORD or TRUENAS_API_KEY).');
  process.exit(1);
}

async function main(): Promise<void> {
  const client = new TruenasClient(host, transport, timeoutMs);
  await client.login(creds);
  console.log('✅ login OK\n');

  // 1) interface.query — per-interface `static_routes` (older-release fallback;
  // the field is ABSENT on v26, which uses staticroute.* instead).
  try {
    const ifaces = (await client.call<Record<string, unknown>[]>('interface.query', [], creds)) ?? [];
    console.log(`--- interface.query: ${ifaces.length} interfaces ---`);
    let withRoutes = 0;
    for (const i of ifaces) {
      const sr = i['static_routes'];
      if (!Array.isArray(sr) || sr.length === 0) continue;
      withRoutes++;
      console.log(`  ${String(i['name']).padEnd(12)} desc=${JSON.stringify(i['description'])} static_routes=${JSON.stringify(sr)}`);
    }
    console.log(withRoutes > 0 ? '' : '  (no interface carries per-interface static_routes — v26 uses staticroute.*)');
  } catch (err) {
    console.error(`interface.query FAILED: ${(err as Error).message}`);
  }

  // 2) staticroute.query — the documented v26+ CRUD namespace.
  try {
    const r = await client.call('staticroute.query', [], creds);
    console.log(`\n--- staticroute.query OK (${Array.isArray(r) ? (r as unknown[]).length : '?'} rows) ---`);
    console.log(JSON.stringify(r, null, 2)?.slice(0, 4000));
  } catch (err) {
    console.log(`\n--- staticroute.query: ${(err as Error).message}`);
  }

  process.exit(0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
