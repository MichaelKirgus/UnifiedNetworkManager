/**
 * Live API probe for the TrueNAS plugin — dumps the RAW JSON of every method
 * the v1 monitoring path uses, so field names can be confirmed against a real
 * appliance (the official docs don't render response schemas).
 *
 * Usage (from this folder):
 *   TRUENAS_HOST=10.25.0.10 \
 *   TRUENAS_USER=admin TRUENAS_PASSWORD=secret \
 *   npx tsx probe-api.ts
 *
 * Or with an API key instead of username/password (TrueNAS 26+ needs the
 * owner username — TRUENAS_API_KEY_USERNAME, defaults to root):
 *   TRUENAS_HOST=10.25.0.10 TRUENAS_API_KEY=<id>-<material> npx tsx probe-api.ts
 *
 * Transport defaults to wss (self-signed accepted); set TRUENAS_TRANSPORT=http
 * for plaintext boxes. This file is NOT part of the tsc build (tsconfig only
 * includes src/**) — same convention as plugins/fbox/live-probe.ts.
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

const METHODS = [
  'webui.main.dashboard.sys_info',
  'pool.query',
  'alert.list',
  'system.info',
] as const;

async function main(): Promise<void> {
  const client = new TruenasClient(host, transport, timeoutMs);
  console.log(`\n=== TrueNAS API probe: ${host} (transport=${transport}) ===\n`);

  await client.login(creds);
  console.log('✅ login OK\n');

  for (const method of METHODS) {
    const t0 = Date.now();
    try {
      const result = await client.call(method, [], creds);
      console.log(`--- ${method} (${Date.now() - t0} ms) ---`);
      // Truncate very large payloads (pool.query on big boxes can be verbose).
      const json = JSON.stringify(result, null, 2);
      console.log(json.length > 12_000 ? `${json.slice(0, 12_000)}\n… [truncated ${json.length - 12_000} chars]` : json);
    } catch (err) {
      console.error(`--- ${method} FAILED: ${(err as Error).message}`);
    }
    console.log('');
  }

  // Bonus: confirm the deferred-extension methods exist on this version.
  for (const method of ['disk.query', 'pool.dataset.query', 'sharing.nfs.query', 'sharing.smb.query', 'app.query', 'container.query'] as const) {
    try {
      await client.call(method, [], creds);
      console.log(`✅ ${method} exists`);
    } catch (err) {
      console.log(`⚠️  ${method}: ${(err as Error).message}`);
    }
  }
}

main()
  .catch((err) => {
    console.error('Probe failed:', err instanceof Error ? err.message : err);
    process.exit(1);
  })
  .finally(() => process.exit(process.exitCode ?? 0));
