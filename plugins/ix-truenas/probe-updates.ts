/**
 * READ-ONLY live probe: introspect the TrueNAS appliance's JSON-RPC method
 * catalog for update/release-related methods (core.get_methods) and dump a few
 * safe read-only candidates. NEVER calls any write/update method.
 *
 * Usage (from this folder):
 *   TRUENAS_HOST=10.25.0.10 TRUENAS_API_KEY=<key> npx tsx probe-updates.ts
 */
import { TruenasClient, TruenasCredentials } from './src/client/truenasClient';

const host = process.env['TRUENAS_HOST'] ?? '10.25.0.10';
const apiKey = process.env['TRUENAS_API_KEY'];
if (!apiKey) {
  console.error('Set TRUENAS_HOST + TRUENAS_API_KEY.');
  process.exit(1);
}
const owner = process.env['TRUENAS_API_KEY_USERNAME'] || 'root';

async function main(): Promise<void> {
  const client = new TruenasClient(host, 'auto', 8000);
  const creds: TruenasCredentials = { kind: 'apiKey', username: owner, apiKey };
  await client.login(creds);
  console.log('✅ login OK\n');

  // system.info first — current version + any update fields it carries.
  try {
    const si = (await client.call<Record<string, unknown>>('system.info', [], creds)) as Record<string, unknown>;
    console.log('--- system.info ---');
    console.log(JSON.stringify(si, null, 2));
  } catch (e) {
    console.error(`system.info FAILED: ${(e as Error).message}`);
  }

  // Full method catalog — filter for update/release/upgrade candidates.
  const methods = await client.call<string[]>('core.get_methods', [], creds);
  console.log(`\n--- core.get_methods: ${methods.length} total ---`);
  const interesting = methods.filter((m) => /update|release|upgrade/i.test(m));
  for (const m of interesting.sort()) console.log(`  ${m}`);

  // Safe read-only candidates — dump their raw responses.
  const READ_ONLY_CANDIDATES = [
    'update.check_available',
    'update.pending_update_info',
    'update.release_info',
    'update.latest_version',
    'system.update_check',
  ];
  for (const m of READ_ONLY_CANDIDATES) {
    if (!methods.includes(m)) continue;
    try {
      const r = await client.call<unknown>(m, [], creds);
      console.log(`\n--- ${m} ---`);
      const json = JSON.stringify(r, null, 2);
      console.log(json && json.length > 4000 ? `${json.slice(0, 4000)}… [truncated]` : json);
    } catch (e) {
      console.error(`\n--- ${m} FAILED: ${(e as Error).message}`);
    }
  }

  // Also check what the update namespace offers in general.
  const ns = methods.filter((m) => m.startsWith('update.'));
  console.log('\n--- all update.* methods ---');
  for (const m of ns.sort()) console.log(`  ${m}`);
}

main()
  .catch((err) => {
    console.error('Probe failed:', err instanceof Error ? err.message : err);
    process.exit(1);
  })
  .finally(() => process.exit(process.exitCode ?? 0));
