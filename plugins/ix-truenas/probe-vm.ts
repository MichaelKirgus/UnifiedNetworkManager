/**
 * READ-ONLY live probe of the TrueNAS `vm.*` RPC surface — confirms the exact
 * request/response shapes for VM lifecycle + NIC actions before they are wired
 * into the action registry. NEVER mutates: only vm.query / vm.get (by id) and
 * core.get_methods (catalog introspection).
 *
 * Usage (from this folder):
 *   TRUENAS_HOST=10.25.0.10 TRUENAS_API_KEY=<id>-<material> npx tsx probe-vm.ts
 */
import { TruenasClient, TruenasCredentials } from './src/client/truenasClient';

const host = process.env['TRUENAS_HOST'] ?? '10.25.0.10';
const transport = (process.env['TRUENAS_TRANSPORT'] as 'auto' | 'http' | 'https') || 'auto';
const timeoutMs = Number(process.env['TRUENAS_TIMEOUT_MS'] ?? 15000);

let creds: TruenasCredentials;
if (process.env['TRUENAS_API_KEY']) {
  const owner = process.env['TRUENAS_API_KEY_USERNAME'] || 'root';
  creds = { kind: 'apiKey', username: owner, apiKey: process.env['TRUENAS_API_KEY'] };
} else if (process.env['TRUENAS_USER'] && process.env['TRUENAS_PASSWORD']) {
  creds = { kind: 'password', username: process.env['TRUENAS_USER'], password: process.env['TRUENAS_PASSWORD'] };
} else {
  console.error('Set TRUENAS_HOST + (TRUENAS_API_KEY or TRUENAS_USER+TRUENAS_PASSWORD).');
  process.exit(1);
}

async function main(): Promise<void> {
  const client = new TruenasClient(host, transport, timeoutMs);
  console.log(`\n=== TrueNAS VM RPC probe (READ-ONLY): ${host} ===\n`);
  await client.login(creds);
  console.log('✅ login OK\n');

  // 1. vm.query — full list with devices[] (the inventory source).
  const vms = await client.call<Record<string, unknown>[]>('vm.query', [], creds);
  console.log(`--- vm.query: ${vms.length} VMs ---`);
  for (const v of vms) {
    const status = (v['status'] ?? {}) as Record<string, unknown>;
    const devs = Array.isArray(v['devices']) ? (v['devices'] as Record<string, unknown>[]) : [];
    console.log(
      `  id=${String(v['id']).padEnd(4)} name=${String(v['name']).padEnd(16)} state=${String(status['state']).padEnd(9)} devices=${devs.length}`
    );
  }

  // 2. Full JSON of one VM row (devices[] carries per-device ids for NIC ops).
  const first = vms.find((v) => Array.isArray(v['devices']) && (v['devices'] as unknown[]).length > 0) ?? vms[0];
  if (first) {
    console.log(`\n--- vm.query row id=${String(first['id'])} name=${String(first['name'])} full JSON ---`);
    console.log(JSON.stringify(first, null, 2).slice(0, 7000));
  }

  // 3. Sanity: does core.get_method work AT ALL for a known method?
  try {
    const m = await client.call<Record<string, unknown>>('core.get_method', ['vm.query'], creds);
    console.log(`\n--- core.get_method(vm.query) raw ---`);
    console.log(JSON.stringify(m).slice(0, 800));
  } catch (e) {
    console.error(`core.get_method(vm.query) failed: ${(e as Error).message}`);
  }

  // 4. core.get_methods returns an OBJECT map name→schema. Dump the exact param
  // schemas for the methods we will wire into actions (read-only introspection).
  try {
    const all = (await client.call<Record<string, unknown>>('core.get_methods', [], creds)) as Record<string, unknown>;
    const wanted = [
      'vm.start', 'vm.stop', 'vm.poweroff', 'vm.restart', 'vm.suspend', 'vm.resume', 'vm.delete',
      'vm.device.create', 'vm.device.delete',
    ];
    console.log(`\n--- method schemas (raw) ---`);
    for (const name of wanted) {
      const m = all[name] as Record<string, unknown> | undefined;
      if (!m) { console.log(`  ❌ ${name}: not in catalog`); continue; }
      // The schema object shape varies by version — dump the whole thing compactly.
      console.log(`\n  === ${name} ===`);
      console.log(JSON.stringify(m, null, 2).slice(0, 1800));
    }
    // nic_attach_choices — the actual list of bridges available to attach.
    try {
      const choices = await client.call<unknown>('vm.device.nic_attach_choices', [], creds);
      console.log(`\n--- vm.device.nic_attach_choices ---`);
      console.log(JSON.stringify(choices, null, 2).slice(0, 1500));
    } catch (e) {
      console.error(`nic_attach_choices failed: ${(e as Error).message}`);
    }
  } catch (e) {
    console.error(`core.get_methods failed: ${(e as Error).message}`);
  }

  await client.close?.();
}

main().catch((e) => {
  console.error('probe crashed:', e);
  process.exit(1);
});
