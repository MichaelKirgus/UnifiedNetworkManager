/**
 * READ-ONLY live probe — what does TrueNAS `vm.query` actually return for CPU
 * topology (vcpus / cores / threads)? Decides how the VMs page's new Cores and
 * Threads columns get their data. NEVER mutates: vm.query + core.get_methods only.
 *
 * Usage (from this folder):
 *   TRUENAS_HOST=10.25.0.10 TRUENAS_API_KEY=<id>-<material> npx tsx probe-vm-cpu.ts
 */
import { TruenasClient, type TruenasCredentials } from './src/client/truenasClient';

const host = process.env['TRUENAS_HOST'] ?? '10.25.0.10';
const transport = (process.env['TRUENAS_TRANSPORT'] as 'auto' | 'http' | 'https') || 'auto';
const timeoutMs = Number(process.env['TRUENAS_TIMEOUT_MS'] ?? 20_000);

async function main(): Promise<void> {
  const apiKey = process.env['TRUENAS_API_KEY'];
  if (!apiKey) { console.error('Set TRUENAS_HOST + TRUENAS_API_KEY.'); process.exit(1); }
  const creds: TruenasCredentials = { kind: 'apiKey', username: 'root', apiKey };

  const client = new TruenasClient(host, transport, timeoutMs);
  await client.login(creds);
  console.log(`✅ logged in to ${host}\n`);

  // 1. vm.query — full rows; dump the CPU-relevant fields of every VM + one full row.
  const vms = await client.call<Record<string, unknown>[]>('vm.query', [], creds);
  console.log(`--- vm.query: ${vms.length} VMs ---`);
  for (const v of vms) {
    const status = (v['status'] ?? {}) as Record<string, unknown>;
    console.log(
      `  id=${String(v['id']).padEnd(4)} name=${String(v['name']).padEnd(20)} state=${String(status['state']).padEnd(9)}` +
      ` vcpus=${String(v['vcpus'] ?? '—').padEnd(4)} cores=${String((v as Record<string, unknown>)['cores'] ?? 'ABSENT').padEnd(6)}` +
      ` threads=${String((v as Record<string, unknown>)['threads'] ?? 'ABSENT')}`
    );
  }
  const first = vms[0];
  if (first) {
    console.log(`\n--- vm.query row id=${String(first['id'])} name=${String(first['name'])} — full JSON ---`);
    console.log(JSON.stringify(first, null, 2).slice(0, 6000));
  }

  // 2. Does the appliance expose a per-VM CPU-utilization RPC? (read-only catalog introspection)
  try {
    const all = await client.call<Record<string, unknown>>('core.get_methods', [], creds);
    const names = Object.keys(all as Record<string, unknown>).filter((n) => /vm|cpu/i.test(n));
    console.log(`\n--- catalog methods matching vm|cpu (${names.length}) ---`);
    for (const n of names) console.log(`  ${n}`);
  } catch (e) {
    console.error(`core.get_methods failed: ${(e as Error).message}`);
  }

  // 3. system.info — host-level CPU facts (for context).
  try {
    const si = await client.call<Record<string, unknown>>('system.info', [], creds);
    console.log(`\n--- system.info (cpu-relevant) ---`);
    console.log(JSON.stringify({ model: si['model'], cores: si['cores'], core_count: si['core_count'], threads_per_core: si['threads_per_core'] }));
  } catch (e) {
    console.error(`system.info failed: ${(e as Error).message}`);
  }

  // 4. vm.get on the first VM — sometimes richer than vm.query rows.
  if (first && typeof first['id'] === 'number') {
    try {
      const one = await client.call<Record<string, unknown>>('vm.get', [first['id']], creds);
      console.log(`\n--- vm.get(${first['id']}) CPU fields ---`);
      console.log(JSON.stringify({ vcpus: one['vcpus'], cores: (one as Record<string, unknown>)['cores'], threads: (one as Record<string, unknown>)['threads'] }));
    } catch (e) {
      console.error(`vm.get failed: ${(e as Error).message}`);
    }
  }
}

main().catch((e) => { console.error('FATAL:', e instanceof Error ? e.message : e); process.exit(1); });
