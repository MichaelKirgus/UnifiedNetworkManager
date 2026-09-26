/**
 * READ-ONLY — dump vm.device.create's full argument documentation (it lists the
 * attributes per dtype) + iommu_enabled. Settles the exact attribute names for
 * PCI / USB / DISPLAY passthrough devices before writing the attach actions.
 *
 * Usage: TRUENAS_HOST=10.25.0.10 TRUENAS_API_KEY=<key> npx tsx probe-vm-devdoc.ts
 */
import { TruenasClient, type TruenasCredentials } from './src/client/truenasClient';

const host = process.env['TRUENAS_HOST'] ?? '10.25.0.10';
const transport = (process.env['TRUENAS_TRANSPORT'] as 'auto' | 'http' | 'https') || 'auto';

async function main(): Promise<void> {
  const apiKey = process.env['TRUENAS_API_KEY'];
  if (!apiKey) { console.error('Set TRUENAS_HOST + TRUENAS_API_KEY.'); process.exit(1); }
  const creds: TruenasCredentials = { kind: 'apiKey', username: 'root', apiKey };
  const client = new TruenasClient(host, transport, 30_000);
  await client.login(creds);

  const all = await client.call<Record<string, unknown>>('core.get_methods', [], creds);
  const spec = (all as Record<string, unknown>)['vm.device.create'] as Record<string, unknown>;
  console.log('=== vm.device.create full doc ===');
  console.log(String(spec['description'] ?? ''));

  try {
    const iommu = await client.call<unknown>('vm.device.iommu_enabled', [], creds);
    console.log(`\n=== iommu_enabled: ${JSON.stringify(iommu)} ===`);
  } catch (e) {
    console.log(`iommu_enabled failed: ${(e as Error).message}`);
  }

  // Also dump the vm.device.update doc (resize semantics + which attrs are mutable).
  const upd = (all as Record<string, unknown>)['vm.device.update'] as Record<string, unknown>;
  console.log('\n=== vm.device.update full doc ===');
  console.log(String(upd['description'] ?? ''));
}

main().catch((e) => { console.error('FATAL:', e instanceof Error ? e.message : e); process.exit(1); });
