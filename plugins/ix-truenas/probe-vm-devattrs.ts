/**
 * READ-ONLY live probe — full attribute dump of every attached VM device, to
 * design the generic "edit device" contract (which fields exist per dtype and
 * which are editable). Also lists the vm.device.* RPC methods on this release.
 * NEVER mutates: vm.query + core.get_methods only.
 *
 * Usage (from this folder):
 *   TRUENAS_HOST=10.25.0.10 TRUENAS_API_KEY=<id>-<material> npx tsx probe-vm-devattrs.ts [VMname]
 */
import { TruenasClient, type TruenasCredentials } from './src/client/truenasClient';

const host = process.env['TRUENAS_HOST'] ?? '10.25.0.10';
const transport = (process.env['TRUENAS_TRANSPORT'] as 'auto' | 'http' | 'https') || 'auto';
const timeoutMs = Number(process.env['TRUENAS_TIMEOUT_MS'] ?? 30_000);

function norm(d: unknown): { dtype: string; attrs: Record<string, unknown>; id?: number } | null {
  if (!d || typeof d !== 'object') return null;
  const obj = d as Record<string, unknown>;
  const topDtype = typeof obj['dtype'] === 'string' ? (obj['dtype'] as string) : undefined;
  if (topDtype) return { dtype: topDtype, attrs: obj, id: typeof obj['id'] === 'number' ? (obj['id'] as number) : undefined };
  const attrs = (obj['attributes'] ?? {}) as Record<string, unknown>;
  const attrDtype = typeof attrs['dtype'] === 'string' ? (attrs['dtype'] as string) : undefined;
  return attrDtype ? { dtype: attrDtype, attrs, id: typeof obj['id'] === 'number' ? (obj['id'] as number) : undefined } : null;
}

async function main(): Promise<void> {
  const apiKey = process.env['TRUENAS_API_KEY'];
  if (!apiKey) { console.error('Set TRUENAS_HOST + TRUENAS_API_KEY.'); process.exit(1); }
  const creds: TruenasCredentials = { kind: 'apiKey', username: 'root', apiKey };

  const client = new TruenasClient(host, transport, timeoutMs);
  await client.login(creds);
  console.log(`✅ logged in to ${host}\n`);

  // 1. vm.device.* methods available on this release.
  try {
    const methods = (await client.call<string[]>('core.get_methods', [], creds)) ?? [];
    console.log('--- vm.device.* / vm.* methods ---');
    for (const m of methods) if (/^vm\./.test(m)) console.log(`  ${m}`);
  } catch (e) {
    console.error('core.get_methods failed:', e instanceof Error ? e.message : String(e));
  }

  // 2. Full attribute dump per device.
  const vms = await client.call<Record<string, unknown>[]>('vm.query', [], creds);
  const onlyVm = process.argv[2];
  console.log(`\n--- full device attributes (${vms.length} VMs) ---`);
  for (const v of vms) {
    const name = String(v['name']);
    if (onlyVm && !name.toLowerCase().includes(onlyVm.toLowerCase())) continue;
    const status = (v['status'] ?? {}) as Record<string, unknown>;
    console.log(`\nVM ${name} [${String(status['state'] ?? '?')}] id=${v['id']}`);
    const devicesRaw = Array.isArray(v['devices']) ? (v['devices'] as Record<string, unknown>[]) : [];
    for (const d of devicesRaw) {
      const dev = norm(d);
      if (!dev) continue;
      // Drop the nested vm reference + dtype noise — show every real attribute.
      const attrs: Record<string, unknown> = {};
      for (const [k, val] of Object.entries(dev.attrs)) {
        if (k === 'vm' || k === 'order') continue;
        attrs[k] = val;
      }
      console.log(`  #${dev.id ?? '?'} ${dev.dtype.padEnd(8)} ${JSON.stringify(attrs)}`);
    }
  }

  await client.close().catch(() => undefined);
}

main().catch((e) => { console.error('FATAL', e instanceof Error ? e.stack : String(e)); process.exit(1); });
