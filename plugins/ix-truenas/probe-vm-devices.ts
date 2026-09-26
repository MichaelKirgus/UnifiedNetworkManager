/**
 * READ-ONLY live probe — what VM device types does this TrueNAS appliance
 * expose, and which `vm.device.*_choices` RPCs exist to feed attach dialogs?
 * Decides the plugin's "attachable device types" contract for the VMs page.
 * NEVER mutates: vm.query + core.get_methods + *_choices only.
 *
 * Usage (from this folder):
 *   TRUENAS_HOST=10.25.0.10 TRUENAS_API_KEY=<id>-<material> npx tsx probe-vm-devices.ts
 */
import { TruenasClient, type TruenasCredentials } from './src/client/truenasClient';

const host = process.env['TRUENAS_HOST'] ?? '10.25.0.10';
const transport = (process.env['TRUENAS_TRANSPORT'] as 'auto' | 'http' | 'https') || 'auto';
const timeoutMs = Number(process.env['TRUENAS_TIMEOUT_MS'] ?? 30_000);

function norm(d: unknown): { dtype: string; attrs: Record<string, unknown> } | null {
  if (!d || typeof d !== 'object') return null;
  const obj = d as Record<string, unknown>;
  const topDtype = typeof obj['dtype'] === 'string' ? (obj['dtype'] as string) : undefined;
  if (topDtype) return { dtype: topDtype, attrs: obj };
  const attrs = (obj['attributes'] ?? {}) as Record<string, unknown>;
  const attrDtype = typeof attrs['dtype'] === 'string' ? (attrs['dtype'] as string) : undefined;
  return attrDtype ? { dtype: attrDtype, attrs } : null;
}

async function main(): Promise<void> {
  const apiKey = process.env['TRUENAS_API_KEY'];
  if (!apiKey) { console.error('Set TRUENAS_HOST + TRUENAS_API_KEY.'); process.exit(1); }
  const creds: TruenasCredentials = { kind: 'apiKey', username: 'root', apiKey };

  const client = new TruenasClient(host, transport, timeoutMs);
  await client.login(creds);
  console.log(`✅ logged in to ${host}\n`);

  // 1. Every device of every VM — dtype census + one full sample per dtype.
  const vms = await client.call<Record<string, unknown>[]>('vm.query', [], creds);
  const samples: Record<string, string> = {};
  console.log(`--- vm.device census across ${vms.length} VMs ---`);
  for (const v of vms) {
    const name = String(v['name']);
    const devicesRaw = Array.isArray(v['devices']) ? (v['devices'] as Record<string, unknown>[]) : [];
    const line: string[] = [];
    for (const d of devicesRaw) {
      const dev = norm(d);
      if (!dev) continue;
      let label = '';
      const a = dev.attrs;
      switch (dev.dtype) {
        case 'NIC': label = `nic(${a['type'] ?? '?'}/${String(a['nic_attach'] ?? '?').slice(0, 12)})`; break;
        case 'DISK': label = `disk(${a['type'] ?? '?'})${a['path'] ? '' : '/zvol'}`; break;
        case 'CDROM': label = `cdrom(${String(a['path'] ?? '').slice(-24) || 'empty'})`; break;
        case 'DISPLAY': label = `display(${a['type'] ?? '?'})`; break;
        case 'PCI': label = `pci(${a['hostdev'] ?? a['device_id'] ?? '?'})`; break;
        case 'USB': {
          const bus = a['bus_number'], addr = a['address'];
          label = `usb(${typeof bus === 'number' ? bus : '?'}:${typeof addr === 'number' ? addr : '?'})${a['hostdev'] ? '/' + String(a['hostdev']) : ''}`;
          break;
        }
        default: label = dev.dtype.toLowerCase();
      }
      line.push(label);
      if (!samples[dev.dtype]) samples[dev.dtype] = JSON.stringify(d, null, 2).slice(0, 1500);
    }
    console.log(`  ${name.padEnd(16)} [${line.join(' ')}]`);
  }

  // 2. Which vm.device.* methods exist at all?
  const all = await client.call<Record<string, unknown>>('core.get_methods', [], creds);
  const methodNames = Object.keys(all as Record<string, unknown>);
  console.log(`\n--- vm.device.* methods (${methodNames.filter((m) => m.startsWith('vm.device.')).length}) ---`);
  for (const n of methodNames.filter((m) => m.startsWith('vm.device.'))) {
    const spec = (all as Record<string, unknown>)[n] as Record<string, unknown>;
    console.log(`  ${n}  ${JSON.stringify(spec['description'] ?? '').slice(0, 120)}`);
  }

  // 3. Call every *_choices method that exists — dump the shape of each result.
  const choiceMethods = methodNames.filter((m) => m.startsWith('vm.device.') && m.endsWith('_choices'));
  for (const m of choiceMethods) {
    try {
      const r = await client.call<unknown>(m, [], creds);
      console.log(`\n--- ${m} ---`);
      console.log(JSON.stringify(r, null, 2).slice(0, 3500));
    } catch (e) {
      console.log(`\n--- ${m} FAILED: ${(e as Error).message}`);
    }
  }

  // 4. Full sample device rows per dtype (for the attribute contract).
  for (const [dtype, json] of Object.entries(samples)) {
    console.log(`\n=== SAMPLE DEVICE ROW — dtype ${dtype} ===`);
    console.log(json);
  }
}

main().catch((e) => { console.error('FATAL:', e instanceof Error ? e.message : e); process.exit(1); });
