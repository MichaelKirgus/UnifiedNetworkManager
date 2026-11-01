/**
 * verify-dns-page.ts — read-only live check of the DNS page pipeline:
 *   1. Waits for the telemetry worker to ingest `dnsEntries` into
 *      device_dns_entries (polls GET /v1/dns until rows appear or timeout).
 *   2. Prints the grouped response (lowercase name → ips + device chips).
 *   3. Asserts the known GW_Ralf LCOS entries are present (read-only probe —
 *      never writes to production).
 *
 * Usage: npx tsx scripts/verify-dns-page.ts
 */
import { readFileSync } from 'node:fs';

const env = readFileSync(new URL('../.env', import.meta.url), 'utf8');
const m = env.match(/^UNM_API_TOKEN=(.+)$/m);
if (!m) throw new Error('UNM_API_TOKEN not found in .env');
const TOKEN = m[1].trim();

const BASE = process.env.UNM_BASE_URL ?? 'http://localhost:3000/v1';

async function fetchDns(): Promise<unknown> {
  const r = await fetch(`${BASE}/dns`, { headers: { Authorization: `Bearer ${TOKEN}` } });
  if (!r.ok) throw new Error(`GET /dns → ${r.status}: ${(await r.text()).slice(0, 300)}`);
  return r.json();
}

interface DnsRow { name: string; ips: string[]; devices: Array<{ deviceId: string; deviceName?: string | null; pluginName?: string | null; ips: string[] }> }

// Inventory polls are staggered across the (default) 15-min window — allow a
// full window + margin before giving up.
const TIMEOUT_MS = Number(process.env.VERIFY_TIMEOUT_MS ?? 960_000);

async function main(): Promise<void> {
  const started = Date.now();
  let rows: DnsRow[] = [];
  for (;;) {
    try {
      rows = (await fetchDns()) as DnsRow[];
      if (rows.length > 0) break;
    } catch (e) {
      console.error(`[wait] ${(e as Error).message}`);
    }
    if (Date.now() - started > TIMEOUT_MS) throw new Error('timed out waiting for dnsEntries rows');
    await new Promise((r) => setTimeout(r, 5_000));
  }

  console.log(`\nGET /v1/dns → ${rows.length} grouped row(s):\n`);
  for (const r of rows) {
    const chips = r.devices.map((d) => `${d.deviceName ?? d.deviceId}[${r.ips.join(',')}]`).join(', ');
    console.log(`  ${r.name.padEnd(24)} → ${r.ips.join(' ')}   (${chips})`);
  }

  // --- Known GW_Ralf LCOS entries (verified live via SSH + SNMP, read-only) -----
  const expected: Array<{ name: string; ip: string }> = [
    { name: 'kms03', ip: '10.120.1.22' },
    { name: 'kirgusbande', ip: '192.168.178.49' },
    { name: 'wlc-address', ip: '10.25.0.20' },
  ];
  let failures = 0;
  for (const e of expected) {
    const row = rows.find((r) => r.name === e.name);
    if (!row || !row.ips.includes(e.ip)) {
      console.error(`✗ missing: ${e.name} → ${e.ip}`);
      failures++;
    } else {
      console.log(`✓ present: ${e.name} → ${e.ip} (${row.devices.length} device(s))`);
    }
  }

  // Grouping contract: names must be lowercase.
  const badCase = rows.filter((r) => r.name !== r.name.toLowerCase());
  if (badCase.length > 0) { console.error(`✗ non-lowercase group keys: ${badCase.map((r) => r.name).join(', ')}`); failures++; }

  console.log(failures === 0 ? '\nDNS page pipeline OK.' : `\n${failures} check(s) FAILED.`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
