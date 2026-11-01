/**
 * probe-opnsense-dns.ts — READ-ONLY live probe of OPNSENSE01's DNS backends.
 *
 * Answers the question "why does GET /v1/dns show no OPNsense entries?":
 *   1. Fetches the device's apiKey/apiSecret via the API (GET /secrets/:id,
 *      decrypted for admins — never printed in full).
 *   2. Queries the appliance DIRECTLY:
 *        - GET /api/unbound/overview/is_enabled     (backend detection)
 *        - GET /api/unbound/settings/search_host_override
 *        - GET /api/dnsmasq/settings/search_host
 *   3. Prints what each backend actually holds, so we can tell "unbound has no
 *      host overrides" apart from "detection picked the wrong backend".
 *
 * Usage (from the repo root): ./node_modules/.bin/tsx scripts/probe-opnsense-dns.ts
 */
import https from 'node:https';
import fs from 'node:fs';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const DEVICE_ID = process.env.OPN_DEVICE_ID ?? '2eb40794-fd9c-4139-a381-184197b4f97a';

async function main(): Promise<void> {
  const env = fs.readFileSync(new URL('../.env', import.meta.url), 'utf8');
  const m = env.match(/^UNM_API_TOKEN=(.+)$/m);
  if (!m) throw new Error('UNM_API_TOKEN not found in .env');
  const TOKEN = m[1].trim();

  async function apiGet(p: string): Promise<unknown> {
    const r = await fetch(`${API}${p}`, { headers: { Authorization: `Bearer ${TOKEN}` } });
    if (!r.ok) throw new Error(`GET ${p} → ${r.status}: ${(await r.text()).slice(0, 300)}`);
    return r.json();
  }

  // No single-device GET route — filter the list.
  const devices = (await apiGet('/devices')) as Array<{ id: string; managementAddress?: string }>;
  const host = devices.find((d) => d.id === DEVICE_ID)?.managementAddress ?? '';
  if (!host) throw new Error('device has no managementAddress');
  console.log(`OPNSENSE01 → ${host}`);

  // The opnsense assignment's primary secret (apiKey type).
  const dpRow = (await apiGet(`/devices/${DEVICE_ID}/plugins`)) as unknown;
  let secretId: string | null = null;
  {
    const list = Array.isArray(dpRow) ? dpRow : ((dpRow as { plugins?: unknown[] })?.plugins ?? []);
    for (const p of list as Array<Record<string, unknown>>) {
      if (p['pluginId'] === 'b0e6c8a2-4f1e-4a3d-9c7b-1a2b3c4d5e6f') {
        secretId = typeof p['secretId'] === 'string' ? p['secretId'] : null;
      }
    }
  }
  if (!secretId) throw new Error('no opnsense assignment with a bound secret found');

  const sec = (await apiGet(`/secrets/${secretId}`)) as { fields?: Record<string, string> };
  const apiKey = sec.fields?.['apiKey'] ?? '';
  const apiSecret = sec.fields?.['apiSecret'] ?? '';
  if (!apiKey) throw new Error('secret has no apiKey field');
  console.log(`credentials: apiKey=${apiKey.slice(0, 4)}… (${apiKey.length} chars)`);

  // --- Direct appliance queries (self-signed TLS accepted — read-only GETs) -----
  function opnGet(path: string): Promise<{ status: number; body: unknown }> {
    const url = new URL(`https://${host}${path}`);
    return new Promise((resolve, reject) => {
      const req = https.request(
        {
          host: url.hostname,
          port: url.port || 443,
          path: url.pathname + url.search,
          method: 'GET',
          auth: `${apiKey}:${apiSecret}`,
          rejectUnauthorized: false,
          timeout: 15_000,
        },
        (res) => {
          let data = '';
          res.on('data', (c) => (data += c));
          res.on('end', () => {
            try { resolve({ status: res.statusCode ?? 0, body: JSON.parse(data) }); }
            catch { resolve({ status: res.statusCode ?? 0, body: data.slice(0, 500) }); }
          });
        },
      );
      req.on('error', reject);
      req.on('timeout', () => req.destroy(new Error('timeout')));
      req.end();
    });
  }

  const enabled = await opnGet('/api/unbound/overview/is_enabled').catch((e) => ({ status: -1, body: String(e) }));
  console.log(`\nunbound is_enabled → ${JSON.stringify(enabled.body).slice(0, 200)}`);

  const unboundRows = await opnGet('/api/unbound/settings/search_host_override').catch((e) => ({ status: -1, body: String(e) }));
  {
    const d = unboundRows.body as { rows?: Array<Record<string, unknown>>; total?: number };
    console.log(`\nunbound search_host_override → HTTP ${unboundRows.status}, total=${d?.total ?? '?'} row(s):`);
    if (Array.isArray(d?.rows) && d.rows.length > 0) {
      console.log('   RAW first row:', JSON.stringify(d.rows[0]));
      console.log('   RAW second row:', JSON.stringify(d.rows[1] ?? null));
    }
    for (const r of (d?.rows ?? []).slice(0, 8)) console.log(`   ${String(r['hostname'] ?? '').padEnd(28)} → ${r['address']} (${r['type'] ?? ''})`);
  }

  const dnsmasqRows = await opnGet('/api/dnsmasq/settings/search_host').catch((e) => ({ status: -1, body: String(e) }));
  {
    const d = dnsmasqRows.body as { rows?: Array<Record<string, unknown>>; total?: number };
    console.log(`\ndnsmasq search_host → HTTP ${dnsmasqRows.status}, total=${d?.total ?? '?'} row(s):`);
    for (const r of d?.rows ?? []) console.log(`   ${String(r['name'] ?? '').padEnd(28)} → ${r['ip']} (${r['type'] ?? ''})`);
  }
}

main().catch((e) => { console.error(e); process.exit(1); });
