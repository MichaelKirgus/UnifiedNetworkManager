/**
 * READ-ONLY ground-truth probe for OPNsense DHCP config emission.
 * Decrypts the device's API key via GET /secrets/:id, then hits the raw
 * backend endpoints the plugin uses and prints their shapes verbatim:
 *   - /api/kea/service/status        (backend auto-detect)
 *   - /api/kea/dhcpv4/get            (Kea full config — subnets/pools shape)
 *   - /api/kea/dhcpv4/search_reservation
 *   - /api/dnsmasq/settings/search_range
 *   - /api/services/dhcp/staticmap/search
 * No writes, no state changes.
 *
 * Usage: ./node_modules/.bin/tsx scripts/probe-opnsense-dhcp.ts [deviceName]
 */
import path from 'node:path';
import fs from 'node:fs';
import https from 'node:https';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const DEVICE_NAME = process.argv[2] ?? 'OPNSENSE01';
const OPNSENSE_PLUGIN_ID = 'b0e6c8a2-4f1e-4a3d-9c7b-1a2b3c4d5e6f';

const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));

function envValue(key: string): string | null {
  try {
    const m = new RegExp(`^${key}=(.+)$`, 'm').exec(fs.readFileSync(path.resolve(process.cwd(), '.env'), 'utf8'));
    return m?.[1]?.trim() ?? null;
  } catch {
    return null;
  }
}

async function mintAdminToken(pool: import('pg').Pool): Promise<string | null> {
  const jwt = apiRequire('jsonwebtoken') as { sign: (p: Record<string, unknown>, s: string, o?: { expiresIn?: number }) => string };
  const secret = envValue('JWT_SECRET') ?? 'dev-secret';
  const row = (await pool.query(`SELECT id, username, roles, permissions FROM users WHERE username = 'admin'`)).rows[0] as
    | { id: string; username: string; roles: unknown; permissions: unknown }
    | undefined;
  if (!row) return null;
  const parseArr = (v: unknown): string[] => {
    if (Array.isArray(v)) return v.filter((x): x is string => typeof x === 'string');
    if (typeof v !== 'string') return [];
    try {
      const p = JSON.parse(v);
      return Array.isArray(p) ? p.filter((x: unknown): x is string => typeof x === 'string') : [];
    } catch {
      return [];
    }
  };
  return jwt.sign({ sub: row.id, username: row.username, roles: parseArr(row.roles), permissions: parseArr(row.permissions), amr: ['totp'] }, secret, { expiresIn: 3600 });
}

/** One GET against the appliance (self-signed TLS accepted). */
function getAppliance(host: string, urlPath: string, apiKey: string, apiSecret: string): Promise<{ status: number; body: unknown }> {
  return new Promise((resolve) => {
    const req = https.get(
      { host, port: 443, path: urlPath, rejectUnauthorized: false, headers: { Authorization: `Basic ${Buffer.from(`${apiKey}:${apiSecret}`).toString('base64')}` }, timeout: 15_000 },
      (res) => {
        let data = '';
        res.on('data', (d) => { data += d; });
        res.on('end', () => {
          try { resolve({ status: res.statusCode ?? 0, body: JSON.parse(data) }); } catch { resolve({ status: res.statusCode ?? 0, body: data.slice(0, 2000) }); }
        });
      }
    );
    req.on('error', (e) => resolve({ status: -1, body: `transport error: ${e.message}` }));
    req.on('timeout', () => { req.destroy(); resolve({ status: -1, body: 'timeout' }); });
  });
}

async function main(): Promise<void> {
  const { Pool } = apiRequire('pg');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm' });
  const token = await mintAdminToken(pool);
  if (!token) throw new Error('could not mint admin token');

  const devRow = (await pool.query(`SELECT id, "managementAddress" FROM devices WHERE name = $1`, [DEVICE_NAME])).rows[0] as
    | { id: string; managementAddress: string }
    | undefined;
  if (!devRow) throw new Error(`device ${DEVICE_NAME} not found`);

  const bindRow = (await pool.query(
    `SELECT "secretId" FROM device_plugins WHERE "deviceId" = $1 AND "pluginId" = $2`,
    [devRow.id, OPNSENSE_PLUGIN_ID]
  )).rows[0] as { secretId: string | null } | undefined;
  if (!bindRow?.secretId) throw new Error('no opnsense assignment / secret for device');

  const sr = await fetch(`${API}/secrets/${bindRow.secretId}`, { headers: { Authorization: `Bearer ${token}` } });
  if (!sr.ok) throw new Error(`GET /secrets → HTTP ${sr.status}`);
  const fields = ((await sr.json()) as { fields?: Record<string, string> }).fields ?? {};
  await pool.end();

  let host: string;
  try {
    const u = new URL(devRow.managementAddress.includes('://') ? devRow.managementAddress : `http://${devRow.managementAddress}`);
    host = u.hostname.replace(/^\[|\]$/g, '');
  } catch {
    host = devRow.managementAddress.split('/')[0].split(':')[0];
  }

  const apiKey = fields['apiKey'] ?? '';
  const apiSecret = fields['apiSecret'] ?? '';
  if (!apiKey || !apiSecret) throw new Error(`secret has no apiKey/apiSecret (keys: ${Object.keys(fields).join(',')})`);

  console.log(`\n=== OPNsense DHCP probe (${DEVICE_NAME} @ https://${host}) ===`);

  const status = await getAppliance(host, '/api/kea/service/status', apiKey, apiSecret);
  console.log('\n--- /api/kea/service/status ---');
  console.log(`HTTP ${status.status}:`, JSON.stringify(status.body));

  const keaCfg = await getAppliance(host, '/api/kea/dhcpv4/get', apiKey, apiSecret);
  console.log('\n--- /api/kea/dhcpv4/get (first 6000 chars) ---');
  console.log(`HTTP ${keaCfg.status}:`, JSON.stringify(keaCfg.body).slice(0, 6000));

  const keaSubnets = await getAppliance(host, '/api/kea/dhcpv4/search_subnet', apiKey, apiSecret);
  console.log('\n--- /api/kea/dhcpv4/search_subnet ---');
  console.log(`HTTP ${keaSubnets.status}:`, JSON.stringify(keaSubnets.body).slice(0, 6000));

  const keaRes = await getAppliance(host, '/api/kea/dhcpv4/search_reservation', apiKey, apiSecret);
  console.log('\n--- /api/kea/dhcpv4/search_reservation ---');
  console.log(`HTTP ${keaRes.status}:`, JSON.stringify(keaRes.body).slice(0, 2000));

  const dnsmasqRange = await getAppliance(host, '/api/dnsmasq/settings/search_range', apiKey, apiSecret);
  console.log('\n--- /api/dnsmasq/settings/search_range ---');
  console.log(`HTTP ${dnsmasqRange.status}:`, JSON.stringify(dnsmasqRange.body).slice(0, 2000));

  const staticmap = await getAppliance(host, '/api/services/dhcp/staticmap/search', apiKey, apiSecret);
  console.log('\n--- /api/services/dhcp/staticmap/search ---');
  console.log(`HTTP ${staticmap.status}:`, JSON.stringify(staticmap.body).slice(0, 2000));

  // Which DHCP service is actually running? (informational)
  const services = await getAppliance(host, '/api/core/service/search', apiKey, apiSecret);
  if (keaCfg.status === 200 && keaRes.status !== 200) {
    console.log('\n--- /api/core/service/search (dhcp-ish rows) ---');
    const s = JSON.stringify(services.body).slice(0, 3000);
    console.log(`HTTP ${services.status}:`, s);
  }
}

main().catch((e) => {
  console.error('[probe] fatal:', e);
  process.exit(1);
});
