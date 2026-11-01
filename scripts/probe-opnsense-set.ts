/**
 * Ground-truth probe for the OPNsense Kea `set_reservation` payload shape on
 * REAL firmware. The live no-op edit (scripts/verify-dhcp-set.ts) came back as
 * HTTP 200 with body {"result":"failed"} — this script finds out why:
 *   1. GET /api/kea/dhcpv4/search_reservation → full row for the target MAC
 *      (what fields does a reservation row actually carry? what is `subnet`?)
 *   2. GET /api/kea/dhcpv4/get_reservation/{uuid} → verbatim response shape
 *   3. POST set_reservation with several payload variants (all no-op: same
 *      values as the existing reservation) and prints status + body for each,
 *      so we can see exactly which variant the firmware accepts.
 *
 * Usage: ./node_modules/.bin/tsx scripts/probe-opnsense-set.ts [deviceName] [mac]
 */
import path from 'node:path';
import fs from 'node:fs';
import https from 'node:https';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const DEVICE_NAME = process.argv[2] ?? 'OPNSENSE01';
const TARGET_MAC = (process.argv[3] ?? '00:18:dd:41:12:1d').toLowerCase();
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

type ApplianceResult = { status: number; body: unknown };

function applianceRequest(
  host: string,
  method: 'GET' | 'POST',
  urlPath: string,
  apiKey: string,
  apiSecret: string,
  jsonBody?: unknown
): Promise<ApplianceResult> {
  return new Promise((resolve) => {
    const payload = jsonBody === undefined ? null : JSON.stringify(jsonBody);
    const req = https.request(
      {
        host,
        port: 443,
        path: urlPath,
        method,
        rejectUnauthorized: false,
        headers: {
          Authorization: `Basic ${Buffer.from(`${apiKey}:${apiSecret}`).toString('base64')}`,
          // NOTE: Content-Type json on a bodyless GET makes the appliance reply
          // 400 "Invalid JSON syntax" — only send it with an actual payload.
          ...(payload ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) } : {}),
        },
        timeout: 15_000,
      },
      (res) => {
        let data = '';
        res.on('data', (d) => { data += d; });
        res.on('end', () => {
          try { resolve({ status: res.statusCode ?? 0, body: JSON.parse(data) }); } catch { resolve({ status: res.statusCode ?? 0, body: data.slice(0, 4000) }); }
        });
      }
    );
    req.on('error', (e) => resolve({ status: -1, body: `transport error: ${e.message}` }));
    req.on('timeout', () => { req.destroy(); resolve({ status: -1, body: 'timeout' }); });
    if (payload) req.write(payload);
    req.end();
  });
}

function show(label: string, r: ApplianceResult): void {
  console.log(`\n--- ${label} ---`);
  console.log(`HTTP ${r.status}:`, JSON.stringify(r.body));
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

  console.log(`\n=== OPNsense Kea set_reservation probe (${DEVICE_NAME} @ https://${host}, target MAC ${TARGET_MAC}) ===`);

  // 1. Find the reservation row for the target MAC.
  const search = await applianceRequest(host, 'GET', '/api/kea/dhcpv4/search_reservation?rowCount=200', apiKey, apiSecret);
  show('search_reservation (full)', search);

  let rows: Record<string, unknown>[] = [];
  if (search.status === 200 && typeof search.body === 'object' && search.body !== null) {
    const d = search.body as Record<string, unknown>;
    rows = Array.isArray(d['rows']) ? (d['rows'] as Record<string, unknown>[]) : [];
  }
  let target = rows.find((r) => typeof r['hw_address'] === 'string' && (r['hw_address'] as string).toLowerCase() === TARGET_MAC);
  if (!target) {
    // No reservation for the requested MAC on this appliance — fall back to
    // the first row so the probe works against any device.
    target = rows[0];
    console.log(`\n>>> no reservation for ${TARGET_MAC} on this device — falling back to first row`);
  }
  if (!target) throw new Error('no reservation rows in search_reservation (nothing to test)');
  console.log('\n>>> target row:', JSON.stringify(target, null, 2));

  const uuid = typeof target['uuid'] === 'string' ? (target['uuid'] as string) : '';
  if (!uuid) throw new Error('target row has no uuid');

  // 2. get_reservation verbatim shape.
  const one = await applianceRequest(host, 'GET', `/api/kea/dhcpv4/get_reservation/${encodeURIComponent(uuid)}`, apiKey, apiSecret);
  show(`get_reservation/${uuid} (verbatim)`, one);

  // Derive the values we'll echo back (no-op edit).
  let item: Record<string, unknown> = {};
  if (one.status === 200 && typeof one.body === 'object' && one.body !== null) {
    const d = one.body as Record<string, unknown>;
    const inner = (d['reservation'] ?? d['item']) as Record<string, unknown> | undefined;
    if (inner) item = { ...inner };
  }
  console.log('\n>>> parsed get_reservation item:', JSON.stringify(item, null, 2));

  // Subnet: get_reservation returns a relation map {uuid: {value, selected}} —
  // the selected entry's key is the subnet recordset uuid. Also accept plain
  // string/array shapes for other firmware versions.
  const subnetVal = item['subnet'];
  let subnetStr: string | null = null;
  if (typeof subnetVal === 'string' && subnetVal !== '') {
    subnetStr = subnetVal;
  } else if (Array.isArray(subnetVal) && typeof subnetVal[0] === 'string') {
    subnetStr = subnetVal[0];
  } else if (subnetVal && typeof subnetVal === 'object') {
    const map = subnetVal as Record<string, { value?: string; selected?: number | boolean }>;
    for (const [k, v] of Object.entries(map)) {
      if ((v?.selected === 1 || v?.selected === true) && typeof k === 'string' && k !== '') {
        subnetStr = k;
        break;
      }
    }
    // Fallback: the search_reservation row carries the plain uuid.
    if (!subnetStr && typeof target['subnet'] === 'string') subnetStr = target['subnet'];
  }

  // 3. Payload variants — all no-op edits of the same reservation.
  // The base controller reads POST[$post_field] with post_field='reservation'
  // (setBase("reservation", "reservations.reservation", $uuid)) — so the body
  // key must be `reservation`, NOT `item`.
  const hw = typeof item['hw_address'] === 'string' ? (item['hw_address'] as string) : TARGET_MAC;
  const ip = typeof item['ip_address'] === 'string' ? (item['ip_address'] as string) : '';
  const hostname = typeof item['hostname'] === 'string' && item['hostname'] !== '' ? (item['hostname'] as string) : undefined;

  type Variant = { name: string; body: unknown };
  const variants: Variant[] = [];

  // V1 — correct key, subnet as plain uuid string.
  const v1: Record<string, unknown> = { hw_address: hw, ip_address: ip };
  if (hostname) v1['hostname'] = hostname;
  if (subnetStr) v1['subnet'] = subnetStr;
  variants.push({ name: 'V1 {reservation:{hw_address,ip_address[,hostname],subnet:string}}', body: { reservation: v1 } });

  // V2 — correct key, subnet as uuid array (GUI relation format).
  if (subnetStr) {
    const v2: Record<string, unknown> = { hw_address: hw, ip_address: ip };
    if (hostname) v2['hostname'] = hostname;
    v2['subnet'] = [subnetStr];
    variants.push({ name: 'V2 subnet as array', body: { reservation: v2 } });
  }

  // V3 — correct key, minimal (no subnet at all) to see if it's truly required.
  const v3: Record<string, unknown> = { hw_address: hw, ip_address: ip };
  variants.push({ name: 'V3 no-subnet', body: { reservation: v3 } });

  for (const v of variants) {
    const r = await applianceRequest(host, 'POST', `/api/kea/dhcpv4/set_reservation/${encodeURIComponent(uuid)}`, apiKey, apiSecret, v.body);
    show(`set_reservation ${v.name} → body=${JSON.stringify(v.body)}`, r);
  }

  // 5. Confirm the reservation is unchanged after all attempts.
  const after = await applianceRequest(host, 'GET', `/api/kea/dhcpv4/get_reservation/${encodeURIComponent(uuid)}`, apiKey, apiSecret);
  show('get_reservation AFTER (unchanged check)', after);
}

main().catch((e) => { console.error(e); process.exit(1); });
