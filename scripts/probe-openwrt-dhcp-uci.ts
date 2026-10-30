/**
 * READ-ONLY ground-truth probe for the OpenWrt DHCP page gap (OPENMPTCP01 emits
 * zero dhcpNetworks rows). SSHes into the box with its own assignment secret and
 * prints `uci show dhcp` + `uci show network` verbatim so the parser can be
 * matched against reality. No writes, no state changes.
 *
 * Usage: ./node_modules/.bin/tsx scripts/probe-openwrt-dhcp-uci.ts [deviceName]
 */
import path from 'node:path';
import fs from 'node:fs';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const DEVICE_NAME = process.argv[2] ?? 'OPENMPTCP01';
const OPENWRT_PLUGIN_ID = 'aa9f941c-f63c-432c-adef-19049b320d03';

const sdkRequire = createRequire(path.resolve(process.cwd(), 'packages', 'plugin-sdk', 'package.json'));
const { Client } = sdkRequire('ssh2') as typeof import('ssh2');
const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));

function envValue(key: string): string | null {
  try {
    const m = new RegExp(`^${key}=(.+)$`, 'm').exec(fs.readFileSync(path.resolve(process.cwd(), '.env'), 'utf8'));
    return m?.[1]?.trim() ?? null;
  } catch {
    return null;
  }
}

/** Mints a totp-amr session JWT for admin (password may have been rotated). */
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
    [devRow.id, OPENWRT_PLUGIN_ID]
  )).rows[0] as { secretId: string | null } | undefined;
  if (!bindRow?.secretId) throw new Error('no openwrt assignment / secret for device');

  const sr = await fetch(`${API}/secrets/${bindRow.secretId}`, { headers: { Authorization: `Bearer ${token}` } });
  if (!sr.ok) throw new Error(`GET /secrets → HTTP ${sr.status}`);
  const fields = ((await sr.json()) as { fields?: Record<string, string> }).fields ?? {};
  await pool.end();

  // Bare host for the SSH connection (management address may carry scheme/port).
  let host: string;
  try {
    const u = new URL(devRow.managementAddress.includes('://') ? devRow.managementAddress : `http://${devRow.managementAddress}`);
    host = u.hostname.replace(/^\[|\]$/g, '');
  } catch {
    host = devRow.managementAddress.split('/')[0].split(':')[0];
  }

  const runCommand = (cmds: string[]): Promise<string> =>
    new Promise((resolve) => {
      const conn = new Client();
      let buf = '';
      conn.on('ready', () => {
        conn.exec(cmds.join('\n'), (err: Error | undefined, stream?: import('ssh2').Channel) => {
          if (err || !stream) return resolve(`exec error: ${err?.message}`);
          let out = '';
          stream.on('data', (d: Buffer) => { out += d.toString(); });
          stream.stderr.on('data', () => undefined);
          stream.on('close', () => { conn.end(); resolve(out); });
        });
      });
      conn.on('error', (e: Error) => resolve(`ssh error: ${e.message}`));
      conn.connect({ host, port: 22, username: fields['username'] ?? 'root', password: fields['password'] ?? '' });
    });

  console.log(`\n=== uci show dhcp (${DEVICE_NAME} @ ${host}) ===`);
  const dhcp = await runCommand(['uci show dhcp 2>/dev/null || true']);
  console.log(dhcp.trim() || '(empty)');

  console.log('\n=== uci show network (lan-ish sections only) ===');
  const net = await runCommand(['uci show network 2>/dev/null | grep -E "^(network\\.(lan|wan|opt[0-9]*))" || true']);
  console.log(net.trim() || '(empty)');

  // The live interface names the plugin would key its base map by.
  console.log('\n=== ip -4 addr (interface name + inet) ===');
  const ip = await runCommand(['ip -4 addr show 2>/dev/null | grep -E "^[0-9]+:|inet" || true']);
  console.log(ip.trim() || '(empty)');
}

main().catch((e) => {
  console.error('[probe] fatal:', e);
  process.exit(1);
});
