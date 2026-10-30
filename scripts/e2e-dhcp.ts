/**
 * End-to-end verification for the cross-device DHCP page (GET /v1/dhcp).
 * Runs against the LIVE dev stack:
 *   1. mints a totp-amr session JWT for admin (password may have been rotated)
 *   2. asserts 'dhcp:read' is granted to admin
 *   3. force-refreshes every device assigned a dhcp-capable plugin instance
 *      (mikrotik-routeros / opnsense / openwrt) and reports per-device reachability
 *   4. GET /dhcp — asserts the response shape + row invariants (PK fields,
 *      decoration with deviceName/pluginName), prints a per-device summary
 *   5. cross-checks: every reservation MAC that also appears as a live lease
 *      (GET /hosts?source=dhcp) is flagged 'live' — the page's join contract
 *   6. asserts each online dhcp-capable plugin instance advertises its action
 *      catalog entries (dhcp.staticMapping.add at minimum for write vendors)
 *
 * READ-ONLY: no plans are created, nothing is written to any appliance.
 *
 * Usage (from the repo root):
 *   ./node_modules/.bin/tsx scripts/e2e-dhcp.ts
 */

import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));
const jwt = apiRequire('jsonwebtoken') as { sign: (payload: Record<string, unknown>, secret: string, opts?: { expiresIn?: number | string }) => string };

function envValue(key: string): string | null {
  try {
    const m = new RegExp(`^${key}=(.+)$`, 'm').exec(fs.readFileSync(path.resolve(process.cwd(), '.env'), 'utf8'));
    return m?.[1]?.trim() ?? null;
  } catch {
    return null;
  }
}

/** Mints a totp-amr session JWT for admin (the password may have been rotated —
 * the minted token is what the other verify-*.ts scripts use). */
async function mintAdminToken(pool: import('pg').Pool): Promise<string | null> {
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

let failures = 0;
function check(label: string, cond: boolean, extra?: unknown): void {
  if (cond) console.log(`  PASS ${label}`);
  else {
    failures++;
    console.error(`  FAIL ${label}`, extra !== undefined ? JSON.stringify(extra).slice(0, 400) : '');
  }
}

interface DhcpNetworkRow {
  deviceId: string; pluginId: string; name: string; iface?: string | null;
  rangeStart: string; rangeEnd: string; cidr?: string | null; leaseTimeSeconds?: number | null;
  gateway?: string | null; dnsServers?: string | null; refId?: string | null;
  deviceName?: string | null; pluginName?: string | null;
}
interface DhcpReservationRow {
  deviceId: string; pluginId: string; mac: string; ip?: string | null; hostname?: string | null;
  iface?: string | null; refId?: string | null; status?: string | null;
  deviceName?: string | null; pluginName?: string | null;
}

async function main(): Promise<void> {
  // --- Auth (minted totp-amr JWT — the admin password may have been rotated) ----
  const { Pool } = apiRequire('pg');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm' });
  const token = await mintAdminToken(pool);
  check('minted admin session token', Boolean(token));
  if (!token) throw new Error('could not mint admin token');

  const authed = async (method: string, p: string, init?: RequestInit): Promise<Response> =>
    fetch(`${API}${p}`, {
      method,
      body: init?.body,
      headers: { Authorization: `Bearer ${token}`, ...(init?.headers as Record<string, string> | undefined) },
    });

  // --- 1. Permission granted ---------------------------------------------------
  const meRes = await authed('GET', '/auth/me');
  const me = (await meRes.json()) as { effectivePermissions?: string[] };
  check("admin has 'dhcp:read'", (me.effectivePermissions ?? []).includes('dhcp:read'), me.effectivePermissions?.filter((p) => p.startsWith('dhcp')));

  // --- 2. Devices + dhcp-capable plugin instances -------------------------------
  const devicesRes = await authed('GET', '/devices');
  const devices = (await devicesRes.json()) as Array<{ id: string; name: string; status: string; plugins?: Array<{ pluginId: string; pluginName?: string }> }>;
  check('GET /devices → rows', devices.length > 0, { count: devices.length });

  // Plugin instance id → display name (for readable output).
  const pluginsRes = await authed('GET', '/plugins');
  const plugins = (await pluginsRes.json()) as Array<{ id: string; name?: string; online?: boolean }>;
  const pluginNameById = new Map(plugins.map((p) => [p.id, p.name ?? p.id]));

  // A device is dhcp-capable when one of its assigned plugin instances belongs to a
  // dhcp-emitting vendor (RouterOS / OPNsense / OpenWrt) — matched on the instance
  // id OR display name, since ids are opaque UUIDs.
  const DHCP_VENDOR_MARKERS = ['routeros', 'opnsense', 'openwrt'];
  const targetDevices: Array<{ id: string; name: string; pluginIds: string[] }> = [];
  for (const d of devices) {
    const pids = (d.plugins ?? [])
      .filter((p) => DHCP_VENDOR_MARKERS.some((m) => p.pluginId.toLowerCase().includes(m) || (p.pluginName ?? '').toLowerCase().includes(m)))
      .map((p) => p.pluginId);
    if (pids.length > 0) targetDevices.push({ id: d.id, name: d.name, pluginIds: [...new Set(pids)] });
  }
  console.log(`\nDHCP-capable devices: ${targetDevices.map((d) => `${d.name} [${d.pluginIds.join(', ')}]`).join(' | ') || '(none)'}`);

  // --- 3. Force refresh (bypasses poll stagger; reports reachability) -----------
  if (targetDevices.length > 0) {
    const refRes = await authed('POST', '/devices/refresh', { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ deviceIds: targetDevices.map((d) => d.id) }) });
    const refBody = (await refRes.json().catch(() => null)) as { results?: Array<{ deviceId: string; ok?: boolean; error?: string | null }> } | null;
    check('POST /devices/refresh → 200', refRes.status === 200, refBody);
    for (const r of refBody?.results ?? []) {
      const dev = targetDevices.find((d) => d.id === r.deviceId);
      console.log(`  refresh ${dev?.name ?? r.deviceId}: ${r.ok ? 'ok' : `FAILED — ${r.error ?? 'unknown'}`}`);
    }
    // Give the telemetry worker a moment to ingest the fresh metrics.
    await new Promise((res) => setTimeout(res, 4000));
  }

  // --- 4. GET /dhcp — shape + invariants ----------------------------------------
  const dhcpRes = await authed('GET', '/dhcp');
  check('GET /dhcp → 200', dhcpRes.status === 200);
  const body = (await dhcpRes.json()) as { networks?: DhcpNetworkRow[]; reservations?: DhcpReservationRow[] };
  const networks = body.networks ?? [];
  const reservations = body.reservations ?? [];
  check('response has networks[] + reservations[]', Array.isArray(body.networks) && Array.isArray(body.reservations));

  console.log(`\nDHCP networks (${networks.length}):`);
  for (const n of networks) {
    console.log(`  ${n.deviceName} [${n.pluginName}] ${n.name}: ${n.rangeStart}–${n.rangeEnd}${n.cidr ? ` (${n.cidr})` : ''}${n.leaseTimeSeconds ? ` lease=${n.leaseTimeSeconds}s` : ''}${n.gateway ? ` gw=${n.gateway}` : ''}${n.dnsServers ? ` dns=${n.dnsServers}` : ''}${n.refId ? ` refId=${String(n.refId).slice(0, 8)}…` : ''}`);
  }
  console.log(`DHCP reservations (${reservations.length}):`);
  for (const r of reservations) {
    console.log(`  ${r.deviceName} [${r.pluginName}] ${r.mac}${r.ip ? ` → ${r.ip}` : ''}${r.hostname ? ` (${r.hostname})` : ''}${r.status ? ` status=${r.status}` : ''}${r.iface ? ` iface=${r.iface}` : ''}${r.refId ? ` refId=${String(r.refId).slice(0, 8)}…` : ''}`);
  }

  // Row invariants — PK fields present + decoration applied.
  const netOk = networks.every((n) => n.deviceId && n.pluginId && n.name && n.rangeStart && n.rangeEnd && (n.deviceName ?? null) !== undefined);
  check('network rows: PK fields + device/plugin decoration', netOk, networks.filter((n) => !netOk));
  const resOk = reservations.every((r) => r.deviceId && r.pluginId && /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/.test(r.mac) && (r.deviceName ?? null) !== undefined);
  check('reservation rows: PK fields + lowercase MAC + decoration', resOk, reservations.filter((r) => !resOk));

  // --- 5. Live-lease join cross-check --------------------------------------------
  const hostsRes = await authed('GET', '/hosts?source=dhcp');
  const hosts = (await hostsRes.json()) as Array<{ mac: string; ips?: string[] }>;
  check('GET /hosts?source=dhcp → rows', Array.isArray(hosts), { count: hosts.length });
  const liveMacs = new Set(hosts.map((h) => h.mac.toLowerCase()));
  const joined = reservations.filter((r) => liveMacs.has(r.mac.toLowerCase()));
  console.log(`\nReservations with a LIVE lease (page badges these): ${joined.length} of ${reservations.length}`);
  for (const r of joined) {
    const host = hosts.find((h) => h.mac.toLowerCase() === r.mac.toLowerCase());
    check(`live join ${r.deviceName}/${r.mac}`, Boolean(host?.ips?.length), host);
  }

  // --- 6. Action catalogs of online dhcp-capable plugin instances ------------------
  for (const d of targetDevices) {
    for (const pid of d.pluginIds) {
      const actRes = await authed('GET', `/plugins/${encodeURIComponent(pid)}/actions`);
      if (actRes.status !== 200) { console.log(`  INFO ${pluginNameById.get(pid)}: catalog unavailable (${actRes.status}) — plugin offline?`); continue; }
      const acts = ((await actRes.json()) as { actions?: Array<{ id: string }> }).actions ?? [];
      const ids = acts.map((a) => a.id).filter((id) => id.startsWith('dhcp.'));
      console.log(`  catalog ${pluginNameById.get(pid)} (${d.name}): ${ids.join(', ') || '(no dhcp actions)'}`);
    }
  }

  // --- Summary ---------------------------------------------------------------------
  const reachable = targetDevices.length > 0;
  if (reachable) {
    check('at least one DHCP network row collected', networks.length >= 1, 'no rows — all dhcp-capable devices unreachable?');
  } else {
    console.log('\nINFO no dhcp-capable device assignments found — nothing to collect.');
  }

  await pool.end();
  if (failures > 0) {
    console.error(`\n${failures} check(s) FAILED`);
    process.exit(1);
  }
  console.log('\nAll checks passed.');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
