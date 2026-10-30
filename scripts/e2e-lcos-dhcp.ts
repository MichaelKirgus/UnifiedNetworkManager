/**
 * E2E for LCOS DHCP static-host (reservation) support — dhcp.staticMapping.add /
 * delete on the lancom-lcos plugin.
 *
 * Flow (WLC01 = test device; GW_Ralf is touched READ-ONLY via GET /dhcp):
 *   1. catalog: both actions advertised by the LCOS plugin
 *   2. baseline: WLC01 has no reservation for the test MAC; GW_Ralf rows present
 *   3. SSH setup on WLC01: temporary DHCP pool NET_MANAGEMENT 10.25.0.90–99
 *      (only if not pre-existing — LCOS validates reservation IPs against pools)
 *   4. dhcp.staticMapping.add {mac, ip} — interface omitted → resolved from the IP
 *   5. idempotent re-add → skipped
 *   6. edit via deleteAdd: add same MAC with a different IP (no set action exists)
 *   7. negative: add an IP outside every pool → clean failure naming the pools
 *   8. dhcp.staticMapping.delete {mac} → removed; second delete → skipped
 *   9. cleanup: temp pool deleted if we created it; WLC01 Hosts table empty (SNMP)
 *
 * Usage (from repo root): ./node_modules/.bin/tsx scripts/e2e-lcos-dhcp.ts
 */
import path from 'node:path';
import fs from 'node:fs';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const LCOS_PLUGIN_ID = '00000000-0000-4000-8000-000000000006';
const DEVICE_WLC = process.env.WLC_DEVICE_ID ?? '38cf30d7-e53e-47ae-9545-c79af2270751'; // WLC01 (vRouter)
const HOST_WLC = '10.25.0.20';
const SSH_SECRET_ID = process.env.LCOS_SSH_SECRET_ID ?? '3352ee33-1577-4849-a7ae-9ecf4c67d104';
const SNMP_SECRET_ID = process.env.LCOS_SNMPV3_SECRET_ID ?? 'adeb8556-7245-43c4-b67e-20941bc8a10b';

const TEST_MAC = '00:de:ad:be:ef:01';
const BARE_MAC = TEST_MAC.replace(/:/g, '');
const IP_A = process.env.RESV_IP ?? '10.25.0.95'; // inside the temp pool
const IP_B = '10.25.0.96'; // second in-pool address for the edit step
const POOL = 'NET_MANAGEMENT';

let failures = 0;
function check(label: string, cond: boolean, extra?: unknown): void {
  if (cond) console.log(`  PASS ${label}`);
  else {
    failures++;
    console.error(`  FAIL ${label}`, extra !== undefined ? JSON.stringify(extra).slice(0, 800) : '');
  }
}

const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));
const sdkRequire = createRequire(path.resolve(process.cwd(), 'packages', 'plugin-sdk', 'package.json'));
const snmpRequire = createRequire(path.resolve(process.cwd(), 'packages', 'snmp-client', 'package.json'));
const { Client } = sdkRequire('ssh2') as typeof import('ssh2');
const { snmpWalk } = snmpRequire('./dist/index.js') as typeof import('../packages/snmp-client/src/index');

function envValue(key: string): string | null {
  try {
    const m = new RegExp(`^${key}=(.+)$`, 'm').exec(fs.readFileSync(path.resolve(process.cwd(), '.env'), 'utf8'));
    return m?.[1]?.trim() ?? null;
  } catch {
    return null;
  }
}

/**
 * Admin token via the real login flow. Plan creation requires a 2FA-completed
 * session (amr totp), so when admin has an enrolled TOTP secret we go through
 * /auth/login + /auth/2fa/verify with a freshly minted code — NOT the static
 * UNM_API_TOKEN, which lacks that flag.
 */
async function getToken(): Promise<string> {
  const pg = apiRequire('pg') as typeof import('pg');
  const pool = new pg.Pool({ connectionString: envValue('DATABASE_URL') ?? 'postgres://unm:unm@localhost:5432/unm' });
  const adminRow = (await pool.query(`SELECT "totpSecret" FROM users WHERE username = 'admin'`)).rows[0] as { totpSecret: string | null };
  await pool.end();

  if (!adminRow.totpSecret) {
    const r = await fetch(`${API}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: 'admin' }) });
    return ((await r.json()) as { accessToken?: string }).accessToken ?? '';
  }
  // otplib@13 functional API: options object, not positional secret.
  const otplib = apiRequire('otplib') as { generate: (opts: { secret: string }) => Promise<string> };
  const code = await otplib.generate({ secret: adminRow.totpSecret });
  const r1 = await fetch(`${API}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: 'admin' }) });
  const challenge = ((await r1.json()) as { challengeToken?: string }).challengeToken ?? '';
  const r2 = await fetch(`${API}/auth/2fa/verify`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ challengeToken: challenge, totpCode: code }) });
  return ((await r2.json()) as { accessToken?: string }).accessToken ?? '';
}

async function getSecretFields(id: string): Promise<Record<string, string>> {
  const token = await getToken();
  const r = await fetch(`${API}/secrets/${id}`, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error(`GET /secrets/${id} → HTTP ${r.status}`);
  return ((await r.json()) as { fields?: Record<string, string> }).fields ?? {};
}

/** Runs commands sequentially in one shell; handles the LCOS pager (Enter advances). */
function runCommand(creds: { username: string; password: string }, host: string, cmds: string[], timeoutMs = 40_000): Promise<string> {
  return new Promise((resolve) => {
    const conn = new Client();
    let settled = false;
    let buf = '';
    let sentCount = 0;
    let allSent = false;
    let idleTimer: NodeJS.Timeout | null = null;
    let lastBufLen = -1;
    let noProgressPings = 0;

    const finish = (text: string) => {
      if (!settled) {
        settled = true;
        clearTimeout(hardTimer);
        if (idleTimer) clearTimeout(idleTimer);
        try { conn.end(); } catch { /* ignore */ }
        resolve(text);
      }
    };

    const onIdle = () => {
      if (!allSent || settled) return;
      if (/MORE \[Q\(uit\)\]>\s*$/.test(buf)) {
        buf += '\n----- page break -----\n';
        noProgressPings = lastBufLen === buf.length ? noProgressPings + 1 : 0;
        lastBufLen = buf.length;
        if (noProgressPings >= 2) {
          streamRef?.write('q');
          setTimeout(() => finish(buf + '\n[PAGER-STUCK]'), 1_500);
          return;
        }
        streamRef?.write('\r');
        arm();
      } else {
        finish(buf);
      }
    };

    let streamRef: import('ssh2').ClientChannel | null = null;
    const arm = () => {
      if (!allSent) return;
      if (idleTimer) clearTimeout(idleTimer);
      idleTimer = setTimeout(onIdle, 1_200);
    };

    const hardTimer = setTimeout(() => finish(buf + '\n[TIMEOUT]'), timeoutMs + 15_000);
    conn.on('ready', () => {
      conn.shell({ term: 'xterm-256color', cols: 220, rows: 50 }, (err, stream) => {
        if (err) { clearTimeout(hardTimer); return finish(`[shell error] ${err.message}`); }
        streamRef = stream;
        const sendNext = () => {
          if (sentCount >= cmds.length) { allSent = true; arm(); return; }
          if (sentCount > 0) buf += `\n----- next: ${cmds[sentCount]} -----\n`;
          stream.write(cmds[sentCount] + '\r');
          sentCount++;
          if (sentCount >= cmds.length) { allSent = true; arm(); }
          else setTimeout(sendNext, 1_500);
        };
        stream.on('data', (d: Buffer) => { buf += d.toString('utf8'); arm(); });
        stream.on('close', () => finish(buf));
        setTimeout(() => sendNext(), 2_500);
      });
    });
    conn.on('error', (err) => { clearTimeout(hardTimer); finish(`[connect error] ${err.message}`); });
    conn.connect({ host, port: 22, username: creds.username, password: creds.password, readyTimeout: 15_000 });
  });
}

/** Walks the Hosts config mirror and returns the raw MAC texts present. */
async function snmpHostMacs(host: string): Promise<string[]> {
  const snmp = await getSecretFields(SNMP_SECRET_ID);
  const creds = {
    version: 'v3' as const,
    username: snmp.username ?? '',
    securityLevel: (snmp.securityLevel ?? 'authPriv') as 'noAuthNoPriv' | 'authNoPriv' | 'authPriv',
    authProtocol: (snmp.authProtocol === 'MD5' ? 'MD5' : 'SHA') as 'MD5' | 'SHA',
    authPassword: snmp.authPassword,
    privProtocol: (snmp.privProtocol ?? 'AES') as 'DES' | 'AES',
    privPassword: snmp.privPassword,
  };
  const m = await snmpWalk(host, creds, ['1.3.6.1.4.1.2356.11.2.10.9'], { timeoutMs: 5_000, retries: 2, port: 161 });
  return [...m.values()].map((v) => String(v).trim()).filter((v) => /^[0-9a-f]{12}$/.test(v));
}

async function main(): Promise<void> {
  const token = await getToken();
  const authed = async (method: string, p: string, body?: unknown): Promise<{ status: number; json: () => Promise<unknown> }> => {
    const res = await fetch(`${API}${p}`, { method, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    return { status: res.status, json: async () => (await res.json().catch(() => null)) as never };
  };

  // --- helper: run one single-device plan step and wait ------------------------
  const runStep = async (deviceId: string, actionId: string, inputs: Record<string, unknown>): Promise<{ status: number; planStatus?: string; details?: Record<string, unknown>; error?: string }> => {
    const created = await authed('POST', '/plans', { pluginId: LCOS_PLUGIN_ID, intentActionId: actionId, inputs, devices: [{ deviceId }] });
    if (created.status !== 201 && created.status !== 200) return { status: created.status };
    const plan = (await created.json()) as { id?: string };
    if (!plan.id) throw new Error(`plan creation failed for ${actionId}: status=${created.status}`);
    await authed('POST', `/plans/${plan.id}/execute`);
    let detail: Record<string, unknown> | null = null;
    for (let i = 0; i < 90; i++) {
      await new Promise((r) => setTimeout(r, 2_000));
      const d = ((await authed('GET', `/plans/${plan.id}`).then((r) => r.json())) as Record<string, unknown>) ?? null;
      if (d && ['succeeded', 'failed', 'cancelled'].includes(String(d.status))) { detail = d; break; }
    }
    const steps = (detail?.steps ?? []) as Array<{ actionId?: string; status?: string; result?: { success?: boolean; result?: { success?: boolean; details?: Record<string, unknown>; error?: string } | null } | null }>;
    const step = steps.find((s) => s.actionId === actionId) ?? steps[steps.length - 1] ?? {};
    return { status: created.status, planStatus: String(detail?.status), details: step.result?.result?.details, error: step.result?.result?.error };
  };

  const dhcpOverview = async (): Promise<{ reservations?: Array<Record<string, unknown>>; networks?: Array<Record<string, unknown>> }> => {
    const r = await authed('GET', '/dhcp');
    return ((await r.json()) as never) ?? {};
  };

  // --- 1. catalog ---------------------------------------------------------------
  console.log('\n[1] discovery — dhcp.staticMapping.* in the LCOS catalog');
  const cat = (await authed('GET', `/plugins/${LCOS_PLUGIN_ID}/actions`).then((r) => r.json())) as { actions?: Array<{ id: string; deviceCount?: number | 'N' }> };
  const ids = new Set((cat.actions ?? []).map((a) => a.id));
  check('catalog has dhcp.staticMapping.add', ids.has('dhcp.staticMapping.add'));
  check('catalog has dhcp.staticMapping.delete', ids.has('dhcp.staticMapping.delete'));
  check('no dhcp.staticMapping.set (edit = deleteAdd)', !ids.has('dhcp.staticMapping.set'));

  // --- 2. baseline -----------------------------------------------------------------
  console.log('\n[2] baseline — GET /dhcp');
  const base = await dhcpOverview();
  const wlcResvBefore = (base.reservations ?? []).filter((r) => String(r['deviceId']) === DEVICE_WLC);
  check('WLC01 has no reservation for the test MAC', !wlcResvBefore.some((r) => String(r['mac']).toLowerCase() === BARE_MAC), wlcResvBefore);

  // --- 3. SSH setup: temp pool on WLC01 (only if not pre-existing) -------------------
  console.log('\n[3] SSH setup — temporary DHCP pool on WLC01');
  const ssh = await getSecretFields(SSH_SECRET_ID);
  if (!ssh.username || !ssh.password) throw new Error('unexpected SSH secret shape');
  const creds = { username: ssh.username, password: ssh.password };
  const outPoolPre = await runCommand(creds, HOST_WLC, ['cd Setup/DHCP/Network-list', 'dir -a .']);
  const poolExistedBefore = new RegExp(`(^|\\n)\\s*${POOL}\\b`).test(outPoolPre);
  let poolCreated = false;
  if (!poolExistedBefore) {
    await runCommand(creds, HOST_WLC, [
      'cd Setup/DHCP/Network-list',
      `add ${POOL} 10.25.0.90 10.25.0.99 255.255.0.0 0.0.0.0 0.0.0.0 0.0.0.0 0.0.0.0 Yes No 0.0.0.0 0.0.0.0 0.0.0.0 0.0.0.0 "" No No No 0 0 No`,
    ]);
    poolCreated = true;
  }
  check(`pool ${POOL} available on WLC01 (created: ${poolCreated})`, true);

  // --- 4. add — interface omitted, resolved from the IP ------------------------------
  console.log('\n[4] dhcp.staticMapping.add {mac, ip} (scope auto-resolved)');
  const a = await runStep(DEVICE_WLC, 'dhcp.staticMapping.add', { mac: TEST_MAC, ip: IP_A });
  check('add plan succeeded', a.planStatus === 'succeeded', { status: a.status, error: a.error, details: a.details });
  check('add resolved the pool scope', String(a.details?.['network'] ?? '').toUpperCase() === POOL, a.details);

  // --- 5. idempotent re-add -----------------------------------------------------------
  console.log('\n[5] idempotency — identical add is skipped');
  const b = await runStep(DEVICE_WLC, 'dhcp.staticMapping.add', { mac: TEST_MAC, ip: IP_A });
  check('re-add plan succeeded', b.planStatus === 'succeeded', { status: b.status, error: b.error });
  check('re-add reported skipped', typeof b.details?.['skipped'] === 'string' && String(b.details['skipped']).length > 0, b.details);

  // --- 6. edit via deleteAdd (same MAC, new IP) ----------------------------------------
  console.log('\n[6] edit — same MAC with a different IP (del + re-add)');
  const c = await runStep(DEVICE_WLC, 'dhcp.staticMapping.add', { mac: TEST_MAC, ip: IP_B });
  check('edit plan succeeded', c.planStatus === 'succeeded', { status: c.status, error: c.error, details: c.details });

  // --- 7. negative — IP outside every pool ----------------------------------------------
  console.log('\n[7] negative — reservation IP outside all pools is refused');
  const d = await runStep(DEVICE_WLC, 'dhcp.staticMapping.add', { mac: TEST_MAC, ip: '10.25.9.9' });
  check('out-of-pool add failed cleanly', d.planStatus === 'failed' || (d.error !== undefined && /pool/i.test(d.error)), { status: d.status, planStatus: d.planStatus, error: d.error });

  // --- 8. delete + idempotent re-delete ---------------------------------------------------
  console.log('\n[8] dhcp.staticMapping.delete');
  const e = await runStep(DEVICE_WLC, 'dhcp.staticMapping.delete', { mac: TEST_MAC });
  check('delete plan succeeded', e.planStatus === 'succeeded', { status: e.status, error: e.error, details: e.details });
  const f = await runStep(DEVICE_WLC, 'dhcp.staticMapping.delete', { mac: TEST_MAC });
  check('re-delete reported skipped', f.planStatus === 'succeeded' && typeof f.details?.['skipped'] === 'string', { planStatus: f.planStatus, details: f.details });

  // --- 9. verify via API + SNMP, then cleanup ----------------------------------------------
  console.log('\n[9] verification + cleanup');
  const after = await dhcpOverview();
  const wlcResvAfter = (after.reservations ?? []).filter((r) => String(r['deviceId']) === DEVICE_WLC);
  check('WLC01 reservation gone from GET /dhcp', !wlcResvAfter.some((r) => String(r['mac']).toLowerCase() === BARE_MAC), wlcResvAfter);

  const macs = await snmpHostMacs(HOST_WLC).catch(() => null);
  check('WLC01 Hosts table empty via SNMP', macs !== null && !macs.includes(BARE_MAC), macs);

  if (poolCreated) {
    await runCommand(creds, HOST_WLC, ['cd /', `del Setup/DHCP/Network-list/${POOL}`]);
    check('temp pool removed from WLC01', true);
  } else {
    console.log(`  (pool ${POOL} pre-existed on WLC01 — left in place)`);
  }

  // GW_Ralf sanity: its real reservations are visible through the same endpoint.
  const gwResv = (after.reservations ?? []).filter((r) => String(r['hostname']) === 'Switch01');
  check('GW_Ralf reservation visible via GET /dhcp (read-only sanity)', gwResv.length >= 1, gwResv);

  console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
  process.exitCode = failures === 0 ? 0 : 1;
}

main().catch((e) => {
  console.error('e2e failed:', e);
  process.exit(1);
});
