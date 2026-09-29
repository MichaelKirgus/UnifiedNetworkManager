/**
 * PROBE (WLC01 test device only): can SNMP SET create a row in the LCOS
 * TCP-IP Network-list table (lcsSetup family 1.2.7.30)?
 *
 *   1. GET 1.2.7.30.<row>.<col> for existing rows → is the table SNMP-readable?
 *   2. SET a NEW row's col .1 (Network-name) to "UNM_PROBE_NET" → does the
 *      agent create the row on write (like lcsSetupNtpRqAddressTable did)?
 *   3. If created: fill col .2/.3 (IP/mask), verify by re-read, then DELETE via
 *      CLI `del Setup/TCP-IP/Network-list/UNM_PROBE_NET` and confirm gone.
 *
 * This decides the write transport for the canonical network.create intent:
 * SNMP SET (preferred per fleet rule) vs CLI table commands.
 *
 * Usage: ./node_modules/.bin/tsx scripts/probe-lcos-netlist-set.ts [host]
 */
import path from 'node:path';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const HOST = process.argv[2] ?? '10.25.0.20'; // WLC01 — TEST device only
const SNMP_SECRET_ID = process.env.LCOS_SNMPV3_SECRET_ID ?? 'adeb8556-7245-43c4-b67e-20941bc8a10b';
const SSH_SECRET_ID = process.env.LCOS_WEB_SECRET_ID ?? '3352ee33-1577-4849-a7ae-9ecf4c67d104';

// lcsSetupTcpIpNetworkListTable (LCF family 1.2.7.30):
//   col .1 Network-name, .2 IP-Address, .3 IP-Netmask, .4 VLAN-ID, .5 Interface,
//   .6 Src-check, .7 Type, .8 Rtg-tag, .9 Comment (per readscript tab header).
const NETLIST_BASE = '1.3.6.1.4.1.2356.11.1.2.7.30';

const sdkRequire = createRequire(path.resolve(process.cwd(), 'packages', 'plugin-sdk', 'package.json'));
const { Client } = sdkRequire('ssh2') as typeof import('ssh2');
const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));
const snmpRequire = createRequire(path.resolve(process.cwd(), 'packages', 'snmp-client', 'package.json'));
const { snmpGet, snmpSet } = snmpRequire('./dist/index.js') as typeof import('../packages/snmp-client/src/index');

async function getToken(): Promise<string> {
  const { Pool } = apiRequire('pg');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm' });
  const adminRow = (await pool.query(`SELECT "totpSecret" FROM users WHERE username='admin'`)).rows[0] as { totpSecret: string | null };
  let token: string | null = null;
  if (!adminRow.totpSecret) {
    const r = await fetch(`${API}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: 'admin' }) });
    token = ((await r.json()) as { accessToken?: string }).accessToken ?? null;
  } else {
    const { authenticator } = apiRequire('otplib');
    const code = authenticator.generate(adminRow.totpSecret);
    const r1 = await fetch(`${API}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: 'admin' }) });
    const challenge = ((await r1.json()) as { challengeToken?: string }).challengeToken ?? '';
    const r2 = await fetch(`${API}/auth/2fa/verify`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ challengeToken: challenge, totpCode: code }) });
    token = ((await r2.json()) as { accessToken?: string }).accessToken ?? null;
  }
  await pool.end();
  if (!token) throw new Error('UNM API login failed');
  return token;
}

async function getSecretFields(id: string): Promise<Record<string, string>> {
  const token = await getToken();
  const r = await fetch(`${API}/secrets/${id}`, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error(`GET /secrets/${id} → HTTP ${r.status}`);
  return ((await r.json()) as { fields?: Record<string, string> }).fields ?? {};
}

/** Minimal pager-aware SSH shell runner (same pattern as lcos-snmpv3-setup.ts). */
function runCommand(creds: { username: string; password: string }, cmds: string[], timeoutMs = 45_000): Promise<string> {
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
        if (noProgressPings >= 2) { streamRef?.write('q'); setTimeout(() => finish(buf + '\n[PAGER-STUCK]'), 1_500); return; }
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
      idleTimer = setTimeout(onIdle, 1_500);
    };

    const hardTimer = setTimeout(() => finish(buf + '\n[TIMEOUT]'), timeoutMs + 15_000);
    conn.on('ready', () => {
      conn.shell({ term: 'xterm-256color', cols: 220, rows: 50 }, (err, stream) => {
        if (err) { clearTimeout(hardTimer); return finish(`[shell error] ${err.message}`); }
        streamRef = stream;
        const sendNext = () => {
          if (sentCount >= cmds.length) { allSent = true; arm(); return; }
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
    conn.connect({ host: HOST, port: 22, username: creds.username, password: creds.password, readyTimeout: 15_000 });
  });
}

async function main() {
  const snmp = await getSecretFields(SNMP_SECRET_ID);
  if (!snmp.authPassword || !snmp.privPassword) throw new Error('SNMPv3 secret missing passphrases');
  const creds = {
    version: 'v3' as const,
    username: snmp.username ?? '',
    securityLevel: (snmp.securityLevel ?? 'authPriv') as 'noAuthNoPriv' | 'authNoPriv' | 'authPriv',
    authProtocol: (snmp.authProtocol === 'MD5' ? 'MD5' : 'SHA') as 'MD5' | 'SHA',
    authPassword: snmp.authPassword,
    privProtocol: (snmp.privProtocol ?? 'AES') as 'DES' | 'AES',
    privPassword: snmp.privPassword,
  };
  const opts = { timeoutMs: 8_000, retries: 2 };

  // --- Step 1: is the table SNMP-readable via plain GET? -------------------
  console.log('== Step 1: GET existing rows (col .1 Network-name) ==');
  for (const row of [1, 2, 3]) {
    try {
      const m = await snmpGet(HOST, creds, [`${NETLIST_BASE}.${row}.1`], opts);
      console.log(`  ${NETLIST_BASE}.${row}.1 → ${JSON.stringify([...m.values()])}`);
    } catch (e) {
      console.log(`  ${NETLIST_BASE}.${row}.1 → ERROR ${(e as Error).message}`);
    }
  }

  // --- Step 2: try to CREATE row 4 via SNMP SET ----------------------------
  const PROBE_NAME = 'UNM_PROBE_NET';
  console.log('\n== Step 2: SET new row .4.1 =', JSON.stringify(PROBE_NAME), '(text) ==');
  let created = false;
  try {
    await snmpSet(HOST, creds, `${NETLIST_BASE}.4.1`, 's', PROBE_NAME, opts);
    console.log('  SET accepted by agent.');
  } catch (e) {
    console.log(`  SET rejected: ${(e as Error).message}`);
  }

  // Re-read to see if the row materialized.
  await new Promise((r) => setTimeout(r, 2_000));
  try {
    const m = await snmpGet(HOST, creds, [`${NETLIST_BASE}.4.1`], opts);
    const v = [...m.values()][0];
    console.log(`  re-read ${NETLIST_BASE}.4.1 → ${JSON.stringify(v)}`);
    created = typeof v === 'string' && v.includes(PROBE_NAME);
  } catch (e) {
    console.log(`  re-read failed: ${(e as Error).message} (row likely not created)`);
  }

  if (!created) {
    console.log('\nRESULT: SNMP SET does NOT create Network-list rows → CLI is the write transport.');
    return;
  }

  // --- Step 3: fill IP/mask, verify, then clean up via CLI ------------------
  console.log('\n== Step 3: row created — filling .4.2/.4.3 (10.99.0.2/255.255.0.0) ==');
  try { await snmpSet(HOST, creds, `${NETLIST_BASE}.4.2`, 'a', '10.99.0.2', opts); console.log('  .4.2 SET ok'); } catch (e) { console.log(`  .4.2 rejected: ${(e as Error).message}`); }
  try { await snmpSet(HOST, creds, `${NETLIST_BASE}.4.3`, 'a', '255.255.0.0', opts); console.log('  .4.3 SET ok'); } catch (e) { console.log(`  .4.3 rejected: ${(e as Error).message}`); }
  await new Promise((r) => setTimeout(r, 1_500));
  const m2 = await snmpGet(HOST, creds, [`${NETLIST_BASE}.4.1`, `${NETLIST_BASE}.4.2`, `${NETLIST_BASE}.4.3`], opts).catch(() => new Map());
  console.log('  re-read row 4:', JSON.stringify([...m2.entries()]));

  // Cleanup: CLI del by name (single-key rows are deletable from root).
  const ssh = await getSecretFields(SSH_SECRET_ID);
  if (!ssh.username || !ssh.password) throw new Error('SSH secret missing username/password');
  console.log('\n== Step 4: cleanup via CLI `del Setup/TCP-IP/Network-list/' + PROBE_NAME + '` ==');
  const out = await runCommand(ssh, ['cd /', `del Setup/TCP-IP/Network-list/${PROBE_NAME}`, 'cd Setup/TCP-IP/Network-list', 'dir -a']);
  console.log(out.split('\n').slice(-20).join('\n'));

  // Final SNMP re-read — row should be gone.
  await new Promise((r) => setTimeout(r, 1_500));
  try {
    const m3 = await snmpGet(HOST, creds, [`${NETLIST_BASE}.4.1`], opts);
    console.log('final re-read .4.1 →', JSON.stringify([...m3.values()]));
  } catch (e) {
    console.log(`final re-read: ${(e as Error).message} (row gone — clean)`);
  }
  console.log('\nRESULT: SNMP SET CAN create Network-list rows → preferred transport for network.create.');
}

main().catch((e) => {
  console.error('probe failed:', e);
  process.exit(1);
});
