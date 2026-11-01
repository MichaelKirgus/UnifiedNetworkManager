/**
 * Probe: does LCOS support IN-PLACE editing of a DHCP Hosts row via targeted
 * column sets (the WLAN-slot pattern: `cd <table-parent>` + `set <Table> <rowkey> <Column> <value>`)?
 *
 * WLC01 only. Creates the temp pool + reservation first, then tries:
 *   cd Setup/DHCP
 *   set Hosts 00deadbeef01 IP-Address 10.25.0.96
 * and verifies via dir -a + SNMP (.2.10.9). Cleans up everything afterwards.
 *
 * Usage: ./node_modules/.bin/tsx scripts/probe-lcos-dhcp-set.ts
 */
import path from 'node:path';
import fs from 'node:fs';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const HOST = '10.25.0.20'; // WLC01 — test device only!
const SSH_SECRET_ID = process.env.LCOS_SSH_SECRET_ID ?? '3352ee33-1577-4849-a7ae-9ecf4c67d104';

const sdkRequire = createRequire(path.resolve(process.cwd(), 'packages', 'plugin-sdk', 'package.json'));
const { Client } = sdkRequire('ssh2') as typeof import('ssh2');
const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));
const snmpRequire = createRequire(path.resolve(process.cwd(), 'packages', 'snmp-client', 'package.json'));
const { snmpWalk } = snmpRequire('./dist/index.js') as typeof import('../packages/snmp-client/src/index');

function envValue(key: string): string | null {
  try {
    const m = new RegExp(`^${key}=(.+)$`, 'm').exec(fs.readFileSync(path.resolve(process.cwd(), '.env'), 'utf8'));
    return m?.[1]?.trim() ?? null;
  } catch {
    return null;
  }
}

async function getToken(): Promise<string> {
  const envFile = fs.readFileSync(path.resolve(process.cwd(), '.env'), 'utf8');
  const m = /^UNM_API_TOKEN=(.+)$/m.exec(envFile);
  if (process.env.UNM_API_TOKEN ?? m?.[1]?.trim()) return process.env.UNM_API_TOKEN ?? m![1].trim();
  const jwt = apiRequire('jsonwebtoken') as { sign: (p: Record<string, unknown>, s: string, o?: { expiresIn?: number }) => string };
  const pg = apiRequire('pg') as typeof import('pg');
  const pool = new pg.Pool({ connectionString: envValue('DATABASE_URL') ?? 'postgres://unm:unm@localhost:5432/unm' });
  const row = (await pool.query(`SELECT id, username, roles, permissions FROM users WHERE username='admin'`)).rows[0] as { id: string; username: string; roles: unknown; permissions: unknown };
  await pool.end();
  const parseArr = (v: unknown): string[] => Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : (typeof v === 'string' ? (() => { try { const p = JSON.parse(v); return Array.isArray(p) ? p.filter((x: unknown): x is string => typeof x === 'string') : []; } catch { return []; } })() : []);
  return jwt.sign({ sub: row.id, username: row.username, roles: parseArr(row.roles), permissions: parseArr(row.permissions), amr: ['totp'] }, envValue('JWT_SECRET') ?? 'dev-secret', { expiresIn: 3600 });
}

async function getSecretFields(id: string): Promise<Record<string, string>> {
  const token = await getToken();
  const r = await fetch(`${API}/secrets/${id}`, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error(`GET /secrets/${id} → HTTP ${r.status}`);
  return ((await r.json()) as { fields?: Record<string, string> }).fields ?? {};
}

function runCommand(creds: { username: string; password: string }, cmds: string[], timeoutMs = 40_000): Promise<string> {
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
        if (noProgressPings >= 2) { streamRef?.write('q'); setTimeout(() => finish(buf), 1_500); return; }
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
          // LCOS vRouter is SLOW — a `cd` sent while the previous command is still
          // processing gets dropped and the shell stays in the old directory.
          else setTimeout(sendNext, 3_500);
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

async function snmpHosts(): Promise<string> {
  const snmp = await getSecretFields('adeb8556-7245-43c4-b67e-20941bc8a10b');
  const creds = {
    version: 'v3' as const,
    username: snmp.username ?? '',
    securityLevel: (snmp.securityLevel ?? 'authPriv') as 'noAuthNoPriv' | 'authNoPriv' | 'authPriv',
    authProtocol: (snmp.authProtocol === 'MD5' ? 'MD5' : 'SHA') as 'MD5' | 'SHA',
    authPassword: snmp.authPassword,
    privProtocol: (snmp.privProtocol ?? 'AES') as 'DES' | 'AES',
    privPassword: snmp.privPassword,
  };
  const m = await snmpWalk(HOST, creds, ['1.3.6.1.4.1.2356.11.2.10.9'], { timeoutMs: 5_000, retries: 2, port: 161 });
  return [...m.entries()].sort((a, b) => a[0].localeCompare(b[0], undefined, { numeric: true }))
    .map(([oid, v]) => `  ${oid.replace(/^1\.3\.6\.1\.4\.1\.2356\./, '')} = ${String(v).replace(/\n/g, ' ')}`).join('\n');
}

async function main(): Promise<void> {
  const ssh = await getSecretFields(SSH_SECRET_ID);
  if (!ssh.username || !ssh.password) throw new Error('unexpected SSH secret shape');
  const creds = { username: ssh.username, password: ssh.password };

  const BARE = '00deadbeef02'; // distinct from the write-cycle probe's MAC
  const POOL = 'NET_MANAGEMENT';
  const IP1 = '10.25.0.94';
  const IP2 = '10.25.0.96';

  const log: string[] = [];

  console.log('### setup: pool + reservation ###');
  let out = await runCommand(creds, [
    'cd /Setup/DHCP/Network-list',
    `add ${POOL} 10.25.0.90 10.25.0.99 255.255.0.0 0.0.0.0 0.0.0.0 0.0.0.0 0.0.0.0 Yes No 0.0.0.0 0.0.0.0 0.0.0.0 0.0.0.0 "" No No No 0 0 No`,
    'cd /Setup/DHCP/Hosts',
    `add ${BARE} ${POOL} ${IP1} "" ""`,
    'dir -a .',
  ]);
  log.push('SETUP:\n' + out);
  console.log(out.split('\n').slice(-14).join('\n'));

  console.log('\n### SET attempt: cd Setup/DHCP + set Hosts <mac> IP-Address <newip> ###');
  const outSet = await runCommand(creds, [
    'cd /Setup/DHCP',
    `set Hosts ${BARE} IP-Address ${IP2}`,
    'cd /Setup/DHCP/Hosts',
    'dir -a .',
  ]);
  log.push('SET:\n' + outSet);
  console.log(outSet.split('\n').slice(-16).join('\n'));

  const afterSet = await snmpHosts().catch(() => '(snmp read failed)');
  console.log('SNMP after set:\n' + afterSet);
  log.push('SNMP after set:\n' + afterSet);

  const setWorked = afterSet.includes(IP2) && !afterSet.split(BARE).some((seg, i) => i > 0 && seg.includes(IP1));
  console.log(`\nSET ${setWorked ? 'WORKED — in-place column edit is supported' : 'DID NOT WORK (or unverified)'}`);

  // Also try the Hostname + Network-name columns while we're here.
  if (setWorked) {
    console.log('\n### SET attempt: Hostname + Network-name ###');
    const outSet2 = await runCommand(creds, [
      'cd /Setup/DHCP',
      `set Hosts ${BARE} Hostname "unm-test-host"`,
      `set Hosts ${BARE} Network-name NET_MANAGEMENT`, // no-op value — tests the column is settable at all
      'cd /Setup/DHCP/Hosts',
      'dir -a .',
    ]);
    log.push('SET2:\n' + outSet2);
    console.log(outSet2.split('\n').slice(-14).join('\n'));
  }

  console.log('\n### cleanup ###');
  const outClean = await runCommand(creds, [
    'cd /',
    `del Setup/DHCP/Hosts/${BARE}`,
    `del Setup/DHCP/Network-list/${POOL}`,
    'cd /Setup/DHCP/Hosts',
    'dir -a .',
  ]);
  log.push('CLEANUP:\n' + outClean);
  console.log(outClean.split('\n').slice(-14).join('\n'));

  fs.writeFileSync('/tmp/lcos-dhcp-probe/wlc01_set_probe.txt', log.join('\n\n===== session =====\n\n'));
}

main().catch((e) => {
  console.error('probe failed:', e);
  process.exit(1);
});
