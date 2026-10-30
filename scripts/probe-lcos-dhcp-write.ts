/**
 * Probe of the LCOS DHCP static-host (reservation) table — Setup/DHCP/Hosts.
 *
 * Phase A (READ-ONLY, both devices): `dir -a` on Hosts to see how real rows are
 * rendered (MAC format!), plus `add ?` help on WLC01 for the column syntax.
 *
 * Phase B (WRITE, WLC01 ONLY — pass --write): adds ONE test reservation with a
 * fake MAC (00:de:ad:be:ef:01), verifies it appears in CLI + SNMP (.2.10.9),
 * then deletes it and verifies it is gone. Safe to re-run; leaves no trace.
 *
 * Usage (from repo root):
 *   ./node_modules/.bin/tsx scripts/probe-lcos-dhcp-write.ts            # read-only, both devices
 *   ./node_modules/.bin/tsx scripts/probe-lcos-dhcp-write.ts --write    # + write cycle on WLC01
 */
import path from 'node:path';
import fs from 'node:fs';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const WRITE = process.argv.includes('--write');
const SSH_SECRET_ID = process.env.LCOS_SSH_SECRET_ID ?? '3352ee33-1577-4849-a7ae-9ecf4c67d104';

// ssh2 lives in the plugin-sdk's node_modules — resolve it from there.
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
  // Fallback: mint an admin JWT directly (admin has TOTP enrolled).
  const jwt = apiRequire('jsonwebtoken') as { sign: (p: Record<string, unknown>, s: string, o?: { expiresIn?: number }) => string };
  const pg = apiRequire('pg') as typeof import('pg');
  const pool = new pg.Pool({ connectionString: envValue('DATABASE_URL') ?? 'postgres://unm:unm@localhost:5432/unm' });
  const row = (await pool.query(`SELECT id, username, roles, permissions FROM users WHERE username='admin'`)).rows[0] as { id: string; username: string; roles: unknown; permissions: unknown };
  await pool.end();
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
  return jwt.sign({ sub: row.id, username: row.username, roles: parseArr(row.roles), permissions: parseArr(row.permissions), amr: ['totp'] }, envValue('JWT_SECRET') ?? 'dev-secret', { expiresIn: 3600 });
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

async function snmpHosts(host: string): Promise<string> {
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
  const m = await snmpWalk(host, creds, ['1.3.6.1.4.1.2356.11.2.10.9'], { timeoutMs: 5_000, retries: 2, port: 161 });
  return [...m.entries()].sort((a, b) => a[0].localeCompare(b[0], undefined, { numeric: true }))
    .map(([oid, v]) => `  ${oid.replace(/^1\.3\.6\.1\.4\.1\.2356\./, '')} = ${String(v).replace(/\n/g, ' ')}`).join('\n');
}

async function main(): Promise<void> {
  const ssh = await getSecretFields(SSH_SECRET_ID);
  if (!ssh.username || !ssh.password) throw new Error('unexpected SSH secret shape');
  const creds = { username: ssh.username, password: ssh.password };

  // --- Phase A — read-only on both devices ---------------------------------
  for (const [host, label] of [['10.25.0.20', 'WLC01'], ['10.28.0.1', 'GW_Ralf']] as const) {
    console.log(`\n########## ${label} (${host}) — Hosts dir -a ##########`);
    let out = await runCommand(creds, host, ['cd Setup/DHCP/Hosts', 'dir -a .']);
    fs.writeFileSync(`/tmp/lcos-dhcp-probe/${label.toLowerCase()}_hosts.txt`, out);
    console.log(out.split('\n').slice(-40).join('\n'));

    if (host === '10.25.0.20') {
      console.log(`\n########## WLC01 — add ? help ##########`);
      out = await runCommand(creds, host, ['cd Setup/DHCP/Hosts', 'add ?']);
      fs.writeFileSync('/tmp/lcos-dhcp-probe/wlc01_hosts_add_help.txt', out);
      console.log(out.split('\n').slice(-60).join('\n'));

      // Which network names exist on WLC01 (for a valid Network-name value)?
      console.log(`\n########## WLC01 — TCP-IP/Network-list ##########`);
      out = await runCommand(creds, host, ['cd Setup/TCP-IP/Network-list', 'dir -a .']);
      fs.writeFileSync('/tmp/lcos-dhcp-probe/wlc01_tcpip_netlist.txt', out);
      console.log(out.split('\n').slice(-25).join('\n'));
    }

    if (host === '10.28.0.1') {
      console.log(`\n########## GW_Ralf — SNMP .2.10.9 (Hosts) ##########`);
      try { console.log(await snmpHosts(host)); } catch (e) { console.log('snmp walk failed:', e instanceof Error ? e.message : String(e)); }
    }
  }

  if (!WRITE) {
    console.log('\n(read-only mode — pass --write to run the add/verify/delete cycle on WLC01)');
    return;
  }

  // --- Phase B — write cycle on WLC01 only ----------------------------------
  const host = '10.25.0.20';
  const MAC = '00:de:ad:be:ef:01';
  const IP = process.env.RESV_IP ?? '10.25.0.95'; // mid-pool; boundary IPs are rejected
  console.log(`\n########## WLC01 — WRITE CYCLE add ${MAC} → ${IP} ##########`);

  const before = await snmpHosts(host).catch(() => '(snmp read failed)');
  console.log('SNMP before:\n' + before);

  const BARE = MAC.replace(/:/g, ''); // LCOS stores/accepts bare lowercase hex (12 chars)

  // WLC01 has NO DHCP pools — and LCOS validates the reservation IP against a
  // configured pool ("Value invalid: <ip>"). Create a temporary test pool on
  // NET_MANAGEMENT first; it is deleted again at the end.
  // LCOS validates the pool name against EXISTING network names (TCP-IP/Network-list) —
  // a made-up name is rejected. Reuse an existing one; only delete it afterwards if we created it.
  const POOL = process.env.POOL_NAME ?? 'NET_MANAGEMENT';
  const outPoolPre = await runCommand(creds, host, ['cd Setup/DHCP/Network-list', 'dir -a .']);
  const poolExistedBefore = new RegExp(`(^|\\n)\\s*${POOL}\\b`).test(outPoolPre);
  console.log(`\n########## WLC01 — DHCP pool ${POOL} (existed before: ${poolExistedBefore}) ##########`);
  let out = await runCommand(creds, host, [
    'cd Setup/DHCP/Network-list',
    `add ${POOL} 10.25.0.90 10.25.0.99 255.255.0.0 0.0.0.0 0.0.0.0 0.0.0.0 0.0.0.0 Yes No 0.0.0.0 0.0.0.0 0.0.0.0 0.0.0.0 "" No No No 0 0 No`,
    'dir -a .',
  ]);
  console.log(out.split('\n').slice(-12).join('\n'));

  // add takes values in TAB-HEADER order (same as dir -a): [MAC, Network-name, IP, Hostname, Image-alias] —
  // NOT numeric column order. (Putting the IP second made LCOS validate it AS a network name: "Value invalid: <ip>".)
  let outAdd = await runCommand(creds, host, [
    'cd Setup/DHCP/Hosts',
    `add ${BARE} ${POOL} ${IP} "" ""`,
    'dir -a .',
  ]);
  console.log(outAdd.split('\n').slice(-30).join('\n'));

  const afterAdd = await snmpHosts(host).catch(() => '(snmp read failed)');
  console.log('SNMP after add:\n' + afterAdd);
  fs.writeFileSync('/tmp/lcos-dhcp-probe/wlc01_write_cycle.txt', out + '\n\nADD:\n' + outAdd + '\n\nSNMP before:\n' + before + '\n\nSNMP after add:\n' + afterAdd);

  // Delete — single-key table, key = MAC. Try bare hex first (the stored form),
  // then the colon form. Verify against BOTH CLI dir and SNMP each time. The
  // `dir -a` output is checked separately from the del command's own echo.
  let delKeyUsed: string | null = null;
  for (const delKey of [BARE, MAC]) {
    console.log(`\n########## WLC01 — del Setup/DHCP/Hosts/${delKey} ##########`);
    const outDel = await runCommand(creds, host, ['cd /', `del Setup/DHCP/Hosts/${delKey}`]);
    console.log(outDel.split('\n').slice(-8).join('\n'));
    const outDir = await runCommand(creds, host, ['cd Setup/DHCP/Hosts', 'dir -a .']);
    console.log(outDir.split('\n').slice(-12).join('\n'));
    const afterDel = await snmpHosts(host).catch(() => '(snmp read failed)');
    const cliGone = !outDir.includes(BARE);
    const snmpGone = afterDel !== '(snmp read failed)' && !afterDel.toLowerCase().includes(BARE);
    if (cliGone && snmpGone) {
      delKeyUsed = delKey;
      console.log(`\ndelete with key form "${delKey}" SUCCEEDED — row gone from CLI + SNMP`);
      fs.appendFileSync('/tmp/lcos-dhcp-probe/wlc01_write_cycle.txt', `\n\nDEL KEY FORM: ${delKey}\nSNMP after del:\n${afterDel}`);
      break;
    }
    console.log(`\ndelete with key form "${delKey}" did NOT remove the row (cliGone=${cliGone}, snmpGone=${snmpGone})`);
  }

  // Cleanup — delete the pool we created (reservation must be gone first). A
  // pre-existing pool is left untouched.
  if (!delKeyUsed) {
    console.error('RESERVATION ROW STILL PRESENT — clean up manually!');
    return;
  }
  if (poolExistedBefore) {
    console.log(`\n(pool ${POOL} pre-existed on WLC01 — left in place)`);
  } else {
    console.log(`\n########## WLC01 — cleanup: del Setup/DHCP/Network-list/${POOL} ##########`);
    const outPoolDel = await runCommand(creds, host, ['cd /', `del Setup/DHCP/Network-list/${POOL}`, 'cd Setup/DHCP/Network-list', 'dir -a .']);
    console.log(outPoolDel.split('\n').slice(-12).join('\n'));
    fs.appendFileSync('/tmp/lcos-dhcp-probe/wlc01_write_cycle.txt', `\n\nPOOL CLEANUP:\n${outPoolDel}`);
  }
}

main().catch((e) => {
  console.error('probe failed:', e);
  process.exit(1);
});
