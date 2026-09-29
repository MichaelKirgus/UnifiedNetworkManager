/**
 * Creates the SNMPv3 user `root` on a LANCOM LCOS device (WLC01, 10.25.0.20 —
 * TEST device) so UNM's stored "LANCOM SNMPv3 public/private" secret works:
 *   1. SFTP-read /config and remove any orphaned `probeuser` Groups row left by
 *      earlier probes (CLI del cannot address multi-key rows; LCF edit is the
 *      fallback — CLI del is tried first).
 *   2. CLI: cd Setup/SNMP/Users + add root HMAC-SHA <auth> "" AES128 <priv> "" active
 *      (validated grammar: bare enum names, tab-header column order).
 *   3. CLI: cd Setup/SNMP/Groups + add SNMPv3(USM) "root" SNMPv3-ReadWrite active
 *      (WLC01 already ships the SNMPv3-ReadWrite profile — verified via readscript).
 *   4. Verify with the STORED secret's fields: snmpGet DNS default + no-op SET of
 *      the same value (proves authPriv READ and WRITE access, changes nothing).
 *
 * Idempotent: skips creation when the rows already exist; re-creates a missing
 * Groups mapping for an existing user. Passphrases are fetched at runtime from
 * the UNM API and never printed in full.
 *
 * Usage (from repo root): ./node_modules/.bin/tsx scripts/lcos-snmpv3-setup.ts [host]
 */
import path from 'node:path';
import fs from 'node:fs';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
// Physical LCOS devices (e.g. GW_Ralf, 10.94) expose an EMPTY SFTP /config file
// (opens but never delivers data) — pass --cli-only to skip all SFTP steps and
// detect rows via CLI `dir -a` output instead. --verify-only skips creation.
const ARGS = process.argv.slice(2);
const HOST = ARGS.find((a) => !a.startsWith('--')) ?? '10.25.0.20';
const CLI_ONLY = ARGS.includes('--cli-only');
const VERIFY_ONLY = ARGS.includes('--verify-only');
const PORT = Number(process.env.LCOS_SSH_PORT ?? 22);
const SSH_SECRET_ID = process.env.LCOS_WEB_SECRET_ID ?? '3352ee33-1577-4849-a7ae-9ecf4c67d104';
const SNMP_SECRET_ID = process.env.LCOS_SNMPV3_SECRET_ID ?? 'adeb8556-7245-43c4-b67e-20941bc8a10b';

// LCOS MIB: DNS default scalar (IpAddress, read-write) — used for the no-op SET.
const OID_DNS_DEFAULT = '1.3.6.1.4.1.2356.11.2.7.7.0';
const OID_USERS_BASE = '1.3.6.1.4.1.2356.11.1.2.9.32';

const sdkRequire = createRequire(path.resolve(process.cwd(), 'packages', 'plugin-sdk', 'package.json'));
const { Client } = sdkRequire('ssh2') as typeof import('ssh2');
const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));
// Load the BUILT snmp-client (main → dist/index.js) via its own package.json so
// net-snmp resolves from packages/snmp-client/node_modules.
const snmpRequire = createRequire(path.resolve(process.cwd(), 'packages', 'snmp-client', 'package.json'));
const { snmpGet, snmpSet, snmpWalk } = snmpRequire('./dist/index.js') as typeof import('../packages/snmp-client/src/index');

// ---------------------------------------------------------------------------
// UNM API: login (admin + TOTP) → decrypted secret fields
// ---------------------------------------------------------------------------

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
  const j = (await r.json()) as { fields?: Record<string, string> };
  return j.fields ?? {};
}

// ---------------------------------------------------------------------------
// SSH shell: validated LCOS CLI runner (pager-aware, idle-terminated)
// ---------------------------------------------------------------------------

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
          buf += `\n----- sent: ${cmds[sentCount]} -----\n`;
          stream.write(cmds[sentCount] + '\r');
          sentCount++;
          setTimeout(sendNext, 900);
        };
        stream.on('data', (d: Buffer) => {
          buf += d.toString();
          if (!allSent) return; // keep sending until the queue drains
          arm();
        });
        stream.once('close', () => finish(buf + '\n[STREAM-CLOSED]'));
        setTimeout(sendNext, 1_500); // let the login prompt settle first
      });
    });
    conn.on('error', (err) => finish(`[conn error] ${err.message}`));
    conn.connect({ host: HOST, port: PORT, username: creds.username, password: creds.password, readyTimeout: 20_000 });
  });
}

// ---------------------------------------------------------------------------
// SFTP /config — mirrors the plugin SDK's stream pattern (raw fastGet fails on LCOS)
// ---------------------------------------------------------------------------

function sftpReadConfig(creds: { username: string; password: string }): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const conn = new Client();
    let settled = false;
    const timer = setTimeout(() => fail(new Error('SFTP read /config timed out after 90s')), 90_000);
    const fail = (e: Error) => { if (!settled) { settled = true; clearTimeout(timer); try { conn.end(); } catch { /* ignore */ } reject(e); } };

    conn.on('ready', () => {
      conn.sftp((err, sftp) => {
        if (err) return fail(err as Error);
        const chunks: Buffer[] = [];
        let total = 0;
        const rs = sftp.createReadStream('/config');
        rs.on('data', (d: Buffer) => {
          total += d.length;
          if (total > 20 * 1024 * 1024) return fail(new Error('SFTP read /config exceeded 20 MiB'));
          chunks.push(d);
        });
        rs.on('error', (e: Error) => fail(e));
        rs.on('close', () => { clearTimeout(timer); if (!settled) { settled = true; conn.end(); resolve(Buffer.concat(chunks)); } });
      });
    });
    conn.on('error', (err) => fail(err as Error));
    conn.connect({ host: HOST, port: PORT, username: creds.username, password: creds.password, readyTimeout: 20_000 });
  });
}

function sftpWriteConfig(creds: { username: string; password: string }, data: Buffer): Promise<void> {
  return new Promise((resolve, reject) => {
    const conn = new Client();
    let settled = false;
    const timer = setTimeout(() => fail(new Error('SFTP write /config timed out after 90s')), 90_000);
    const fail = (e: Error) => { if (!settled) { settled = true; clearTimeout(timer); try { conn.end(); } catch { /* ignore */ } reject(e); } };

    conn.on('ready', () => {
      conn.sftp((err, sftp) => {
        if (err) return fail(err as Error);
        const ws = sftp.createWriteStream('/config');
        ws.on('error', (e: Error) => fail(e));
        ws.end(data, () => { /* close fires after flush ack */ });
        ws.on('close', () => { clearTimeout(timer); if (!settled) { settled = true; conn.end(); resolve(); } });
      });
    });
    conn.on('error', (err) => fail(err as Error));
    conn.connect({ host: HOST, port: PORT, username: creds.username, password: creds.password, readyTimeout: 20_000 });
  });
}

// ---------------------------------------------------------------------------
// LCF parsing — CRLF lines; cell lines are `(oid) = value` (6-space indent);
// a row's first cell is the col-1 line. Row indices renumber on delete, so we
// locate rows by CONTENT (Security-Name column), never by index.
// ---------------------------------------------------------------------------

const CELL_RE = /^\((\d+(?:\.\d+)*)\) = (.*)$/;

function lcfLines(raw: Buffer): string[] {
  return raw.toString('binary').split('\r\n');
}

/** Returns the row index of every row in table `family` whose column `col2` value === name. */
function findRowsByCol2(lines: string[], family: string, col2: number, name: string): number[] {
  const famParts = family.split('.').length; // '1.2.9.28' → 4
  const rows = new Map<number, string>(); // rowIndex → col2 value
  for (const line of lines) {
    const m = CELL_RE.exec(line.trim());
    if (!m) continue;
    const segs = m[1].split('.');
    // LCF cell OIDs are exactly family + rowIndex + colIdx (e.g. 1.2.9.32.1.1).
    if (segs.length !== famParts + 2) continue;
    if (segs.slice(0, famParts).join('.') !== family) continue;
    const rowIdx = Number(segs[famParts]);
    const colIdx = Number(segs[famParts + 1]);
    if (colIdx === 1 && !rows.has(rowIdx)) rows.set(rowIdx, ''); // mark row existence
    if (colIdx === col2) rows.set(rowIdx, m[2].trim());
  }
  const out: number[] = [];
  for (const [rowIdx, val] of rows) if (val === name) out.push(rowIdx);
  return out;
}

/** Removes every cell line belonging to the given row indices of `family`. */
function removeRows(lines: string[], family: string, rowIndices: number[]): { lines: string[]; removedCells: number } {
  const famParts = family.split('.').length;
  const drop = new Set<string>();
  for (const ri of rowIndices) {
    for (let i = 0; i < lines.length; i++) {
      const m = CELL_RE.exec(lines[i].trim());
      if (!m) continue;
      const segs = m[1].split('.');
      if (segs.length === famParts + 2 && segs.slice(0, famParts).join('.') === family && Number(segs[famParts]) === ri) {
        drop.add(i);
      }
    }
  }
  return { lines: lines.filter((_, i) => !drop.has(i)), removedCells: drop.size };
}

// ---------------------------------------------------------------------------
// CLI-only row detection (for devices with an unreadable SFTP /config)
// ---------------------------------------------------------------------------

/** Lists a table via `cd <dir>` + `dir -a` and reports whether any data row contains `needle`. */
async function cliTableHasRow(creds: { username: string; password: string }, dir: string, needle: string): Promise<boolean> {
  const out = await runCommand(creds, [`cd ${dir}`, 'dir -a']);
  // Data rows start at column 0 (no leading spaces); header/separator lines are indented or '='/'-'.
  // Prompt lines (`root@GW_Ralf:/…`) also start at col 0 — exclude anything containing '@'.
  return out.split('\n').some((l) => l.length > 0 && !/^\s/.test(l) && !l.includes('@') && !/^[=|-]+$/.test(l.trim()) && l.includes(needle));
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  const ssh = await getSecretFields(SSH_SECRET_ID);
  if (!ssh.username || !ssh.password) throw new Error('SSH secret missing username/password');
  const snmp = await getSecretFields(SNMP_SECRET_ID);
  console.log(`SNMPv3 secret: user=${snmp.username} level=${snmp.securityLevel} auth=${snmp.authProtocol} priv=${snmp.privProtocol}`);

  // --- Step 1: read /config, find orphaned probeuser Groups row ------------
  let raw: Buffer | null = null;
  let lines: string[] = [];
  if (CLI_ONLY) {
    console.log('CLI-only mode — skipping SFTP /config steps');
  } else {
    raw = await sftpReadConfig(ssh);
    console.log(`SFTP GET /config → ${raw.length} bytes`);
    lines = lcfLines(raw);
  }

  const GROUPS_FAMILY = '1.2.9.28'; // Setup/SNMP/Groups: [1] Security-Model, [2] Security-Name, [3] Group-Name, [5] Status
  const USERS_FAMILY = '1.2.9.32';  // Setup/SNMP/Users: col1 hidden key (empty), [2] User-Name, [5] Auth-Proto, [6] Auth-Pass, [8] Priv-Proto, [9] Priv-Pass, [13] Status

  if (CLI_ONLY) {
    const hasProfile = await cliTableHasRow(ssh, 'Setup/SNMP/Accesses', 'SNMPv3-ReadWrite');
    if (!hasProfile) throw new Error('ABORT: no SNMPv3-ReadWrite profile found in Accesses table — refusing to guess a profile name');
    console.log('SNMPv3-ReadWrite profile present (CLI dir check)');
  } else {
    if (!lines.some((l) => l.includes('SNMPv3-ReadWrite'))) {
      throw new Error('ABORT: no SNMPv3-ReadWrite profile row found in Groups table — refusing to guess a profile name');
    }
  }

  let probeRows = CLI_ONLY ? [] : findRowsByCol2(lines, GROUPS_FAMILY, 2, 'probeuser');
  if (probeRows.length) {
    console.log(`orphaned probeuser Groups rows: ${JSON.stringify(probeRows)} — trying CLI del first`);
    const outDel = await runCommand(ssh, ['del Setup/SNMP/Groups/probeuser', 'cd Setup/SNMP/Groups', 'dir -a']);
    console.log(outDel.split('\n').slice(-25).join('\n'));
    raw = await sftpReadConfig(ssh);
    lines = lcfLines(raw);
    probeRows = findRowsByCol2(lines, GROUPS_FAMILY, 2, 'probeuser');
  } else {
    console.log('no orphaned probeuser Groups row — skipping cleanup');
  }

  if (probeRows.length) {
    // CLI del cannot address multi-key rows → SFTP LCF edit (validated fallback).
    const { lines: next, removedCells } = removeRows(lines, GROUPS_FAMILY, probeRows);
    console.log(`LCF edit: removing ${removedCells} cell lines for probeuser row(s) ${JSON.stringify(probeRows)}`);
    await sftpWriteConfig(ssh, Buffer.from(next.join('\r\n'), 'binary'));
    raw = await sftpReadConfig(ssh);
    lines = lcfLines(raw);
    const stillThere = findRowsByCol2(lines, GROUPS_FAMILY, 2, 'probeuser');
    if (stillThere.length) throw new Error(`LCF edit did not remove probeuser row(s): ${JSON.stringify(stillThere)}`);
    console.log('probeuser Groups row removed — verified by re-read');
  }

  // --- Step 2: create the root user + Groups mapping via CLI ---------------
  const authProto = snmp.authProtocol === 'MD5' ? 'HMAC-MD5' : 'HMAC-SHA';
  const privProto = snmp.privProtocol === 'AES' ? 'AES128' : 'DES40'; // DES unsupported by our transport anyway
  if (!snmp.authPassword || !snmp.privPassword) throw new Error('SNMPv3 secret missing auth/priv passphrases');

  let hasRootUser = CLI_ONLY ? await cliTableHasRow(ssh, 'Setup/SNMP/Users', 'root') : findRowsByCol2(lines, USERS_FAMILY, 2, 'root').length > 0;
  let hasRootGroup = CLI_ONLY ? await cliTableHasRow(ssh, 'Setup/SNMP/Groups', 'root') : findRowsByCol2(lines, GROUPS_FAMILY, 2, 'root').length > 0;
  if (VERIFY_ONLY) {
    console.log(`verify-only: root user=${hasRootUser} groups-mapping=${hasRootGroup}`);
    if (!hasRootUser || !hasRootGroup) throw new Error('ABORT (verify-only): rows missing — run without --verify-only first');
  } else if (hasRootUser && hasRootGroup) {
    console.log('root user + Groups mapping already present — skipping creation');
  } else {
    if (!hasRootUser) {
      const outAdd = await runCommand(ssh, [
        'cd Setup/SNMP/Users',
        `add root ${authProto} "${snmp.authPassword}" "" ${privProto} "${snmp.privPassword}" "" active`,
        'dir -a',
      ]);
      console.log('\n===== add user =====');
      console.log(outAdd.split('\n').slice(-20).join('\n'));
    } else {
      console.log('root user row already present — skipping user creation');
    }
    if (!hasRootGroup) {
      const outMap = await runCommand(ssh, [
        'cd Setup/SNMP/Groups',
        'add SNMPv3(USM) "root" SNMPv3-ReadWrite active',
        'dir -a',
      ]);
      console.log('\n===== add Groups mapping =====');
      console.log(outMap.split('\n').slice(-20).join('\n'));
    } else {
      console.log('root Groups mapping already present — skipping');
    }

    // Re-check to confirm both rows landed (CLI dir on physical devices, LCF re-read elsewhere).
    if (CLI_ONLY) {
      hasRootUser = await cliTableHasRow(ssh, 'Setup/SNMP/Users', 'root');
      hasRootGroup = await cliTableHasRow(ssh, 'Setup/SNMP/Groups', 'root');
      if (!hasRootUser || !hasRootGroup) throw new Error('rows not confirmed after CLI add (dir re-check failed)');
    } else {
      raw = await sftpReadConfig(ssh);
      lines = lcfLines(raw);
      if (!findRowsByCol2(lines, USERS_FAMILY, 2, 'root').length) throw new Error('Users row for root not found after CLI add');
      if (!findRowsByCol2(lines, GROUPS_FAMILY, 2, 'root').length) throw new Error('Groups mapping for root not found after CLI add');
    }
    console.log('both rows confirmed');
  }

  // --- Step 3: verify with the stored secret's fields ----------------------
  const creds = {
    version: 'v3' as const,
    username: snmp.username ?? '',
    securityLevel: (snmp.securityLevel ?? 'authPriv') as 'noAuthNoPriv' | 'authNoPriv' | 'authPriv',
    authProtocol: (snmp.authProtocol === 'MD5' ? 'MD5' : 'SHA') as 'MD5' | 'SHA',
    authPassword: snmp.authPassword,
    privProtocol: (snmp.privProtocol ?? 'AES') as 'DES' | 'AES',
    privPassword: snmp.privPassword,
  };
  const opts = { timeoutMs: 5_000, retries: 2 };

  // READ check — DNS default scalar; fall back to a Users-table walk if unset.
  let readOk = false;
  try {
    const got = await snmpGet(HOST, creds, [OID_DNS_DEFAULT], opts);
    console.log(`SNMPv3 GET ${OID_DNS_DEFAULT} → ${got.size ? JSON.stringify([...got.values()]) : '(absent — no default DNS set)'}`);
    readOk = true;
  } catch (err) {
    console.log(`SNMPv3 GET failed: ${(err as Error).message}`);
  }
  if (!readOk) {
    const walk = await snmpWalk(HOST, creds, OID_USERS_BASE, opts); // throws on auth failure
    console.log(`SNMPv3 WALK ${OID_USERS_BASE} → ${walk.size} varbinds (auth OK)`);
  }

  // WRITE check — no-op SET of the DNS default to its own current value.
  const cur = await snmpGet(HOST, creds, [OID_DNS_DEFAULT], opts).catch(() => new Map());
  const curVal = cur.get(`.${OID_DNS_DEFAULT}`);
  if (typeof curVal === 'string' && /^\d+\.\d+\.\d+\.\d+$/.test(curVal)) {
    try {
      await snmpSet(HOST, creds, OID_DNS_DEFAULT, 'a', curVal, opts);
      console.log(`SNMPv3 no-op SET ${OID_DNS_DEFAULT} = ${curVal} → ACCEPTED (write access OK)`);
    } catch (err) {
      throw new Error(`no-op SET rejected: ${(err as Error).message}`);
    }
  } else {
    // No default DNS configured — use the Users table's own row instead? No:
    // config-table OIDs are not SNMP-writable. Fall back to a second scalar:
    // system name (1.3.6.1.2.1.1.5.0) is standard read-write on LCOS agents.
    const sysName = await snmpGet(HOST, creds, ['1.3.6.1.2.1.1.5.0'], opts);
    const nameVal = sysName.get('.1.3.6.1.2.1.1.5.0');
    if (typeof nameVal === 'string') {
      await snmpSet(HOST, creds, '1.3.6.1.2.1.1.5.0', 's', nameVal, opts);
      console.log(`SNMPv3 no-op SET sysName = ${nameVal} → ACCEPTED (write access OK)`);
    } else {
      throw new Error('could not find a writable scalar for the no-op SET verification');
    }
  }

  console.log('\nDONE — stored SNMPv3 credential now works on', HOST);
}

main().catch((e) => {
  console.error('FAILED:', e instanceof Error ? (e.stack ?? e.message) : e);
  process.exit(1);
});
