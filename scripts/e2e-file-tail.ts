/**
 * End-to-end verification for rotation-aware log-file tailing (SDK fileTail core,
 * wired into the Generic SSH plugin). Runs against the LIVE dev stack and uses
 * MAIL04 — a mailcow host with root SSH via the generic-ssh plugin.
 *
 * Drives one full cursor lifecycle through real beats:
 *   1. baseline      — new file with 25 lines, logTailBaselineLines=10 → exactly
 *                      the NEWEST 10 lines are ingested (line-16..line-25)
 *   2. append        — +5 lines via SFTP read/rewrite (same inode grows) → range
 *                      read picks up exactly line-26..line-30, no duplicates
 *   3. rotation      — rename app.log → app.log.1 + fresh file with 4 lines
 *                      (new inode) → baseline of the new file only
 *   4. truncate      — SFTP write shrinks the file in place (same inode, size <
 *                      offset) → reset read from byte 0 picks up t1..t3 once
 *   5. invariants    — COUNT(*) == COUNT(DISTINCT vendorEventId), every row
 *                      carries the device id + management address hostname
 *
 * File mutations go through the API's POST /devices/:id/filesystem proxy (the
 * same SFTP path the webapp uses) so no out-of-band SSH is needed. Beats are
 * forced with POST /devices/refresh; results are read straight from Postgres
 * (security_events), like the other live E2Es. Auth = UNM_API_TOKEN from .env
 * (long-lived, bypasses 2FA — admin/admin no longer works post-onboarding).
 *
 * Usage (from the repo root):
 *   ./node_modules/.bin/tsx scripts/e2e-file-tail.ts
 */

import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const SSH_PLUGIN_ID = '00000000-0000-4000-8000-00000000000c'; // Generic SSH Plugin (Linux)
const TARGET_DEVICE_NAME = process.env.E2E_SSH_HOST ?? 'MAIL04';

// pg lives in api/node_modules; resolve through a require rooted at the API package.
const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));

/** UNM_API_TOKEN from the repo .env (the reliable auth path — see session notes). */
function readApiToken(): string {
  const envPath = path.resolve(process.cwd(), '.env');
  const line = fs.readFileSync(envPath, 'utf8').split('\n').find((l) => l.startsWith('UNM_API_TOKEN='));
  const token = (line ?? '').slice('UNM_API_TOKEN='.length).trim();
  if (!token) throw new Error(`UNM_API_TOKEN not found in ${envPath}`);
  return token;
}

let failures = 0;
function check(label: string, cond: boolean, extra?: unknown): void {
  if (cond) console.log(`  PASS ${label}`);
  else {
    failures++;
    console.error(`  FAIL ${label}`, extra !== undefined ? JSON.stringify(extra).slice(0, 500) : '');
  }
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

async function main(): Promise<void> {
  const token = readApiToken();
  const authed = async <T = unknown>(method: string, p: string, body?: unknown): Promise<{ status: number; data: T }> => {
    const res = await fetch(`${API}${p}`, {
      method,
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });
    let data: T | null = null;
    try { data = (await res.json()) as T; } catch { /* non-JSON body */ }
    return { status: res.status, data: data ?? (null as unknown as T) };
  };

  const { Pool } = apiRequire('pg');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm' });

  // --- Target device + bound SSH secret (filesystem ops need the secretId) ----
  const devices = (await authed<Array<{ id: string; name?: string; managementAddress?: string }>>('GET', '/devices')).data ?? [];
  const target = devices.find((d) => d.name === TARGET_DEVICE_NAME);
  check(`device ${TARGET_DEVICE_NAME} found`, Boolean(target), devices.map((d) => d.name));
  if (!target) throw new Error('target device not found');

  const bindRow = (await pool.query(
    `SELECT dp."secretId" FROM device_plugins dp WHERE dp."deviceId" = $1 AND dp."pluginId" = $2`,
    [target.id, SSH_PLUGIN_ID],
  )).rows[0] as { secretId: string | null } | undefined;
  const fsSecretId = bindRow?.secretId ?? '';
  check('device has a bound SSH secret', Boolean(fsSecretId));

  // Unique per run — no collision with leftovers from earlier runs.
  const runid = `fte2e${Date.now().toString(36).slice(-5)}`;
  const label = `fte2e-${runid}`;
  const dir = `/var/log/unm-e2e/${runid}`;
  const file = `${dir}/app.log`;

  /** SFTP op through the API proxy (same path as the webapp Files button). Retries transient 502 / socket errors. */
  const fsOp = async <T = unknown>(op: string, p: string, extra?: Record<string, unknown>): Promise<{ status: number; data: T }> => {
    let last: { status: number; data: T } | null = null;
    for (let attempt = 1; attempt <= 3; attempt++) {
      try {
        const r = await authed<T>('POST', `/devices/${target.id}/filesystem`, { op, path: p, pluginId: SSH_PLUGIN_ID, secretId: fsSecretId, context: { kind: 'root' }, ...extra });
        if (r.status !== 502) return r; // non-transient → surface immediately
        last = r;
      } catch (e) {
        last = { status: 0, data: e as unknown as T }; // network-level failure (socket hang up etc.)
      }
      await sleep(2_000);
    }
    return last ?? { status: 0, data: null as unknown as T };
  };

  /** Force one monitoring beat for the device. */
  const refresh = async (): Promise<void> => {
    await authed('POST', '/devices/refresh', { deviceIds: [target.id] }).catch(() => undefined);
  };

  /** Polls security_events until the row count for our label reaches `want` (or times out). */
  const waitRows = async (what: string, want: number, timeoutMs = 120_000): Promise<number> => {
    const deadline = Date.now() + timeoutMs;
    let last = -1;
    for (;;) {
      const r = await pool.query(`SELECT COUNT(*)::int AS n FROM security_events WHERE "appname" = $1`, [label]);
      last = (r.rows[0] as { n: number }).n;
      if (last >= want) return last;
      if (Date.now() >= deadline) break;
      await sleep(3_000);
    }
    console.error(`  (timed out waiting for ${what}: have ${last}, wanted ${want})`);
    return last;
  };

  const rowsFor = async (): Promise<Array<{ message: string; vendorEventId: string; deviceId: string | null; hostname: string | null }>> => {
    const r = await pool.query(
      `SELECT "message", "vendorEventId", "deviceId", "hostname" FROM security_events WHERE "appname" = $1 ORDER BY "tsMs", "message"`,
      [label],
    );
    return r.rows as Array<{ message: string; vendorEventId: string; deviceId: string | null; hostname: string | null }>;
  };

  // --- Configure the feature on this device -----------------------------------
  const setRes = await authed('PUT', `/devices/${target.id}/plugins/${SSH_PLUGIN_ID}/settings`, {
    settings: { logSources: `${file} ${label}`, logTailIntervalMs: 10_000, logTailBaselineLines: 10 },
  });
  check('plugin options accepted (logSources + throttle + baseline)', setRes.status === 200, setRes.data);

  // --- Beat 1: baseline of a new file -----------------------------------------
  const mk = await fsOp('mkdir', dir, { parents: true });
  check('mkdir on host', mk.status === 200, mk.data);
  const lines25 = Array.from({ length: 25 }, (_, i) => `line-${String(i + 1).padStart(2, '0')} payload ${i}`).join('\n') + '\n';
  const w1 = await fsOp('write', file, { contentBase64: Buffer.from(lines25).toString('base64') });
  check('wrote 25-line log file on host', w1.status === 200, w1.data);

  await refresh();
  const n1 = await waitRows('baseline rows (newest 10 of 25)', 10);
  let rows = await rowsFor();
  check(`beat 1: exactly the newest 10 lines ingested (${n1})`, n1 === 10 && rows.length === 10, rows.map((r) => r.message));
  const expectedBaseline = Array.from({ length: 10 }, (_, i) => `line-${String(i + 16).padStart(2, '0')}`);
  check('beat 1: messages are line-16..line-25', rows.map((r) => r.message.slice(0, 7)).sort().join(',') === expectedBaseline.join(','), rows.map((r) => r.message));

  // --- Beat 2: append (same inode grows → range read) --------------------------
  const rd = await fsOp<{ result?: { contentBase64?: string } }>('read', file);
  const oldBytes = Buffer.from(rd.data?.result?.contentBase64 ?? '', 'base64');
  check('filesystem read of current file', rd.status === 200 && oldBytes.toString() === lines25, { status: rd.status, len: oldBytes.length });
  const appended = 'line-26 x\nline-27 x\nline-28 x\nline-29 x\nline-30 x\n';
  const w2 = await fsOp('write', file, { contentBase64: Buffer.concat([oldBytes, Buffer.from(appended)]).toString('base64') });
  check('appended 5 lines (SFTP rewrite)', w2.status === 200, w2.data);

  await refresh();
  const n2 = await waitRows('append rows (+5)', 15);
  rows = await rowsFor();
  check(`beat 2: total is now 15 (${n2})`, n2 === 15 && rows.length === 15, rows.map((r) => r.message).slice(-6));
  const gotNew = rows.filter((r) => /^line-2[6-9]|^line-30/.test(r.message)).length;
  check('beat 2: exactly the 5 appended lines are new', gotNew === 5, rows.map((r) => r.message).slice(-8));

  // --- Beat 3: rotation (rename away + fresh file → new inode baseline) --------
  const rn = await fsOp('rename', file, { targetPath: `${file}.1` }); // path=source, targetPath=dest
  check('renamed app.log → app.log.1 on host', rn.status === 200, rn.data);
  const w3 = await fsOp('write', file, { contentBase64: Buffer.from('rot-a\nrot-b\nrot-c\nrot-d\n').toString('base64') });
  check('wrote fresh 4-line app.log (new inode)', w3.status === 200, w3.data);

  await refresh();
  const n3 = await waitRows('rotation rows (+4)', 19);
  rows = await rowsFor();
  check(`beat 3: total is now 19 (${n3})`, n3 === 19 && rows.length === 19, rows.map((r) => r.message).slice(-6));
  const rots = rows.filter((r) => /^rot-[abcd]$/.test(r.message)).length;
  check('beat 3: all 4 lines of the rotated-in file ingested', rots === 4, rows.map((r) => r.message).slice(-8));

  // --- Beat 4: truncate (same inode shrinks → reset read from byte 0) ----------
  const w4 = await fsOp('write', file, { contentBase64: Buffer.from('t1\nt2\nt3\n').toString('base64') });
  check('truncated app.log to 3 short lines (same inode)', w4.status === 200, w4.data);

  await refresh();
  const n4 = await waitRows('truncate rows (+3)', 22);
  rows = await rowsFor();
  check(`beat 5: total is now 22 (${n4})`, n4 === 22 && rows.length === 22, rows.map((r) => r.message).slice(-6));
  const ts = rows.filter((r) => /^t[1-3]$/.test(r.message)).length;
  check('beat 5: t1..t3 each ingested exactly once', ts === 3, rows.map((r) => r.message).slice(-8));

  // --- Invariants --------------------------------------------------------------
  const dup = await pool.query(
    `SELECT COUNT(*)::int AS total, COUNT(DISTINCT "vendorEventId")::int AS "distinctIds" FROM security_events WHERE "appname" = $1`,
    [label],
  );
  const { total, distinctIds } = dup.rows[0] as { total: number; distinctIds: number };
  check('no duplicate vendorEventIds across all beats', total === distinctIds && total === 22, { total, distinctIds });

  const badScope = await pool.query(
    `SELECT COUNT(*)::int AS n FROM security_events WHERE "appname" = $1 AND ("deviceId" IS DISTINCT FROM $2 OR "hostname" IS DISTINCT FROM $3)`,
    [label, target.id, target.managementAddress ?? null],
  );
  check('every row carries the device id + management address hostname', (badScope.rows[0] as { n: number }).n === 0);

  // --- Cleanup (best-effort — a failed cleanup must not fail the run) ----------
  try {
    await fsOp('unlink', file).catch(() => undefined);
    await fsOp('unlink', `${file}.1`).catch(() => undefined);
    await fsOp('rmdir', dir).catch(() => undefined);
    const del = await authed('DELETE', `/devices/${target.id}/plugins/${SSH_PLUGIN_ID}/settings`);
    check('plugin options reset to defaults', del.status === 200, del.data);
    await pool.query(`DELETE FROM security_events WHERE "appname" = $1`, [label]);
    console.log('  cleanup: host files removed, settings reset, test rows deleted');
  } catch (e) {
    console.error('  WARN cleanup failed:', (e as Error).message);
  }

  await pool.end();
  console.log(failures === 0 ? '\nE2E FILE-TAIL: ALL PASS' : `\nE2E FILE-TAIL: ${failures} FAILURE(S)`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error('E2E crashed:', e);
  process.exit(1);
});
