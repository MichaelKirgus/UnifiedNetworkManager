/**
 * E2E — rotation-aware log tailing on a TrueNAS appliance (ix-truenas plugin).
 *
 * Non-invasive: no host files are created or modified. The test tails the
 * appliance's own /var/log/auth.log with a UNIQUE label and verifies:
 *   beat 1 — baseline ingests ≈N newest lines of an unseen file (live file →
 *            small race tolerance; the cap proves the budget, not exact count);
 *   scoping — every row carries the device id + management-address hostname;
 *   dedupe  — no duplicate vendorEventIds.
 *   beat 2 — SOFT check: natural growth picked up incrementally (auth.log only
 *            grows on SSH/auth activity; if none happens in the window this is
 *            reported as WARN, not FAIL — the grow→range-read path itself is
 *            covered deterministically by scripts/e2e-file-tail.ts on MAIL04).
 *
 * MERGE-SAFE settings handling: the device's current per-device override rows
 * are read from Postgres BEFORE the run and restored EXACTLY in cleanup (this
 * script may run against a device whose logSources is already configured by a
 * human — e.g. /var/log/*.log — which must survive the test).
 *
 * Run from repo root:  ./node_modules/.bin/tsx scripts/e2e-file-tail-truenas.ts
 * Env overrides: E2E_TRUENAS_DEVICE (default KIRGUSBANDE), API_BASE, DATABASE_URL.
 */

import { createRequire } from 'node:module';
import path from 'node:path';
import fs from 'node:fs';

const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const TRUENAS_PLUGIN_ID = '00000000-0000-4000-8000-000000000009';
const TARGET_DEVICE_NAME = process.env.E2E_TRUENAS_DEVICE ?? 'KIRGUSBANDE';
const LOG_FILE = '/var/log/auth.log'; // exists on SCALE, non-empty; grows on SSH activity
const BASELINE_LINES = 20;

function readApiToken(): string {
  const envPath = path.resolve(process.cwd(), '.env');
  if (!fs.existsSync(envPath)) throw new Error('no .env in repo root — cannot read UNM_API_TOKEN');
  const m = fs.readFileSync(envPath, 'utf8').match(/^UNM_API_TOKEN=(.+)$/m);
  if (!m) throw new Error('UNM_API_TOKEN not found in .env');
  return m[1].trim();
}

let failures = 0;
function check(what: string, ok: boolean, detail?: unknown): void {
  console.log(`  ${ok ? 'PASS' : 'FAIL'} ${what}${ok || detail === undefined ? '' : ` ${JSON.stringify(detail)}`}`);
  if (!ok) failures++;
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

  // --- Target device ----------------------------------------------------------
  const devices = (await authed<Array<{ id: string; name?: string; managementAddress?: string }>>('GET', '/devices')).data ?? [];
  const target = devices.find((d) => d.name === TARGET_DEVICE_NAME);
  check(`device ${TARGET_DEVICE_NAME} found`, Boolean(target), devices.map((d) => d.name));
  if (!target) throw new Error('target device not found');

  // Unique per run — no collision with leftovers from earlier runs.
  const runid = `fte2e${Date.now().toString(36).slice(-5)}`;
  const label = `fte2e-tru-${runid}`;

  /** Force one monitoring beat for the device. */
  const refresh = async (): Promise<void> => {
    await authed('POST', '/devices/refresh', { deviceIds: [target.id] }).catch(() => undefined);
  };

  /** One SSH exec on the appliance via the plugin's probe endpoint — may open a
   *  fresh pooled session (→ "Accepted publickey" line in auth.log) when none is
   *  idle. Best-effort growth stimulus for beat 2; never fails the run. */
  const sshStimulus = async (): Promise<void> => {
    await authed('GET', `/devices/${target.id}/probe?pluginId=${TRUENAS_PLUGIN_ID}&keys=deviceTime`).catch(() => undefined);
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

  // --- Merge-safe settings takeover --------------------------------------------
  // Read the device's CURRENT override rows (value column is JSON text) so we can
  // restore them EXACTLY in cleanup — a human may have configured logSources here.
  const origRows = await pool.query(
    `SELECT "optionKey", "value" FROM plugin_settings WHERE "deviceId" = $1 AND "pluginId" = $2`,
    [target.id, TRUENAS_PLUGIN_ID],
  );
  const originalSettings: Record<string, unknown> = {};
  for (const r of origRows.rows as Array<{ optionKey: string; value: string }>) {
    try { originalSettings[r.optionKey] = JSON.parse(r.value); } catch { /* keep raw */ originalSettings[r.optionKey] = r.value; }
  }

  // --- Merge-safe STATE takeover -------------------------------------------------
  // A human's live run may have left a file-tail state row for this host (cursors
  // for their /var/log/*.log files). My target file must start UNSEEN so beat 1 is
  // a deterministic baseline — remove ONLY the cursor for LOG_FILE from the blob,
  // keep the original, and restore it EXACTLY in cleanup. (If their pattern later
  // re-baselines the file, identical vendorEventIds are absorbed by API dedupe.)
  const hostKey = String(target.managementAddress ?? '').replace(/^https?:\/\//i, '');
  const stRow = await pool.query(
    `SELECT "value" AS v FROM plugin_state WHERE "namespace"='file-tail' AND "pluginId"=$1 AND "key"=$2`,
    [TRUENAS_PLUGIN_ID, hostKey],
  );
  let originalStateBlob: string | null = (stRow.rows[0] as { v?: unknown } | undefined)?.v as string | null;
  if (originalStateBlob) {
    await pool.query(
      `UPDATE plugin_state
       SET "value" = (jsonb_set("value"::jsonb, '{cursors}', ("value"::jsonb #> '{cursors}') - $3, false))::text
       WHERE "namespace"='file-tail' AND "pluginId"=$1 AND "key"=$2`,
      [TRUENAS_PLUGIN_ID, hostKey, LOG_FILE],
    );
    console.log(`  (removed pre-existing ${LOG_FILE} cursor from the state blob; original saved for restore)`);
  }

  const setRes = await authed('PUT', `/devices/${target.id}/plugins/${TRUENAS_PLUGIN_ID}/settings`, {
    settings: { ...originalSettings, logSources: `${LOG_FILE} ${label}`, logTailIntervalMs: 10_000, logTailBaselineLines: BASELINE_LINES },
  });
  check('plugin options accepted (merged over existing overrides)', setRes.status === 200, setRes.data);

  // --- Beat 1: baseline of an unseen file --------------------------------------
  // auth.log is LIVE (SSH activity), so a second beat can race in within the
  // throttle window — assert "baseline happened" as ≈N rows; the cap proves the
  // budget works (a whole-file ingest would be hundreds of thousands of lines).
  await refresh();
  const n1 = await waitRows(`baseline rows (newest ${BASELINE_LINES} lines)`, BASELINE_LINES);
  let rows = await rowsFor();
  check(
    `beat 1: baseline ingested ≈${BASELINE_LINES} lines, not the whole file (${n1})`,
    n1 >= BASELINE_LINES && n1 < BASELINE_LINES + 80,
    { have: n1, sample: rows.map((r) => r.message).slice(0, 2) },
  );

  // --- Scoping + dedupe invariants (on beat-1 rows) -----------------------------
  const badScope = await pool.query(
    `SELECT COUNT(*)::int AS n FROM security_events WHERE "appname" = $1 AND ("deviceId" IS DISTINCT FROM $2 OR "hostname" IS DISTINCT FROM $3)`,
    [label, target.id, target.managementAddress ?? null],
  );
  check('every row carries the device id + management address hostname', (badScope.rows[0] as { n: number }).n === 0);

  const dup = await pool.query(
    `SELECT COUNT(*)::int AS total, COUNT(DISTINCT "vendorEventId")::int AS "distinctIds" FROM security_events WHERE "appname" = $1`,
    [label],
  );
  const { total, distinctIds } = dup.rows[0] as { total: number; distinctIds: number };
  check('no duplicate vendorEventIds', total === distinctIds && total >= BASELINE_LINES, { total, distinctIds });

  // --- Beat 2 (SOFT): natural growth picked up incrementally --------------------
  // auth.log only grows on SSH/auth activity. Stimulate with periodic probe calls
  // (a fresh pooled session logs "Accepted publickey") and wait generously. If
  // nothing happens in the window this is a WARN, not a FAIL — the grow→range-read
  // path is covered deterministically by scripts/e2e-file-tail.ts (MAIL04).
  const growthDeadline = Date.now() + 180_000;
  let grown = n1;
  while (Date.now() < growthDeadline) {
    await sshStimulus();
    await refresh();
    await sleep(20_000);
    const r = await pool.query(`SELECT COUNT(*)::int AS n FROM security_events WHERE "appname" = $1`, [label]);
    grown = (r.rows[0] as { n: number }).n;
    if (grown > n1) break;
  }
  rows = await rowsFor();
  if (grown > n1) {
    check(`beat 2: file growth picked up incrementally (+${grown - n1} lines)`, true);
  } else {
    console.log('  WARN beat 2: no auth activity in the 180 s window — growth path not exercised here (covered by e2e-file-tail.ts on MAIL04)');
  }

  // --- Cleanup (best-effort — a failed cleanup must not fail the run) ----------
  try {
    if (Object.keys(originalSettings).length > 0) {
      const restore = await authed('PUT', `/devices/${target.id}/plugins/${TRUENAS_PLUGIN_ID}/settings`, { settings: originalSettings });
      check('original plugin options restored exactly', restore.status === 200, restore.data);
    } else {
      const del = await authed('DELETE', `/devices/${target.id}/plugins/${TRUENAS_PLUGIN_ID}/settings`);
      check('plugin options reset to defaults (none were set)', del.status === 200, del.data);
    }
    // Restore the original file-tail state blob exactly (their cursors + lastReadAt).
    if (originalStateBlob) {
      await pool.query(
        `UPDATE plugin_state SET "value"=$3 WHERE "namespace"='file-tail' AND "pluginId"=$1 AND "key"=$2`,
        [TRUENAS_PLUGIN_ID, hostKey, originalStateBlob],
      );
    } else {
      await pool.query(
        `DELETE FROM plugin_state WHERE "namespace"='file-tail' AND "pluginId"=$1 AND "key"=$2`,
        [TRUENAS_PLUGIN_ID, hostKey],
      );
    }
    await pool.query(`DELETE FROM security_events WHERE "appname" = $1`, [label]);
    console.log('  cleanup: settings + state blob restored, test rows deleted');
  } catch (e) {
    console.error('  WARN cleanup failed:', (e as Error).message);
  }

  await pool.end();
  console.log(failures === 0 ? '\nE2E FILE-TAIL TRUENAS: ALL PASS' : `\nE2E FILE-TAIL TRUENAS: ${failures} FAILURE(S)`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error('E2E crashed:', e);
  process.exit(1);
});
