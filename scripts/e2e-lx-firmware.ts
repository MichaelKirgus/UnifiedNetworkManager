/**
 * e2e-lx-firmware.ts — end-to-end verification of the LCOS-LX firmware update feature.
 *
 * SAFE MODE (default) — touches AP_Wohnzimmer only with READS + REJECTED/no-op prefights:
 *   1. device exists, has a selected hardware model, is assigned to the LX plugin
 *   2. the deployed plugin catalog contains firmware.update (dangerous, no re-dispatch,
 *      repoFileId+url sources) and the onlineUpdateFeed option defaults to enabled
 *   3a. ONLINE FEED: the plugin's Updates row matches what LANCOM's public release
 *       server actually publishes for this model right now (fetched independently by
 *       this script — a newer feed version must yield an actionable url row, an equal
 *       one must not)
 *   3b. a dummy .upx uploaded to the file repo (category firmware) shows up as an
 *      actionable updates row after a forced device refresh (repo → /monitoring wiring)
 *   4. NEGATIVE model guard: a plan flashing a WRONG-MODEL image fails in preflight
 *      before anything is uploaded (executed through the real 2FA-gated plan path;
 *      the auto-prepended config.backup.download step runs first and succeeds)
 *   4b. URL SOURCE no-op: when feed version == live version, a plan with `url` input
 *       succeeds as an idempotent no-op (schema + preflight accept url; nothing is
 *       downloaded or flashed — safe mode never flashes)
 *   5. cleanup of everything created (dummy files + plans); the config backup file
 *      is KEPT as a rollback point
 *
 * LIVE MODE — the actual flash, only with an explicit env flag:
 *   LX_FW_E2E_LIVE=1 (+ either LX_FW_FILE=/path/to/LC-LX-6500-7.20.0192-RU1.upx to
 *   upload first, or LX_FW_REPO_FILE_ID=<id> for an already-uploaded image) creates
 *   and executes the real plan on the device and verifies the new version post-reboot.
 *
 * Prereqs: dev stack up (docker compose -f docker-compose.dev.yml), AP_Wohnzimmer
 * reachable, admin TOTP in the DB (minted codes via otplib v13 — no browser login).
 *
 * Usage (from the repo root):
 *   npx tsx scripts/e2e-lx-firmware.ts                 # safe mode
 *   LX_FW_E2E_LIVE=1 LX_FW_FILE=$HOME/Downloads/LC-LX-6500-7.20.0192-RU1.upx \
 *     npx tsx scripts/e2e-lx-firmware.ts               # real flash (DOWNTIME!)
 */

import path from 'node:path';
import fs from 'node:fs';
import crypto from 'node:crypto';
import { execSync } from 'node:child_process';
import { createRequire } from 'node:module';

const API = process.env.UNM_API_URL ?? 'http://localhost:3000/v1';
/** Ephemeral DB user for the 2FA-gated plan endpoints — created + deleted per run. */
const E2E_USERNAME = 'e2e';
const DEVICE_NAME = process.env.LX_FW_DEVICE ?? 'AP_Wohnzimmer';
const LX_PLUGIN_UUID = '00000000-0000-4000-8000-000000000004';
const LIVE = process.env.LX_FW_E2E_LIVE === '1';
const REAL_FILE = process.env.LX_FW_FILE ?? '';
const REAL_REPO_ID = process.env.LX_FW_REPO_FILE_ID ?? '';
/** LIVE mode alternative: flash straight from a URL (broker download) instead of a repo upload. */
const LIVE_URL = process.env.LX_FW_URL ?? '';
/** LANCOM's public release server — the same endpoint the plugin's feed uses by default. */
const FEED_BASE = 'https://ftp.lancom.de/LANCOM-Releases';
/**
 * Version baked into the dummy file names. Must be STRICTLY newer than whatever
 * firmware the device is running (findRepoFirmwareTarget only offers strictly
 * newer builds) — so use a far-future version instead of a real one, which would
 * stop producing an Updates row once a live flash has brought the device up to it.
 */
const DUMMY_VERSION = '9.99.9999';

// pg + otplib live in api/node_modules — resolve through the API package.
const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));

let passed = 0;
let failed = 0;
function check(label: string, ok: boolean, detail?: unknown): void {
  if (ok) {
    passed++;
    console.log(`  ✅ ${label}`);
  } else {
    failed++;
    console.log(`  ❌ ${label}${detail !== undefined ? ` — ${JSON.stringify(detail).slice(0, 400)}` : ''}`);
  }
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** Coarse version compare for E2E assertions — numeric dot segments only ("7.20.0192-RU1" → [7,20,192]). */
function verCmp(a: string, b: string): number {
  const norm = (v: string) => v.split('.').map((p) => parseInt(p, 10)).filter((n) => Number.isFinite(n));
  const [na, nb] = [norm(a), norm(b)];
  for (let i = 0; i < Math.max(na.length, nb.length); i++) {
    const d = (na[i] ?? 0) - (nb[i] ?? 0);
    if (d !== 0) return d > 0 ? 1 : -1;
  }
  return 0;
}

/** Fetches LANCOM's release listing for a model from the HOST (independent of the plugin's egress path). */
async function fetchFeedVersion(modelDigits: string): Promise<{ version: string; fileName: string } | null> {
  try {
    const res = await fetch(`${FEED_BASE}/LC-LX-${modelDigits}/`);
    if (!res.ok) return null;
    const html = await res.text();
    const re = /<a\s+href="([^"]+\.upx)"[^>]*>[^<]*<\/a>\s*\d{2}-[A-Za-z]{3}-\d{4}\s+\d{2}:\d{2}\s+(\d+)/g;
    let best: { version: string; fileName: string } | null = null;
    let m: RegExpExecArray | null;
    while ((m = re.exec(html)) !== null) {
      const v = m[1].match(/LC-LX-\d{3,4}[-_](.+?)\.upx$/i)?.[1] ?? '';
      if (!v || (best && verCmp(best.version, v) >= 0)) continue;
      best = { version: v, fileName: m[1] };
    }
    return best;
  } catch {
    return null; // host has no egress — the feed check is skipped by the caller
  }
}

/**
 * Mints a JWT for the 2FA-gated plan endpoints WITHOUT touching any real account:
 * creates an ephemeral `e2e` user (random password + fresh TOTP secret, admin role,
 * explicit permissions copied from the seeded admin), logs in through the REAL
 * two-step flow (password → challenge → minted TOTP code via otplib v13), and
 * deletes the user again. The JWT is stateless — it stays valid after deletion.
 */
async function login(): Promise<string> {
  const { Pool } = apiRequire('pg');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm' });
  try {
    const bcrypt = apiRequire('bcryptjs') as { hashSync: (s: string, cost: number) => string };
    const otplib = apiRequire('otplib') as { generateSecret: () => string; generateSync: (opts: { strategy: string; secret: string }) => string };

    // Replace a leftover from a crashed run — the e2e account is always ephemeral.
    await pool.query(`DELETE FROM users WHERE username = $1`, [E2E_USERNAME]);
    const adminPerms = (await pool.query(`SELECT permissions FROM users WHERE username = 'admin'`)).rows[0]?.permissions ?? '[]';
    const password = `e2e-${crypto.randomBytes(16).toString('hex')}`;
    const totpSecret = otplib.generateSecret();
    await pool.query(
      `INSERT INTO users (id, username, "passwordHash", "totpSecret", roles, permissions, "createdAt", disabled, "deviceScope")
       VALUES ($1, $2, $3, $4, '["admin"]', $5, $6, false, '{}')`,
      [crypto.randomUUID(), E2E_USERNAME, bcrypt.hashSync(password, 10), totpSecret, adminPerms, new Date().toISOString()]
    );

    const r1 = await fetch(`${API}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: E2E_USERNAME, password }) });
    const j1 = (await r1.json().catch(() => null)) as { accessToken?: string; challengeToken?: string } | null;
    if (!r1.ok || !j1) throw new Error(`login step 1 failed: HTTP ${r1.status} ${JSON.stringify(j1).slice(0, 300)}`);
    if (j1.accessToken && !j1.challengeToken) return j1.accessToken; // no 2FA required — direct token

    const code = otplib.generateSync({ strategy: 'totp', secret: totpSecret });
    const r2 = await fetch(`${API}/auth/2fa/verify`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ challengeToken: j1.challengeToken ?? '', totpCode: code }) });
    return ((await r2.json().catch(() => null)) as { accessToken?: string } | null)?.accessToken ?? '';
  } finally {
    await pool.query(`DELETE FROM users WHERE username = $1`, [E2E_USERNAME]).catch(() => undefined);
    await pool.end();
  }
}

/** Uploads raw bytes to the file repo (octet-stream + x-file-name header contract). */
async function uploadFile(token: string, name: string, data: Buffer, category = 'firmware'): Promise<{ id: string; sha256?: string | null }> {
  const res = await fetch(`${API}/files`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/octet-stream', Authorization: `Bearer ${token}`, 'x-file-name': name, 'x-file-category': category },
    body: new Uint8Array(data),
  });
  const json = (await res.json().catch(() => null)) as { file?: { id: string; sha256?: string | null } } | null;
  if (!res.ok || !json?.file) throw new Error(`upload ${name} failed: HTTP ${res.status} ${JSON.stringify(json).slice(0, 300)}`);
  return json.file;
}

async function main(): Promise<void> {
  console.log(`e2e-lx-firmware — device=${DEVICE_NAME} live=${LIVE ? 'YES (REAL FLASH)' : 'no (safe mode)'}`);
  const token = await login();
  check('authenticated', Boolean(token));
  if (!token) process.exit(2);

  const authed = async (method: string, p: string, body?: unknown): Promise<{ status: number; json: () => Promise<any> }> => {
    const res = await fetch(`${API}${p}`, {
      method,
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return { status: res.status, json: async () => (await res.json().catch(() => null)) as never };
  };

  // --- 1. Device -----------------------------------------------------------------
  const devices = await authed('GET', '/devices').then((r) => r.json());
  const device = (Array.isArray(devices) ? devices : []).find((d: { name?: string }) => d.name === DEVICE_NAME);
  check(`device ${DEVICE_NAME} found`, Boolean(device), devices?.length ?? 'no list');
  if (!device) process.exit(2);

  const modelDigits = String(device.model ?? '').match(/(\d{3,4})/)?.[1] ?? null;
  check('device has a selected hardware model', Boolean(modelDigits), device.model ?? '(null — set it on the Devices page first)');
  if (!modelDigits) process.exit(2);

  // --- 2. Catalog -----------------------------------------------------------------
  const catalog = await authed('GET', `/plugins/${LX_PLUGIN_UUID}/actions`).then((r) => r.json());
  const actions: Array<Record<string, any>> = (catalog?.actions ?? []) as Array<Record<string, any>>;
  const fwAction = actions.find((a) => a.id === 'firmware.update');
  check('catalog contains firmware.update', Boolean(fwAction), actions.map((a) => a.id).slice(0, 40));
  if (fwAction) {
    check('action is riskLevel dangerous', fwAction.riskLevel === 'dangerous', fwAction.riskLevel);
    check('action has retryOnDispatchFailure=false', fwAction.retryOnDispatchFailure === false, fwAction.retryOnDispatchFailure);
    check('inputSchema exposes repoFileId + url sources', Boolean(fwAction.inputSchema?.repoFileId) && Boolean(fwAction.inputSchema?.url), fwAction.inputSchema ?? null);
  }

  // The online feed must be a plugin option, defaulting to ENABLED.
  const optsRes = await authed('GET', `/plugins/${LX_PLUGIN_UUID}/options`);
  const optsBody: any = await optsRes.json();
  const feedOpt: any = (optsBody?.options ?? []).find((o: any) => o.key === 'onlineUpdateFeed');
  check('plugin option onlineUpdateFeed exists', Boolean(feedOpt), optsBody?.options?.map((o: any) => o.key));
  if (feedOpt) {
    check('onlineUpdateFeed is boolean, default enabled', feedOpt.type === 'boolean' && feedOpt.default === true, feedOpt);
    check('onlineUpdateFeed effective value is not disabled', optsBody?.effectiveValues?.onlineUpdateFeed !== false, optsBody?.effectiveValues ?? null);
  }

  // --- 3. Dummy file → actionable updates row --------------------------------------
  const dummyName = `LC-LX-${modelDigits}-${DUMMY_VERSION}.upx`;
  const dummyData = Buffer.alloc(4096, 0); // content is irrelevant — never flashed in safe mode
  let dummyId: string | null = null;
  let wrongId: string | null = null;

  // The updates-row check needs a REAL /monitoring poll to run — and polling is
  // skipped for disabled devices (this dev stack intentionally disables most of
  // its fleet). Temporarily re-enable the target device; restored in finally.
  const { Pool } = apiRequire('pg');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm' });
  let wasDisabled = false;
  try {
    const enRow = (await pool.query(`SELECT enabled FROM devices WHERE id = $1`, [device.id])).rows[0] as { enabled?: boolean } | undefined;
    if (enRow && enRow.enabled === false) {
      await pool.query(`UPDATE devices SET enabled = true WHERE id = $1`, [device.id]);
      wasDisabled = true;
      console.log('  … temporarily enabling device polling (was disabled — restored at the end)');
    }

    // --- 3a. Online release feed — assert against what LANCOM publishes RIGHT NOW --
    // Independent ground truth: this script fetches the vendor listing from the host
    // (plain internet egress) and compares it with the row the plugin produced via its
    // own brokered path. A strictly-newer feed version must yield an actionable url
    // row; an equal/older one must not.
    const t0 = Date.now();
    let feedRefresh = await authed('POST', '/devices/refresh', { deviceIds: [device.id] });
    if (!(feedRefresh.status === 200 || feedRefresh.status === 202)) {
      await sleep(15_000); // plugin still starting — one retry
      feedRefresh = await authed('POST', '/devices/refresh', { deviceIds: [device.id] });
    }
    check('forced device refresh accepted (feed phase)', feedRefresh.status === 200 || feedRefresh.status === 202, feedRefresh.status);

    const feedInfo = await fetchFeedVersion(modelDigits!);
    let liveCore: string | null = null; // hoisted — section 4b (url no-op) needs it too
    if (!feedInfo) {
      console.log('  … skipping online-feed assertion (host could not reach ftp.lancom.de)');
    } else {
      let feedRow: any = null;
      const deadline = Date.now() + 90_000; // first poll may include a cold feed fetch (≤15 s)
      while (Date.now() < deadline && !liveCore) {
        await sleep(5_000);
        const r = await pool.query(`SELECT metrics, "collectedAt" FROM telemetry WHERE "deviceId" = $1 ORDER BY "collectedAt" DESC LIMIT 1`, [device.id]);
        if (!r.rows[0] || new Date(r.rows[0].collectedAt).getTime() <= t0) continue;
        let m: any;
        try { m = JSON.parse(r.rows[0].metrics); } catch { continue; }
        const sw = typeof m?.['system.swVersion'] === 'string' ? (m['system.swVersion'] as string) : null;
        if (!sw) continue;
        liveCore = sw.split(' / ')[0].trim();
        feedRow = (Array.isArray(m.updates) ? m.updates : []).find((u: any) => u.kind === 'firmware' && u.applyActionId === 'firmware.update') ?? null;
      }
      check('telemetry carries the live swVersion', Boolean(liveCore), '(no fresh telemetry within 90s)');
      if (liveCore) {
        const feedNewer = verCmp(feedInfo.version, liveCore) > 0;
        if (feedNewer) {
          check('newer vendor release → actionable url row', Boolean(feedRow), feedRow ?? '(no firmware.update row within 90s)');
          if (feedRow) {
            check('row points at the vendor URL', typeof feedRow.applyInput?.url === 'string' && feedRow.applyInput.url.includes(`${FEED_BASE}/LC-LX-${modelDigits}/`), feedRow.applyInput);
            check('row carries the file name for preflight', feedRow.applyInput?.fileName === feedInfo.fileName, feedRow.applyInput);
          }
        } else {
          check(`vendor release not newer than live (${feedInfo.version} vs ${liveCore}) → no actionable row`, !feedRow, feedRow ?? null);
        }
      }
    }

    const uploaded = await uploadFile(token, dummyName, dummyData);
    dummyId = uploaded.id;
    check(`dummy ${dummyName} uploaded to repo`, Boolean(dummyId), uploaded);

    // Clear the plugin's in-memory repo-list TTL cache so the forced refresh sees
    // the fresh file immediately (repeated runs would otherwise hit a stale list).
    if (!process.env.LX_FW_E2E_NO_RESTART) {
      console.log('  … restarting lancom-lx-plugin (clears repo-list cache)');
      execSync('docker compose -f docker-compose.dev.yml restart lancom-lx-plugin', { cwd: process.cwd(), stdio: 'pipe' });
      await sleep(10_000); // give the plugin a moment to come back up
    }

    let refresh = await authed('POST', '/devices/refresh', { deviceIds: [device.id] });
    if (!(refresh.status === 200 || refresh.status === 202)) {
      await sleep(15_000); // plugin still starting — one retry
      refresh = await authed('POST', '/devices/refresh', { deviceIds: [device.id] });
    }
    check('forced device refresh accepted', refresh.status === 200 || refresh.status === 202, refresh.status);

    // Wait for the telemetry row carrying the actionable updates entry.
    let row: any = null;
    const deadline = Date.now() + 120_000;
    while (Date.now() < deadline && !row) {
      await sleep(5_000);
      const r = await pool.query(`SELECT metrics FROM telemetry WHERE "deviceId" = $1 ORDER BY "collectedAt" DESC LIMIT 1`, [device.id]);
      if (!r.rows[0]) continue;
      let m: any;
      try { m = JSON.parse(r.rows[0].metrics); } catch { continue; }
      const updates = Array.isArray(m?.updates) ? m.updates : [];
      row = updates.find((u: any) => u.kind === 'firmware' && u.applyActionId === 'firmware.update') ?? null;
    }
    check('updates row is actionable (repo file matched)', Boolean(row), row ?? '(no firmware.update row within 120s)');
    if (row) {
      check('row points at the dummy repo file', row.applyInput?.repoFileId === dummyId, row.applyInput);
      check('row shows target version from file name', row.latestVersion === DUMMY_VERSION, row.latestVersion);
      check('row carries sizeBytes', typeof row.sizeBytes === 'number' && row.sizeBytes > 0, row.sizeBytes);

      // The Updates page's data source must expose the SAME actionable row — it is
      // what the Files-page "Flash devices…" deep link (?file=<id>) filters on.
      const updRes = await authed('GET', '/updates');
      const updBody: any = await updRes.json();
      const updRows: Array<any> = updBody?.rows ?? [];
      const updRow = updRows.find((u) => u.deviceId === device.id && u.applyActionId === 'firmware.update' && u.applyInput?.repoFileId === dummyId);
      check('GET /updates exposes the actionable row for the repo file', Boolean(updRow), updRow ?? `no matching row among ${updRows.length} rows`);
    }

    // --- 4. Negative model guard through the real plan path -------------------------
    const wrongDigits = modelDigits === '6400' ? '6500' : '6400';
    const wrongName = `LC-LX-${wrongDigits}-${DUMMY_VERSION}.upx`;
    try {
      // Distinct bytes on purpose — identical content would be DEDUPLICATED by the
      // repo into the primary dummy's id and defeat the model-mismatch scenario.
      const uploaded = await uploadFile(token, wrongName, Buffer.alloc(4096, 0x42));
      wrongId = uploaded.id;

      const planRes = await authed('POST', '/plans', {
        pluginId: LX_PLUGIN_UUID,
        intentActionId: 'firmware.update',
        inputs: { repoFileId: wrongId },
        devices: [{ deviceId: device.id }],
      });
      const plan = await planRes.json();
      check('plan created (wrong-model image)', planRes.status === 201 || planRes.status === 200, { status: planRes.status, plan });
      if (!plan?.id) throw new Error(`no plan id: ${JSON.stringify(plan).slice(0, 300)}`);

      const exec = await authed('POST', `/plans/${plan.id}/execute`);
      check('plan execution started', exec.status === 200 || exec.status === 202, exec.status);

      let planState: any = null;
      const deadline = Date.now() + 180_000;
      while (Date.now() < deadline) {
        await sleep(5_000);
        planState = await authed('GET', `/plans/${plan.id}`).then((r) => r.json());
        if (['succeeded', 'failed', 'cancelled'].includes(planState?.status)) break;
      }
      check('plan finished FAILED (model guard tripped)', planState?.status === 'failed', planState?.status);
      const steps: Array<any> = planState?.steps ?? [];
      const fwStep = steps.find((s) => s.actionId === 'firmware.update');
      const backupStep = steps.find((s) => s.actionId === 'config.backup.download');
      check('auto-prepended config backup step ran first', Boolean(backupStep), steps.map((s) => `${s.actionId}:${s.status}`));
      // planSteps.result stores {success, result: <ActionResult>} — the error lives one level deeper.
      const errText = String(fwStep?.result?.result?.error ?? fwStep?.result?.error ?? '');
      check('firmware step rejected the wrong-model image in preflight', /for model \d{3,4}/.test(errText) && !/staged|upload/i.test(errText), errText.slice(0, 300));

      // Cleanup: delete this plan (the backup file stays as a rollback point).
      await authed('DELETE', `/plans/${plan.id}`);
    } catch (e) {
      check('negative model-guard plan flow', false, e instanceof Error ? e.message : String(e));
    }

    // --- 4b. URL source — idempotent no-op (schema + preflight, zero egress) ---------
    // Only when the vendor's newest release EQUALS the live version: then a url-input
    // plan must succeed as a no-op BEFORE any download happens. When the feed is newer
    // we skip on purpose — safe mode must never risk a real flash. (Version compare,
    // not string equality — the device reports "7.20.0192RU1", the file name says
    // "7.20.0192-RU1".)
    if (feedInfo && liveCore && verCmp(feedInfo.version, liveCore) === 0) {
      const urlName = `LC-LX-${modelDigits}-${feedInfo.version}.upx`;
      try {
        const planRes = await authed('POST', '/plans', {
          pluginId: LX_PLUGIN_UUID,
          intentActionId: 'firmware.update',
          inputs: { url: `${FEED_BASE}/LC-LX-${modelDigits}/${urlName}`, fileName: urlName },
          devices: [{ deviceId: device.id }],
        });
        const plan = await planRes.json();
        check('plan created (url source, same version)', planRes.status === 201 || planRes.status === 200, { status: planRes.status, plan });
        if (plan?.id) {
          const exec = await authed('POST', `/plans/${plan.id}/execute`);
          check('url-source plan execution started', exec.status === 200 || exec.status === 202, exec.status);
          let planState: any = null;
          const deadline = Date.now() + 180_000;
          while (Date.now() < deadline) {
            await sleep(5_000);
            planState = await authed('GET', `/plans/${plan.id}`).then((r) => r.json());
            if (['succeeded', 'failed', 'cancelled'].includes(planState?.status)) break;
          }
          const steps: Array<any> = planState?.steps ?? [];
          const fwStep = steps.find((s) => s.actionId === 'firmware.update');
          const fwResult = (fwStep?.result?.result ?? fwStep?.result ?? {}) as Record<string, unknown>;
          check('url-source plan succeeded as no-op (nothing downloaded or flashed)', planState?.status === 'succeeded' && fwResult.success === true && fwResult.applied === false, { status: planState?.status, details: fwResult.details ?? null });
          await authed('DELETE', `/plans/${plan.id}`);
        }
      } catch (e) {
        check('url-source no-op plan flow', false, e instanceof Error ? e.message : String(e));
      }
    } else {
      console.log(`  … skipping url-source no-op test (feed ${feedInfo?.version ?? 'unknown'} ≠ live — safe mode must never flash)`);
    }

    // --- LIVE MODE: the real flash ---------------------------------------------------
    if (LIVE) {
      let liveRepoId = REAL_REPO_ID;
      if (!liveRepoId && !LIVE_URL && REAL_FILE) {
        console.log(`  … uploading ${REAL_FILE} (${fs.statSync(REAL_FILE).size} bytes)`);
        const up = await uploadFile(token, path.basename(REAL_FILE), fs.readFileSync(REAL_FILE));
        liveRepoId = up.id;
      }
      if (!liveRepoId && !LIVE_URL) {
        check('LIVE mode needs LX_FW_REPO_FILE_ID, LX_FW_FILE or LX_FW_URL', false);
      } else {
        const planRes = await authed('POST', '/plans', {
          pluginId: LX_PLUGIN_UUID,
          intentActionId: 'firmware.update',
          inputs: liveRepoId ? { repoFileId: liveRepoId } : { url: LIVE_URL, fileName: path.basename(LIVE_URL) },
          devices: [{ deviceId: device.id }],
        });
        const plan = await planRes.json();
        check('live flash plan created', Boolean(plan?.id), plan);
        if (plan?.id) {
          await authed('POST', `/plans/${plan.id}/execute`);
          console.log(`  … waiting for the real flash + reboot (up to 25 min)`);
          let planState: any = null;
          const deadline = Date.now() + 1_500_000;
          while (Date.now() < deadline) {
            await sleep(15_000);
            planState = await authed('GET', `/plans/${plan.id}`).then((r) => r.json());
            if (['succeeded', 'failed', 'cancelled'].includes(planState?.status)) break;
          }
          const steps: Array<any> = planState?.steps ?? [];
          const fwStep = steps.find((s) => s.actionId === 'firmware.update');
          // planSteps.result stores {success, result: <ActionResult>} — one level deeper.
          const fwResult = (fwStep?.result?.result ?? fwStep?.result ?? {}) as Record<string, unknown>;
          check('live flash succeeded + verified', planState?.status === 'succeeded' && fwResult.verified === true, { status: planState?.status, details: fwResult.details ?? null });
        }
      }
    }

    // --- 5. Cleanup -------------------------------------------------------------------
    if (dummyId) {
      const del = await authed('DELETE', `/files/${dummyId}`);
      check('cleanup: dummy file deleted', del.status === 200 || del.status === 204, del.status);
    }
    if (wrongId) {
      const del = await authed('DELETE', `/files/${wrongId}`);
      check('cleanup: wrong-model file deleted', del.status === 200 || del.status === 204, del.status);
    }
  } finally {
    // Never leave dummies behind on a crash — and restore the polling flag.
    if (dummyId) await authed('DELETE', `/files/${dummyId}`).catch(() => undefined);
    if (wrongId) await authed('DELETE', `/files/${wrongId}`).catch(() => undefined);
    if (wasDisabled) {
      await pool.query(`UPDATE devices SET enabled = false WHERE id = $1`, [device.id]).catch(() => undefined);
      console.log('  … restored device polling to disabled');
    }
    await pool.end().catch(() => undefined);
  }

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed > 0 ? 1 : 0);
}

main().catch((e) => {
  console.error('FATAL', e);
  process.exit(2);
});
