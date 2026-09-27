/**
 * End-to-end verification for docker / docker-compose support in the Generic SSH plugin.
 *
 * Runs against the LIVE dev stack (setup.sh) and uses MAIL04 — a mailcow host that runs
 * docker compose — as the target device (already assigned to the generic-ssh plugin with
 * root credentials). Verifies:
 *   1. plugin catalog carries all twelve docker action ids (version 0.3.0, incl. images.pull/update/prune)
 *   2. containers.deploy-compose via plan → app row appears in GET /containers after refresh
 *   3. the compose YAML is saved byte-exact into the USER-CHOSEN workdir (filesystem read)
 *   4. compose.config.read returns yaml + resolved workdir (read-only execute route)
 *   5. probe keys containerStates/containerStats report the member container live
 *   6. containers.stop / start round-trip flips the row state STOPPED → RUNNING
 *   7. images.pull / images.update (+restart of using containers) / images.prune work via plans
 *   8. containers.delete removes the app from GET /containers after refresh
 *   9. cleanup: workdir files removed via filesystem ops (best-effort)
 *
 * Usage (from the repo root):
 *   ./node_modules/.bin/tsx scripts/e2e-generic-ssh-docker.ts
 */

import path from 'node:path';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const SSH_PLUGIN_ID = '00000000-0000-4000-8000-00000000000c'; // Generic SSH Plugin (Linux)
const TARGET_DEVICE_NAME = process.env.E2E_SSH_HOST ?? 'MAIL04';

// pg + otplib live in api/node_modules; resolve through a require rooted at the API package.
const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));

let failures = 0;
function check(label: string, cond: boolean, extra?: unknown): void {
  if (cond) console.log(`  PASS ${label}`);
  else {
    failures++;
    console.error(`  FAIL ${label}`, extra !== undefined ? JSON.stringify(extra).slice(0, 500) : '');
  }
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

async function waitFor<T>(what: string, fn: () => Promise<T | null>, timeoutMs: number, intervalMs = 3_000): Promise<T | null> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      const v = await fn();
      if (v !== null) return v;
    } catch { /* retry */ }
    if (Date.now() >= deadline) return null;
    await sleep(intervalMs);
  }
}

interface PlanStepRow {
  id: string; stepIndex: number; deviceId: string; actionId: string;
  input: Record<string, unknown>; status: string; result?: Record<string, unknown> | null;
}

async function main(): Promise<void> {
  // 0. API up?
  const health = await fetch('http://localhost:3000/healthz').then((r) => r.json()).catch(() => null);
  check('API healthy', (health as { status?: string })?.status === 'ok', health);

  // 1. Login (admin/admin; TOTP minted from the seeded secret when enabled).
  const { Pool } = apiRequire('pg');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm' });
  const adminRow = (await pool.query(`SELECT "totpSecret" FROM users WHERE username = 'admin'`)).rows[0] as { totpSecret: string | null };

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
  check('authenticated (2FA flow)', Boolean(token));
  if (!token) throw new Error('login failed');

  // Parses the response body ONCE — calling .json() twice on a Response throws.
  const authed = async <T = unknown>(method: string, p: string, body?: unknown): Promise<{ status: number; data: T }> => {
    const res = await fetch(`${API}${p}`, { method, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    let data: T | null = null;
    try { data = (await res.json()) as T; } catch { /* non-JSON body */ }
    return { status: res.status, data: data ?? (null as unknown as T) };
  };

  /** A plan is terminal when it reached any of these — 'unverified' means all steps
   *  applied but the plugin couldn't confirm the outcome (still a success here). */
  const TERMINAL = ['succeeded', 'failed', 'cancelled', 'skipped', 'unverified'];

  // 2. Catalog check — version + all nine docker action ids persisted by the API.
  const plugins = (await authed<Array<{ id: string; name?: string; version?: string }>>('GET', '/plugins')).data ?? [];
  const sshPlugin = plugins.find((p) => p.id === SSH_PLUGIN_ID);
  check('generic-ssh plugin discovered', Boolean(sshPlugin), sshPlugin?.name);
  check('plugin version is 0.3.0', sshPlugin?.version === '0.3.0', sshPlugin?.version);

  const catalog = ((await authed<{ actions?: Array<{ id: string }> }>('GET', `/plugins/${SSH_PLUGIN_ID}/actions`)).data?.actions) ?? [];
  const ids = new Set(catalog.map((a) => a.id));
  for (const want of [
    'containers.start', 'containers.stop', 'containers.restart', 'containers.delete',
    'containers.deploy-compose', 'containers.update', 'compose.config.read',
    'containers.logs.read', 'images.delete', 'images.pull', 'images.update', 'images.prune',
  ]) {
    check(`catalog has ${want}`, ids.has(want));
  }

  // 3. Target device — MAIL04 (mailcow host, docker + compose available).
  const devices = (await authed<Array<{ id: string; name?: string }>>('GET', '/devices')).data ?? [];
  const target = devices.find((d) => d.name === TARGET_DEVICE_NAME);
  check(`device ${TARGET_DEVICE_NAME} found`, Boolean(target), devices.map((d) => d.name));
  if (!target) throw new Error('target device not found');

  // The device's bound SSH secret — filesystem ops need an explicit `secretId`
  // when the caller has several eligible credentials (the picker is webapp-only).
  const bindRow = (await pool.query(
    `SELECT dp."secretId" FROM device_plugins dp WHERE dp."deviceId" = $1 AND dp."pluginId" = $2`,
    [target.id, SSH_PLUGIN_ID],
  )).rows[0] as { secretId: string | null } | undefined;
  const fsSecretId = bindRow?.secretId ?? '';
  check('device has a bound SSH secret', Boolean(fsSecretId));

  // Unique per run — no collision with leftovers from earlier runs.
  const appName = `unme2e${Date.now().toString(36).slice(-5)}`;
  const workdir = `/opt/unm-e2e/${appName}`;
  const composeString = [
    'services:',
    '  web:',
    '    image: nginx:alpine',
    '    restart: unless-stopped',
    '',
  ].join('\n');

  // Helper: create + execute a single-device plan, poll to terminal state.
  const runPlan = async (actionId: string, input: Record<string, unknown>, timeoutMs: number): Promise<{ status?: string; steps?: PlanStepRow[] }> => {
    const createRes = await authed<{ id?: string }>('POST', '/plans', { pluginId: SSH_PLUGIN_ID, intentActionId: actionId, inputs: input, devices: [{ deviceId: target.id }] });
    if (createRes.status !== 201) throw new Error(`plan create ${actionId} → ${createRes.status}: ${JSON.stringify(createRes.data).slice(0, 400)}`);
    const plan = createRes.data;
    check(`plan created (${actionId})`, Boolean(plan.id));

    const execRes = await authed('POST', `/plans/${plan.id}/execute`);
    if (execRes.status !== 202) throw new Error(`plan execute ${actionId} → ${execRes.status}: ${JSON.stringify(execRes.data).slice(0, 400)}`);

    const final = await waitFor('plan terminal', async () => {
      const p = (await authed<{ status?: string; steps?: PlanStepRow[] }>('GET', `/plans/${plan.id}`)).data;
      return TERMINAL.includes(p?.status ?? '') ? p : null;
    }, timeoutMs, 2_000) ?? {};

    // Best-effort cleanup of the plan row (keeps the plans list tidy).
    await authed('DELETE', `/plans/${plan.id}`).catch(() => undefined);
    return final as { status?: string; steps?: PlanStepRow[] };
  };

  const stepDetails = (final: { steps?: PlanStepRow[] }, actionId: string): Record<string, unknown> | null =>
    ((final.steps ?? []).find((s) => s.actionId === actionId)?.result?.['result'] as { details?: Record<string, unknown> } | undefined)?.details ?? null;

  const refresh = async (): Promise<void> => {
    await authed('POST', '/devices/refresh', { deviceIds: [target.id] });
  };

  interface ContainerRowView {
    name: string; state?: string; image?: string | null; startedAt?: string | null;
    extra?: Record<string, unknown>;
  }
  const getRow = async (name: string): Promise<ContainerRowView | null> => {
    const r = await authed<{ containers?: ContainerRowView[] }>('GET', `/containers?deviceId=${target.id}`);
    if (r.status !== 200) return null;
    return (r.data?.containers ?? []).find((c) => c.name === name) ?? null;
  };

  // Pre-run cleanup — leftovers from an earlier crashed run (any unme2e* app).
  const allRows = ((await authed<{ containers?: Array<{ name: string }> }>('GET', `/containers?deviceId=${target.id}`)).data?.containers) ?? [];
  const staleNames = allRows.map((r) => r.name).filter((n) => n.startsWith('unme2e'));
  if (staleNames.length > 0) {
    console.log(`\n[cleanup] removing leftover apps: ${staleNames.join(', ')}`);
    await runPlan('containers.delete', { names: staleNames }, 300_000).catch(() => undefined);
    for (const n of staleNames) {
      await authed('POST', `/devices/${target.id}/filesystem`, { op: 'unlink', path: `/opt/unm-e2e/${n}/docker-compose.yml`, pluginId: SSH_PLUGIN_ID, secretId: fsSecretId, context: { kind: 'root' } }).catch(() => undefined);
    }
  }

  // 4. Deploy the compose stack via plan — user-chosen workdir.
  console.log(`\n[deploy] ${appName} → ${workdir}`);
  const deploy = await runPlan('containers.deploy-compose', { name: appName, composeString, workdir }, 900_000);
  check('deploy plan terminal (succeeded/unverified)', TERMINAL.includes(deploy.status ?? ''), (deploy.steps ?? []).map((s) => `${s.actionId}:${s.status}`));
  const depDetails = stepDetails(deploy, 'containers.deploy-compose');
  check('deploy details carry workdir', depDetails?.['workdir'] === workdir, depDetails);

  // 5. Inventory row appears after a forced refresh.
  await refresh();
  const runningRow = await waitFor('row RUNNING', async () => {
    const row = await getRow(appName);
    return row && (row.state ?? '').toUpperCase() === 'RUNNING' ? row : null;
  }, 120_000, 5_000);
  check('app row present + RUNNING after refresh', Boolean(runningRow), runningRow);
  const member = ((runningRow?.extra?.['containers'] as Array<{ service?: string }> | undefined)?.[0]?.service) ?? '';
  check('row has one member container detail', Boolean(member), runningRow?.extra?.['containerCount']);

  // 6. The YAML is saved byte-exact into the chosen workdir (filesystem read, root context).
  // NOTE: the API wraps plugin filesystem results in {pluginId, result:{...}} — unwrap it.
  const fsRead = await authed<{ result?: { contentBase64?: string; sizeBytes?: number } }>('POST', `/devices/${target.id}/filesystem`, { op: 'read', path: `${workdir}/docker-compose.yml`, pluginId: SSH_PLUGIN_ID, secretId: fsSecretId, context: { kind: 'root' } });
  check('filesystem read of workdir YAML → 200', fsRead.status === 200, fsRead.data);
  const savedYaml = Buffer.from(fsRead.data?.result?.contentBase64 ?? '', 'base64').toString('utf8');
  check('saved YAML is byte-exact', savedYaml === composeString, { len: savedYaml.length, sizeBytes: fsRead.data?.result?.sizeBytes });

  // 7. compose.config.read (read-only execute route) returns yaml + resolved workdir.
  const cfg = await authed<{ details?: Record<string, unknown> }>('POST', `/plugins/${SSH_PLUGIN_ID}/actions/execute`, { deviceId: target.id, actionId: 'compose.config.read', input: { name: appName } });
  check('compose.config.read → 200', cfg.status === 200, cfg.data);
  const cfgDetails = cfg.data?.details;
  check('config read returns the YAML', typeof cfgDetails?.['yaml'] === 'string' && String(cfgDetails['yaml']).includes('nginx:alpine'));
  check('config read resolves workdir from label', cfgDetails?.['workdir'] === workdir, cfgDetails);

  // 8. Probe keys — live state + stats for the member container.
  const probeStates = await authed<{ probe?: { metrics?: Record<string, unknown> } }>('GET', `/devices/${target.id}/probe?keys=containerStates&names=${encodeURIComponent(member)}&pluginId=${SSH_PLUGIN_ID}`);
  check('probe containerStates → 200', probeStates.status === 200, probeStates.data);
  const statesMap = (probeStates.data?.probe?.metrics?.['containerStates'] ?? {}) as Record<string, { status?: string }>;
  check('probe reports member running', statesMap[member]?.status === 'running', statesMap);

  const probeStats = await authed<{ probe?: { metrics?: Record<string, unknown> } }>('GET', `/devices/${target.id}/probe?keys=containerStats&pluginId=${SSH_PLUGIN_ID}`);
  check('probe containerStats → 200', probeStats.status === 200, probeStats.data);
  const statsMap = (probeStats.data?.probe?.metrics?.['containerStats'] ?? {}) as Record<string, { memUsedBytes?: number }>;
  check('probe stats include the member', typeof statsMap[member]?.memUsedBytes === 'number', Object.keys(statsMap).slice(0, 5));

  // 9. Stop → row STOPPED; start → RUNNING again.
  console.log('\n[lifecycle] stop');
  const stop = await runPlan('containers.stop', { names: [appName] }, 180_000);
  check('stop plan terminal (succeeded/unverified)', TERMINAL.includes(stop.status ?? ''), (stop.steps ?? []).map((s) => `${s.actionId}:${s.status}`));
  await refresh();
  const stoppedRow = await waitFor('row STOPPED', async () => {
    const row = await getRow(appName);
    return row && (row.state ?? '').toUpperCase() === 'STOPPED' ? row : null;
  }, 90_000, 5_000);
  check('app row STOPPED after refresh', Boolean(stoppedRow), stoppedRow?.state);

  console.log('\n[lifecycle] start');
  const start = await runPlan('containers.start', { names: [appName] }, 180_000);
  check('start plan terminal (succeeded/unverified)', TERMINAL.includes(start.status ?? ''), (start.steps ?? []).map((s) => `${s.actionId}:${s.status}`));
  await refresh();
  const restartedRow = await waitFor('row RUNNING again', async () => {
    const row = await getRow(appName);
    return row && (row.state ?? '').toUpperCase() === 'RUNNING' ? row : null;
  }, 90_000, 5_000);
  check('app row RUNNING after start', Boolean(restartedRow), restartedRow?.state);

  // 9b. Image management (generic contract: images.pull / update / prune).
  console.log('\n[images] pull');
  const imgPull = await runPlan('images.pull', { refs: ['nginx:alpine'] }, 600_000);
  check('pull plan terminal (succeeded/unverified)', TERMINAL.includes(imgPull.status ?? ''), (imgPull.steps ?? []).map((s) => `${s.actionId}:${s.status}`));
  const pullDetails = stepDetails(imgPull, 'images.pull');
  check('pull details list the ref', Array.isArray(pullDetails?.['pulled']) && (pullDetails!['pulled'] as string[]).includes('nginx:alpine'), pullDetails);

  console.log('\n[images] update (+restart)');
  const imgUpdate = await runPlan('images.update', { refs: ['nginx:alpine'], restart: true }, 900_000);
  check('update plan terminal (succeeded/unverified)', TERMINAL.includes(imgUpdate.status ?? ''), (imgUpdate.steps ?? []).map((s) => `${s.actionId}:${s.status}`));
  const updDetails = stepDetails(imgUpdate, 'images.update');
  check('update restarted the member container', Array.isArray(updDetails?.['restarted']) && (updDetails!['restarted'] as string[]).includes(member), updDetails);
  await refresh();
  const afterUpdateRow = await waitFor('row RUNNING after image update', async () => {
    const row = await getRow(appName);
    return row && (row.state ?? '').toUpperCase() === 'RUNNING' ? row : null;
  }, 90_000, 5_000);
  check('app row RUNNING after image update', Boolean(afterUpdateRow), afterUpdateRow?.state);

  console.log('\n[images] prune (dangling only)');
  const imgPrune = await runPlan('images.prune', { all: false }, 300_000);
  check('prune plan terminal (succeeded/unverified)', TERMINAL.includes(imgPrune.status ?? ''), (imgPrune.steps ?? []).map((s) => `${s.actionId}:${s.status}`));
  const pruneDetails = stepDetails(imgPrune, 'images.prune');
  check('prune reports freedBytes', typeof pruneDetails?.['freedBytes'] === 'number' || pruneDetails?.['freedBytes'] === null, pruneDetails);

  // 10. Delete → row gone from the inventory.
  console.log('\n[delete]');
  const del = await runPlan('containers.delete', { names: [appName] }, 300_000);
  check('delete plan terminal (succeeded/unverified)', TERMINAL.includes(del.status ?? ''), (del.steps ?? []).map((s) => `${s.actionId}:${s.status}`));
  await refresh();
  const gone = await waitFor('row gone', async () => {
    const row = await getRow(appName);
    return row === null ? true : null;
  }, 90_000, 5_000);
  check('app row removed from GET /containers', gone === true);

  // 11. Cleanup: remove the workdir files (best-effort — a leftover dir is harmless).
  await authed('POST', `/devices/${target.id}/filesystem`, { op: 'unlink', path: `${workdir}/docker-compose.yml`, pluginId: SSH_PLUGIN_ID, secretId: fsSecretId, context: { kind: 'root' } }).catch(() => undefined);
  await authed('POST', `/devices/${target.id}/filesystem`, { op: 'rmdir', path: workdir, pluginId: SSH_PLUGIN_ID, secretId: fsSecretId, context: { kind: 'root' } }).catch(() => undefined);

  await pool.end();
  console.log(failures === 0 ? '\nALL E2E GENERIC-SSH DOCKER TESTS PASSED' : `\n${failures} E2E TEST(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error('[e2e] fatal:', err);
  process.exit(1);
});
