/**
 * Ground-truth probe for the "saved YAML is byte-exact {len:0}" E2E failure.
 *
 * 1. SFTP round-trip: write a known file via POST /devices/:id/filesystem, read it back.
 *    → isolates whether the SFTP transport itself can return non-empty content.
 * 2. Deploy a compose stack via plan (containers.deploy-compose) into /opt/unm-e2e/<name>.
 * 3. Immediately: filesystem-read of <workdir>/docker-compose.yml (SFTP) AND
 *    containers.logs.read is NOT useful here — instead we re-deploy nothing, just read.
 * 4. Prints sizes + first bytes so we can compare against the expected YAML.
 *
 * Usage: ./node_modules/.bin/tsx scripts/probe-ssh-fs.ts
 */

import path from 'node:path';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const SSH_PLUGIN_ID = '00000000-0000-4000-8000-00000000000c';
const TARGET_DEVICE_NAME = process.env.E2E_SSH_HOST ?? 'MAIL04';

const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));

async function main(): Promise<void> {
  const { Pool } = apiRequire('pg');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm' });
  const adminRow = (await pool.query(`SELECT "totpSecret" FROM users WHERE username = 'admin'`)).rows[0] as { totpSecret: string | null };

  let token: string;
  if (!adminRow.totpSecret) {
    const r = await fetch(`${API}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: 'admin' }) });
    token = ((await r.json()) as { accessToken?: string }).accessToken ?? '';
  } else {
    const { authenticator } = apiRequire('otplib');
    const code = authenticator.generate(adminRow.totpSecret);
    const r1 = await fetch(`${API}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: 'admin' }) });
    const challenge = ((await r1.json()) as { challengeToken?: string }).challengeToken ?? '';
    const r2 = await fetch(`${API}/auth/2fa/verify`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ challengeToken: challenge, totpCode: code }) });
    token = ((await r2.json()) as { accessToken?: string }).accessToken ?? '';
  }
  if (!token) throw new Error('login failed');

  const authed = async <T = unknown>(method: string, p: string, body?: unknown): Promise<{ status: number; data: T }> => {
    const res = await fetch(`${API}${p}`, { method, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    let data: T | null = null;
    try { data = (await res.json()) as T; } catch { /* non-JSON */ }
    return { status: res.status, data: data ?? (null as unknown as T) };
  };

  const devices = (await authed<Array<{ id: string; name?: string }>>('GET', '/devices')).data ?? [];
  const target = devices.find((d) => d.name === TARGET_DEVICE_NAME);
  if (!target) throw new Error(`device ${TARGET_DEVICE_NAME} not found`);

  const bindRow = (await pool.query(
    `SELECT dp."secretId" FROM device_plugins dp WHERE dp."deviceId" = $1 AND dp."pluginId" = $2`,
    [target.id, SSH_PLUGIN_ID],
  )).rows[0] as { secretId: string | null } | undefined;
  const fsSecretId = bindRow?.secretId ?? '';

  // --- 1. SFTP round-trip -------------------------------------------------
  const probePath = '/opt/unm-e2e/probe-roundtrip.txt';
  const known = 'UNM-SFTP-PROBE\nline two with content 0123456789\n'.repeat(3);
  const w = await authed('POST', `/devices/${target.id}/filesystem`, { op: 'write', path: probePath, contentBase64: Buffer.from(known).toString('base64'), pluginId: SSH_PLUGIN_ID, secretId: fsSecretId, context: { kind: 'root' } });
  console.log(`[1] SFTP write → ${w.status}`, w.data ? JSON.stringify(w.data).slice(0, 200) : '');
  const rd = await authed<{ result?: { contentBase64?: string; sizeBytes?: number } }>('POST', `/devices/${target.id}/filesystem`, { op: 'read', path: probePath, pluginId: SSH_PLUGIN_ID, secretId: fsSecretId, context: { kind: 'root' } });
  const rdBuf = Buffer.from(rd.data?.result?.contentBase64 ?? '', 'base64');
  console.log(`[1] SFTP read → ${rd.status} sizeBytes=${rd.data?.sizeBytes} decodedLen=${rdBuf.length} expected=${known.length} match=${rdBuf.toString('utf8') === known}`);

  // --- 2. Deploy a stack ---------------------------------------------------
  const appName = `unme2ep${Date.now().toString(36).slice(-4)}`;
  const workdir = `/opt/unm-e2e/${appName}`;
  const composeString = ['services:', '  web:', '    image: nginx:alpine', ''].join('\n');

  // Clean any leftover probe app first.
  const allRows = ((await authed<{ containers?: Array<{ name: string }> }>('GET', `/containers?deviceId=${target.id}`)).data?.containers) ?? [];
  for (const n of allRows.map((r) => r.name).filter((x) => x.startsWith('unme2ep'))) {
    await authed('POST', '/plans', { pluginId: SSH_PLUGIN_ID, intentActionId: 'containers.delete', inputs: { names: [n] }, devices: [{ deviceId: target.id }] }).then(async (c) => { if (c.status === 201 && c.data?.id) await authed('POST', `/plans/${(c.data as { id: string }).id}/execute`); });
    await new Promise((r) => setTimeout(r, 8_000));
  }

  const createRes = await authed<{ id?: string }>('POST', '/plans', { pluginId: SSH_PLUGIN_ID, intentActionId: 'containers.deploy-compose', inputs: { name: appName, composeString, workdir }, devices: [{ deviceId: target.id }] });
  if (createRes.status !== 201 || !createRes.data?.id) throw new Error(`deploy plan create failed: ${JSON.stringify(createRes.data).slice(0, 300)}`);
  const planId = createRes.data.id;
  await authed('POST', `/plans/${planId}/execute`);

  // Poll to terminal.
  let finalStatus = '';
  for (let i = 0; i < 120; i++) {
    await new Promise((r) => setTimeout(r, 3_000));
    const p = (await authed<{ status?: string }>('GET', `/plans/${planId}`)).data;
    if (['succeeded', 'failed', 'cancelled', 'skipped', 'unverified'].includes(p?.status ?? '')) { finalStatus = p?.status ?? ''; break; }
  }
  console.log(`[2] deploy plan → ${finalStatus} (${appName})`);

  // --- 3. Read the saved YAML back over SFTP --------------------------------
  const yamlRead = await authed<{ result?: { contentBase64?: string; sizeBytes?: number } }>('POST', `/devices/${target.id}/filesystem`, { op: 'read', path: `${workdir}/docker-compose.yml`, pluginId: SSH_PLUGIN_ID, secretId: fsSecretId, context: { kind: 'root' } });
  const yamlBuf = Buffer.from(yamlRead.data?.result?.contentBase64 ?? '', 'base64');
  console.log(`[3] SFTP read of saved YAML → ${yamlRead.status} sizeBytes=${yamlRead.data?.sizeBytes} decodedLen=${yamlBuf.length}`);
  console.log(`    content: ${JSON.stringify(yamlBuf.toString('utf8').slice(0, 200))}`);

  // Also stat it — does the file even exist?
  const st = await authed<{ sizeBytes?: number; isDirectory?: boolean }>('POST', `/devices/${target.id}/filesystem`, { op: 'stat', path: `${workdir}/docker-compose.yml`, pluginId: SSH_PLUGIN_ID, secretId: fsSecretId, context: { kind: 'root' } });
  console.log(`[3] stat → ${st.status} ${JSON.stringify(st.data)}`);

  // List the workdir.
  const ls = await authed<{ entries?: Array<{ name: string; sizeBytes: number | null }> }>('POST', `/devices/${target.id}/filesystem`, { op: 'list', path: workdir, pluginId: SSH_PLUGIN_ID, secretId: fsSecretId, context: { kind: 'root' } });
  console.log(`[3] list ${workdir} → ${ls.status} ${JSON.stringify(ls.data?.entries)}`);

  // --- 4. compose.config.read (SSH cat path) ---------------------------------
  const cfg = await authed<{ details?: Record<string, unknown>; error?: string }>('POST', `/plugins/${SSH_PLUGIN_ID}/actions/execute`, { deviceId: target.id, actionId: 'compose.config.read', input: { name: appName } });
  console.log(`[4] compose.config.read → ${cfg.status} workdir=${(cfg.data?.details as Record<string, unknown> | undefined)?.['workdir']} yamlLen=${typeof (cfg.data?.details as Record<string, unknown> | undefined)?.['yaml'] === 'string' ? String((cfg.data!.details as Record<string, unknown>)['yaml']).length : 'n/a'} err=${cfg.data?.error ?? ''}`);

  // --- cleanup ---------------------------------------------------------------
  const delCreate = await authed<{ id?: string }>('POST', '/plans', { pluginId: SSH_PLUGIN_ID, intentActionId: 'containers.delete', inputs: { names: [appName] }, devices: [{ deviceId: target.id }] });
  if (delCreate.status === 201 && delCreate.data?.id) await authed('POST', `/plans/${delCreate.data.id}/execute`);
  await new Promise((r) => setTimeout(r, 5_000));
  await authed('DELETE', `/plans/${planId}`).catch(() => undefined);
  await authed('POST', `/devices/${target.id}/filesystem`, { op: 'unlink', path: probePath, pluginId: SSH_PLUGIN_ID, secretId: fsSecretId, context: { kind: 'root' } }).catch(() => undefined);

  await pool.end();
}

main().then(() => process.exit(0)).catch((e) => { console.error('PROBE FAILED:', e); process.exit(1); });
