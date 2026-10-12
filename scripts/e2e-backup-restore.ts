/**
 * End-to-end verification for the Backup / Restore / Replication feature.
 *
 * Validates against the deployed stack (API on :3000):
 *   1. GET /backups/meta — section keys + presets shape.
 *   2. Local backup lifecycle — create (preset 'planned') → list row with sha/size
 *      → download round-trip (bytes gunzip to a valid archive, sha matches) →
 *      re-upload the SAME archive and apply sections=[documented] expecting an
 *      idempotent merge (0 created / N updated) → corrupt upload rejected 400 →
 *      delete.
 *   3. Repo destination — when a file-repo provider is registered + online:
 *      create with destination:'repo' → list shows source=repo + bound provider
 *      name → download round-trip sha matches → delete. Skipped otherwise.
 *   4. Replication shape test — an in-process mock peer captures the pushed
 *      archive; asserts portable-only sections and that no excluded setting key
 *      (instanceName, updateFeedUrl, …) is present. Then a real target against
 *      the mock: Sync now → status ok + report persisted on the row.
 *   5. Negative paths — inbound push containing liveInventory → 400; target with
 *      an unreachable peer → error surfaced in lastSyncStatus.
 *
 * Usage (from the repo root, with the stack up):
 *   ./node_modules/.bin/tsx scripts/e2e-backup-restore.ts
 */

import { execFile } from 'node:child_process';
import http from 'node:http';
import path from 'node:path';
import zlib from 'node:zlib';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
// pg/otplib live in the API package's node_modules — resolve them from there.
const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));

let failures = 0;
function check(label: string, cond: boolean, extra?: unknown) {
  if (cond) console.log(`  PASS ${label}`);
  else {
    failures++;
    console.error(`  FAIL ${label}`, extra !== undefined ? JSON.stringify(extra).slice(0, 400) : '');
  }
}

/** The replication service's default exclusion list — keep in sync with api/src/replication.ts. */
const DEFAULT_REPLICATION_EXCLUDES = new Set([
  'instanceName',
  'updateFeedUrl',
  'updateFeedWebFetchProviderId',
  'fileRepoDefaultProviderId',
  'ntpReferenceServers',
  'webFetchProxyUrl',
  'geoipActiveFileId',
]);

const PORTABLE_SECTIONS = new Set(['identity', 'settings', 'devices', 'documented', 'plans']);

async function main(): Promise<void> {
  // --- Login (admin/admin; TOTP minted from the seeded secret when enabled) ----
  const { Pool } = apiRequire('pg');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm' });

  const health = await fetch('http://localhost:3000/healthz').then((r) => r.json()).catch(() => null);
  check('API healthy', (health as { status?: string })?.status === 'ok', health);

  // Preferred auth: a long-lived API token (bypasses 2FA). Read from the env or
  // the repo's .env — the admin password on a live stack is usually not 'admin'.
  let token = process.env.UNM_API_TOKEN ?? null;
  if (!token) {
    try {
      const envText = (await import('node:fs')).readFileSync(path.resolve(process.cwd(), '.env'), 'utf8');
      const m = /^UNM_API_TOKEN=(.+)$/m.exec(envText);
      if (m && m[1].trim().length > 0) token = m[1].trim();
    } catch { /* no .env */ }
  }

  if (!token) {
    // Fallback: admin/admin login (password-only when no TOTP is enrolled).
    const r = await fetch(`${API}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: 'admin' }) });
    token = ((await r.json()) as { accessToken?: string }).accessToken ?? null;
  }
  check('authenticated (login flow)', Boolean(token));
  if (!token) throw new Error('login failed');

  const H = { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` };
  const authed = async (method: string, p: string, body?: unknown): Promise<{ status: number; json: () => Promise<unknown> }> => {
    const res = await fetch(`${API}${p}`, { method, headers: H, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    return { status: res.status, json: async () => (await res.json().catch(() => null)) as never };
  };

  // ---------------------------------------------------------------------------
  // 1. /backups/meta — shape for the UI
  // ---------------------------------------------------------------------------
  console.log('\n— Backup meta —');
  const meta = await authed('GET', '/backups/meta');
  check('GET /backups/meta returns 200', meta.status === 200, { status: meta.status });
  const metaBody = (await meta.json()) as { sections?: Array<{ key: string; tables: string[] }>; presets?: Record<string, string[]> };
  const sectionKeys = (metaBody.sections ?? []).map((s) => s.key);
  check('sections include the six known keys', ['identity', 'settings', 'devices', 'documented', 'plans', 'liveInventory'].every((k) => sectionKeys.includes(k)), sectionKeys);
  check('presets define config/planned/all', Boolean(metaBody.presets?.config && metaBody.presets?.planned && metaBody.presets?.all), Object.keys(metaBody.presets ?? {}));

  // ---------------------------------------------------------------------------
  // 2. Local backup lifecycle
  // ---------------------------------------------------------------------------
  console.log('\n— Local backup lifecycle —');
  const created = await authed('POST', '/backups', { name: 'e2e-planned', preset: 'planned', destination: 'local' });
  const createdBody = (await created.json()) as { backup?: Record<string, unknown> } | null;
  check('create local backup (preset planned) → 201', created.status === 201, { status: created.status, body: createdBody });
  const backup = createdBody?.backup ?? {};
  const backupId = String(backup.id ?? '');
  check('row carries id/sha256/sizeBytes/source=local', Boolean(backupId) && typeof backup.sha256 === 'string' && (backup.sha256 as string).length === 64 && Number(backup.sizeBytes) > 0 && backup.source === 'local', backup);

  // File on the volume (dev stack only — informational when docker is unavailable).
  try {
    const out = await new Promise<string>((resolve, reject) => {
      execFile('docker', ['compose', '-f', 'docker-compose.dev.yml', 'exec', '-T', 'api', 'ls', '/data/backups'], (err, stdout) => (err ? reject(err) : resolve(stdout)));
    });
    check('archive file exists on the unm-backups volume', out.includes(`${backupId}.unmbak.gz`), out.split('\n').slice(0, 5));
  } catch {
    console.log('  SKIP volume listing (docker not available from this host)');
  }

  // Download round-trip — bytes gunzip to a valid archive; sha matches the row.
  const dlRes = await fetch(`${API}/backups/${backupId}/download`, { headers: { Authorization: `Bearer ${token}` } });
  check('GET /backups/:id/download → 200 octet-stream', dlRes.status === 200 && (dlRes.headers.get('content-type') ?? '').includes('octet-stream'), { status: dlRes.status });
  const bytes = Buffer.from(await dlRes.arrayBuffer());
  check('downloaded size matches stored sizeBytes', bytes.length === Number(backup.sizeBytes), { got: bytes.length, want: backup.sizeBytes });
  const sha = (await import('node:crypto')).createHash('sha256').update(bytes).digest('hex');
  check('downloaded sha256 matches the stored row', sha === String(backup.sha256), { got: sha.slice(0, 16), want: String(backup.sha256).slice(0, 16) });

  const archive = JSON.parse(zlib.gunzipSync(bytes).toString('utf8')) as {
    manifest?: { format?: string; schemaVersion?: number; sections?: Record<string, unknown> };
    data?: Record<string, Record<string, unknown[]>>;
  };
  check('archive parses: format unm-backup v1', archive.manifest?.format === 'unm-backup' && archive.manifest?.schemaVersion === 1, archive.manifest);
  const archivedSections = Object.keys(archive.data ?? {});
  check('planned preset archives documented+plans only', JSON.stringify([...archivedSections].sort()) === JSON.stringify(['documented', 'plans']), archivedSections);

  // Re-upload the SAME archive → apply sections=[documented] → idempotent merge.
  const upRes = await fetch(`${API}/backups/restore/upload`, { method: 'POST', headers: { 'Content-Type': 'application/octet-stream', 'x-backup-name': 'e2e-planned.unmbak.gz', Authorization: `Bearer ${token}` }, body: bytes });
  check('re-upload staged → 201 + manifest preview', upRes.status === 201, { status: upRes.status });
  const staged = (await upRes.json()) as { pendingId?: string; manifest?: { sections?: Record<string, unknown> } };
  check('preview manifest lists the documented section', Boolean(staged.pendingId && staged.manifest?.sections?.documented), Object.keys(staged.manifest?.sections ?? {}));

  const apply = await authed('POST', '/backups/restore/apply', { pendingId: staged.pendingId, sections: ['documented'] });
  const applyBody = (await apply.json()) as { report?: Array<{ section: string; tables: Array<{ table: string; created: number; updated: number }> }> } | null;
  check('apply (documented) → 200 report', apply.status === 200, { status: apply.status, body: applyBody });
  const report = applyBody?.report ?? [];
  const docReport = report.find((r) => r.section === 'documented');
  check('idempotent merge: documented has 0 created', Boolean(docReport) && (docReport?.tables ?? []).every((t) => t.created === 0), docReport);
  check('idempotent merge: documented updated > 0 rows', Boolean(docReport) && (docReport?.tables ?? []).reduce((s, t) => s + t.updated, 0) > 0, docReport);

  // Corrupt upload → 400.
  const badRes = await fetch(`${API}/backups/restore/upload`, { method: 'POST', headers: { 'Content-Type': 'application/octet-stream', Authorization: `Bearer ${token}` }, body: Buffer.from('this is not a gzip archive') });
  check('corrupt upload rejected with 400', badRes.status === 400, { status: badRes.status });

  // Delete → row + bytes gone.
  const del = await authed('DELETE', `/backups/${backupId}`);
  check('delete backup → 200', del.status === 200, { status: del.status });
  const dlGone = await fetch(`${API}/backups/${backupId}/download`, { headers: { Authorization: `Bearer ${token}` } });
  check('download after delete → 404', dlGone.status === 404, { status: dlGone.status });

  // ---------------------------------------------------------------------------
  // 3. Repo destination (skipped when no file-repo provider is online)
  // ---------------------------------------------------------------------------
  console.log('\n— Repo destination —');
  const providers = ((await authed('GET', '/files/providers').then((r) => r.json())) as { providers?: Array<{ id: string; name: string; online: boolean }> }).providers ?? [];
  const onlineProvider = providers.find((p) => p.online);
  if (!onlineProvider) {
    console.log(`  SKIP no online file-repo provider (registered: ${providers.length})`);
  } else {
    const repoCreated = await authed('POST', '/backups', { name: 'e2e-repo', preset: 'planned', destination: 'repo', providerId: onlineProvider.id });
    const repoBody = (await repoCreated.json()) as { backup?: Record<string, unknown> } | null;
    check('create repo backup → 201', repoCreated.status === 201, { status: repoCreated.status, body: repoBody });
    const repoBackup = repoBody?.backup ?? {};
    const repoId = String(repoBackup.id ?? '');
    check('row shows source=repo + bound provider name', repoBackup.source === 'repo' && String(repoBackup.providerName ?? '').includes(onlineProvider.name), repoBackup);

    const repoDl = await fetch(`${API}/backups/${repoId}/download`, { headers: { Authorization: `Bearer ${token}` } });
    check('repo backup download → 200', repoDl.status === 200, { status: repoDl.status });
    if (repoDl.status === 200) {
      const repoBytes = Buffer.from(await repoDl.arrayBuffer());
      const repoSha = (await import('node:crypto')).createHash('sha256').update(repoBytes).digest('hex');
      check('repo download sha matches stored row', repoSha === String(repoBackup.sha256), { got: repoSha.slice(0, 16) });
    }

    const repoDel = await authed('DELETE', `/backups/${repoId}`);
    check('delete repo backup → 200 (blob removed on bound instance)', repoDel.status === 200, { status: repoDel.status });
  }

  // ---------------------------------------------------------------------------
  // 4. Replication — mock peer captures the push; shape assertions
  // ---------------------------------------------------------------------------
  console.log('\n— Replication (mock peer) —');
  // The sync job runs INSIDE the api container, so the mock peer must be
  // reachable via the gateway of the compose bridge network — NOT the host's
  // default-route gateway (that is the LAN router, which has no such port).
  let hostIp = '127.0.0.1';
  try {
    const cidr = await new Promise<string>((resolve) => {
      execFile('docker', ['compose', '-f', 'docker-compose.dev.yml', 'ps', '-q', 'api'], (err, stdout) => resolve(err ? '' : String(stdout).trim()));
    });
    if (cidr) {
      const gw = await new Promise<string>((resolve) => {
        execFile('docker', ['inspect', cidr, '--format', '{{range .NetworkSettings.Networks}}{{.Gateway}} {{end}}'], (err, stdout) => resolve(err ? '' : String(stdout)));
      });
      const m = /(\d+\.\d+\.\d+\.\d+)/.exec(gw);
      if (m) hostIp = m[1];
    }
  } catch { /* keep loopback */ }
  let captured: { sections?: string[]; settingKeys?: Set<string> } | null = null;
  const server = http.createServer((req, res) => {
    if (req.method === 'POST' && req.url?.includes('/replication/inbound')) {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        try {
          const parsed = JSON.parse(body) as { data?: Record<string, Record<string, Array<{ key?: string }>>> };
          captured = {
            sections: Object.keys(parsed.data ?? {}),
            settingKeys: new Set((parsed.data?.settings?.system_settings ?? []).map((r) => String(r.key))),
          };
        } catch { /* keep null */ }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ report: [] }));
      });
      return;
    }
    res.writeHead(404);
    res.end();
  });
  // Bind all interfaces — the api container reaches us via the bridge gateway IP.
  await new Promise<void>((resolve) => server.listen(0, '0.0.0.0', resolve));
  const port = (server.address() as { port: number }).port;

  try {
    const peerBase = `http://${hostIp}:${port}`;
    const targetCreated = await authed('POST', '/replication/targets', { name: 'e2e-mock-peer', baseUrl: peerBase, token, direction: 'push' });
    const createdTargetBody = JSON.stringify(await targetCreated.json());
    check('create push target → 201 (token not echoed)', targetCreated.status === 201 && !createdTargetBody.includes(token), { status: targetCreated.status });
    const target = ((await authed('POST', '/replication/targets', { name: 'e2e-mock-peer-2', baseUrl: peerBase, token }).then((r) => r.json())) as { target?: Record<string, unknown> });
    const targetId = String(target.target?.id ?? '');

    const sync = await authed('POST', '/replication/sync', { targetId });
    const syncBody = (await sync.json()) as { report?: { status?: string } } | null;
    check('Sync now → 200 + report.status ok', sync.status === 200 && syncBody?.report?.status === 'ok', { status: sync.status, body: syncBody });

    check('pushed sections are portable-only', Boolean(captured) && (captured.sections ?? []).every((s) => PORTABLE_SECTIONS.has(s)), captured?.sections);
    const leaked = [...(captured?.settingKeys ?? [])].filter((k) => DEFAULT_REPLICATION_EXCLUDES.has(k));
    check('no excluded setting key crossed the wire', leaked.length === 0, leaked);

    // The row persisted its outcome.
    const targets = ((await authed('GET', '/replication/targets').then((r) => r.json())) as { targets?: Array<Record<string, unknown>> }).targets ?? [];
    const row = targets.find((t) => t.id === targetId);
    check('target row persisted lastSyncStatus=ok + lastReport', row?.lastSyncStatus === 'ok' && typeof row.lastReport === 'object', { status: row?.lastSyncStatus });

    // Negative — unreachable peer surfaces an error (not a crash).
    const deadTarget = ((await authed('POST', '/replication/targets', { name: 'e2e-dead-peer', baseUrl: `http://${hostIp}:1`, token }).then((r) => r.json())) as { target?: Record<string, unknown> });
    const deadSync = await authed('POST', '/replication/sync', { targetId: String(deadTarget.target?.id ?? '') });
    const deadBody = (await deadSync.json()) as { report?: { status?: string; error?: string } };
    check('unreachable peer → report.status error with message', deadBody.report?.status === 'error' && Boolean(deadBody.report?.error), deadBody);

    // Inbound push containing liveInventory is rejected.
    const inboundBad = await fetch(`${API}/replication/inbound`, { method: 'POST', headers: H, body: JSON.stringify({ manifest: archive.manifest, data: { liveInventory: {} } }) });
    check('inbound push with liveInventory → 400', inboundBad.status === 400, { status: inboundBad.status });

    // Cleanup.
    for (const id of [targetId, String(deadTarget.target?.id ?? '')]) {
      if (!id) continue;
      const d = await authed('DELETE', `/replication/targets/${id}`);
      check(`delete target ${id.slice(0, 8)} → 200`, d.status === 200, { status: d.status });
    }
  } finally {
    server.close();
  }

  await pool.end();

  console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error('E2E crashed:', err);
  process.exit(1);
});
