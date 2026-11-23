#!/usr/bin/env tsx
/**
 * Live E2E for Sigma log-rule feeds (Phase 2) + flat file-repo tags:
 *   A. Fixture — a local HTTP server on the host serves deterministic multi-doc
 *      Sigma YAML; reachable from the api container via host.docker.internal
 *      (extra_hosts in docker-compose.dev.yml). Fetching goes through the
 *      web-fetch plugin, never direct egress from the API.
 *   B. Create feed (yaml-url, intervalMinutes=0 → manual only) + sync #1: all
 *      docs imported as source='feed' rules; raw snapshot stored in the file
 *      repo with tags ['log-rules', <feed-slug>].
 *   C. File-repo tag checks — GET /files?tag=log-rules finds the snapshot,
 *      PATCH /files/:id/tags round-trips, GET /files/tags lists distinct tags.
 *   D. Sync #2 (changed content) — one doc updated, one removed from the feed
 *      → upsert + prune-disable semantics; a user-owned rule with a colliding
 *      title is reported as conflict and NOT taken over.
 *   E. Delete feed — its rules convert to source='user' (feedId null), nothing lost.
 *   F. Cleanup (KEEP=1 leaves the test data in place).
 *
 * All test rows carry distinctive values (e2e-* names/markers) so cleanup
 * deletes precisely what this script created.
 *
 * Usage: tsx scripts/e2e-log-rule-feeds.ts   (from repo root; reads UNM_API_TOKEN from .env)
 */
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';

const API = process.env.API_URL || 'http://localhost:3000/v1';
const KEEP = process.env.KEEP === '1';

const FEED_NAME = 'e2e-log-rule-feed';
const RULE_ALPHA = 'E2E Feed Alpha';
const RULE_BETA = 'E2E Feed Beta';
const RULE_GAMMA = 'E2E Feed Gamma'; // removed from the feed in sync #2 → disabled, never deleted
const CONFLICT_TITLE = 'E2E Conflict Rule'; // user-owned; the feed must NOT take it over

/** One deterministic Sigma document (the single-line subset UNM supports). */
function sigmaDoc(title: string, marker: string): string {
  return [
    `title: ${title}`,
    `id: e2e-${title.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`,
    'status: test',
    `description: E2E fixture rule for ${marker}.`,
    'level: medium',
    'detection:',
    '  sel_marker:',
    '    message:',
    `      contains: '${marker}'`,
    'condition: sel_marker',
    '',
  ].join('\n');
}

const FEED_V1 = [sigmaDoc(RULE_ALPHA, 'e2e-alpha-marker'), sigmaDoc(RULE_BETA, 'e2e-beta-marker'), sigmaDoc(RULE_GAMMA, 'e2e-gamma-marker')].join('---\n');
// Sync #2: alpha UPDATED (new marker), beta unchanged, gamma REMOVED, conflict doc ADDED.
const FEED_V2 = [sigmaDoc(RULE_ALPHA, 'e2e-alpha-marker-v2'), sigmaDoc(RULE_BETA, 'e2e-beta-marker'), sigmaDoc(CONFLICT_TITLE, 'e2e-conflict-marker')].join('---\n');

// ── Plumbing ─────────────────────────────────────────────────────────────────
function sleep(ms: number): Promise<void> { return new Promise((r) => setTimeout(r, ms)); }
let failures = 0;
function check(name: string, ok: boolean, extra = ''): void {
  console.log(`  ${ok ? 'ok  ' : 'FAIL'} ${name}${extra ? ` — ${extra}` : ''}`);
  if (!ok) failures += 1;
}

const envFile = path.resolve(process.cwd(), '.env');
let token = process.env.UNM_API_TOKEN || '';
if (!token && fs.existsSync(envFile)) {
  const line = fs.readFileSync(envFile, 'utf8').split('\n').find((l) => l.startsWith('UNM_API_TOKEN='));
  if (line) token = line.slice(line.indexOf('=') + 1).trim().replace(/^"|"$/g, '');
}
if (!token) { console.error('No UNM_API_TOKEN found (.env or env) — aborting'); process.exit(2); }

async function api<T>(method: string, urlPath: string, body?: unknown): Promise<{ status: number; data: T }> {
  const res = await fetch(`${API}${urlPath}`, {
    method,
    headers: { Authorization: `Bearer ${token}`, ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}) },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let data: T;
  try { data = text ? (JSON.parse(text) as T) : (undefined as unknown as T); } catch { data = text as unknown as T; }
  return { status: res.status, data };
}

// ── Fixture server (host port → api container via host.docker.internal) ─────
let feedBody = FEED_V1;
const fixture = http.createServer((req, res) => {
  if (req.url === '/feed.yml') {
    res.writeHead(200, { 'Content-Type': 'application/x-yaml' });
    res.end(feedBody);
  } else {
    res.writeHead(404);
    res.end('not found');
  }
});

interface LogRuleRow { id: string; name: string; source: string; enabled: boolean; feedId: string | null; sigmaYaml: string }
interface FeedRow { id: string; name: string; kind: string; url: string; pathPrefix: string | null; enabled: boolean; intervalMinutes: number; lastSyncAt: string | null; lastError: string | null; ruleCount: number; repoFileId: string | null }
interface SyncResult { syncedAt: string; totalDocs: number; created: number; updated: number; unchanged: number; disabled: number; skipped: Array<{ name: string | null; error: string }>; conflicts: Array<{ name: string; owner: string }>; repoFileId: string | null }
interface RepoFileRow { id: string; name: string; category: string; tags: string[] }

/** Coerces an (possibly error-shaped) sync payload into a SyncResult so downstream checks fail cleanly. */
function asSyncResult(x: unknown): SyncResult {
  const d = (x ?? {}) as Partial<SyncResult>;
  return { syncedAt: '', totalDocs: 0, created: 0, updated: 0, unchanged: 0, disabled: 0, skipped: [], conflicts: [], repoFileId: null, ...d };
}

async function main(): Promise<void> {
  // Bind ALL interfaces — the api/web-fetch containers reach this host via the
  // bridge gateway IP (host.docker.internal → e.g. 172.17.0.1), NOT loopback, so
  // a 127.0.0.1-only bind would ECONNREFUSE from inside the stack. The port is
  // ephemeral and the server dies with this process.
  await new Promise<void>((resolve) => fixture.listen(0, resolve));
  const port = (fixture.address() as { port: number }).port;
  const feedUrl = `http://host.docker.internal:${port}/feed.yml`;
  console.log(`Fixture server on host port ${port} — api container reaches it at ${feedUrl}`);

  // Pre-clean residue from previous/interrupted runs (idempotent).
  for (const f of (await api<{ feeds: FeedRow[] }>('GET', '/log-rule-feeds')).data.feeds) {
    if (f.name === FEED_NAME) await api('DELETE', `/log-rule-feeds/${f.id}`);
  }
  let rules = (await api<{ rules: LogRuleRow[] }>('GET', '/log-rules')).data.rules;
  for (const n of [RULE_ALPHA, RULE_BETA, RULE_GAMMA, CONFLICT_TITLE]) {
    const r = rules.find((x) => x.name === n && x.source === 'user');
    if (r) await api('DELETE', `/log-rules/${r.id}`);
  }
  // Leftover raw snapshots from interrupted runs (category log-rule-feeds).
  for (const f of (await api<{ files: RepoFileRow[] }>('GET', '/files?category=log-rule-feeds')).data.files) {
    if (f.name.startsWith('log-rule-feed-e2e-log-rule-feed')) await api('DELETE', `/files/${f.id}`);
  }

  // B. Create feed + sync #1 ────────────────────────────────────────────────
  console.log('\nB. create feed + first sync');
  const created = await api<FeedRow>('POST', '/log-rule-feeds', { name: FEED_NAME, kind: 'yaml-url', url: feedUrl, intervalMinutes: 0 });
  check('create feed → 201', created.status === 201, `status=${created.status} ${JSON.stringify(created.data).slice(0, 160)}`);
  const feedId = (created.data as FeedRow).id;

  const sync1 = await api<SyncResult>('POST', `/log-rule-feeds/${feedId}/sync`);
  check('sync #1 → 200', sync1.status === 200, `status=${sync1.status} ${JSON.stringify(sync1.data).slice(0, 240)}`);
  const r1 = asSyncResult(sync1.data);
  check('sync #1 created=3 / totalDocs=3', r1.created === 3 && r1.totalDocs === 3, JSON.stringify({ created: r1.created, totalDocs: r1.totalDocs }));
  check('sync #1 stored raw snapshot in file repo', typeof r1.repoFileId === 'string' && !!r1.repoFileId, `repoFileId=${String(r1.repoFileId)}`);

  rules = (await api<{ rules: LogRuleRow[] }>('GET', '/log-rules')).data.rules;
  const alpha1 = rules.find((x) => x.name === RULE_ALPHA);
  check('alpha rule source=feed + feedId set', !!alpha1 && alpha1.source === 'feed' && alpha1.feedId === feedId, `source=${String(alpha1?.source)} feedId=${String(alpha1?.feedId)}`);

  // C. File-repo tag checks ─────────────────────────────────────────────────
  console.log('\nC. file-repo flat tags');
  const byTag = (await api<{ files: RepoFileRow[] }>('GET', '/files?tag=log-rules')).data.files;
  check('snapshot findable via GET /files?tag=log-rules', byTag.some((f) => f.id === r1.repoFileId));
  const snap = byTag.find((f) => f.id === r1.repoFileId);
  check('snapshot tagged log-rules + feed slug', !!snap && snap.tags.includes('log-rules') && snap.tags.includes(FEED_NAME.toLowerCase()), `tags=${(snap?.tags ?? []).join(',')}`);

  const patched = await api<{ file: RepoFileRow }>('PATCH', `/files/${r1.repoFileId}/tags`, { tags: ['log-rules', FEED_NAME.toLowerCase(), 'e2e-marker'] });
  check('PATCH /files/:id/tags round-trips', patched.status === 200 && (patched.data.file.tags ?? []).includes('e2e-marker'), `status=${patched.status}`);
  const distinct = (await api<{ tags: string[] }>('GET', '/files/tags')).data.tags;
  check('GET /files/tags lists the new tag', distinct.includes('e2e-marker'));

  // D. Conflict setup + sync #2 ─────────────────────────────────────────────
  console.log('\nD. changed content — upsert, prune-disable, conflict');
  const conflictRule = await api<LogRuleRow>('POST', '/log-rules', { yaml: sigmaDoc(CONFLICT_TITLE, 'user-owned-conflict') });
  check('create user rule with colliding title → 201', conflictRule.status === 201, `status=${conflictRule.status}`);

  feedBody = FEED_V2;
  const sync2 = await api<SyncResult>('POST', `/log-rule-feeds/${feedId}/sync`);
  check('sync #2 → 200', sync2.status === 200, `status=${sync2.status} ${JSON.stringify(sync2.data).slice(0, 300)}`);
  const r2 = asSyncResult(sync2.data);
  check('sync #2 updated=1 (alpha)', r2.updated === 1, JSON.stringify({ updated: r2.updated }));
  check('sync #2 unchanged=1 (beta)', r2.unchanged === 1, JSON.stringify({ unchanged: r2.unchanged }));
  check('sync #2 disabled=1 (gamma pruned from feed)', r2.disabled === 1, JSON.stringify({ disabled: r2.disabled }));
  check('sync #2 conflict reported, NOT taken over', r2.conflicts.some((c) => c.name === CONFLICT_TITLE && c.owner === 'user'), JSON.stringify(r2.conflicts));

  rules = (await api<{ rules: LogRuleRow[] }>('GET', '/log-rules')).data.rules;
  const alpha2 = rules.find((x) => x.name === RULE_ALPHA);
  check('alpha YAML refreshed to v2 marker', !!alpha2 && alpha2.sigmaYaml.includes('e2e-alpha-marker-v2'));
  const gamma = rules.find((x) => x.name === RULE_GAMMA);
  check('gamma disabled (never deleted)', !!gamma && gamma.enabled === false && gamma.source === 'feed', `enabled=${String(gamma?.enabled)} source=${String(gamma?.source)}`);
  const conflictAfter = rules.find((x) => x.name === CONFLICT_TITLE);
  check('conflict rule still user-owned (feedId null)', !!conflictAfter && conflictAfter.source === 'user' && conflictAfter.feedId === null, `source=${String(conflictAfter?.source)}`);

  // E. Delete feed → rules convert to user ──────────────────────────────────
  console.log('\nE. delete feed');
  const del = await api<{ deleted: boolean; convertedRules: number }>('DELETE', `/log-rule-feeds/${feedId}`);
  check('delete feed → 200 + convertedRules=3', del.status === 200 && (del.data as { deleted?: boolean }).deleted === true && (del.data as { convertedRules?: number }).convertedRules === 3, JSON.stringify(del.data));
  rules = (await api<{ rules: LogRuleRow[] }>('GET', '/log-rules')).data.rules;
  check('all feed rules now user-owned with feedId null', [RULE_ALPHA, RULE_BETA, RULE_GAMMA].every((n) => { const r = rules.find((x) => x.name === n); return !!r && r.source === 'user' && r.feedId === null; }));

  // F. Cleanup ───────────────────────────────────────────────────────────────
  console.log('\nF. cleanup');
  if (!KEEP) {
    for (const n of [RULE_ALPHA, RULE_BETA, RULE_GAMMA, CONFLICT_TITLE]) {
      const r = rules.find((x) => x.name === n);
      if (r && r.source === 'user') await api('DELETE', `/log-rules/${r.id}`);
    }
    // The live snapshot is the one from the LAST successful sync — earlier ones
    // are pruned as superseded by feeds.ts (so r1's id may already be gone).
    const currentSnapshot = typeof r2.repoFileId === 'string' && r2.repoFileId ? r2.repoFileId : r1.repoFileId;
    if (typeof currentSnapshot === 'string' && currentSnapshot) {
      const gone = await api('DELETE', `/files/${currentSnapshot}`);
      check('snapshot file removed from repo', gone.status === 204, `status=${gone.status}`);
    }
    // Drop the e2e-marker tag residue if any other tagged file kept it (none expected).
    await sleep(250);
    console.log('cleanup done');
  } else {
    console.log('KEEP=1 — leaving test data in place');
  }

  fixture.close();
  console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  fixture.close();
  process.exit(1);
});
