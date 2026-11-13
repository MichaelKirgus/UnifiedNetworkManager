#!/usr/bin/env tsx
/**
 * Live E2E for threat intelligence (Phase 3):
 *   0. Pre-clean — idempotently removes residue from previous/interrupted runs
 *      (so a KEEP=1 or crashed run can never block a fresh start).
 *   A. Feed fetch — a local HTTP server serves a deterministic IOC list; the
 *      script registers it via POST /v1/threat-intel/sources and asserts the
 *      worker fetched + stored exactly the expected indicators (snapshot).
 *   B. Matching (firewall events) — a DISABLED source is seeded directly with
 *      a unique IOC, then crafted firewall_events rows hit enabled-feed IOCs
 *      (src side + CIDR dst side) plus one row hitting only the disabled
 *      IOC; asserts 'ioc-hit' findings with correct sides/sources and that
 *      the disabled indicator produced nothing. One notification per tuple.
 *   C. Matching (flows) — a flow_agg_5m row in the next unprocessed bucket
 *      hits an enabled-feed IOC; asserts the finding after the bucket closes.
 *   D. Cleanup (set KEEP=1 to leave the test data in place).
 *
 * All test rows carry distinctive values (e2e-threat-* names, TEST-NET IPs)
 * so cleanup deletes precisely what this script created.
 *
 * Usage: tsx scripts/e2e-threat-intel.ts   (from repo root; reads UNM_API_TOKEN from .env)
 */
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { execSync } from 'node:child_process';
import { createRequire } from 'node:module';

// Run from the repo root (tsx scripts/e2e-threat-intel.ts).
const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));
const { Pool } = apiRequire('pg') as typeof import('pg');

const API = process.env.API_URL || 'http://localhost:8080/v1';
const KEEP = process.env.KEEP === '1';

// TEST-NET ranges — never routable, safe to use in assertions.
const FEED_IOC_HOST = '198.51.100.66'; // exact host from the enabled feed
const FEED_CIDR = '203.0.113.0/24'; // network from the enabled feed
const CIDR_HIT_IP = '203.0.113.77'; // inside FEED_CIDR — dst-side hit
const FEED_V6 = '2001:db8::66'; // v6 host from the enabled feed
const SEED_IOC = '198.51.100.77'; // only in the DISABLED source — must never match
const FW_DEVICE = 'e2e-threat-device';
const FLOW_SRC = '10.0.0.7';

const FEED_NAME = 'e2e-threat-feed';
const SEED_NAME = 'e2e-threat-seed';

// Deterministic feed content: 3 valid entries (host, CIDR, v6) + noise lines.
const FEED_BODY = [
  '# e2e threat feed — deterministic content',
  FEED_IOC_HOST,
  FEED_CIDR,
  '; semicolon comment line',
  '',
  'not-an-ip',
  'http://example.com/junk',
  FEED_V6,
].join('\n');

const BUCKET_MS = 300_000;
const PROCESS_LAG_MS = 2 * BUCKET_MS;

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

const pool = new Pool({ connectionString: process.env.DATABASE_URL || 'postgresql://unm:unm@localhost:5432/unm' });

async function api<T>(method: string, p: string, body?: unknown): Promise<{ status: number; data: T }> {
  const res = await fetch(`${API}${p}`, {
    method,
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let data: T;
  try { data = (await res.json()) as T; } catch { data = undefined as unknown as T; }
  return { status: res.status, data };
}

async function pollUntil(timeoutMs: number, fn: () => Promise<boolean>): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try { if (await fn()) return true; } catch { /* retry */ }
    await sleep(5_000);
  }
  return false;
}

interface TiSource { id: string; name: string; url: string; format: string; enabled: boolean; iocCount: number; lastSuccessAt: string | null; lastError: string | null }
interface TiHit { id: string; srcIp: string; dstIp: string | null; detail: string; lastSeenAt: string }
interface TiResponse { enabled: boolean; worker: { lastRunAt: string | null; lastError: string | null; iocTotal: number; cursorBucketMs: number; fwWatermarkMs: number }; sources: TiSource[]; recentHits: TiHit[] }

/** Container→host address for the local feed server (docker bridge gateway). */
function discoverHostForContainers(): string {
  const raw = execSync(`docker inspect unifiednetworkmanager-api-1 --format '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}'`, { encoding: 'utf8' }).trim();
  const ip = raw.split(/\s+/)[0];
  if (!ip || !ip.includes('.')) throw new Error(`could not determine API container IP (got "${raw}")`);
  return `${ip.split('.').slice(0, 3).join('.')}.1`; // standard bridge gateway x.y.0.1
}

// ── A: feed fetch ────────────────────────────────────────────────────────────
async function phaseA(serverPort: number): Promise<string> {
  console.log('\n[A] Feed fetch — local HTTP server + POST /threat-intel/sources');
  const host = discoverHostForContainers();
  const url = `http://${host}:${serverPort}/iocs.txt`;

  // Seed the DISABLED source FIRST: its rows exist before the feed's fetch
  // invalidates the worker's IOC cache, so the post-fetch cache rebuild sees
  // everything (and excludes the disabled source).
  const seedCreate = await api<TiSource>('POST', '/threat-intel/sources', { name: SEED_NAME, url: 'http://127.0.0.1:9/none', format: 'ip-list' });
  check('seed source created (disabled later)', seedCreate.status === 201, `status=${seedCreate.status}`);
  const seedId = seedCreate.data?.id ?? '';
  const seedDisable = await api<TiSource>('PATCH', `/threat-intel/sources/${seedId}`, { enabled: false });
  check('seed source disabled', seedDisable.status === 200 && seedDisable.data?.enabled === false);
  await pool.query(
    `INSERT INTO threat_iocs (id, "sourceId", ioc, "firstSeenAt", "lastSeenAt")
     VALUES ($3, $1, $2::inet, now()::text, now()::text)`,
    [seedId, SEED_IOC, crypto.randomUUID()]
  );

  const created = await api<TiSource>('POST', '/threat-intel/sources', { name: FEED_NAME, url, format: 'ip-list' });
  check('feed source created (201)', created.status === 201, `status=${created.status} ${JSON.stringify(created.data ?? {}).slice(0, 80)}`);
  const feedId = created.data?.id ?? '';

  // The creation triggers an immediate fetch — poll until it lands.
  const fetched = await pollUntil(90_000, async () => {
    const r = await api<TiResponse>('GET', '/threat-intel');
    if (r.status !== 200) return false;
    const s = r.data.sources.find((x) => x.id === feedId);
    return Boolean(s && s.iocCount === 3 && s.lastSuccessAt);
  });
  check('feed fetched with exactly 3 indicators', fetched, 'expected iocCount=3 (host + CIDR + v6; comments/URLs/garbage skipped)');

  const state = await api<TiResponse>('GET', '/threat-intel');
  const feed = state.data?.sources.find((x) => x.id === feedId);
  check('feed lastError is null after success', !feed?.lastError, feed?.lastError ?? '');
  const cnt = await pool.query(`SELECT COUNT(*)::int AS n FROM threat_iocs WHERE "sourceId" = $1`, [feedId]);
  check('threat_iocs rows match iocCount', Number(cnt.rows[0]?.n ?? -1) === 3, `${cnt.rows[0]?.n} row(s)`);

  return feedId;
}

// ── B: firewall-event matching ───────────────────────────────────────────────
async function phaseB(): Promise<void> {
  console.log('\n[B] Matching — crafted firewall_events vs the active IOC set');

  // Rows with tsMs <= the worker's firewall watermark are NEVER scanned (the
  // watermark starts at "now" on API boot and only advances). Our crafted
  // events are stamped with Date.now() at insert time, so we must ensure the
  // watermark is not AHEAD of that stamp — a boot-time reset or a clock-skewed
  // device row could otherwise make them invisible. (A stale watermark on a
  // quiet network is fine: our rows simply sit ahead of it.)
  const wmReady = await pollUntil(90_000, async () => {
    const r = await api<TiResponse>('GET', '/threat-intel');
    if (r.status !== 200 || !r.data) return false;
    const wm = Number(r.data.worker.fwWatermarkMs ?? 0);
    return wm > 0 && Date.now() - wm >= -5_000; // tolerate up to 5 s of device skew
  });
  check('firewall watermark behind our future stamp', wmReady, 'watermark must not be ahead of now (clock-skewed rows would skip the crafted events)');

  const nowMs = Date.now();
  // ev1: SRC is a listed host. ev2: DST falls inside a listed CIDR.
  // ev3: SRC is only in the DISABLED source — must NOT produce a finding.
  const events: Array<{ id: string; src: string; dst: string; action: string; tsMs: number }> = [
    { id: 'e2e-ti-fw-1', src: FEED_IOC_HOST, dst: '10.0.0.5', action: 'drop', tsMs: nowMs + 1_000 },
    { id: 'e2e-ti-fw-2', src: '10.0.0.9', dst: CIDR_HIT_IP, action: 'pass', tsMs: nowMs + 2_000 },
    { id: 'e2e-ti-fw-3', src: SEED_IOC, dst: '10.0.0.6', action: 'drop', tsMs: nowMs + 3_000 },
  ];
  for (const e of events) {
    await pool.query(
      `INSERT INTO firewall_events (id, "pluginId", "deviceId", ts, "tsMs", action, reason, "interfaceName", "srcIp", "dstIp", proto, "srcPort", "dstPort", "ruleId", "ruleName", "vendorEventId")
       VALUES ($1, 'e2e', $2, (to_timestamp($3 / 1000.0) AT TIME ZONE 'UTC')::text, $3, $4, NULL, '', $5, $6, '6', NULL, NULL, NULL, NULL, $7)`,
      [e.id, FW_DEVICE, e.tsMs, e.action, e.src, e.dst, crypto.randomUUID()]
    );
  }

  // Poll until both expected tuples appear as open findings (worker beat = 60 s;
  // events are ahead of the watermark, so one or two beats must suffice).
  // NOTE: lookups use inet EQUALITY, never "::text" keys — PostgreSQL renders
  // inet host addresses with a /32 suffix ('198.51.100.66/32'), while equality
  // comparisons ignore the host prefix.
  const tupleOpen = async (src: string, dst: string): Promise<boolean> => {
    const r = await pool.query(
      `SELECT 1 FROM flow_security_findings WHERE kind = 'ioc-hit' AND status = 'open' AND "srcIp" = $1::inet AND "dstIp" = $2::inet`,
      [src, dst]
    );
    return r.rows.length > 0;
  };
  const seen = await pollUntil(4 * 60_000, async () => {
    return (await tupleOpen(FEED_IOC_HOST, '10.0.0.5')) && (await tupleOpen('10.0.0.9', CIDR_HIT_IP));
  });
  check('both firewall-event tuples raised ioc-hit findings', seen, 'worker beat is 60 s — both (src-side host hit + dst-side CIDR hit) expected');

  const ctxOf = async (src: string, dst: string): Promise<{ iocHits?: Array<{ ip: string; sources: string[]; side: string }> } | null> => {
    const r = await pool.query(
      `SELECT context FROM flow_security_findings WHERE kind = 'ioc-hit' AND status = 'open' AND "srcIp" = $1::inet AND "dstIp" = $2::inet`,
      [src, dst]
    );
    return r.rows[0] ? (JSON.parse(String(r.rows[0].context)) as { iocHits?: Array<{ ip: string; sources: string[]; side: string }> }) : null;
  };

  const ev1Ctx = await ctxOf(FEED_IOC_HOST, '10.0.0.5');
  check('ev1 hit recorded on the SRC side with feed name', ev1Ctx?.iocHits?.some((h) => h.ip === FEED_IOC_HOST && h.side === 'src' && h.sources.includes(FEED_NAME)) ?? false, JSON.stringify(ev1Ctx?.iocHits ?? []).slice(0, 120));

  const ev2Ctx = await ctxOf('10.0.0.9', CIDR_HIT_IP);
  check('ev2 CIDR hit recorded on the DST side', ev2Ctx?.iocHits?.some((h) => h.ip === CIDR_HIT_IP && h.side === 'dst' && h.sources.includes(FEED_NAME)) ?? false, JSON.stringify(ev2Ctx?.iocHits ?? []).slice(0, 120));

  const disabledHit = await pool.query(`SELECT COUNT(*)::int AS n FROM flow_security_findings WHERE kind = 'ioc-hit' AND "srcIp" = $1::inet`, [SEED_IOC]);
  check('disabled-source IOC produced NO finding', Number(disabledHit.rows[0]?.n ?? -1) === 0, `${disabledHit.rows[0]?.n} row(s)`);

  const notifs = await pool.query(
    `SELECT "dedupeKey", title FROM notifications WHERE "dedupeKey" IN ($1, $2)`,
    [`flow-security:ioc-hit:${FEED_IOC_HOST}:10.0.0.5`, `flow-security:ioc-hit:10.0.0.9:${CIDR_HIT_IP}`]
  );
  check('one notification per hit tuple', notifs.rows.length === 2, `${notifs.rows.length}/2 rows`);

  // False-positive guard: the only matchable indicators are TEST-NET addresses
  // (documentation ranges — real traffic can never contain them), so at this
  // point EXACTLY the two crafted tuples may exist. A broken CIDR containment
  // check would flood this with findings on live device traffic.
  const fp = await pool.query(`SELECT COUNT(*)::int AS n FROM flow_security_findings WHERE kind = 'ioc-hit' AND status = 'open'`);
  check('no false positives on unlisted traffic (exactly the 2 crafted tuples)', Number(fp.rows[0]?.n ?? -1) === 2, `${fp.rows[0]?.n} open ioc-hit findings`);
}

// ── C: flow matching (bucket-aligned) ────────────────────────────────────────
async function phaseC(): Promise<void> {
  console.log('\n[C] Matching — flow_agg_5m destination in the next unprocessed bucket');
  const state = await api<TiResponse>('GET', '/threat-intel');
  if (state.status !== 200 || !state.data) throw new Error(`/threat-intel → ${state.status}`);
  check('worker enabled', state.data.enabled === true);
  const cursor = state.data.worker.cursorBucketMs;
  const S = cursor + BUCKET_MS; // first unprocessed bucket start
  console.log(`  worker cursor=${new Date(cursor).toISOString()} target bucket S=${new Date(S).toISOString()}`);

  await pool.query(
    `INSERT INTO flow_agg_5m (bucket, "srcIp", "dstIp", proto, bytes, packets, "estBytes", "srcClass", "dstClass", "srcHostname")
     VALUES ($1, $2::inet, $3::inet, 6, 2_097_152, 262_144, 2_097_152, 'internal', 'internet', 'e2e-threat-flow-src')`,
    [new Date(S).toISOString(), FLOW_SRC, FEED_IOC_HOST]
  );

  // Wait until the bucket closed at least one full rollup interval ago.
  const readyAt = S + PROCESS_LAG_MS;
  let waited = 0;
  while (Date.now() < readyAt) {
    if (waited % 30_000 === 0) console.log(`  waiting for bucket to close — ~${Math.ceil((readyAt - Date.now()) / 60_000)} min left`);
    await sleep(15_000); waited += 15_000;
  }

  const seen = await pollUntil(4 * 60_000, async () => {
    const r = await pool.query(`SELECT COUNT(*)::int AS n FROM flow_security_findings WHERE kind = 'ioc-hit' AND status = 'open' AND "srcIp" = $1::inet AND "dstIp" = $2::inet`, [FLOW_SRC, FEED_IOC_HOST]);
    return Number(r.rows[0]?.n ?? 0) > 0;
  });
  check('flow destination hit raised an ioc-hit finding', seen, `${FLOW_SRC} → ${FEED_IOC_HOST}`);

  const row = await pool.query(`SELECT context FROM flow_security_findings WHERE kind = 'ioc-hit' AND "srcIp" = $1::inet AND "dstIp" = $2::inet`, [FLOW_SRC, FEED_IOC_HOST]);
  const ctx = JSON.parse(String(row.rows[0]?.context ?? '{}')) as { iocHits?: Array<{ ip: string; sources: string[] }>; estBytes?: number };
  check('flow finding context carries IOC source + volume', (ctx.iocHits?.some((h) => h.ip === FEED_IOC_HOST && h.sources.includes(FEED_NAME)) ?? false) && (ctx.estBytes ?? 0) > 0, JSON.stringify(ctx).slice(0, 120));
}

// ── D: cleanup ───────────────────────────────────────────────────────────────
/** Deletes every row this script may create — idempotent; used by the pre-clean
 *  (step 0) and by the final cleanup. */
async function purgeE2eRows(): Promise<void> {
  const state = await api<TiResponse>('GET', '/threat-intel');
  for (const name of [FEED_NAME, SEED_NAME]) {
    const src = state.data?.sources.find((x) => x.name === name);
    if (!src) continue;
    const r = await api<{ deleted: boolean }>('DELETE', `/threat-intel/sources/${src.id}`);
    console.log(`  source ${name} → ${r.status}`);
  }
  const e2eIps = [FEED_IOC_HOST, CIDR_HIT_IP, SEED_IOC, FLOW_SRC];
  await pool.query(
    `DELETE FROM flow_security_findings WHERE kind = 'ioc-hit' AND ("srcIp" = ANY($1::inet[]) OR "dstIp" = ANY($2::inet[]))`,
    [e2eIps, e2eIps]
  );
  await pool.query(
    `DELETE FROM notifications WHERE "dedupeKey" IN ($1, $2, $3, $4)`,
    [
      `flow-security:ioc-hit:${FEED_IOC_HOST}:10.0.0.5`,
      `flow-security:ioc-hit:10.0.0.9:${CIDR_HIT_IP}`,
      // The flow path builds the key from "srcIp"::text, which PG renders with /32.
      `flow-security:ioc-hit:${FLOW_SRC}:${FEED_IOC_HOST}`,
      `flow-security:ioc-hit:${FLOW_SRC}/32:${FEED_IOC_HOST}/32`,
    ]
  );
  await pool.query(`DELETE FROM firewall_events WHERE "deviceId" = $1`, [FW_DEVICE]);
  await pool.query(`DELETE FROM flow_agg_5m WHERE "srcIp" = $1::inet AND "dstIp" = $2::inet`, [FLOW_SRC, FEED_IOC_HOST]);
}

async function phaseCleanup(): Promise<void> {
  if (KEEP) { console.log('\n[D] Cleanup skipped (KEEP=1)'); return; }
  console.log('\n[D] Cleanup');
  await purgeE2eRows();
  console.log('  done');
}

// ── Main ─────────────────────────────────────────────────────────────────────
async function main(): Promise<void> {
  // Local feed server — reachable from the API container via the bridge gateway.
  const server = http.createServer((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(FEED_BODY);
  });
  await new Promise<void>((resolve) => server.listen(0, '0.0.0.0', resolve));
  const port = (server.address() as { port: number }).port;

  try {
    console.log('[0] Pre-clean — removing residue from previous/interrupted runs');
    await purgeE2eRows();
    await phaseA(port);
    await phaseB();
    await phaseC();
    await phaseCleanup();
  } finally {
    server.close();
    await pool.end();
  }

  console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error('\nE2E aborted:', err);
  process.exit(1);
});
