#!/usr/bin/env tsx
/**
 * Live E2E for the flow security insights feature (Phase 1):
 *   A. worker detection — seed synthetic rows into the NEXT unprocessed
 *      flow_agg_5m bucket (new internet destination above the byte threshold,
 *      a horizontal port scan, and an egress-baseline breach with seeded
 *      hourly history) and assert the findings + notifications land.
 *   B. automation trigger — create a rule with a `securityFinding` trigger +
 *      notification action, let it seed its watermark, insert one synthetic
 *      finding, and assert the rule fires with rendered {{finding.*}} tokens.
 *   C. cleanup (set KEEP=1 to leave the test data in place).
 *
 * Test IPs live in documentation ranges (TEST-NET-3 203.0.113.0/24 for
 * internet dsts, 192.168.50.0/24 + 10.99.0.0/24 for sources/internal dsts)
 * so they cannot collide with real traffic. Phase A rebuilds the worker's
 * seen-destination baseline (POST /flows/security/baseline/reset) BEFORE
 * seeding — otherwise the lazy boot-time load would count our freshly seeded
 * rows as "known" and detector 1 would skip them. The internet destination
 * IPs are still randomized per run as defense-in-depth for KEEP=1 re-runs.
 *
 * Usage: tsx scripts/e2e-flow-security.ts   (from repo root; reads UNM_API_TOKEN from .env)
 */
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';

// Run from the repo root (tsx scripts/e2e-flow-security.ts).
const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));
const { Pool } = apiRequire('pg') as typeof import('pg');

const API = process.env.API_URL || 'http://localhost:3000/v1';
const KEEP = process.env.KEEP === '1';

// ── Test identity ────────────────────────────────────────────────────────────
const DST_A = `203.0.113.${65 + Math.floor(Math.random() * 60)}`; // new-destination (detector 1)
const DST_B = `203.0.113.${65 + Math.floor(Math.random() * 60)}`; // egress pair dst (detectors 1+3)
const SRC_NEW = '192.168.50.201';
const SRC_SCAN = '192.168.50.202';
const SRC_EGRESS = '192.168.50.203';
const SRC_TRIGGER = '192.168.50.204'; // synthetic finding for the automation test
const DST_TRIGGER = `203.0.113.${65 + Math.floor(Math.random() * 60)}`;
const SCAN_DSTS = Array.from({ length: 12 }, (_, i) => `10.99.0.${i + 1}`); // ≥ default minDsts (10), < 3×

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

interface FindingRow {
  id: string; kind: string; severity: string; srcIp: string; dstIp: string | null;
  detail: string; context: Record<string, unknown> | null; deviceId: string | null;
  deviceName: string | null; firstSeenAt: string; lastSeenAt: string; occurrences: number; status: string;
}
interface SecurityResponse { findings: FindingRow[]; worker: { enabled: boolean; lastRunAt: string | null; lastError: string | null; cursorBucketMs: number; seenDstCount: number } }

const BUCKET_MS = 300_000;
const PROCESS_LAG_MS = 2 * BUCKET_MS;

// ── Phase A: worker detection ────────────────────────────────────────────────
async function phaseA(): Promise<void> {
  console.log('\n[A] Worker detection — seeding the next unprocessed flow_agg_5m bucket');
  const sec = await api<SecurityResponse>('GET', '/flows/security');
  if (sec.status !== 200) throw new Error(`/flows/security → ${sec.status}`);
  check('worker enabled', sec.data.worker.enabled === true);
  const cursor = sec.data.worker.cursorBucketMs;
  const S = cursor + BUCKET_MS; // first unprocessed bucket start
  console.log(`  cursor=${new Date(cursor).toISOString()} target bucket S=${new Date(S).toISOString()}`);

  // Rebuild the seen-destination baseline BEFORE seeding: the lazy boot-time
  // load would otherwise run after our rows exist in flow_agg_5m and detector
  // 1 would treat every seeded destination as "known".
  const reset = await api<{ reloaded: boolean; size: number }>('POST', '/flows/security/baseline/reset');
  check('seen-destination baseline rebuilt pre-seed', reset.status === 200 && reset.data?.reloaded === true,
    `status=${reset.status} ${JSON.stringify(reset.data ?? {}).slice(0, 80)}`);

  // Seed immediately (weekly partitions already cover future buckets) — the
  // worker cannot advance its cursor past S before now >= S + PROCESS_LAG_MS,
  // so the rows are guaranteed to be inside the first batch that includes S.
  const sIso = new Date(S).toISOString();
  await pool.query(
    `INSERT INTO flow_agg_5m (bucket, "srcIp", "dstIp", proto, bytes, packets, "estBytes", "srcClass", "dstClass", "srcHostname")
     VALUES ($1, $2::inet, $3::inet, 6, $4, $5, $4, 'internal', 'internet', 'e2e-flowsec-src')`,
    [sIso, SRC_NEW, DST_A, 5_242_880, 6_553] // 5 MiB ≥ default alert threshold (1 MiB) → warning + notification
  );
  for (const d of SCAN_DSTS) {
    await pool.query(
      `INSERT INTO flow_agg_5m (bucket, "srcIp", "dstIp", proto, bytes, packets, "estBytes", "srcClass", "dstClass")
       VALUES ($1, $2::inet, $3::inet, 6, 100, 2, 100, 'internal', 'internal')`,
      [sIso, SRC_SCAN, d]
    );
  }
  // Egress pair: hourly history (median baseline) + a big transfer inside the window.
  const nowMs = Date.now();
  let historyRows = 0;
  for (let h = 26; h >= 7; h--) {
    const bIso = new Date(nowMs - h * 3_600_000).toISOString().replace(/:\d\d\.\d+Z$/, ':00.000Z');
    try {
      await pool.query(
        `INSERT INTO flow_agg_1h (bucket, "srcIp", "dstIp", proto, bytes, packets, "estBytes", "srcClass", "dstClass")
         VALUES ($1, $2::inet, $3::inet, 6, $4, $5, $4, 'internal', 'internet')`,
        [bIso, SRC_EGRESS, DST_B, 10_485_760, 1_310_720] // 10 MiB/h → median baseline
      );
      historyRows += 1;
    } catch (err) {
      console.warn(`  (history row at ${bIso} failed — ${(err as Error).message})`);
    }
  }
  check('egress hourly history seeded', historyRows >= 5, `${historyRows}/20 rows`);
  await pool.query(
    `INSERT INTO flow_agg_5m (bucket, "srcIp", "dstIp", proto, bytes, packets, "estBytes", "srcClass", "dstClass")
     VALUES ($1, $2::inet, $3::inet, 6, $4, $5, $4, 'internal', 'internet')`,
    [sIso, SRC_EGRESS, DST_B, 314_572_800, 39_321_600] // 300 MiB in the window → avg 50 MiB/h = 5× median
  );
  console.log(`  seeded: new-dst ${SRC_NEW}→${DST_A}, scan ${SRC_SCAN}→${SCAN_DSTS.length} dsts, egress ${SRC_EGRESS}→${DST_B}`);

  // Wait until bucket S is processable (closed ≥ one full rollup interval ago).
  const readyAt = S + PROCESS_LAG_MS;
  let waited = 0;
  while (Date.now() < readyAt) {
    const leftMin = Math.ceil((readyAt - Date.now()) / 60_000);
    if (waited % 30_000 === 0) console.log(`  waiting for bucket to close — ~${leftMin} min left`);
    await sleep(15_000); waited += 15_000;
  }

  // Poll for the findings (worker beat = 60 s).
  const deadline = Date.now() + 4 * 60_000;
  let found: FindingRow[] = [];
  while (Date.now() < deadline) {
    const r = await api<SecurityResponse>('GET', '/flows/security?status=all&limit=200');
    if (r.status === 200) found = r.data.findings;
    const have = (kind: string, src: string, dst?: string | null) =>
      found.some((f) => f.kind === kind && f.srcIp === src && (dst === undefined ? true : f.dstIp === dst));
    if (have('new-destination', SRC_NEW, DST_A) && have('port-scan', SRC_SCAN) && have('egress-baseline', SRC_EGRESS, DST_B)) break;
    await sleep(20_000);
  }

  const fNew = found.find((f) => f.kind === 'new-destination' && f.srcIp === SRC_NEW && f.dstIp === DST_A);
  check('finding: new-destination (warning)', !!fNew && fNew.severity === 'warning', fNew ? `${fNew.detail.slice(0, 80)}…` : 'missing');
  const fScan = found.find((f) => f.kind === 'port-scan' && f.srcIp === SRC_SCAN);
  check('finding: port-scan (warning, dst null)', !!fScan && fScan.severity === 'warning' && fScan.dstIp === null,
    fScan ? `distinctDsts=${(fScan.context as Record<string, unknown> | null)?.distinctDsts}` : 'missing');
  const fEgress = found.find((f) => f.kind === 'egress-baseline' && f.srcIp === SRC_EGRESS && f.dstIp === DST_B);
  check('finding: egress-baseline (warning)', !!fEgress && fEgress.severity === 'warning',
    fEgress ? `ratio=${(fEgress.context as Record<string, unknown> | null)?.ratio}` : 'missing');
  const fNewB = found.find((f) => f.kind === 'new-destination' && f.srcIp === SRC_EGRESS && f.dstIp === DST_B);
  check('finding: egress dst also flagged new-destination', !!fNewB, '(expected — first-time pair above threshold)');

  const worker = (await api<SecurityResponse>('GET', '/flows/security')).data.worker;
  check('worker lastRunAt set + no error', !!worker.lastRunAt && worker.lastError === null, `lastError=${worker.lastError}`);

  // Notifications: one per freshly detected finding.
  const nr = await pool.query(
    `SELECT title, severity FROM notifications WHERE "dedupeKey" IN ($1,$2,$3,$4)`,
    [
      `flow-security:new-destination:${SRC_NEW}:${DST_A}`,
      `flow-security:port-scan:${SRC_SCAN}:`,
      `flow-security:new-destination:${SRC_EGRESS}:${DST_B}`,
      `flow-security:egress-baseline:${SRC_EGRESS}:${DST_B}`,
    ]
  );
  check('notifications emitted (4 dedupe keys)', nr.rows.length === 4, `${nr.rows.length}/4`);

  // kind/status filters on the route.
  const filtered = await api<SecurityResponse>('GET', `/flows/security?kind=port-scan&status=open`);
  check('route filter kind=port-scan', filtered.status === 200 && filtered.data.findings.every((f) => f.kind === 'port-scan')
    && filtered.data.findings.some((f) => f.srcIp === SRC_SCAN));
}

// ── Phase B: securityFinding automation trigger ──────────────────────────────
async function phaseB(): Promise<void> {
  console.log('\n[B] Automation trigger — rule with securityFinding trigger + notification action');
  const created = await api<{ automation: { id: string } }>('POST', '/automations', {
    name: 'E2E flow-security finding (auto)',
    description: 'Temporary E2E rule — safe to delete.',
    triggers: [{ id: 't-fs-1', type: 'securityFinding' }],
    actions: [{
      id: 'a-notif-1', type: 'notification', severity: 'warning',
      titleTemplate: 'E2E {{finding.kind}} from {{finding.srcIp}} to {{finding.dstIp}}',
      messageTemplate: '{{finding.detail}} (severity: {{finding.severity}})',
    }],
  });
  if (created.status !== 201) throw new Error(`POST /automations → ${created.status}: ${JSON.stringify(created.data).slice(0, 300)}`);
  const ruleId = created.data.automation.id;
  check('rule created', !!ruleId, ruleId);

  // Wait for the first automations tick to seed the finding watermark (tick = 15 s).
  let wm: string | null = null;
  for (let i = 0; i < 8 && !wm; i++) {
    await sleep(15_000);
    const r = await pool.query(`SELECT value FROM automation_state WHERE "automationId" = $1 AND "stateKey" = 'findingWatermark'`, [ruleId]);
    wm = r.rows.length > 0 ? String(r.rows[0].value) : null;
  }
  check('watermark seeded on first tick', !!wm, wm ?? 'no automation_state row after 2 min');

  // Insert TWO synthetic findings just after the watermark (same condition, two
  // rows) → one scan must see both and fire exactly ONCE with matchCount=2,
  // using the newest finding for the context.
  const tB = new Date(Date.now() - 10_000).toISOString();
  const tA = new Date().toISOString();
  await pool.query(
    `INSERT INTO flow_security_findings (id, kind, severity, "srcIp", "dstIp", detail, context, "deviceId", "firstSeenAt", "lastSeenAt", occurrences, status)
     VALUES ($1, 'new-destination', 'critical', $2::inet, $3::inet, 'E2E synthetic — burst row (older)', '{}', NULL, $4, $4, 1, 'open')`,
    [`e2e-finding-${Date.now()}-b`, SRC_TRIGGER, DST_TRIGGER, tB]
  );
  await pool.query(
    `INSERT INTO flow_security_findings (id, kind, severity, "srcIp", "dstIp", detail, context, "deviceId", "firstSeenAt", "lastSeenAt", occurrences, status)
     VALUES ($1, 'new-destination', 'critical', $2::inet, $3::inet, 'E2E synthetic — automation trigger test', '{"estBytes": 999}', NULL, $4, $4, 1, 'open')`,
    [`e2e-finding-${Date.now()}`, SRC_TRIGGER, DST_TRIGGER, tA]
  );

  // Poll the run history (tick = 15 s).
  let runs: { triggerType: string; status: string; context: unknown }[] = [];
  for (let i = 0; i < 8; i++) {
    await sleep(15_000);
    const r = await api<{ runs: { triggerType: string; status: string; context: string }[] }>('GET', `/automations/${ruleId}/runs`);
    if (r.status === 200) runs = r.data.runs;
    if (runs.length > 0) break;
  }
  check('automation run recorded', runs.length >= 1, `${runs.length} run(s)`);
  const run = runs[0];
  // The API already returns `context` as a parsed object (serializeRun) — accept both shapes.
  let ctx: Record<string, unknown> = {};
  try {
    const rawCtx: unknown = run?.context;
    if (typeof rawCtx === 'string') ctx = JSON.parse(rawCtx);
    else if (rawCtx && typeof rawCtx === 'object') ctx = rawCtx as Record<string, unknown>;
  } catch { /* keep {} */ }
  check('run context carries finding', run?.triggerType === 'securityFinding' && String(ctx.srcIp ?? '') === SRC_TRIGGER,
    `status=${run?.status} ctx=${JSON.stringify(ctx).slice(0, 120)}`);

  const nr = await pool.query(`SELECT title FROM notifications WHERE "dedupeKey" = $1`, [`automation:${ruleId}:a-notif-1`]);
  check('action notification rendered {{finding.*}}',
    nr.rows.length === 1 && nr.rows[0].title === `E2E new-destination from ${SRC_TRIGGER} to ${DST_TRIGGER}`,
    nr.rows[0]?.title ?? 'missing');

  // Both findings are now behind the watermark → no further firings.
  await sleep(35_000); // two more ticks
  const r2 = await api<{ runs: unknown[] }>('GET', `/automations/${ruleId}/runs`);
  check('burst fired once, no re-fire', r2.data.runs.length === 1 && Number(ctx.matchCount ?? 0) === 2,
    `${r2.data.runs.length} run(s), matchCount=${String(ctx.matchCount)}`);

  if (!KEEP) {
    await api('DELETE', `/automations/${ruleId}`);
    await pool.query(`DELETE FROM automation_state WHERE "automationId" = $1`, [ruleId]);
    await pool.query(`DELETE FROM automation_runs WHERE "automationId" = $1`, [ruleId]);
    await pool.query(`DELETE FROM notifications WHERE "dedupeKey" = $1`, [`automation:${ruleId}:a-notif-1`]);
  }
}

// ── Phase C: cleanup ─────────────────────────────────────────────────────────
async function phaseC(): Promise<void> {
  if (KEEP) { console.log('\n[C] KEEP=1 — leaving test data in place'); return; }
  console.log('\n[C] Cleanup');
  const srcs = [SRC_NEW, SRC_SCAN, SRC_EGRESS, SRC_TRIGGER];
  const r1 = await pool.query(`DELETE FROM flow_security_findings WHERE "srcIp" = ANY($1::inet[])`, [srcs]);
  const r2 = await pool.query(
    `DELETE FROM notifications WHERE "dedupeKey" IN ($1,$2,$3,$4)`,
    [
      `flow-security:new-destination:${SRC_NEW}:${DST_A}`,
      `flow-security:port-scan:${SRC_SCAN}:`,
      `flow-security:new-destination:${SRC_EGRESS}:${DST_B}`,
      `flow-security:egress-baseline:${SRC_EGRESS}:${DST_B}`,
    ]
  );
  const r3 = await pool.query(`DELETE FROM flow_agg_5m WHERE "srcIp" = ANY($1::inet[])`, [srcs]);
  const r4 = await pool.query(`DELETE FROM flow_agg_1h WHERE "srcIp" = $1::inet`, [SRC_EGRESS]);
  console.log(`  findings=${r1.rowCount} notifications=${r2.rowCount} agg5m=${r3.rowCount} agg1h=${r4.rowCount}`);
}

// ── Main ─────────────────────────────────────────────────────────────────────
async function main(): Promise<void> {
  try {
    await phaseA();
    await phaseB();
    await phaseC();
  } catch (err) {
    console.error('\nE2E aborted:', err);
    failures += 1;
  } finally {
    await pool.end();
  }
  console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(2);
});
