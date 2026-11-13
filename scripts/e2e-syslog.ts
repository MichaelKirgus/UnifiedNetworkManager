#!/usr/bin/env tsx
/**
 * Live E2E for syslog ingestion (Phase 2):
 *   A. Ingest — send crafted BSD + RFC5424 datagrams to UDP :514 (the host's
 *      published port), poll GET /v1/security-events and assert level mapping,
 *      hostname/appname parsing, vendor src/dst extraction and dedup on resend.
 *   B. Automation trigger — create a rule with a log trigger source='security'
 *      + notification action, wait for the watermark seed, send two matching
 *      datagrams (a burst) and assert exactly ONE run with matchCount=2 plus
 *      the rendered notification.
 *   C. Cleanup (set KEEP=1 to leave the test data in place).
 *
 * Every test row carries the distinctive hostname 'e2e-syslog-host' so cleanup
 * deletes precisely what this script created — no other table is touched.
 *
 * Usage: tsx scripts/e2e-syslog.ts   (from repo root; reads UNM_API_TOKEN from .env)
 */
import dgram from 'node:dgram';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';

// Run from the repo root (tsx scripts/e2e-syslog.ts).
const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));
const { Pool } = apiRequire('pg') as typeof import('pg');

const API = process.env.API_URL || 'http://localhost:3000/v1';
const KEEP = process.env.KEEP === '1';
const SYSLOG_HOST = 'e2e-syslog-host';
const PLUGIN_UUID = '00000000-0000-4000-8000-0000000013';

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

/** Send one line to the collector's published UDP port on localhost. */
function sendUdp(line: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const sock = dgram.createSocket('udp4');
    sock.send(Buffer.from(line, 'utf8'), 514, '127.0.0.1', (err) => {
      sock.close();
      if (err) reject(err); else resolve();
    });
  });
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
/** BSD syslog line stamped with the CURRENT UTC date/time. The collector
 *  container runs TZ=UTC by default, so a UTC stamp lands at its true instant
 *  (stays inside the route's default 1h window and the trigger's 24h floor).
 *  In production, set SYSLOG_TZ to the fleet's zone for real devices. */
function bsdLine(pri: number, appname: string, message: string): string {
  const now = new Date();
  const p2 = (n: number) => String(n).padStart(2, '0');
  return `<${pri}>${MONTHS[now.getUTCMonth()]} ${p2(now.getUTCDate())} ${p2(now.getUTCHours())}:${p2(now.getUTCMinutes())}:${p2(now.getUTCSeconds())} ${SYSLOG_HOST} ${appname}[4242]: ${message}`;
}

interface SecurityEventRow {
  id: string; tsMs: number; level: string; severity: string | null; facility: string | null;
  hostname: string | null; appname: string | null; srcIp: string | null; dstIp: string | null;
  message: string; vendorEventId: string; deviceId: string | null;
}
interface SecurityEventsResponse { fromMs: number; toMs: number; rows: SecurityEventRow[]; summary: { total: number; byLevel: Record<string, number> } }

async function waitForPlugin(): Promise<void> {
  for (let i = 0; i < 30; i++) {
    const r = await api<{ id: string; name: string }[]>('GET', '/plugins');
    if (r.status === 200) {
      const p = r.data.find((x) => x.id === PLUGIN_UUID || /syslog/i.test(x.name));
      if (p) return;
    }
    await sleep(3_000);
  }
  throw new Error('syslog-collector plugin not registered after 90s');
}

// ── Phase A: ingest over UDP :514 ────────────────────────────────────────────
async function phaseA(): Promise<void> {
  console.log('\n[A] Ingest — BSD + RFC5424 datagrams over UDP :514');
  await waitForPlugin();
  check('plugin registered', true, PLUGIN_UUID);

  // auth.critical (PRI 34) → level 'error'; OPNsense arrow shape carries src/dst.
  const bsd = bsdLine(34, 'opnsense', 'block inet tcp 203.0.113.7:51234 -> 198.51.100.1:443 on vtnet0');
  // local2.notice (PRI 165) → level 'info'; RFC5424 with structured data.
  const rfc = `<165>1 ${new Date().toISOString()} ${SYSLOG_HOST} sshd 999 ID47 [x-forwarded-for="203.0.113.8"] Accepted publickey for admin from 203.0.113.8 port 55556`;

  await sendUdp(bsd);
  await sendUdp(rfc);
  await sendUdp(bsd); // exact resend — must dedup (same vendorEventId)

  let rows: SecurityEventRow[] = [];
  for (let i = 0; i < 20 && rows.length < 2; i++) {
    await sleep(3_000);
    const r = await api<SecurityEventsResponse>('GET', `/security-events?search=${SYSLOG_HOST}`);
    if (r.status === 200) rows = r.data.rows;
  }
  check('both events ingested', rows.length >= 2, `${rows.length} row(s)`);

  const opnsenseRows = rows.filter((x) => x.appname === 'opnsense');
  check('BSD line parsed (auth.critical → error)',
    opnsenseRows.length === 1 && opnsenseRows[0].level === 'error' && opnsenseRows[0].severity === 'critical',
    JSON.stringify(opnsenseRows[0] ?? {}).slice(0, 140));
  check('BSD vendor IPs extracted (OPNsense arrow)',
    opnsenseRows[0]?.srcIp === '203.0.113.7' && opnsenseRows[0]?.dstIp === '198.51.100.1',
    `${opnsenseRows[0]?.srcIp} -> ${opnsenseRows[0]?.dstIp}`);
  check('resend deduped (one row per vendorEventId)', opnsenseRows.length === 1, `${opnsenseRows.length} rows`);

  const sshdRows = rows.filter((x) => x.appname === 'sshd');
  check('RFC5424 line parsed (local2.notice → info)',
    sshdRows.length === 1 && sshdRows[0].level === 'info' && sshdRows[0].facility === 'local2',
    JSON.stringify(sshdRows[0] ?? {}).slice(0, 140));
}

// ── Phase B: security-source automation trigger ──────────────────────────────
async function phaseB(): Promise<void> {
  console.log('\n[B] Automation trigger — log trigger source=security + notification action');
  const created = await api<{ automation: { id: string } }>('POST', '/automations', {
    name: 'E2E syslog security events (auto)',
    description: 'Temporary E2E rule — safe to delete.',
    triggers: [{ id: 't-log-1', type: 'log', source: 'security', pattern: 'e2e-syslog-trigger' }],
    actions: [{
      id: 'a-notif-1', type: 'notification', severity: 'warning',
      titleTemplate: 'E2E syslog trigger fired ({{trigger.type}})',
      messageTemplate: '{{log.message}}',
    }],
  });
  if (created.status !== 201) throw new Error(`POST /automations → ${created.status}: ${JSON.stringify(created.data).slice(0, 300)}`);
  const ruleId = created.data.automation.id;
  check('rule created', !!ruleId, ruleId);

  // Wait for the first automations tick to seed the log watermark (tick = 15 s).
  // Phase A's rows are inside the 24h window, so the scan has rows to advance past.
  let wm: string | null = null;
  for (let i = 0; i < 8 && !wm; i++) {
    await sleep(15_000);
    const r = await pool.query(`SELECT value FROM automation_state WHERE "automationId" = $1 AND "triggerId" = 't-log-1' AND "stateKey" = 'logWatermark'`, [ruleId]);
    wm = r.rows.length > 0 ? String(r.rows[0].value) : null;
  }
  check('watermark seeded on first tick', !!wm, wm ?? 'no automation_state row after 2 min');

  // Two matching datagrams (a burst) → one scan sees both → exactly ONE run
  // with matchCount=2 using the NEWEST match as context. The short gap makes
  // the RFC line's tsMs strictly newer than the BSD line's, so "second event"
  // is deterministically the representative row.
  await sendUdp(bsdLine(134, 'e2e-app', `e2e-syslog-trigger first event at ${Date.now()}`)); // local0.info
  await sleep(1_500);
  await sendUdp(`<165>1 ${new Date().toISOString()} ${SYSLOG_HOST} e2e-app - - - e2e-syslog-trigger second event`);

  let runs: { triggerType: string; status: string; context: unknown }[] = [];
  for (let i = 0; i < 8; i++) {
    await sleep(15_000);
    const r = await api<{ runs: { triggerType: string; status: string; context: string }[] }>('GET', `/automations/${ruleId}/runs`);
    if (r.status === 200) runs = r.data.runs;
    if (runs.length > 0) break;
  }
  check('automation run recorded', runs.length >= 1, `${runs.length} run(s)`);
  const run = runs[0];
  // The API already returns `context` as a parsed object — accept both shapes.
  let ctx: Record<string, unknown> = {};
  try {
    const rawCtx: unknown = run?.context;
    if (typeof rawCtx === 'string') ctx = JSON.parse(rawCtx);
    else if (rawCtx && typeof rawCtx === 'object') ctx = rawCtx as Record<string, unknown>;
  } catch { /* keep {} */ }
  check('run context carries log match (burst → one run, matchCount=2)',
    run?.triggerType === 'log' && String(ctx.source ?? '') === 'security' && Number(ctx.matchCount ?? 0) === 2,
    `status=${run?.status} ctx=${JSON.stringify(ctx).slice(0, 160)}`);

  const nr = await pool.query(`SELECT title, message FROM notifications WHERE "dedupeKey" = $1`, [`automation:${ruleId}:a-notif-1`]);
  check('action notification rendered {{log.message}} (newest match)',
    nr.rows.length === 1 && String(nr.rows[0].message) === 'e2e-syslog-trigger second event',
    `title=${nr.rows[0]?.title ?? 'missing'} msg=${String(nr.rows[0]?.message ?? '').slice(0, 60)}`);

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
  const r = await pool.query(`DELETE FROM security_events WHERE hostname = $1`, [SYSLOG_HOST]);
  console.log(`  security_events=${r.rowCount}`);
}

// ── Main ─────────────────────────────────────────────────────────────────────
async function main(): Promise<void> {
  try {
    await phaseA();
    await phaseB();
    await phaseC();
  } catch (err) {
    console.error('E2E aborted:', err);
    failures += 1;
  } finally {
    await pool.end();
  }
  if (failures > 0) {
    console.log(`\n${failures} CHECK(S) FAILED`);
    process.exit(1);
  }
  console.log('\nALL CHECKS PASSED');
}

main();
