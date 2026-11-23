#!/usr/bin/env tsx
/**
 * Live E2E for the flow security Phase 2 detectors:
 *   A. beaconing — seed a (src → internet dst) pair active in six consecutive
 *      5-minute buckets (sub-5-min period ≈ constant C2 check-in), plus two
 *      negative controls (high-jitter spacing, and perfectly periodic but
 *      heavy transfers). Assert exactly the positive pair raises a 'beacon'
 *      finding. NOTE: flow tiers carry a 2-bucket process lag, so Phase A
 *      waits ~40–45 min of real time for the seeded buckets to become
 *      processable — run it in the background.
 *   B. DNS heuristics — insert dns_query_events rows for DGA-like domains
 *      (ten distinct names per client to cross the volume gate, plus human-word,
 *      low-volume and whitelisted-zone negatives) and tunneling traffic (long
 *      subdomain labels, high volume; plus a short-label negative). Assert 'dga'
 *      and 'dns-tunnel' findings land with the right attribution.
 *   C. cleanup (set KEEP=1 to leave the test data in place).
 *
 * Test identities live in reserved ranges so they cannot collide with real
 * traffic: sources/clients 10.99.1.x (RFC1918 → internal), internet dsts
 * randomized per run inside TEST-NET-3 (203.0.113.0/24), DNS names on the
 * IANA-reserved .test / .example TLDs. Phase A rebuilds the worker's
 * seen-destination baseline BEFORE seeding and plants a small history row for
 * each test destination in an already-processed bucket — otherwise detector 1
 * would also flag them as new destinations (noise, not wrong).
 *
 * Usage: tsx scripts/e2e-flow-security-phase2.ts   (from repo root; reads UNM_API_TOKEN from .env)
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { createRequire } from 'node:module';

// Run from the repo root (tsx scripts/e2e-flow-security-phase2.ts).
const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));
const { Pool } = apiRequire('pg') as typeof import('pg');

const API = process.env.API_URL || 'http://localhost:3000/v1';
const KEEP = process.env.KEEP === '1';

// ── Test identity ────────────────────────────────────────────────────────────
const randOctet = () => 65 + Math.floor(Math.random() * 60); // TEST-NET-3, same range as Phase 1 E2E
const SRC_BEACON = '10.99.1.1';
const DST_BEACON = `203.0.113.${randOctet()}`; // positive: six consecutive buckets (sub-5-min period)
const SRC_JITTER = '10.99.1.2';
const DST_JITTER = `203.0.113.${randOctet()}`; // negative: irregular spacing (cv ≈ 60%)
const SRC_HEAVY = '10.99.1.3';
const DST_HEAVY = `203.0.113.${randOctet()}`; // negative: periodic but 50 MiB/bucket (> 4 MiB gate)
// Positive DNS names are randomized per run: the dnsSecurity worker keeps
// in-boot dedupe caches (dgaReported / tunnelState) that survive across E2E
// runs, so a fixed name would be silently skipped on re-runs.
const CLIENT_DGA = '10.99.1.4';
// Volume gate (default 10 distinct DGA-like domains per client): seed exactly the
// threshold count — crossing it confirms the client and reports EVERY tracked
// domain, so all ten must land as findings.
const DGA_DOMAINS_POS: string[] = (() => {
  const out = new Set<string>();
  while (out.size < 10) out.add(`${randConsonantLabel(14)}.test`); // H = log2(14) ≈ 3.81 ≥ 3.6, zero vowels
  return [...out];
})();
const DGA_DOMAIN_POS = DGA_DOMAINS_POS[0];
const DGA_DOMAIN_NEG = 'stackoverflow.example'; // len 13 but H ≈ 3.55 < 3.6 (and vowel ratio 31%)
// Volume-gate negative: ONE DGA-like domain (< threshold) → no finding…
const CLIENT_SUPPRESSED = '10.99.1.7';
const SUPPRESSED_DOMAIN = `${randConsonantLabel(14)}.test`;
// …and whitelist negative: a DGA-like label on a whitelisted zone (cloudfront.net is in the default list) → never scored.
const WHITELISTED_DOMAIN = `${randConsonantLabel(14)}.cloudfront.net`;
const CLIENT_TUNNEL = '10.99.1.5';
const TUNNEL_BASE_POS = `tun${randLabel(10)}.test`; // 35 queries, 30-char subdomain labels
const CLIENT_TUNNEL_NEG = '10.99.1.6';
const TUNNEL_BASE_NEG = 'tunnelneg-e2e.test'; // 35 queries but 1-char labels

const ALL_TEST_IPS = [SRC_BEACON, SRC_JITTER, SRC_HEAVY, CLIENT_DGA, CLIENT_SUPPRESSED, CLIENT_TUNNEL, CLIENT_TUNNEL_NEG];
const ALL_TEST_DSTS = [DST_BEACON, DST_JITTER, DST_HEAVY];

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
  id: string; kind: string; severity: string; srcIp: string | null; dstIp: string | null;
  detail: string; context: Record<string, unknown> | null; deviceId: string | null;
  firstSeenAt: string; lastSeenAt: string; occurrences: number; status: string;
}
interface SecurityResponse {
  findings: FindingRow[];
  worker: { enabled: boolean; cursorBucketMs: number; beaconTrackedPairs?: number };
  dnsHeuristics?: { enabled: boolean; watermarkMs: number; lastError: string | null };
}

const BUCKET_MS = 300_000;
const PROCESS_LAG_MS = 2 * BUCKET_MS;

function randLabel(len: number): string {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let s = '';
  for (let i = 0; i < len; i++) s += chars[Math.floor(Math.random() * chars.length)];
  return s;
}

/** `len` DISTINCT consonants — guarantees the DGA gates pass: length ≥ 12,
 *  Shannon entropy log2(len) (≥ 3.8 for len 14), vowel ratio 0. */
function randConsonantLabel(len: number): string {
  const chars = 'bcdfghjklmnpqrstvwxyz'.split('');
  for (let i = chars.length - 1; i > 0; i--) { // Fisher–Yates shuffle
    const j = Math.floor(Math.random() * (i + 1));
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.slice(0, len).join('');
}

// ── Cleanup / pre-clean ──────────────────────────────────────────────────────
async function purgeTestRows(): Promise<void> {
  await pool.query(`DELETE FROM flow_security_findings WHERE "srcIp" = ANY($1::inet[])`, [ALL_TEST_IPS]);
  await pool.query(
    `DELETE FROM notifications WHERE "dedupeKey" LIKE 'flow-security:%' AND ("dedupeKey" LIKE '%10.99.1.%')`
  );
  // Single array parameter (double-wrapped): pg serializes the inner array as one text[] value.
  await pool.query(`DELETE FROM dns_query_events WHERE client = ANY($1)`, [[CLIENT_DGA, CLIENT_SUPPRESSED, CLIENT_TUNNEL, CLIENT_TUNNEL_NEG]]);
  await pool.query(`DELETE FROM flow_agg_5m WHERE "srcIp" = ANY($1::inet[])`, [ALL_TEST_IPS]);
}

// ── Phase A: beaconing ───────────────────────────────────────────────────────
async function phaseA(): Promise<void> {
  console.log('\n[A] Beaconing — seeding periodic + negative-control flow buckets');
  const sec = await api<SecurityResponse>('GET', '/flows/security');
  if (sec.status !== 200) throw new Error(`/flows/security → ${sec.status}`);
  check('flow security worker enabled', sec.data.worker.enabled === true);
  const cursor = sec.data.worker.cursorBucketMs;

  const seed = (bucketMs: number, srcIp: string, dstIp: string, estBytes: number): Promise<unknown> =>
    pool.query(
      `INSERT INTO flow_agg_5m (bucket, "srcIp", "dstIp", proto, bytes, packets, "estBytes", "srcClass", "dstClass")
       VALUES ($1, $2::inet, $3::inet, 6, $4, 2, $4, 'internal', 'internet')`,
      [new Date(bucketMs).toISOString(), srcIp, dstIp, estBytes]
    );

  // History rows in an ALREADY-PROCESSED bucket (before the cursor): they make
  // the test destinations "known" to detector 1 without entering any analysis
  // window. Tiny volume so no other detector notices them either.
  const histBucketMs = cursor - 2 * 3_600_000;
  for (const [src, dst] of [[SRC_BEACON, DST_BEACON], [SRC_JITTER, DST_JITTER], [SRC_HEAVY, DST_HEAVY]] as const) {
    await seed(histBucketMs, src, dst, 1_024);
  }

  // Positive: six CONSECUTIVE buckets — a sub-5-min beacon appears in every
  // bucket (period ≈ 5 min, jitter cv = 0). Consecutive keeps the span short:
  // with the tier's 2-bucket process lag the last one is processable ~40 min
  // after this script starts.
  for (const off of [1, 2, 3, 4, 5, 6]) await seed(cursor + off * BUCKET_MS, SRC_BEACON, DST_BEACON, 2_048);
  // Negative: irregular spacing — intervals [1,4,2,7,3] buckets → cv ≈ 60% ≫ 25%.
  for (const off of [1, 2, 6, 8, 15, 18]) await seed(cursor + off * BUCKET_MS, SRC_JITTER, DST_JITTER, 2_048);
  // Negative: perfectly periodic (cv = 0) but 50 MiB per bucket > 4 MiB gate.
  for (const off of [1, 2, 3, 4, 5, 6]) await seed(cursor + off * BUCKET_MS, SRC_HEAVY, DST_HEAVY, 52_428_800);

  // Rebuild the seen-destination baseline AFTER seeding: the lazy boot-time
  // load predates our rows, so without this reload detector 1 would flag every
  // test destination as new. The seeded buckets are all in the future (not yet
  // processable), so no beat can run between seed and reset.
  const reset = await api<{ reloaded: boolean; size: number }>('POST', '/flows/security/baseline/reset');
  check('seen-destination baseline rebuilt post-seed', reset.status === 200 && reset.data?.reloaded === true,
    `status=${reset.status} ${JSON.stringify(reset.data ?? {}).slice(0, 80)}`);

  // The newest seeded bucket (cursor+6) becomes processable once now ≥ cursor
  // + 8 buckets (2-bucket lag); allow one more bucket of slack for the beat.
  const readyAtMs = cursor + 9 * BUCKET_MS;
  console.log(`  cursor=${new Date(cursor).toISOString()} — waiting until ${new Date(readyAtMs).toISOString()} (~40–45 min)`);

  let beacon: FindingRow | undefined;
  let jitterFinding = false;
  let heavyFinding = false;
  const deadline = readyAtMs + 2 * 60_000; // the wait IS the test — no short cap
  while (Date.now() < deadline) {
    if (Date.now() >= readyAtMs - BUCKET_MS) {
      const r = await api<SecurityResponse>('GET', '/flows/security?kind=beacon');
      if (r.status === 200 && r.data.findings.length > 0) {
        beacon = r.data.findings.find((f) => f.dstIp === DST_BEACON);
        jitterFinding = r.data.findings.some((f) => f.dstIp === DST_JITTER);
        heavyFinding = r.data.findings.some((f) => f.dstIp === DST_HEAVY);
        if (beacon && !jitterFinding && !heavyFinding) break; // all three assertions decidable
      }
    }
    await sleep(10_000);
  }

  check('positive pair raised a beacon finding', !!beacon, beacon ? `severity=${beacon.severity}` : 'none found');
  if (beacon) {
    check('beacon period ≈ 5 min (sub-bucket beacon)', Number(beacon.context?.periodMinutes) === 5, `context=${JSON.stringify(beacon.context ?? {})}`);
    check('beacon bucket count = 6', Number(beacon.context?.bucketCount) === 6);
    check('beacon severity warning (cv=0 but below the critical multiple)', beacon.severity === 'warning');
  }
  check('high-jitter pair NOT flagged', !jitterFinding);
  check('heavy periodic transfer NOT flagged (egress detector\'s domain)', !heavyFinding);

  // The history rows must have suppressed new-destination findings for our dsts.
  const nd = await api<SecurityResponse>('GET', '/flows/security?kind=new-destination');
  const ndOurs = nd.status === 200 ? nd.data.findings.filter((f) => ALL_TEST_DSTS.includes(f.dstIp ?? '')) : [];
  check('no new-destination findings for test destinations (history rows worked)', ndOurs.length === 0,
    ndOurs.map((f) => `${f.srcIp}→${f.dstIp}`).join(', '));
}

// ── Phase B: DNS heuristics ──────────────────────────────────────────────────
async function phaseB(): Promise<void> {
  console.log('\n[B] DNS heuristics — inserting DGA + tunneling query rows');
  const sec = await api<SecurityResponse>('GET', '/flows/security');
  if (sec.status !== 200) throw new Error(`/flows/security → ${sec.status}`);
  check('dns heuristics enabled', sec.data.dnsHeuristics?.enabled === true, JSON.stringify(sec.data.dnsHeuristics ?? {}));

  // Rows must be stamped AFTER the worker's watermark (no history replay). The
  // scan has a +5 min future-skew guard, so wait until now is comfortably AHEAD
  // of the watermark — a clock-skewed appliance row could otherwise push it past
  // our insert time and silently skip us.
  const wm = sec.data.dnsHeuristics?.watermarkMs ?? Date.now();
  while (Date.now() <= wm + 5_000) { await sleep(1_000); }
  const t0 = Date.now();

  // One existing device + plugin to attribute the rows to (NOT NULL columns).
  const devRes = await pool.query(`SELECT id FROM devices LIMIT 1`);
  const plugRes = await pool.query(`SELECT id FROM plugins LIMIT 1`);
  if (devRes.rows.length === 0 || plugRes.rows.length === 0) throw new Error('no device/plugin in DB — cannot seed dns_query_events');
  const deviceId = String(devRes.rows[0].id);
  const pluginId = String(plugRes.rows[0].id);

  let i = 0;
  const insertDns = (client: string, domain: string): Promise<unknown> =>
    pool.query(
      `INSERT INTO dns_query_events (id, "pluginId", "deviceId", "tsMs", client, domain, qtype, action, "vendorEventId")
       VALUES ($1, $2, $3, $4, $5, $6, 'A', 'pass', $7)`,
      [crypto.randomUUID(), pluginId, deviceId, t0 + (i += 1) * 10, client, domain, crypto.randomUUID()]
    );

  for (const d of DGA_DOMAINS_POS) await insertDns(CLIENT_DGA, d); // crosses the volume gate → all ten reported
  await insertDns(CLIENT_DGA, DGA_DOMAIN_POS); // second query — must NOT create a second finding
  await insertDns(CLIENT_DGA, DGA_DOMAIN_NEG);
  await insertDns(CLIENT_SUPPRESSED, SUPPRESSED_DOMAIN); // below the volume gate → no finding
  await insertDns(CLIENT_SUPPRESSED, WHITELISTED_DOMAIN); // whitelisted zone → never scored
  for (let q = 0; q < 35; q++) await insertDns(CLIENT_TUNNEL, `${randLabel(30)}.${TUNNEL_BASE_POS}`);
  for (let q = 0; q < 35; q++) await insertDns(CLIENT_TUNNEL_NEG, `a.${TUNNEL_BASE_NEG}`);

  console.log(`  inserted ${i} rows at tsMs=${t0} (watermark was ${wm}) — waiting for the next beat`);

  let dgaPos: FindingRow | undefined;
  let dgaNeg = false;
  let lowVolLeaked = false;
  let whitelistLeaked = false;
  let posFoundCount = 0;
  let tunnelPos: FindingRow | undefined;
  let tunnelNeg = false;
  const deadline = Date.now() + 3 * 60_000; // two beats at worst (60 s cadence)
  while (Date.now() < deadline) {
    const [dga, tun] = await Promise.all([
      api<SecurityResponse>('GET', '/flows/security?kind=dga'),
      api<SecurityResponse>('GET', '/flows/security?kind=dns-tunnel'),
    ]);
    if (dga.status === 200) {
      dgaPos = dga.data.findings.find((f) => f.context?.domain === DGA_DOMAIN_POS);
      dgaNeg = dga.data.findings.some((f) => f.context?.domain === DGA_DOMAIN_NEG);
      lowVolLeaked = dga.data.findings.some((f) => f.context?.domain === SUPPRESSED_DOMAIN);
      whitelistLeaked = dga.data.findings.some((f) => f.context?.domain === WHITELISTED_DOMAIN);
      posFoundCount = dga.data.findings.filter((f) => DGA_DOMAINS_POS.includes(String(f.context?.domain ?? ''))).length;
    }
    if (tun.status === 200) {
      tunnelPos = tun.data.findings.find((f) => f.context?.baseDomain === TUNNEL_BASE_POS);
      tunnelNeg = tun.data.findings.some((f) => f.context?.baseDomain === TUNNEL_BASE_NEG);
    }
    // dgaPos existing proves ≥1 beat processed the rows — absence of the negatives is decidable then.
    if (dgaPos && !dgaNeg && !lowVolLeaked && !whitelistLeaked && tunnelPos && !tunnelNeg) break;
    await sleep(10_000);
  }

  check('DGA-like domain raised a finding', !!dgaPos, dgaPos ? `src=${dgaPos.srcIp}` : 'none found');
  if (dgaPos) {
    check('DGA finding attributed to the querying client', dgaPos.srcIp === CLIENT_DGA);
    check('DGA context carries label features', Number(dgaPos.context?.labelLen) >= 12 && Number(dgaPos.context?.entropy) > 3.5,
      `context=${JSON.stringify(dgaPos.context ?? {})}`);
  }
  const dgaAll = await api<SecurityResponse>('GET', '/flows/security?kind=dga');
  const posCount = dgaAll.status === 200 ? dgaAll.data.findings.filter((f) => f.context?.domain === DGA_DOMAIN_POS).length : -1;
  check('repeated queries to the same DGA domain do not duplicate findings', posCount === 1, `count=${posCount}`);
  const allPosFound = dgaAll.status === 200 ? dgaAll.data.findings.filter((f) => DGA_DOMAINS_POS.includes(String(f.context?.domain ?? ''))).length : -1;
  check('volume gate crossed → ALL tracked domains of the client reported', allPosFound === DGA_DOMAINS_POS.length, `count=${allPosFound}/${DGA_DOMAINS_POS.length}`);
  check('human-word domain NOT flagged as DGA', !dgaNeg);
  check('single DGA-like domain below the volume gate NOT flagged', !lowVolLeaked);
  check('DGA-like label on a whitelisted zone (cloudfront.net) NOT flagged', !whitelistLeaked);

  check('tunneling traffic raised a finding', !!tunnelPos, tunnelPos ? `src=${tunnelPos.srcIp}` : 'none found');
  if (tunnelPos) {
    check('tunnel finding attributed to the querying client', tunnelPos.srcIp === CLIENT_TUNNEL);
    check('tunnel context carries query count + label length', Number(tunnelPos.context?.queries) >= 30 && Number(tunnelPos.context?.avgLabelLen) >= 24,
      `context=${JSON.stringify(tunnelPos.context ?? {})}`);
  }
  check('short-label high-volume traffic NOT flagged as tunneling', !tunnelNeg);
}

// ── Main ─────────────────────────────────────────────────────────────────────
async function main(): Promise<void> {
  console.log(`flow security Phase 2 E2E — ${API}`);
  console.log('pre-clean (idempotent)');
  await purgeTestRows();

  await phaseA();
  await phaseB();

  if (!KEEP) {
    console.log('\n[C] Cleanup');
    await purgeTestRows();
    const left = await pool.query(
      `SELECT COUNT(*)::int AS n FROM flow_security_findings WHERE "srcIp" = ANY($1::inet[])`, [ALL_TEST_IPS]
    );
    check('cleanup removed all test findings', Number(left.rows[0].n) === 0);
    console.log('cleanup done');
  } else {
    console.log('\nKEEP=1 — leaving test data in place');
  }

  if (failures > 0) {
    console.error(`\n${failures} CHECK(S) FAILED`);
    process.exitCode = 1;
  } else {
    console.log('\nALL CHECKS PASSED');
  }
}

main().catch((err) => {
  console.error('E2E aborted:', err);
  process.exit(1);
});
