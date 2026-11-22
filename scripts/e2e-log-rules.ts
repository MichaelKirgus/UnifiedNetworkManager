#!/usr/bin/env tsx
/**
 * Live E2E for the log-rules feature (docs/LOG-RULES.md §11):
 *   A. boot state — built-in pack seeded, worker stats sane, every rule parses.
 *   B. API error paths — bad YAML → structured 400 naming the unsupported field;
 *      duplicate name → 409; DELETE on a builtin → 400 (protected).
 *   C. detection semantics against real worker beats:
 *        - single-line user rule fires exactly one finding (dedupeKey …:global)
 *        - thresholded builtin (ssh-brute-force, 5/5m per srcIp) does NOT fire
 *          at 3 hits and DOES fire once the window reaches 5 (…:<srcIp>)
 *        - a disabled user rule never fires
 *        - severity override wins over the YAML level on a thresholded user rule
 *   D. multi-document import — per-rule created/error/duplicate results, never all-or-nothing.
 *   E. cleanup (set KEEP=1 to leave the test data in place).
 *
 * Test lines carry unique markers / TEST-NET-3 source addresses so they cannot
 * collide with real traffic; seeded rows are timestamped just past the worker's
 * current watermark (the watermark tracks near-real-time, so `now - 2min` would
 * be invisible to it). Each assertion round waits for one full worker beat.
 *
 * Usage: tsx scripts/e2e-log-rules.ts   (from repo root; reads UNM_API_TOKEN from .env)
 */
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';

// Run from the repo root (tsx scripts/e2e-log-rules.ts).
const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));
const { Pool } = apiRequire('pg') as typeof import('pg');

const API = process.env.API_URL || 'http://localhost:3000/v1';
const KEEP = process.env.KEEP === '1';
/** One worker beat is 60s — wait a bit longer so the next beat has definitely run. */
const BEAT_WAIT_MS = Number(process.env.BEAT_WAIT_MS) || 75_000;

// ── Test identity (unique per run so re-runs never collide) ─────────────────
const RUN = Date.now().toString(36);
const MARKER_A = `E2E-LR-${RUN}-SINGLE`; // single-line user rule
const MARKER_B = `E2E-LR-${RUN}-DISABLED`; // disabled user rule (must never fire)
const MARKER_C = `E2E-LR-${RUN}-THRESHOLD`; // thresholded user rule (override test)
const SRC_BRUTE = `203.0.113.${65 + Math.floor(Math.random() * 60)}`; // TEST-NET-3, brute-force group
const SRC_THRESH = `203.0.113.${90 + Math.floor(Math.random() * 40)}`; // TEST-NET-3, threshold user rule

// ── Plumbing ────────────────────────────────────────────────────────────────
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

interface LogRuleRow {
  id: string; name: string; source: 'builtin' | 'user'; sigmaYaml: string; enabled: boolean;
  severityOverride: string | null; lastError: string | null; createdAt: string; updatedAt: string;
  lastHitAt: string | null; occurrences: number;
}
interface LogRulesResponse {
  enabled: boolean;
  worker: { lastRunAt: string | null; lastError: string | null; watermarkMs: number; rulesEnabled: number | null; hitsLast24h: number };
  rules: LogRuleRow[];
}

/** Seeds one security_events row just past the given watermark (the only window the worker scans). */
async function seedEvent(idSuffix: string, wm: number, offsetMs: number, message: string, appname: string, srcIp: string | null): Promise<void> {
  await pool.query(
    `INSERT INTO security_events (id, "pluginId", "deviceId", "tsMs", level, severity, facility, hostname, appname, "srcIp", "dstIp", message, "vendorEventId")
     VALUES ($1, 'e2e-log-rules', NULL, $2, 'info', NULL, NULL, 'e2e-host', $3, $4, NULL, $5, $6)`,
    [`e2e-lr-${RUN}-${idSuffix}`, wm + offsetMs, appname, srcIp, message, `e2e-lr-ve-${RUN}-${idSuffix}`]
  );
}

/** Open log-rule findings for the given rule ids. */
async function findingsFor(ruleIds: string[]): Promise<Array<{ dedupeKey: string; severity: string; occurrences: number; detail: string }>> {
  const res = await pool.query(
    `SELECT "dedupeKey", severity, occurrences, detail FROM flow_security_findings
     WHERE kind = 'log-rule' AND status = 'open' AND (context::jsonb)->>'ruleId' = ANY($1)`,
    [ruleIds]
  );
  return res.rows;
}

async function main(): Promise<void> {
  console.log('e2e-log-rules — live E2E for Sigma log-rule detection');

  // ── A. boot state ───────────────────────────────────────────────────────────
  const lr0 = await api<LogRulesResponse>('GET', '/log-rules');
  check('GET /log-rules → 200', lr0.status === 200);
  const d0 = lr0.data;
  const builtins = d0.rules.filter((r) => r.source === 'builtin');
  check('built-in pack seeded (≥15 rules)', builtins.length >= 15, `${builtins.length} builtins`);
  // rulesEnabled is null until the first beat builds the cache — asserted after beat 1 below.
  check('worker stats present', typeof d0.worker.watermarkMs === 'number' && d0.worker.watermarkMs > 0, `watermarkMs=${d0.worker.watermarkMs}`);
  const parseErrors = d0.rules.filter((r) => r.lastError !== null);
  check('every rule parses (no lastError)', parseErrors.length === 0, parseErrors.map((r) => `${r.name}: ${r.lastError}`).join('; '));

  // ── B. API error paths ──────────────────────────────────────────────────────
  const bad = await api<{ error: string; issues?: string[] }>('POST', '/log-rules', {
    yaml: 'title: e2e bad\ndetection:\n  s:\n    winlog.eventid: 4625\ncondition: s',
  });
  check('bad rule → 400 naming the unsupported field', bad.status === 400 && /winlog\.eventid/.test(bad.data.error ?? ''), `status=${bad.status}`);
  check('bad rule → structured issues[] with supported set', Array.isArray(bad.data.issues) && bad.data.issues.some((i) => i.includes('message, appname')), JSON.stringify(bad.data.issues ?? []));

  const dup = await api<{ error: string }>('POST', '/log-rules', {
    name: 'ssh-brute-force',
    yaml: 'title: e2e dup\ndetection:\n  s:\n    message:\n      contains: "x"\ncondition: s',
  });
  check('duplicate name → 409', dup.status === 409, `status=${dup.status}`);

  const builtinId = builtins[0]?.id;
  const delBuiltin = await api<{ error: string }>('DELETE', `/log-rules/${builtinId}`);
  check('DELETE on builtin → 400 (protected)', delBuiltin.status === 400, `status=${delBuiltin.status}`);

  // ── C. detection semantics ──────────────────────────────────────────────────
  const ruleA = await api<LogRuleRow>('POST', '/log-rules', {
    name: `e2e-lr-${RUN}-a`,
    yaml: [`title: e2e single line`, 'detection:', '  s:', '    message:', `      contains: '${MARKER_A}'`, 'condition: s'].join('\n'),
  });
  check('create user rule A (single-line) → 201', ruleA.status === 201 && !!ruleA.data.id, `status=${ruleA.status}`);

  const ruleB = await api<LogRuleRow>('POST', '/log-rules', {
    name: `e2e-lr-${RUN}-b`,
    yaml: [`title: e2e disabled`, 'detection:', '  s:', '    message:', `      contains: '${MARKER_B}'`, 'condition: s'].join('\n'),
  });
  check('create user rule B (to be disabled) → 201', ruleB.status === 201 && !!ruleB.data.id, `status=${ruleB.status}`);

  const ruleC = await api<LogRuleRow>('POST', '/log-rules', {
    name: `e2e-lr-${RUN}-c`,
    yaml: [
      'title: e2e threshold user rule',
      'level: low', // → info by default; the override below must win
      'detection:',
      '  s:',
      '    message:',
      `      contains: '${MARKER_C}'`,
      'condition: s',
      'unm.threshold:',
      '  count: 2',
      '  withinMinutes: 5',
      '  groupBy: srcIp',
    ].join('\n'),
  });
  check('create user rule C (thresholded) → 201', ruleC.status === 201 && !!ruleC.data.id, `status=${ruleC.status}`);

  const disableB = await api<LogRuleRow>('PATCH', `/log-rules/${ruleB.data.id}`, { enabled: false });
  check('disable rule B → enabled=false', disableB.status === 200 && disableB.data.enabled === false, `status=${disableB.status}`);

  const overrideC = await api<LogRuleRow>('PATCH', `/log-rules/${ruleC.data.id}`, { severityOverride: 'warning' });
  check('override rule C severity → warning', overrideC.status === 200 && overrideC.data.severityOverride === 'warning', `status=${overrideC.status}`);

  // Beat 1 — single-line fires; brute-force at 3/5 must NOT fire; disabled B must not fire.
  const wm1 = (await api<LogRulesResponse>('GET', '/log-rules')).data.worker.watermarkMs;
  await seedEvent('a1', wm1, 1000, `sshd[900]: ${MARKER_A} synthetic single-line hit`, 'auth.log', null);
  for (let i = 0; i < 3; i++) {
    await seedEvent(`bf${i}`, wm1, 2000 + i * 500, `sshd[901]: Failed password for root from ${SRC_BRUTE} port 6000${i} ssh2`, 'auth.log', SRC_BRUTE);
  }
  await seedEvent('b1', wm1, 4000, `${MARKER_B} synthetic line for a disabled rule`, 'auth.log', null);
  await seedEvent('c0', wm1, 5000, `${MARKER_C} synthetic threshold line one`, 'app.log', SRC_THRESH);
  console.log(`  … waiting one beat (${Math.round(BEAT_WAIT_MS / 1000)}s) for the worker to scan`);
  await sleep(BEAT_WAIT_MS);

  const fA1 = await findingsFor([ruleA.data.id]);
  check('single-line rule fired exactly one finding', fA1.length === 1, `${fA1.length} findings`);
  check('finding dedupeKey is log-rule:<id>:global', fA1[0]?.dedupeKey === `log-rule:${ruleA.data.id}:global`, fA1[0]?.dedupeKey ?? 'n/a');
  const bfRule = d0.rules.find((r) => r.name === 'ssh-brute-force');
  check('thresholded builtin did NOT fire at 3/5', (await findingsFor([bfRule?.id ?? ''])).length === 0, `srcIp=${SRC_BRUTE}`);
  check('disabled rule B never fired', (await findingsFor([ruleB.data.id])).length === 0);
  check('thresholded user rule did NOT fire at 1/2', (await findingsFor([ruleC.data.id])).length === 0, `srcIp=${SRC_THRESH}`);
  const lrAfterBeat = await api<LogRulesResponse>('GET', '/log-rules');
  check('rule cache built after a beat (rulesEnabled ≥ 18)', (lrAfterBeat.data.worker.rulesEnabled ?? 0) >= 18, `rulesEnabled=${lrAfterBeat.data.worker.rulesEnabled}`);

  // Beat 2 — brute-force completes to 5/5 and fires; threshold user rule C reaches 2/2 with the override.
  const wm2 = (await api<LogRulesResponse>('GET', '/log-rules')).data.worker.watermarkMs;
  for (let i = 0; i < 2; i++) {
    await seedEvent(`bf${3 + i}`, wm2, 1000 + i * 500, `sshd[902]: Failed password for root from ${SRC_BRUTE} port 6001${i} ssh2`, 'auth.log', SRC_BRUTE);
  }
  await seedEvent('c1', wm2, 3000, `${MARKER_C} synthetic threshold line two`, 'app.log', SRC_THRESH);
  console.log(`  … waiting one beat (${Math.round(BEAT_WAIT_MS / 1000)}s) for the worker to scan`);
  await sleep(BEAT_WAIT_MS);

  const fBF = await findingsFor([bfRule?.id ?? '']);
  check('thresholded builtin fired at 5/5', fBF.length === 1, `${fBF.length} findings`);
  check('brute-force finding grouped by srcIp', fBF[0]?.dedupeKey === `log-rule:${bfRule?.id}:${SRC_BRUTE}`, fBF[0]?.dedupeKey ?? 'n/a');
  const fC = await findingsFor([ruleC.data.id]);
  check('thresholded user rule fired at 2/2', fC.length === 1, `${fC.length} findings`);
  check('severity override won (warning, not the YAML level info)', fC[0]?.severity === 'warning', `severity=${fC[0]?.severity ?? 'n/a'}`);

  // ── D. multi-document import ────────────────────────────────────────────────
  const imp = await api<{ imported: number; total: number; results: Array<{ name: string | null; status: string; error?: string }> }>('POST', '/log-rules/import', {
    yaml: [
      `title: e2e import ${RUN} good`,
      'detection:',
      '  s:',
      '    message:',
      `      contains: '${MARKER_A}-IMPORT'`,
      'condition: s',
      '---',
      'title: e2e import bad',
      'detection:',
      '  s:',
      '    winlog.eventid: 1',
      'condition: s',
      '---',
      'title: oom-kill', // collides with the seeded builtin name → duplicate
      'detection:',
      '  s:',
      '    message:',
      `      contains: '${MARKER_A}-DUP'`,
      'condition: s',
    ].join('\n'),
  });
  check('import → 201 with per-rule results', imp.status === 201 && imp.data.total === 3, `status=${imp.status}`);
  const byStatus = (s: string) => imp.data.results.filter((r) => r.status === s);
  check('import created the good doc', byStatus('created').length === 1, JSON.stringify(imp.data.results));
  check('import rejected the bad doc with a named error', byStatus('error').length === 1 && /winlog\.eventid/.test(byStatus('error')[0]?.error ?? ''));
  check('import flagged the name collision as duplicate', byStatus('duplicate').length === 1);

  // ── E. cleanup ──────────────────────────────────────────────────────────────
  if (KEEP) {
    console.log('  KEEP=1 — leaving test rules/events/findings in place');
  } else {
    for (const id of [ruleA.data.id, ruleB.data.id, ruleC.data.id]) {
      await api('DELETE', `/log-rules/${id}`);
    }
    const importedName = byStatus('created')[0]?.name;
    if (importedName) {
      const lrNow = (await api<LogRulesResponse>('GET', '/log-rules')).data;
      const impRule = lrNow.rules.find((r) => r.name === importedName);
      if (impRule) await api('DELETE', `/log-rules/${impRule.id}`);
    }
    await pool.query(`DELETE FROM security_events WHERE id LIKE $1`, [`e2e-lr-${RUN}-%`]);
    await pool.query(
      `DELETE FROM flow_security_findings WHERE kind = 'log-rule' AND (context::jsonb)->>'ruleId' = ANY($1)`,
      [[ruleA.data.id, ruleB.data.id, ruleC.data.id, bfRule?.id ?? '']]
    );
    console.log('  cleanup done (test rules, seeded events, test findings removed)');
  }

  await pool.end();
  console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error('e2e-log-rules crashed:', err);
  void pool.end();
  process.exit(1);
});
