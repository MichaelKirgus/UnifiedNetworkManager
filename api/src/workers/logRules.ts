/**
 * Log rules — Sigma-based detection over ingested device log lines
 * (docs/LOG-RULES.md). Scans security_events (syslog forwarding + rotation-
 * aware file tailing) with a tsMs watermark, evaluates the enabled compiled
 * rules from the log_rules table and raises 'log-rule' findings into
 * flow_security_findings — the SAME pipeline as threat-intel hits:
 * notifications on first detection + securityFinding automation trigger.
 *
 * Watermark semantics (same contract as threatIntel's fwWatermarkMs): rows at
 * or below wmMs are never re-scanned, so nothing older than this process's
 * boot is replayed; a clock-skewed device can push tsMs into the future, hence
 * the FUTURE_GUARD_MS. While logRulesEnabled is off the watermark does NOT
 * advance — re-enabling resumes from where it stopped.
 */

import { v4 as uuidv4 } from 'uuid';
import { pool } from '../db';
import { emitNotification } from '../notifications';
import { LEADER_KEYS } from './leader';
import { initWorker, trackBeat } from './stats';
import { getEffectiveSettingValue } from '../systemSettings';
import { upsertFinding } from './flowSecurity';
import { BUILTIN_LOG_RULES } from '../logRules/builtin';
import { CompiledLogRule, LogRuleParseError, LogRuleRow, parseSigmaRule, RuleSeverity } from '../logRules/sigma';

const BEAT_MS = 60_000;
/** Rows newer than now - this are not scanned yet (clock-skew guard). */
const FUTURE_GUARD_MS = 5_000;
const SEVERITIES: readonly string[] = ['info', 'warning', 'critical'];

// ── State ────────────────────────────────────────────────────────────────

/** Epoch ms of the last fully-scanned security_events row (exclusive lower bound). */
let wmMs = Date.now();
/** Overlap guard — a slow beat must not pile up unbounded concurrent scans. */
let busy = false;
let lastRunAt: string | null = null;
let lastError: string | null = null;

interface CompiledRuleRow {
  id: string;
  name: string;
  severityOverride: RuleSeverity | null;
  rule: CompiledLogRule;
}

/** In-memory compiled rules — rebuilt when the enabled-rule set changes. */
let ruleCache: { version: string; rules: CompiledRuleRow[] } | null = null;

/** Rolling-window counters for thresholded rules, keyed `${ruleId}:${groupValue}`. */
const thresholdBuffers = new Map<string, number[]>();

// ── Built-in seeding ───────────────────────────────────────────────────────

/**
 * Seeds/refreshes the built-in pack (source='builtin'). New names are inserted;
 * existing built-ins get their YAML refreshed to this image's version while the
 * user's enabled/severityOverride choices are preserved. A USER rule with a
 * colliding name blocks seeding — user content is never clobbered.
 */
export async function seedBuiltinLogRules(): Promise<void> {
  const nowIso = new Date().toISOString();
  for (const b of BUILTIN_LOG_RULES) {
    const existing = await pool.query(
      `SELECT id, "sigmaYaml" FROM log_rules WHERE name = $1 AND source = 'builtin'`,
      [b.name]
    );
    if (existing.rows.length === 0) {
      const userDup = await pool.query(`SELECT id FROM log_rules WHERE name = $1`, [b.name]);
      if (userDup.rows.length > 0) continue; // user owns this name — leave it alone
      await pool.query(
        `INSERT INTO log_rules (id, name, source, "sigmaYaml", enabled, "severityOverride", "lastError", "createdAt", "updatedAt")
         VALUES ($1, $2, 'builtin', $3, true, NULL, NULL, $4, $4)`,
        [uuidv4(), b.name, b.yaml, nowIso]
      );
    } else if (existing.rows[0].sigmaYaml !== b.yaml) {
      await pool.query(
        `UPDATE log_rules SET "sigmaYaml" = $1, "updatedAt" = $2 WHERE id = $3`,
        [b.yaml, nowIso, existing.rows[0].id]
      );
    }
  }
}

// ── Rule cache ─────────────────────────────────────────────────────────────

/** Route-side invalidation (same-process immediacy); the per-beat version check below is the cross-replica safety net. */
export function invalidateLogRuleCache(): void {
  ruleCache = null;
}

async function ensureRuleCache(): Promise<void> {
  // count + max(updatedAt) — a cheap fingerprint that catches writes from ANY
  // replica (routes are stateless; only the leader runs this worker).
  const verRes = await pool.query(
    `SELECT count(*)::text || ':' || coalesce(max("updatedAt"), '') AS v FROM log_rules WHERE enabled = true`
  );
  const version = String(verRes.rows[0]?.v ?? '0:');
  if (ruleCache && ruleCache.version === version) return;

  const res = await pool.query(
    `SELECT id, name, "severityOverride", "sigmaYaml", "lastError" FROM log_rules WHERE enabled = true ORDER BY name`
  );
  const rules: CompiledRuleRow[] = [];
  for (const r of res.rows) {
    try {
      const rule = parseSigmaRule(String(r.sigmaYaml), { name: String(r.name) });
      const overrideRaw = r.severityOverride ? String(r.severityOverride) : null;
      rules.push({
        id: String(r.id),
        name: String(r.name),
        severityOverride: overrideRaw && SEVERITIES.includes(overrideRaw) ? (overrideRaw as RuleSeverity) : null,
        rule,
      });
      // The user fixed a previously broken rule — clear the surfaced error.
      if (r.lastError) {
        await pool.query(`UPDATE log_rules SET "lastError" = NULL WHERE id = $1`, [r.id]);
      }
    } catch (err) {
      // A broken rule must not take down the whole scanner — skip it and
      // surface the error in the UI (log_rules.lastError).
      const msg = err instanceof LogRuleParseError ? (err.issues.join('; ') || err.message) : (err as Error).message;
      // eslint-disable-next-line no-console
      console.error(`[log-rules] skipping rule "${r.name}":`, msg);
      if (String(r.lastError ?? '') !== msg.slice(0, 500)) {
        await pool.query(`UPDATE log_rules SET "lastError" = $1 WHERE id = $2`, [msg.slice(0, 500), r.id]);
      }
    }
  }
  ruleCache = { version, rules };
}

// ── Hit handling ───────────────────────────────────────────────────────────

async function handleHit(cr: CompiledRuleRow, row: LogRuleRow, deviceId: string | null, tsMs: number): Promise<void> {
  const th = cr.rule.threshold;
  let groupValue: string | null = null;
  if (th) {
    // 'device' grouping keys on the device itself.
    groupValue = th.groupBy === 'srcIp' ? row.srcIp ?? '' : th.groupBy === 'hostname' ? row.hostname ?? '' : deviceId ?? '';
    const key = `${cr.id}:${groupValue}`;
    let buf = thresholdBuffers.get(key);
    if (!buf) {
      buf = [];
      thresholdBuffers.set(key, buf);
    }
    buf.push(tsMs);
    // Prune entries that fell out of the rolling window.
    while (buf.length > 0 && buf[0] < tsMs - th.withinMs) buf.shift();
    if (buf.length < th.count) return; // below threshold — no finding yet
    buf.length = 0; // fired — re-arm for the next N hits
  }

  const severity: RuleSeverity = cr.severityOverride ?? cr.rule.level;
  const dedupeKey = `log-rule:${cr.id}:${groupValue !== null && groupValue !== '' ? groupValue : deviceId ?? 'global'}`;
  const detail = `${cr.rule.name}: ${row.message.slice(0, 240)}`;
  const context: Record<string, unknown> = {
    ruleId: cr.id,
    ruleName: cr.rule.name,
    tags: cr.rule.tags,
    hostname: row.hostname,
    appname: row.appname,
    messageExcerpt: row.message.slice(0, 512),
  };
  if (groupValue) context.groupValue = groupValue;

  const isNew = await upsertFinding({
    kind: 'log-rule',
    srcIp: row.srcIp ?? null,
    dstIp: row.dstIp ?? null,
    severity,
    detail,
    context,
    deviceId,
    dedupeKey,
  });
  if (!isNew) return; // ongoing condition — occurrence already bumped, no re-spam

  try {
    await emitNotification({
      severity,
      source: deviceId ? 'device' : 'system',
      deviceId: deviceId ?? undefined,
      title: `Log rule hit: ${cr.rule.name}`,
      message: detail,
      dedupeKey,
      context,
    });
  } catch (err) {
    // Notifications are best-effort by contract — never break the beat.
    // eslint-disable-next-line no-console
    console.error('[log-rules] notification emission failed:', err);
  }
}

/** Drops threshold buffers whose newest hit fell out of every rule's window. */
function pruneThresholdBuffers(): void {
  const maxWindowMs = ruleCache ? Math.max(...ruleCache.rules.map((r) => r.rule.threshold?.withinMs ?? 0), 0) : 0;
  if (maxWindowMs === 0) return;
  const cutoff = Date.now() - maxWindowMs;
  for (const [key, buf] of thresholdBuffers) {
    if (buf.length === 0 || buf[buf.length - 1] < cutoff) thresholdBuffers.delete(key);
  }
}

// ── Beat ───────────────────────────────────────────────────────────────────

async function beat(): Promise<void> {
  if (busy) return; // previous beat still running — skip this tick
  busy = true;
  try {
    const enabledSetting = await getEffectiveSettingValue('logRulesEnabled');
    if (enabledSetting === false) return; // paused — watermark stays put, re-enable resumes

    const limit = Number(await getEffectiveSettingValue('logRulesScanLimitPerBeat')) || 20_000;
    await ensureRuleCache();
    const rules = ruleCache!.rules;

    if (rules.length === 0) {
      // Nothing to match — fast-forward the watermark (no replay semantics anyway).
      wmMs = Math.max(wmMs, Date.now() - FUTURE_GUARD_MS);
      lastRunAt = new Date().toISOString();
      lastError = null;
      return;
    }

    const res = await pool.query(
      `SELECT id, "deviceId", "tsMs", hostname, appname, facility, "srcIp", "dstIp", message
       FROM security_events WHERE "tsMs" > $1 AND "tsMs" < $2 ORDER BY "tsMs" ASC LIMIT $3`,
      [wmMs, Date.now() - FUTURE_GUARD_MS, limit]
    );
    const rows = res.rows;

    for (const r of rows) {
      const row: LogRuleRow = {
        message: String(r.message ?? ''),
        appname: r.appname ? String(r.appname) : null,
        facility: r.facility ? String(r.facility) : null,
        hostname: r.hostname ? String(r.hostname) : null,
        srcIp: r.srcIp ? String(r.srcIp) : null,
        dstIp: r.dstIp ? String(r.dstIp) : null,
      };
      const deviceId = r.deviceId ? String(r.deviceId) : null;
      const tsMs = Number(r.tsMs);
      for (const cr of rules) {
        if (!cr.rule.evaluate(row)) continue;
        await handleHit(cr, row, deviceId, tsMs);
      }
    }

    // Full page → advance only past the last scanned row (catch-up continues on
    // later beats); partial/empty → everything up to the guard is done.
    if (rows.length < limit) {
      wmMs = Math.max(wmMs, Date.now() - FUTURE_GUARD_MS);
    } else {
      wmMs = Math.max(wmMs, Number(rows[rows.length - 1].tsMs) + 1);
    }

    pruneThresholdBuffers();
    lastRunAt = new Date().toISOString();
    lastError = null;
  } catch (err) {
    lastError = (err as Error).message;
    // eslint-disable-next-line no-console
    console.error('[log-rules] beat failed:', err);
    throw err; // trackBeat records the error; watermark stays put → next beat retries
  } finally {
    busy = false;
  }
}

// ── Stats / lifecycle ──────────────────────────────────────────────────────

/** Snapshot for GET /v1/log-rules (worker status line). */
export function getLogRulesStats(): {
  lastRunAt: string | null;
  lastError: string | null;
  watermarkMs: number;
  rulesEnabled: number | null;
} {
  return {
    lastRunAt,
    lastError,
    watermarkMs: wmMs,
    rulesEnabled: ruleCache ? ruleCache.rules.length : null,
  };
}

/**
 * Starts the log-rules worker. Must be called only after the API has bound its
 * port (same rule as every other worker — see index.ts app.listen). Built-in
 * seeding runs BEFORE the first beat so the pack is available immediately.
 */
export function startLogRulesWorker(): () => void {
  initWorker('logRules', LEADER_KEYS.logRules);
  // eslint-disable-next-line no-console
  console.log('[log-rules] worker started');

  void seedBuiltinLogRules()
    .then(() => trackBeat('logRules', beat))
    .catch((err) => {
      // eslint-disable-next-line no-console
      console.error('[log-rules] initial run failed:', err);
    });

  const timer = setInterval(() => {
    void trackBeat('logRules', beat).catch((err) => {
      // eslint-disable-next-line no-console
      console.error('[log-rules] beat failed:', err);
    });
  }, BEAT_MS);

  return () => clearInterval(timer);
}
