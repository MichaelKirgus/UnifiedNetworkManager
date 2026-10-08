/**
 * @unm/plugin-test-kit — standardized contract suite (tests T1–T8).
 *
 * Runs against ANY built plugin, capability-driven: every plugin gets the full
 * baseline (healthz, /discover validation, settings robustness, monitoring
 * happy-path + dead-target handling); plugins advertising configuration/planning/
 * probe/deviceState get their endpoint contracts checked too. A per-plugin
 * config (plugins/<name>/test/config.mjs) supplies the mock target for T4 and
 * optional extra assertions; without one, only the transport-agnostic tests run.
 */

import { callPlugin, getDeadTcpPort } from './harness.js';
import { validateDiscover } from './discoverValidator.js';

const HEALTHS = new Set(['ok', 'warning', 'critical', 'unknown']);

/** One recorded check result. */
export class CheckRecorder {
  constructor() {
    this.results = []; // {id, label, ok, detail?}
  }
  pass(id, label) {
    this.results.push({ id, label, ok: true });
  }
  fail(id, label, detail) {
    this.results.push({ id, label, ok: false, detail: String(detail).slice(0, 500) });
  }
  check(id, label, cond, detail) {
    if (cond) this.pass(id, label);
    else this.fail(id, label, detail ?? 'assertion failed');
  }
  skip(id, label, reason) {
    this.results.push({ id, label, ok: true, skipped: true, detail: reason });
  }
  get passed() { return this.results.filter((r) => r.ok && !r.skipped).length; }
  get failed() { return this.results.filter((r) => !r.ok).length; }
}

/** Builds a minimal MonitoringRequestBody for the plugin under test. */
function monitoringBody({ address, settings = {}, collectInventory = true }) {
  const body = {
    deviceId: 'test-device-0001',
    managementAddress: address,
    credentials: {},
    model: null,
    firmwareVersion: null,
  };
  if (collectInventory !== undefined) body.collectInventory = collectInventory;
  return { body, settingsHeader: JSON.stringify(settings) };
}

/**
 * Runs the full contract suite against a live plugin.
 *
 * @param {object} opts
 * @param {string} opts.url          Plugin base URL (http://127.0.0.1:<port>).
 * @param {object} [opts.config]     Per-plugin test config:
 *   - monitoringAddress?: string    T4 target (e.g. `127.0.0.1:${mockPort}` or a scheme-prefixed URL)
 *   - settings?: object             x-unm-settings overrides for T4
 *   - expectHealth?: 'ok'|'warning'|'critical'  default: not critical + no system.error
 *   - deadAddress?: string          T5 target (default: closed port on 127.0.0.1)
 *   - settingsForDead?: object      settings for the dead-target poll
 *   - expectDeadHealth?: 'critical'|'warning'|'unknown'  default: not ok
 *   - extraChecks?: async (ctx) => void   plugin-specific assertions (use ctx.check/…)
 */
export async function runContractSuite({ url, config = {} }) {
  const rec = new CheckRecorder();

  // ── T1: healthz ────────────────────────────────────────────────────────────
  try {
    const hz = await callPlugin(url, 'GET', '/healthz');
    rec.check('T1', 'GET /healthz → 200 ok', hz.status === 200 && hz.json?.status === 'ok', `got ${hz.status} ${hz.text.slice(0, 120)}`);
  } catch (err) {
    rec.fail('T1', 'GET /healthz → 200 ok', err.message);
  }

  // ── T2: /discover contract validation ─────────────────────────────────────
  let discover = null;
  try {
    const d = await callPlugin(url, 'GET', '/discover');
    rec.check('T2', 'GET /discover → 200 JSON', d.status === 200 && !!d.json, `got ${d.status}`);
    if (d.status === 200 && d.json) {
      discover = d.json;
      const v = validateDiscover(d.json);
      for (const e of v.errors) rec.fail('T2', `/discover: ${e}`, '');
      for (const w of v.warnings) rec.results.push({ id: 'T2', label: `/discover warning: ${w}`, ok: true, skipped: true, detail: 'warning only' });
      if (v.errors.length === 0) rec.pass('T2', '/discover payload valid');
    }
  } catch (err) {
    rec.fail('T2', 'GET /discover → 200 JSON', err.message);
  }

  // Capability-driven gating. `assumeCaps` lets a config opt a plugin into the
  // monitoring tests even when /discover advertises no capabilities (e.g.
  // flow-collector, web-fetch — they serve /monitoring for self-health but are
  // not device-facing).
  const caps = [...new Set([
    ...(Array.isArray(discover?.capabilities) ? discover.capabilities : []),
    ...(config.assumeCaps ?? []),
  ])];
  const options = Array.isArray(discover?.options) ? discover.options : [];
  const optionKeys = new Set(options.map((o) => o.key));

  // ── T3: settings robustness (malformed x-unm-settings must not crash) ─────
  if (caps.includes('monitoring')) {
    for (const [label, header] of [
      ['missing header', undefined],
      ['invalid JSON', '{not-json'],
      ['wrong shape', '{"bogus": []}'],
    ]) {
      try {
        const r = await callPlugin(url, 'POST', '/monitoring', {
          body: monitoringBody({ address: config.monitoringAddress ?? '127.0.0.1' }).body,
          headers: header !== undefined ? { 'x-unm-settings': header } : {},
        });
        rec.check('T3', `/monitoring survives ${label}`, r.status === 200 && typeof r.json?.health === 'string', `got ${r.status} health=${JSON.stringify(r.json?.health)}`);
      } catch (err) {
        rec.fail('T3', `/monitoring survives ${label}`, err.message);
      }
    }
  } else {
    rec.skip('T3', 'settings robustness', "no 'monitoring' capability");
  }

  // ── T4: monitoring happy path against the mock appliance ───────────────────
  if (caps.includes('monitoring')) {
    if (!config.monitoringAddress) {
      rec.skip('T4', 'monitoring happy-path', 'no test/config.mjs monitoringAddress for this plugin');
    } else {
      try {
        const { body, settingsHeader } = monitoringBody({ address: config.monitoringAddress, settings: config.settings });
        const r = await callPlugin(url, 'POST', '/monitoring', { body, headers: { 'x-unm-settings': settingsHeader }, timeoutMs: 30_000 });
        rec.check('T4', '/monitoring → 200 (always-200 contract)', r.status === 200, `got ${r.status}: ${r.text.slice(0, 200)}`);
        const j = r.json ?? {};
        rec.check('T4', 'health is a known value', HEALTHS.has(j.health), `health=${JSON.stringify(j.health)}`);
        rec.check('T4', 'collectedAt is ISO-8601', typeof j.collectedAt === 'string' && !Number.isNaN(Date.parse(j.collectedAt)), JSON.stringify(j.collectedAt));
        const expectHealth = config.expectHealth;
        if (expectHealth) {
          rec.check('T4', `health === ${expectHealth}`, j.health === expectHealth, `got ${JSON.stringify(j.health)} error=${JSON.stringify(j.error ?? null)}`);
        } else {
          rec.check('T4', 'no system.error metric', !j.metrics || j.metrics['system.error'] === undefined, JSON.stringify(j.metrics?.['system.error'] ?? null));
        }
      } catch (err) {
        rec.fail('T4', '/monitoring happy-path', err.message);
      }
    }
  } else {
    rec.skip('T4', 'monitoring happy-path', "no 'monitoring' capability");
  }

  // ── T5: dead-target handling (bounded failure, no hang) ────────────────────
  if (caps.includes('monitoring')) {
    if (config.skipDeadTarget) {
      rec.skip('T5', 'dead-target handling', "plugin's /monitoring reports its own state, not a target probe");
    } else {
      const dead = config.deadAddress ?? `127.0.0.1:${await getDeadTcpPort()}`;
      try {
        const startedAt = Date.now();
        const { body, settingsHeader } = monitoringBody({ address: dead, settings: config.settingsForDead ?? {} });
        const r = await callPlugin(url, 'POST', '/monitoring', { body, headers: { 'x-unm-settings': settingsHeader }, timeoutMs: 30_000 });
        const elapsed = Date.now() - startedAt;
        rec.check('T5', 'dead target → 200 (no transport error)', r.status === 200, `got ${r.status}`);
        const j = r.json ?? {};
        const expectDeadHealth = config.expectDeadHealth;
        if (expectDeadHealth) {
          rec.check('T5', `dead target health === ${expectDeadHealth}`, j.health === expectDeadHealth, `got ${JSON.stringify(j.health)} error=${JSON.stringify(j.error ?? null)}`);
        } else {
          rec.check('T5', 'dead target not healthy', j.health !== undefined && j.health !== 'ok', `health=${JSON.stringify(j.health)}`);
        }
        rec.check('T5', `failure bounded (< 20 s, API budget is 10 s)`, elapsed < 20_000, `${elapsed} ms`);
      } catch (err) {
        rec.fail('T5', 'dead-target handling', err.message);
      }
    }
  } else {
    rec.skip('T5', 'dead-target handling', "no 'monitoring' capability");
  }

  // ── T6: configuration contract (unknown action / invalid input) ────────────
  if (caps.includes('configuration')) {
    const base = config.monitoringAddress ?? '127.0.0.1';
    try {
      const r = await callPlugin(url, 'POST', '/config', {
        body: { deviceId: 'test-device-0001', managementAddress: base, credentials: {}, actionId: '__no_such_action__', input: {} },
      });
      rec.check('T6', 'unknown actionId → 4xx (not a crash)', r.status >= 400 && r.status < 500 || (r.json?.success === false), `got ${r.status}: ${r.text.slice(0, 200)}`);
    } catch (err) {
      rec.fail('T6', 'unknown actionId handling', err.message);
    }
  } else {
    rec.skip('T6', 'configuration contract', "no 'configuration' capability");
  }

  // ── T7: planning contract (invalid plan → clean 400) ───────────────────────
  if (caps.includes('planning')) {
    const base = config.monitoringAddress ?? '127.0.0.1';
    try {
      const r = await callPlugin(url, 'POST', '/plan', {
        body: { deviceId: 'test-device-0001', managementAddress: base, credentials: {}, actionId: '__no_such_action__', input: {} },
      });
      rec.check('T7', 'invalid plan → 4xx (PlanningError contract)', r.status >= 400 && r.status < 500, `got ${r.status}: ${r.text.slice(0, 200)}`);
    } catch (err) {
      rec.fail('T7', 'planning contract', err.message);
    }
  } else {
    rec.skip('T7', 'planning contract', "no 'planning' capability");
  }

  // ── T8: probe / deviceState envelopes (capability-gated) ───────────────────
  if (caps.includes('probe')) {
    const base = config.monitoringAddress ?? '127.0.0.1';
    try {
      const r = await callPlugin(url, 'POST', '/probe', {
        body: { deviceId: 'test-device-0001', managementAddress: base, credentials: {}, keys: [] },
        timeoutMs: 30_000,
      });
      // A probe against a live mock should answer with the ProbeResult envelope;
      // without a mock target it must still fail CLEANLY (4xx/5xx JSON), not hang.
      rec.check('T8', 'POST /probe answers with JSON envelope (no hang)', r.status < 600 && !!r.json, `got ${r.status}: ${r.text.slice(0, 200)}`);
    } catch (err) {
      rec.fail('T8', 'probe contract', err.message);
    }
  } else {
    rec.skip('T8', 'probe contract', "no 'probe' capability");
  }

  // ── Plugin-specific extra checks ───────────────────────────────────────────
  if (typeof config.extraChecks === 'function') {
    try {
      await config.extraChecks({ url, discover, caps, optionKeys, rec });
    } catch (err) {
      rec.fail('X', 'extra checks crashed', err.stack ?? err.message);
    }
  }

  return rec;
}
