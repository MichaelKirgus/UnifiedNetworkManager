/**
 * End-to-end verification for firewall event ingestion + session monitoring.
 *
 * Runs against the LIVE dev stack started by setup.sh, plus the mock OPNsense
 * appliance (`docker compose up -d mock-appliance`, host network :80/:443):
 *   1. logs in via the real auth flow (TOTP minted from the seeded admin secret)
 *   2. creates one device assigned to the real OPNsense plugin, pointing at
 *      http(s)://host.docker.internal (the mock appliance)
 *   3. forces a poll (POST /devices/refresh) — the plugin's /monitoring handler
 *      collects firewall.states.* metrics AND fire-and-forget pushes new log
 *      rows to POST /plugin/firewall-events
 *   4. asserts: GET /v1/firewall-events returns the seeded events with correct
 *      actions/rule names, action + search filters work, and
 *      GET /v1/firewall-sessions reports total/limit/adaptive from telemetry
 *   5. cleans up everything it created (device, secret)
 *
 * Usage (from the repo root):
 *   docker compose up -d mock-appliance          # once (host network :80/:443)
 *   ./node_modules/.bin/tsx scripts/e2e-firewall-events.ts
 */

import path from 'node:path';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
// Bare hostname the PLUGIN resolves (from inside its container, where
// host.docker.internal maps to the host gateway — see docker-compose.yml).
const MOCK_HOSTNAME = process.env.MOCK_HOSTNAME ?? 'host.docker.internal';

// pg + otplib live in api/node_modules; this script sits outside that tree,
// so resolve them through a require rooted at the API package.
const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));

let failures = 0;
function check(label: string, cond: boolean, extra?: unknown): void {
  if (cond) console.log(`  PASS ${label}`);
  else {
    failures++;
    console.error(`  FAIL ${label}`, extra !== undefined ? JSON.stringify(extra).slice(0, 400) : '');
  }
}

interface EventRow {
  id: string; deviceId: string; ts: string; tsMs?: number | null; action: string;
  srcIp: string; dstIp: string; proto?: string | null; ruleName?: string | null; vendorEventId: string;
}
interface EventsResponse { fromMs: number; toMs: number; rows: EventRow[]; summary: { blocked: number; passed: number; other: number }; }

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function main(): Promise<void> {
  // 0. API up?
  const health = await fetch('http://localhost:3000/healthz').then((r) => r.json()).catch(() => null);
  check('API healthy', (health as { status?: string })?.status === 'ok', health);

  // 1. Login (admin/admin; TOTP minted from the seeded secret when enabled).
  const { Pool } = apiRequire('pg');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm' });
  const adminRow = (await pool.query(`SELECT "totpSecret" FROM users WHERE username = 'admin'`)).rows[0] as { totpSecret: string | null };

  let token: string | null = null;
  if (!adminRow.totpSecret) {
    const r = await fetch(`${API}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: 'admin' }) });
    token = ((await r.json()) as { accessToken?: string }).accessToken ?? null;
  } else {
    const { authenticator } = apiRequire('otplib');
    const code = authenticator.generate(adminRow.totpSecret);
    const r1 = await fetch(`${API}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: 'admin' }) });
    const challenge = ((await r1.json()) as { challengeToken?: string }).challengeToken ?? '';
    const r2 = await fetch(`${API}/auth/2fa/verify`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ challengeToken: challenge, totpCode: code }) });
    token = ((await r2.json()) as { accessToken?: string }).accessToken ?? null;
  }
  check('authenticated (2FA flow)', Boolean(token));
  if (!token) throw new Error('login failed');

  const authed = async (method: string, p: string, body?: unknown): Promise<{ status: number; json: () => Promise<unknown> }> => {
    const res = await fetch(`${API}${p}`, { method, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    return { status: res.status, json: async () => (await res.json().catch(() => null)) as never };
  };

  // 2. Find the OPNsense plugin (vendor 'opnsense' — several plugins advertise
  //    'planning', so capability alone is ambiguous).
  let opnsenseId = '';
  for (let i = 0; i < 30 && !opnsenseId; i++) {
    const plugins = ((await authed('GET', '/plugins').then((r) => r.json())) as Array<{ id: string; vendors?: string[] }>) ?? [];
    opnsenseId = (plugins.find((p) => (p.vendors ?? []).includes('opnsense'))?.id) ?? '';
    if (!opnsenseId) await sleep(1000);
  }
  check('OPNsense plugin discovered', Boolean(opnsenseId), opnsenseId);

  // 3. Credentials + device pointing at the mock appliance.
  const secretRes = await authed('POST', '/secrets', { type: 'apiKey', label: 'e2e fw-events', fields: { apiKey: 'kFw', apiSecret: 'sFw' } });
  const secretId = ((await secretRes.json()) as { id?: string }).id ?? '';
  check('apiKey secret created', Boolean(secretId));

  const devRes = await authed('POST', '/devices', { name: 'e2e-fw-events', vendor: 'OPNsense', deviceTypes: ['router', 'firewall'], managementAddress: MOCK_HOSTNAME, plugins: [{ pluginId: opnsenseId, secretId }] });
  const deviceId = ((await devRes.json()) as { id?: string }).id ?? '';
  check('device created + assigned', Boolean(deviceId), deviceId);

  // The digest cursor is keyed by HOST (not device) in the shared state store and
  // survives across runs. A stale cursor from a previous run would make this run's
  // first poll fetch only rows at-or-newer-than it — clearing it forces a fresh
  // baseline of all seeded events so the assertions are deterministic.
  await pool.query(`DELETE FROM plugin_state WHERE "namespace"='firewall-events' AND key=$1`, [MOCK_HOSTNAME]);

  // 4. Force a poll — the plugin's /monitoring handler collects firewall.states.*
  //    and fire-and-forget pushes new log rows to POST /plugin/firewall-events.
  const refresh = await authed('POST', '/devices/refresh', { deviceIds: [deviceId] });
  const refreshBody = (await refresh.json()) as { results?: Array<{ deviceId: string; ok: boolean }> };
  check('forced poll succeeded', refresh.status === 200 && refreshBody.results?.some((r) => r.ok), refreshBody);

  // 5. Wait for the pushed events to land in GET /v1/firewall-events. The push is
  //    fire-and-forget inside the plugin, so allow a few beats of polling.
  let events: EventsResponse | null = null;
  const fromIso = new Date(Date.now() - 2 * 3600_000).toISOString();
  for (let i = 0; i < 30 && !events?.rows.length; i++) {
    await sleep(2000);
    const r = await authed('GET', `/firewall-events?deviceId=${deviceId}&from=${encodeURIComponent(fromIso)}`);
    if (r.status === 200) events = (await r.json()) as EventsResponse;
  }
  check('firewall events ingested (4 seeded rows)', Boolean(events?.rows.length), { count: events?.rows.length });

  const byAction = new Map<string, number>();
  for (const row of events?.rows ?? []) byAction.set(row.action, (byAction.get(row.action) ?? 0) + 1);
  check('actions pass/block/rdr all present', (byAction.get('pass') ?? 0) >= 2 && (byAction.get('block') ?? 0) === 1 && (byAction.get('rdr') ?? 0) === 1, Object.fromEntries(byAction));

  const web = events?.rows.find((r) => r.ruleName === 'Allow LAN web');
  check('rule name + ports normalized', Boolean(web) && web.dstPort === 443 && web.proto === 'tcp' && web.srcIp === '192.168.1.50', web);

  // Summary counts over the same window/filters (SQL-side).
  check('summary blocked=1 passed>=2 other=1', events?.summary.blocked === 1 && (events?.summary.passed ?? 0) >= 2 && events?.summary.other === 1, events?.summary);

  // Action filter.
  const blockOnly = await authed('GET', `/firewall-events?deviceId=${deviceId}&from=${encodeURIComponent(fromIso)}&action=block`);
  const blockBody = (await blockOnly.json()) as EventsResponse;
  check('action=block filter → only blocks', blockOnly.status === 200 && blockBody.rows.length === 1 && blockBody.rows[0].action === 'block', { count: blockBody.rows?.length });

  // Search filter (matches src/dst IP or rule name).
  const searched = await authed('GET', `/firewall-events?deviceId=${deviceId}&from=${encodeURIComponent(fromIso)}&search=203.0.113.9`);
  const searchBody = (await searched.json()) as EventsResponse;
  check('search on src IP → block + rdr rows', searched.status === 200 && searchBody.rows.length === 2, { count: searchBody.rows?.length });

  // Dedupe: a second poll must not duplicate rows (unique vendorEventId).
  await authed('POST', '/devices/refresh', { deviceIds: [deviceId] }).catch(() => undefined);
  await sleep(4000);
  const again = await authed('GET', `/firewall-events?deviceId=${deviceId}&from=${encodeURIComponent(fromIso)}`);
  const againBody = (await again.json()) as EventsResponse;
  check('re-poll does not duplicate rows', again.status === 200 && againBody.rows.length === events?.rows.length, { first: events?.rows.length, second: againBody.rows?.length });

  // 6. Sessions section — reads the latest telemetry row server-side. The
  //    telemetry worker persists /monitoring responses asynchronously, so poll.
  let sessions: { devices?: Array<{ deviceId: string; totalSessions: number; stateLimit?: number | null; adaptiveEnabled?: boolean | null; adaptiveStartStates?: number | null }> } | null = null;
  for (let i = 0; i < 15 && !sessions?.devices?.length; i++) {
    await sleep(2000);
    const r = await authed('GET', '/firewall-sessions');
    if (r.status === 200) sessions = (await r.json()) as typeof sessions;
  }
  const mine = sessions?.devices?.find((d) => d.deviceId === deviceId);
  check('sessions row present for device', Boolean(mine), sessions?.devices?.map((d) => d.deviceId));
  check('session totals (42/65536)', mine?.totalSessions === 42 && mine?.stateLimit === 65536, mine);
  check('adaptive timeouts on at ≥1000 states', mine?.adaptiveEnabled === true && mine?.adaptiveStartStates === 1000, mine);

  // 7. Cleanup: delete device + secret (firewall_events rows are left to the
  //    retention sweep — they carry no FK and are keyed by deviceId). Also clear
  //    the host-keyed digest cursor so a later run starts from a fresh baseline.
  await pool.query(`DELETE FROM plugin_state WHERE "namespace"='firewall-events' AND key=$1`, [MOCK_HOSTNAME]);
  const delDev = await authed('DELETE', `/devices/${deviceId}`);
  check('DELETE /devices/:id → 204', delDev.status === 204);
  const delSecret = await authed('DELETE', `/secrets/${secretId}`);
  check('DELETE /secrets/:id → 204', delSecret.status === 204);

  pool.end();
}

main()
  .then(() => {
    console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
    process.exit(failures === 0 ? 0 : 1);
  })
  .catch((err) => {
    console.error('e2e crashed:', err);
    process.exit(1);
  });
