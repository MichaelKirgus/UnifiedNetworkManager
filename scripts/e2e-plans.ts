/**
 * End-to-end verification for the action-propagation feature (plans API + executor).
 *
 * Runs against the LIVE dev stack started by setup.sh, plus the mock OPNsense
 * appliance (`docker compose up -d mock-appliance`, host network :80/:443):
 *   1. logs in via the real auth flow (TOTP minted from the seeded admin secret)
 *   2. creates two devices assigned to the real OPNsense plugin (apiKey secrets),
 *      pointing at http(s)://host.docker.internal (the mock appliance)
 *   3. POST /plans with wireguard.tunnel.create → asserts provisioning + steps
 *   4. executes the plan and verifies: dependency ordering, ${steps[N].result.details.uuid}
 *      substitution, namespaced credential injection, best-effort snapshots,
 *      config_jobs traceability
 *   5. cleans up everything it created (plan, devices, secrets)
 *
 * Usage (from the repo root):
 *   docker compose up -d mock-appliance          # once (host network :80/:443)
 *   ./node_modules/.bin/tsx scripts/e2e-plans.ts
 */

import https from 'node:https';
import path from 'node:path';
import { createRequire } from 'node:module';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
// Bare hostname the PLUGIN resolves (from inside its container, where
// host.docker.internal maps to the host gateway — see docker-compose.yml).
const MOCK_HOSTNAME = process.env.MOCK_HOSTNAME ?? 'host.docker.internal';
// Host-side access to the mock (reading captured requests) goes via localhost.
const MOCK_BASE = process.env.MOCK_BASE ?? 'https://localhost';

// pg + otplib live in api/node_modules; this script sits outside that tree,
// so resolve them through a require rooted at the API package (ESM dynamic
// imports would not find bare specifiers from scripts/).
const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));

// The mock serves a self-signed cert; global fetch cannot disable TLS
// verification, so talk to it with node:https + an unverified agent.
const httpsAgent = new https.Agent({ rejectUnauthorized: false });
function mockRequest(method: string, urlPath: string): Promise<{ status: number; body: unknown }> {
  return new Promise((resolve, reject) => {
    const req = https.request(`${MOCK_BASE}${urlPath}`, { method, agent: httpsAgent }, (res) => {
      let data = '';
      res.on('data', (c) => (data += c));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body: JSON.parse(data || 'null') }));
    });
    req.on('error', reject);
    req.end();
  });
}

let failures = 0;
function check(label: string, cond: boolean, extra?: unknown): void {
  if (cond) console.log(`  PASS ${label}`);
  else {
    failures++;
    console.error(`  FAIL ${label}`, extra !== undefined ? JSON.stringify(extra).slice(0, 400) : '');
  }
}

interface PlanStepRow {
  id: string; stepIndex: number; deviceId: string; actionId: string;
  input: Record<string, unknown>; dependsOn?: number[]; secretRefs?: string[];
  bestEffort?: boolean; status: string; result?: Record<string, unknown> | null;
}

interface MockRequest { t: number; method: string; url: string; user: string; body: Record<string, unknown>; }

async function main(): Promise<void> {
  // 0. API up?
  const health = await fetch('http://localhost:3000/healthz').then((r) => r.json()).catch(() => null);
  check('API healthy', (health as { status?: string })?.status === 'ok', health);

  // Mock appliance reachable from the HOST? (The plugin reaches it via host.docker.internal;
  // we reach it directly to read captured requests.)
  const mockOk = await mockRequest('GET', '/__requests').then((r) => r.status === 200).catch(() => false);
  check('mock appliance reachable (host :443)', mockOk);

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

  // 2. Find the OPNsense plugin (capability 'planning') + its persisted catalog.
  let opnsenseId = '';
  let actions: Array<{ id: string; label?: string; deviceCount?: number | 'N'; inputSchema?: Record<string, unknown> }> = [];
  for (let i = 0; i < 30 && !opnsenseId; i++) {
    const plugins = ((await authed('GET', '/plugins').then((r) => r.json())) as Array<{ id: string; capabilities?: string[] }>) ?? [];
    const op = plugins.find((p) => (p.capabilities ?? []).includes('planning'));
    if (op) {
      opnsenseId = op.id;
      actions = (((await authed('GET', `/plugins/${op.id}/actions`).then((r) => r.json())) as { actions?: typeof actions })?.actions) ?? [];
    } else await new Promise((r) => setTimeout(r, 1000));
  }
  check('OPNsense plugin discovered (capability planning)', Boolean(opnsenseId), opnsenseId);
  check('action catalog persisted + served', actions.length > 20, `count=${actions.length}`);
  const wgIntent = actions.find((a) => a.id === 'wireguard.tunnel.create');
  check('catalog reports exact deviceCount=2 for wireguard intent', wgIntent?.deviceCount === 2, wgIntent?.deviceCount);

  // 3. Credentials: one apiKey secret per mock device (distinct keys).
  const mkSecret = async (key: string, secret: string) => {
    const r = await authed('POST', '/secrets', { type: 'apiKey', label: `e2e ${key}`, fields: { apiKey: key, apiSecret: secret } });
    return ((await r.json()) as { id?: string }).id ?? '';
  };
  const secretA = await mkSecret('kA', 'sA');
  const secretB = await mkSecret('kB', 'sB');
  check('apiKey secrets created', Boolean(secretA && secretB));

  // 4. Two devices assigned to the OPNsense plugin, pointing at the mock appliance.
  const mkDevice = async (name: string, secretId: string) => {
    const r = await authed('POST', '/devices', { name, vendor: 'OPNsense', deviceType: 'firewall', managementAddress: MOCK_HOSTNAME, plugins: [{ pluginId: opnsenseId, secretId }] });
    return ((await r.json()) as { id?: string }).id ?? '';
  };
  const devA = await mkDevice('e2e-fw-A', secretA);
  const devB = await mkDevice('e2e-fw-B', secretB);
  check('two devices created + assigned', Boolean(devA && devB), { devA, devB });

  // Reset the mock's request capture so later assertions see only this plan.
  await mockRequest('POST', '/__reset').catch(() => undefined);

  // 5. Negative checks on POST /plans.
  const neg1 = await authed('POST', '/plans', { pluginId: opnsenseId, intentActionId: 'wireguard.tunnel.create', inputs: { name: 'x', subnet: '10.255.0.0/24' }, devices: [{ deviceId: devA }] });
  check('plan with 1 device rejected (needs exactly 2)', neg1.status === 400, await neg1.json());
  const neg2 = await authed('POST', '/plans', { pluginId: opnsenseId, intentActionId: 'nope.nope', inputs: {}, devices: [{ deviceId: devA }, { deviceId: devB }] });
  check('unknown intent rejected (400 from plugin)', neg2.status === 400, await neg2.json());

  // 6. Create the real plan.
  const createRes = await authed('POST', '/plans', {
    pluginId: opnsenseId,
    intentActionId: 'wireguard.tunnel.create',
    inputs: { name: 'e2e-tunnel', subnet: '10.255.0.0/24' },
    devices: [{ deviceId: devA }, { deviceId: devB }],
  });
  const plan = (await createRes.json()) as { id?: string; status?: string; provisionedSecrets?: Array<{ ref: string; secretId: string; type?: string }>; steps?: PlanStepRow[] };
  check('POST /plans → 201', createRes.status === 201, await createRes.json());
  const planId = plan.id ?? '';
  check('plan status ready', plan.status === 'ready');
  check('two provisioned wireguardKeyPair secrets (keyA/keyB)',
    (plan.provisionedSecrets?.length ?? 0) === 2 && plan.provisionedSecrets!.every((p) => p.type === 'wireguardKeyPair') && ['keyA', 'keyB'].every((ref) => plan.provisionedSecrets!.some((p) => p.ref === ref)),
    plan.provisionedSecrets);

  const steps = plan.steps ?? [];
  check('8 steps (2 snapshots + 6 wireguard)', steps.length === 8, `got ${steps.length}`);
  const snaps = steps.filter((s) => s.actionId === 'snapshot.create');
  check('2 best-effort snapshot.create steps', snaps.length === 2 && snaps.every((s) => s.bestEffort));
  const serverA = steps.find((s) => s.deviceId === devA && s.actionId === 'wireguard.server.set')!;
  const peerA = steps.find((s) => s.deviceId === devA && s.actionId === 'wireguard.peer.add')!;
  check('peer A depends on server A', (peerA.dependsOn ?? []).includes(serverA.stepIndex), { peer: peerA.dependsOn, server: serverA.stepIndex });
  check('no key material in plan output', !/privateKey|publicKey/.test(JSON.stringify(plan)));

  // 7. Execute + poll to completion.
  const execRes = await authed('POST', `/plans/${planId}/execute`);
  check('POST /plans/:id/execute → 202', execRes.status === 202, await execRes.json());

  let final: { status?: string; error?: string | null; steps?: PlanStepRow[] } = {};
  const deadline = Date.now() + 90_000;
  while (Date.now() < deadline) {
    const r = await authed('GET', `/plans/${planId}`);
    final = (await r.json()) as typeof final;
    if (['succeeded', 'failed', 'cancelled'].includes(final.status ?? '')) break;
    await new Promise((res2) => setTimeout(res2, 500));
  }
  check('plan reached terminal state', ['succeeded', 'failed', 'cancelled'].includes(final.status ?? ''), final);
  const fsteps = final.steps ?? [];
  check('all 8 steps succeeded', fsteps.length === 8 && fsteps.every((s) => s.status === 'succeeded'), fsteps.map((s) => `${s.actionId}:${s.status}`));

  // 8. Substitution + credential injection (verified against the mock's captured requests).
  // plan_steps.result stores { success, result: ActionResult } — details live one level deeper.
  const serverAResult = (fsteps.find((s) => s.deviceId === devA && s.actionId === 'wireguard.server.set')?.result?.['result'] ?? null) as { details?: Record<string, unknown> } | null;
  const uuidA = serverAResult?.details?.['uuid'];
  check('server A result carries a uuid', typeof uuidA === 'string' && String(uuidA).startsWith('server-kA-'), uuidA);
  const peerAInput = fsteps.find((s) => s.deviceId === devA && s.actionId === 'wireguard.peer.add')?.input;
  check('peer A input had ${steps[N].result.details.uuid} substituted', peerAInput?.['serverUuid'] === uuidA, { got: peerAInput?.['serverUuid'], want: uuidA });

  const mockReqs = (await mockRequest('GET', '/__requests').then((r) => r.body).catch(() => []) as unknown) as MockRequest[];
  const peerAdds = mockReqs.filter((r) => r.url === '/api/wireguard/client/add_client_builder');
  check('mock received exactly 2 peer.add calls', peerAdds.length === 2, peerAdds.map((p) => p.user));
  const peerForA = peerAdds.find((p) => p.user === 'kA')?.body;
  const peerForB = peerAdds.find((p) => p.user === 'kB')?.body;
  check('peer on A carries a remote public key (B material injected under ref)', typeof peerForA?.['publicKey'] === 'string' && String(peerForA['publicKey']).length > 20, peerForA);
  check('peer on B carries a remote public key (A material injected under ref)', typeof peerForB?.['publicKey'] === 'string' && String(peerForB['publicKey']).length > 20, peerForB);
  check('the two peers carry DIFFERENT remote keys', peerForA?.['publicKey'] !== peerForB?.['publicKey']);
  const serverAdds = mockReqs.filter((r) => r.url === '/api/wireguard/server/add_server');
  check('mock received exactly 2 server.add calls (one per device)', serverAdds.length === 2, serverAdds.map((s) => s.user));
  // The private key of each side must have been applied to its OWN server.
  const serverForA = serverAdds.find((p) => p.user === 'kA')?.body;
  check('server on A received a private key (own material injected)', typeof serverForA?.['privateKey'] === 'string' && String(serverForA['privateKey']).length > 20, { has: Boolean(serverForA?.['privateKey']) });

  // 9. Traceability: config_jobs rows mirror the dispatched steps.
  const jobs = await pool.query(`SELECT count(*)::int AS n FROM config_jobs WHERE "planId" = $1`, [planId]);
  check('8 config_jobs rows traceable to the plan', (jobs.rows[0] as { n: number }).n === 8, jobs.rows[0]);

  // 10. Cleanup: delete plan (removes its provisioned secrets), devices, base secrets.
  const delPlan = await authed('DELETE', `/plans/${planId}`);
  check('DELETE /plans/:id → 204', delPlan.status === 204);
  for (const d of [devA, devB]) {
    const r = await authed('DELETE', `/devices/${d}`);
    if (r.status !== 204) console.error(`  note: device delete ${d} → ${r.status}`, await r.json());
  }
  for (const s of [secretA, secretB]) {
    const r = await authed('DELETE', `/secrets/${s}`);
    if (r.status !== 204) console.error(`  note: secret delete ${s} → ${r.status}`, await r.json());
  }
  const leftoverPlans = await pool.query(`SELECT count(*)::int AS n FROM plans WHERE id = $1`, [planId]);
  const leftoverSteps = await pool.query(`SELECT count(*)::int AS n FROM plan_steps WHERE "planId" = $1`, [planId]);
  check('plan + steps removed from DB', (leftoverPlans.rows[0] as { n: number }).n === 0 && (leftoverSteps.rows[0] as { n: number }).n === 0);

  await pool.end();
  console.log(failures === 0 ? '\nALL E2E PLAN TESTS PASSED' : `\n${failures} E2E TEST(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error('[e2e] fatal:', err);
  process.exit(1);
});
