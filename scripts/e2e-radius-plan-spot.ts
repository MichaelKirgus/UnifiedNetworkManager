/**
 * Spot check for the RADIUS local-mutation system plans (throwaway script):
 *   1. create a shared-secret credential,
 *   2. radius.nas-client.create bound to it → verify the DB row AND that the IP
 *      rendered into clients.conf on the FreeRADIUS sidecar volume (hot-apply),
 *   3. remove it again via radius.nas-client.bulk-delete (+ delete the secret).
 */
import path from 'node:path';
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';

const API = process.env.API_BASE ?? 'http://localhost:3000/v1';
const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));

let failures = 0;
function check(label: string, cond: boolean, extra?: unknown) {
  if (cond) console.log(`  PASS ${label}`);
  else {
    failures++;
    console.error(`  FAIL ${label}`, extra !== undefined ? JSON.stringify(extra).slice(0, 300) : '');
  }
}

function envValue(key: string): string | null {
  if (process.env[key]) return process.env[key];
  try {
    const m = require('node:fs').readFileSync(path.resolve(process.cwd(), '.env'), 'utf8').match(new RegExp(`^${key}=(.+)$`, 'm'));
    return m?.[1]?.trim() ?? null;
  } catch {
    return null;
  }
}

async function main(): Promise<void> {
  const jwt = apiRequire('jsonwebtoken');
  const { Pool } = apiRequire('pg');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm' });

  const adminRow = (await pool.query(`SELECT id FROM users WHERE username = 'admin'`)).rows[0] as { id: string };
  const token = jwt.sign(
    { sub: adminRow.id, username: 'admin', roles: [], permissions: ['configs:apply', 'plans:read', 'radius:write', 'secrets:write', 'secrets:delete'], amr: ['totp'] },
    envValue('JWT_SECRET') ?? 'dev-secret',
    { expiresIn: '1h' } as jwt.SignOptions,
  );

  const authed = async (method: string, p: string, body?: unknown) => {
    const res = await fetch(`${API}${p}`, { method, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    return { status: res.status, text: async () => (await res.text()), json: async () => (await res.json().catch(() => null)) as never };
  };

  const planIds: string[] = [];
  let secretId: string | null = null;
  async function runSystemPlan(intentActionId: string, input: Record<string, unknown>) {
    const create = await authed('POST', '/plans/system', { intentActionId, inputs: input });
    if (create.status !== 201) throw new Error(`plan creation failed (${create.status}): ${await create.text()}`);
    const created = ((await create.json()) as { id: string; status: string });
    planIds.push(created.id);
    const exec = await authed('POST', `/plans/${created.id}/execute`);
    if (exec.status !== 202) throw new Error(`plan execution rejected (${exec.status}): ${await exec.text()}`);
    const startedAt = Date.now();
    for (;;) {
      const g = await authed('GET', `/plans/${created.id}`);
      const plan = ((await g.json()) as { id: string; status: string; error?: string | null });
      if (['succeeded', 'unverified', 'failed', 'cancelled', 'skipped'].includes(plan.status)) return plan;
      if (Date.now() - startedAt > 120_000) throw new Error(`plan ${created.id} did not finish in time`);
      await new Promise((r) => setTimeout(r, 750));
    }
  }

  const ip = '192.0.2.65';
  try {
    // --- shared secret --------------------------------------------------------
    console.log('\n— shared-secret credential —');
    const sec = await authed('POST', '/secrets', { type: 'apiKeyNoSecret', label: 'e2e-spot-nas-shared', fields: { apiKey: 'spot-shared-secret-12345' } });
    if (sec.status !== 201) throw new Error(`secret creation failed (${sec.status}): ${await sec.text()}`);
    secretId = ((await sec.json()) as { id: string }).id;
    check('created a shared-secret credential', Boolean(secretId), { id: secretId });

    // --- create -------------------------------------------------------------
    console.log('\n— radius.nas-client.create (via system plan) —');
    const p1 = await runSystemPlan('radius.nas-client.create', { ip, name: 'e2e-spot-nas', secretId });
    check('create plan succeeded', p1.status === 'succeeded' || p1.status === 'unverified', { status: p1.status, error: p1.error });

    const row = (await pool.query(`SELECT * FROM radius_nas_clients WHERE ip = $1`, [ip])).rows[0];
    check('DB row exists with the given name + bound secretId', Boolean(row) && row.name === 'e2e-spot-nas' && row.secretId === secretId, { id: row?.id, name: row?.name, secretId: row?.secretId });

    // The rendered clients.conf on the sidecar volume must now contain the client.
    const rendered = execFileSync('docker', ['exec', 'unifiednetworkmanager-unm-radius-1', 'sh', '-c', `grep -F '${ip}' /data/radius/clients.conf 2>/dev/null || true`], { encoding: 'utf8' });
    check('rendered clients.conf contains the new client IP', rendered.includes(ip), rendered.slice(0, 160));

    // --- bulk delete ----------------------------------------------------------
    console.log('\n— radius.nas-client.bulk-delete (via system plan) —');
    const p2 = await runSystemPlan('radius.nas-client.bulk-delete', { ids: [row.id] });
    check('bulk-delete plan succeeded', p2.status === 'succeeded' || p2.status === 'unverified', { status: p2.status, error: p2.error });
    const after = (await pool.query(`SELECT * FROM radius_nas_clients WHERE ip = $1`, [ip])).rows[0];
    check('DB row removed', !after);

    // --- cleanup --------------------------------------------------------------
    let deletedPlans = 0;
    for (const pid of planIds) {
      const d = await authed('DELETE', `/plans/${pid}`);
      if (d.status === 204 || d.status === 404) deletedPlans++;
    }
    check(`spot plans removed (${planIds.length})`, deletedPlans === planIds.length, { deleted: deletedPlans });

    let secretDeleted = false;
    if (secretId) {
      const sd = await authed('DELETE', `/secrets/${secretId}`);
      secretDeleted = sd.status === 204 || sd.status === 404;
    }
    check('spot secret removed', secretDeleted);
  } finally {
    await pool.end();
  }

  console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
  process.exitCode = failures === 0 ? 0 : 1;
}

main().catch((e) => {
  console.error('spot check crashed:', e);
  process.exit(1);
});
