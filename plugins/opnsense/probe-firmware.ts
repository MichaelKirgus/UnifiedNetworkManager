/**
 * READ-ONLY live probe of the OPNsense firmware API surface — dumps the raw
 * JSON of every endpoint the update feature would use, so field names can be
 * confirmed against a real appliance. NEVER calls update/upgrade/reboot/set.
 * Credentials come from UNM's secrets store for the device assignment.
 *
 * Usage (from repo root):
 *   ./node_modules/.bin/tsx plugins/opnsense/probe-firmware.ts [deviceName]
 */

import path from 'node:path';
import { createRequire } from 'node:module';

const apiRequire = createRequire(path.resolve(process.cwd(), 'api', 'package.json'));
const pluginRequire = createRequire(path.resolve(process.cwd(), 'plugins/opnsense/package.json'));

async function main(): Promise<void> {
  const deviceName = process.argv[2] ?? 'OPNSENSE01';
  const { Pool } = apiRequire('pg');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL ?? 'postgresql://unm:unm@localhost:5432/unm' });

  const devRow = (await pool.query(`SELECT id, "managementAddress" FROM devices WHERE name = $1`, [deviceName])).rows[0];
  if (!devRow) throw new Error(`no device ${deviceName}`);
  const dpRow = (await pool.query(
    `SELECT dp."secretId", p.id AS plugin_id FROM device_plugins dp JOIN plugins p ON p.id = dp."pluginId" WHERE dp."deviceId" = $1 AND p.name ILIKE '%opnsense%'`,
    [devRow.id],
  )).rows[0];
  if (!dpRow) throw new Error(`no opnsense assignment for ${deviceName}`);

  const { getSecret } = await import('../../api/src/secretsProvider');
  const secret = await getSecret(dpRow.secretId);
  console.log(`secret type=${secret.type} fields=[${Object.keys(secret.fields)}]`);

  const host = devRow.managementAddress;
  console.log(`host=${host}\n`);

  const { createClient } = pluginRequire('./src/client/http');
  const client = (createClient as (h: string, c: { apiKey: string; apiSecret: string }, t?: string) => import('axios').AxiosInstance)(
    host,
    { apiKey: secret.fields['apiKey'], apiSecret: secret.fields['apiSecret'] },
    'auto',
  );

  const dump = async (label: string, fn: () => Promise<{ status: number; data: unknown }>) => {
    try {
      const r = await fn();
      console.log(`--- ${label} (HTTP ${r.status}) ---`);
      const json = JSON.stringify(r.data, null, 2);
      console.log(json && json.length > 3000 ? `${json.slice(0, 3000)}… [truncated]` : json);
    } catch (e) {
      console.error(`--- ${label} FAILED: ${(e as Error).message}`);
    }
    console.log('');
  };

  await dump('GET /api/core/firmware/info', () => client.get('/api/core/firmware/info'));
  await dump('POST /api/core/firmware/status', () => client.post('/api/core/firmware/status', {}));
  await dump('GET /api/core/firmware/running', () => client.get('/api/core/firmware/running'));
  await dump('GET /api/core/firmware/getOptions', () => client.get('/api/core/firmware/getOptions'));

  // Changelog for the CURRENT line (read-only) — confirms notes-text shape.
  const info = ((await client.get('/api/core/firmware/info')).data as Record<string, unknown>) ?? {};
  const running = ((await client.get('/api/core/firmware/running')).data as Record<string, unknown>) ?? {};
  console.log(`info keys: [${Object.keys(info)}]`);
  console.log(`running keys: [${Object.keys(running)}]`);

  await pool.end();
}

main().catch((err) => { console.error('PROBE FAILED:', err.message ?? err); process.exit(1); });
