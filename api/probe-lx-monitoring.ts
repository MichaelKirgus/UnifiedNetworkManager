/**
 * One-off probe (dev only): replays exactly what the telemetry worker sends to
 * the LX plugin's /monitoring for AP_Wohnzimmer and prints the response — used
 * to diagnose why no LX telemetry rows exist on the dev stack.
 *
 * Run inside the api container:  docker exec <api> sh -c "cd /app/api && node_modules/.bin/tsx probe-lx-monitoring.ts"
 */
import fs from 'node:fs';
import { db } from './src/db';
import { getSecretFresh } from './src/secretsProvider';
import { parseExtraCredentials } from './src/types/credentialSlots';
import { decryptCredentialSlots, withSlots } from './src/utils/slotCredentials';
import { pluginAxios, setApiMtlsIdentity, setPluginTransports } from './src/utils/pluginHttp';

// A standalone process has an EMPTY plugin-transport registry (defaults to
// plain HTTP) and no mTLS identity — seed both exactly like boot does.
const TLS_DIR = '/data/tls';
setApiMtlsIdentity({
  keyPem: fs.readFileSync(`${TLS_DIR}/tls.key`, 'utf8'),
  certChainPem: fs.readFileSync(`${TLS_DIR}/tls.crt`, 'utf8'),
  caBundlePem: fs.readFileSync(`${TLS_DIR}/ca-bundle.pem`, 'utf8'),
});

async function main(): Promise<void> {
  // Seed the transport registry from the plugins table (like boot does).
  const allPlugins = await db.query.plugins.findMany();
  setPluginTransports(allPlugins.map((p) => ({ endpoint: p.endpoint, tlsLive: p.tlsLive })));

  const device = await db.query.devices.findFirst({ where: (d, { eq }) => eq(d.name, 'AP_Wohnzimmer') });
  if (!device) throw new Error('AP_Wohnzimmer not found');
  console.log(`device ${device.id} enabled=${device.enabled} model=${device.model}`);

  const assignment = await db.query.devicePlugins.findFirst({
    where: (a, { and, eq }) => and(eq(a.deviceId, device.id), eq(a.pluginId, '00000000-0000-4000-8000-000000000004')),
  });
  if (!assignment) throw new Error('no LX assignment');

  const decrypted = assignment.secretId ? await getSecretFresh(assignment.secretId) : null;
  const credentials = withSlots(decrypted?.fields ?? {}, await decryptCredentialSlots(parseExtraCredentials(assignment.extraCredentials)));
  console.log('credential keys:', Object.keys(credentials), '| web slot present:', Boolean((credentials as Record<string, unknown>)['web']));

  const t0 = Date.now();
  try {
    const res = await pluginAxios('http://lancom-lx-plugin:4080').post(
      '/monitoring',
      {
        deviceId: device.id,
        managementAddress: device.managementAddress,
        ipAddresses: [{ address: device.managementAddress, isPrimary: true }],
        model: device.model ?? null,
        firmwareVersion: device.firmwareVersion ?? null,
        credentials,
        collectInventory: false,
      },
      { timeout: 60_000 }
    );
    const body = res.data as { health?: string; error?: string; metrics?: Record<string, unknown> };
    console.log(`\nHTTP ${res.status} in ${Date.now() - t0}ms — health=${body.health}`);
    if (body.error) console.log('error:', body.error);
    const m = body.metrics ?? {};
    console.log('metric keys:', Object.keys(m).join(', '));
    console.log('system.swVersion:', JSON.stringify(m['system.swVersion']));
    console.log('updates:', JSON.stringify(m['updates'], null, 1)?.slice(0, 1500));
  } catch (e) {
    console.error(`FAILED after ${Date.now() - t0}ms:`, (e as Error).message);
  }
  process.exit(0);
}

main().catch((e) => { console.error(e); process.exit(1); });
