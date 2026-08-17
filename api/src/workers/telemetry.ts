import axios from 'axios';
import { v4 as uuidv4 } from 'uuid';
import { db } from '../db';
import { eq } from 'drizzle-orm';
import * as schema from '../db/schema';
import { getSecret } from '../secretsProvider';

const POLL_INTERVAL_MS = 30_000;

interface MonitoringResponse {
  health?: string;
  metrics?: Record<string, number>;
}

async function pollDevice(device: any): Promise<void> {
  const plugin = await db.query.plugins.findFirst({
    where: (plugins, { eq }) => eq(plugins.id, device.pluginId),
  });

  if (!plugin) {
    return;
  }

  try {
    // The secrets provider plugin owns the crypto; the broker fetches the
    // decrypted secret on our behalf. Secrets are typed: `fields` holds the
    // decrypted values. For backward compatibility we also pass the legacy
    // `apiKey`/`apiSecret` keys when the secret is of type `apiKey`.
    const decryptedSecret = await getSecret(device.secretId);
    const credentials = decryptedSecret.fields;

    const response = await axios.post<MonitoringResponse>(
      `${plugin.endpoint.replace(/\/$/, '')}/monitoring`,
      { 
        deviceId: device.id, 
        managementAddress: device.managementAddress,
        credentials,
        ...(decryptedSecret.type === 'apiKey'
          ? { apiKey: credentials.apiKey, apiSecret: credentials.apiSecret }
          : {})
      },
      { timeout: 10_000 }
    );

    const health = response.data?.health ?? 'unknown';
    const metrics = response.data?.metrics ?? {};
    const collectedAt = new Date().toISOString();

    await db.insert(schema.telemetry).values({
      id: uuidv4(),
      deviceId: device.id,
      collectedAt,
      health,
      metrics: JSON.stringify(metrics),
    });

    const status = health === 'ok' ? 'online' : health === 'critical' ? 'offline' : 'degraded';
    await db.update(schema.devices)
      .set({ status })
      .where(eq(schema.devices.id, device.id));
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(`[telemetry] failed to poll device ${device.id}:`, (err as Error).message);
    await db.update(schema.devices)
      .set({ status: 'unknown' })
      .where(eq(schema.devices.id, device.id));
  }
}

async function pollAllDevices(): Promise<void> {
  const devices = await db.query.devices.findMany();
  await Promise.all(devices.map((device) => pollDevice(device)));
}

/**
 * Starts the telemetry polling loop. Every `POLL_INTERVAL_MS`, each known
 * device's plugin is asked for a monitoring snapshot which is normalized
 * and persisted to the `telemetry` table.
 */
export function startTelemetryWorker(): NodeJS.Timeout {
  // eslint-disable-next-line no-console
  console.log(`[telemetry] worker started, polling every ${POLL_INTERVAL_MS / 1000}s`);
  return setInterval(() => {
    pollAllDevices().catch((err) => {
      // eslint-disable-next-line no-console
      console.error('[telemetry] poll cycle failed:', err);
    });
  }, POLL_INTERVAL_MS);
}
