import axios from 'axios';
import { v4 as uuidv4 } from 'uuid';
import { query, DeviceRow, PluginRow } from '../db';

const POLL_INTERVAL_MS = 30_000;

interface MonitoringResponse {
  health?: string;
  metrics?: Record<string, number>;
}

async function pollDevice(device: DeviceRow): Promise<void> {
  const pluginResult = await query<PluginRow>('SELECT * FROM plugins WHERE id = $1', [device.pluginId]);
  const plugin = pluginResult.rows[0];

  if (!plugin) {
    return;
  }

  try {
    const response = await axios.post<MonitoringResponse>(
      `${plugin.endpoint.replace(/\/$/, '')}/monitoring`,
      { deviceId: device.id, managementAddress: device.managementAddress },
      { timeout: 10_000 }
    );

    const health = response.data?.health ?? 'unknown';
    const metrics = response.data?.metrics ?? {};
    const collectedAt = new Date().toISOString();

    await query(
      `INSERT INTO telemetry (id, "deviceId", "collectedAt", health, metrics)
       VALUES ($1, $2, $3, $4, $5)`,
      [uuidv4(), device.id, collectedAt, health, JSON.stringify(metrics)]
    );

    const status = health === 'ok' ? 'online' : health === 'critical' ? 'offline' : 'degraded';
    await query('UPDATE devices SET status = $1 WHERE id = $2', [status, device.id]);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(`[telemetry] failed to poll device ${device.id}:`, (err as Error).message);
    await query('UPDATE devices SET status = $1 WHERE id = $2', ['unknown', device.id]);
  }
}

async function pollAllDevices(): Promise<void> {
  const result = await query<DeviceRow>('SELECT * FROM devices');
  await Promise.all(result.rows.map((device) => pollDevice(device)));
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
