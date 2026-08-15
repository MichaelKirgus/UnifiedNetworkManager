import axios from 'axios';
import { v4 as uuidv4 } from 'uuid';
import { db, DeviceRow, PluginRow } from '../db';

const POLL_INTERVAL_MS = 30_000;

interface MonitoringResponse {
  health?: string;
  metrics?: Record<string, number>;
}

async function pollDevice(device: DeviceRow): Promise<void> {
  const plugin = db.prepare('SELECT * FROM plugins WHERE id = ?').get(device.pluginId) as
    | PluginRow
    | undefined;

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

    db.prepare(
      `INSERT INTO telemetry (id, deviceId, collectedAt, health, metrics)
       VALUES (?, ?, ?, ?, ?)`
    ).run(uuidv4(), device.id, collectedAt, health, JSON.stringify(metrics));

    const status = health === 'ok' ? 'online' : health === 'critical' ? 'offline' : 'degraded';
    db.prepare('UPDATE devices SET status = ? WHERE id = ?').run(status, device.id);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(`[telemetry] failed to poll device ${device.id}:`, (err as Error).message);
    db.prepare('UPDATE devices SET status = ? WHERE id = ?').run('unknown', device.id);
  }
}

async function pollAllDevices(): Promise<void> {
  const devices = db.prepare('SELECT * FROM devices').all() as DeviceRow[];
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
