import axios from 'axios';
import { query, ConfigJobRow, DeviceRow, PluginRow } from '../db';
import { configJobQueue } from '../queue';

const PROCESS_INTERVAL_MS = 5_000;

interface ConfigResponse {
  result?: Record<string, unknown>;
  success?: boolean;
}

async function processJob(jobId: string): Promise<void> {
  const jobResult = await query<ConfigJobRow>('SELECT * FROM config_jobs WHERE id = $1', [jobId]);
  const job = jobResult.rows[0];
  if (!job || job.status !== 'queued') {
    return;
  }

  await query('UPDATE config_jobs SET status = $1 WHERE id = $2', ['running', jobId]);

  const deviceResult = await query<DeviceRow>('SELECT * FROM devices WHERE id = $1', [job.deviceId]);
  const device = deviceResult.rows[0];
  if (!device) {
    await query(
      'UPDATE config_jobs SET status = $1, result = $2, "finishedAt" = $3 WHERE id = $4',
      ['failed', JSON.stringify({ error: 'Device not found' }), new Date().toISOString(), jobId]
    );
    return;
  }

  const pluginResult = await query<PluginRow>('SELECT * FROM plugins WHERE id = $1', [device.pluginId]);
  const plugin = pluginResult.rows[0];
  if (!plugin) {
    await query(
      'UPDATE config_jobs SET status = $1, result = $2, "finishedAt" = $3 WHERE id = $4',
      ['failed', JSON.stringify({ error: 'Plugin not found' }), new Date().toISOString(), jobId]
    );
    return;
  }

  try {
    const secretResult = await query<any>(
      `SELECT encryptedValue FROM secrets WHERE id = $1`,
      [device.secretId]
    );
    const secret = secretResult.rows[0];
    if (!secret) {
      throw new Error(`Secret not found for device ${device.id}`);
    }

    const decryptedSecret = JSON.parse(
      await import('../utils/crypto').then(m => m.decrypt(secret.encryptedValue))
    );

    const response = await axios.post<ConfigResponse>(
      `${plugin.endpoint.replace(/\/$/, '')}/config`,
      {
        deviceId: device.id,
        managementAddress: device.managementAddress,
        apiKey: decryptedSecret.apiKey,
        apiSecret: decryptedSecret.apiSecret,
        action: job.action,
        payload: JSON.parse(job.payload),
      },
      { timeout: 15_000 }
    );

    const status = response.data?.success === false ? 'failed' : 'succeeded';
    await query(
      'UPDATE config_jobs SET status = $1, result = $2, "finishedAt" = $3 WHERE id = $4',
      [status, JSON.stringify(response.data?.result ?? response.data ?? {}), new Date().toISOString(), jobId]
    );
  } catch (err) {
    await query(
      'UPDATE config_jobs SET status = $1, result = $2, "finishedAt" = $3 WHERE id = $4',
      ['failed', JSON.stringify({ error: (err as Error).message }), new Date().toISOString(), jobId]
    );
  }
}

/**
 * Starts the config job processing loop. Every `PROCESS_INTERVAL_MS`, any
 * jobs drained from the in-process queue are dispatched to their device's
 * plugin `/config` endpoint and the resulting status is persisted.
 */
export function startConfigJobWorker(): NodeJS.Timeout {
  // eslint-disable-next-line no-console
  console.log(`[configJob] worker started, processing every ${PROCESS_INTERVAL_MS / 1000}s`);
  return setInterval(() => {
    const jobs = configJobQueue.drain();
    for (const job of jobs) {
      processJob(job.data.jobId).catch((err) => {
        // eslint-disable-next-line no-console
        console.error(`[configJob] failed processing job ${job.data.jobId}:`, err);
      });
    }
  }, PROCESS_INTERVAL_MS);
}
