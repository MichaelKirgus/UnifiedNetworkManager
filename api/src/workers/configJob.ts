import axios from 'axios';
import { db, ConfigJobRow, DeviceRow, PluginRow } from '../db';
import { configJobQueue } from '../queue';

const PROCESS_INTERVAL_MS = 5_000;

interface ConfigResponse {
  result?: Record<string, unknown>;
  success?: boolean;
}

async function processJob(jobId: string): Promise<void> {
  const job = db.prepare('SELECT * FROM config_jobs WHERE id = ?').get(jobId) as ConfigJobRow | undefined;
  if (!job || job.status !== 'queued') {
    return;
  }

  db.prepare('UPDATE config_jobs SET status = ? WHERE id = ?').run('running', jobId);

  const device = db.prepare('SELECT * FROM devices WHERE id = ?').get(job.deviceId) as DeviceRow | undefined;
  if (!device) {
    db.prepare(
      'UPDATE config_jobs SET status = ?, result = ?, finishedAt = ? WHERE id = ?'
    ).run('failed', JSON.stringify({ error: 'Device not found' }), new Date().toISOString(), jobId);
    return;
  }

  const plugin = db.prepare('SELECT * FROM plugins WHERE id = ?').get(device.pluginId) as
    | PluginRow
    | undefined;
  if (!plugin) {
    db.prepare(
      'UPDATE config_jobs SET status = ?, result = ?, finishedAt = ? WHERE id = ?'
    ).run('failed', JSON.stringify({ error: 'Plugin not found' }), new Date().toISOString(), jobId);
    return;
  }

  try {
    const response = await axios.post<ConfigResponse>(
      `${plugin.endpoint.replace(/\/$/, '')}/config`,
      {
        deviceId: device.id,
        managementAddress: device.managementAddress,
        action: job.action,
        payload: JSON.parse(job.payload),
      },
      { timeout: 15_000 }
    );

    const status = response.data?.success === false ? 'failed' : 'succeeded';
    db.prepare(
      'UPDATE config_jobs SET status = ?, result = ?, finishedAt = ? WHERE id = ?'
    ).run(status, JSON.stringify(response.data?.result ?? response.data ?? {}), new Date().toISOString(), jobId);
  } catch (err) {
    db.prepare(
      'UPDATE config_jobs SET status = ?, result = ?, finishedAt = ? WHERE id = ?'
    ).run('failed', JSON.stringify({ error: (err as Error).message }), new Date().toISOString(), jobId);
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
