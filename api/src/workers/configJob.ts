import axios from 'axios';
import { db } from '../db';
import { eq } from 'drizzle-orm';
import * as schema from '../db/schema';
import { configJobQueue } from '../queue';

const PROCESS_INTERVAL_MS = 5_000;

interface ConfigResponse {
  result?: Record<string, unknown>;
  success?: boolean;
}

async function processJob(jobId: string): Promise<void> {
  const job = await db.query.configJobs.findFirst({
    where: (configJobs, { eq }) => eq(configJobs.id, jobId),
  });
  if (!job || job.status !== 'queued') {
    return;
  }

  await db.update(schema.configJobs)
    .set({ status: 'running' })
    .where(eq(schema.configJobs.id, jobId));

  const device = await db.query.devices.findFirst({
    where: (devices, { eq }) => eq(devices.id, job.deviceId),
  });
  if (!device) {
    await db.update(schema.configJobs)
      .set({ 
        status: 'failed', 
        result: JSON.stringify({ error: 'Device not found' }), 
        finishedAt: new Date().toISOString() 
      })
      .where(eq(schema.configJobs.id, jobId));
    return;
  }

  const plugin = await db.query.plugins.findFirst({
    where: (plugins, { eq }) => eq(plugins.id, device.pluginId),
  });
  if (!plugin) {
    await db.update(schema.configJobs)
      .set({ 
        status: 'failed', 
        result: JSON.stringify({ error: 'Plugin not found' }), 
        finishedAt: new Date().toISOString() 
      })
      .where(eq(schema.configJobs.id, jobId));
    return;
  }

  try {
    const secret = await db.query.secrets.findFirst({
      where: (secrets, { eq }) => eq(secrets.id, device.secretId),
    });
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
    await db.update(schema.configJobs)
      .set({ 
        status, 
        result: JSON.stringify(response.data?.result ?? response.data ?? {}), 
        finishedAt: new Date().toISOString() 
      })
      .where(eq(schema.configJobs.id, jobId));
  } catch (err) {
    await db.update(schema.configJobs)
      .set({ 
        status: 'failed', 
        result: JSON.stringify({ error: (err as Error).message }), 
        finishedAt: new Date().toISOString() 
      })
      .where(eq(schema.configJobs.id, jobId));
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
