import axios from 'axios';
import { db } from '../db';
import { and, asc, eq } from 'drizzle-orm';
import * as schema from '../db/schema';
import { configJobQueue } from '../queue';
import { getSecretFresh } from '../secretsProvider';
import { emitNotification } from '../notifications';
import { initWorker, trackBeat } from './stats';
import { settingsHeaders } from '../pluginSettings';
import { parseExtraCredentials } from '../types/credentialSlots';
import { decryptCredentialSlots, withSlots } from '../utils/slotCredentials';

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

  // Resolve the assignment that executes this job. New jobs always carry an
  // explicit pluginId; legacy rows (pre-multi-plugin) fall back to the device's
  // primary assignment.
  let assignment = null;
  if (job.pluginId) {
    assignment = await db.query.devicePlugins.findFirst({
      where: and(
        eq(schema.devicePlugins.deviceId, job.deviceId),
        eq(schema.devicePlugins.pluginId, job.pluginId)
      ),
    });
  }
  if (!assignment) {
    const all = await db.query.devicePlugins.findMany({
      where: (rows) => eq(rows.deviceId, job.deviceId),
      orderBy: [asc(schema.devicePlugins.createdAt)],
    });
    assignment = all.find((a) => a.isPrimary) ?? all[0] ?? null;
  }
  if (!assignment) {
    await db.update(schema.configJobs)
      .set({ 
        status: 'failed', 
        result: JSON.stringify({ error: 'No plugin assignment found for this device' }), 
        finishedAt: new Date().toISOString() 
      })
      .where(eq(schema.configJobs.id, jobId));
    return;
  }

  const plugin = await db.query.plugins.findFirst({
    where: (plugins, { eq }) => eq(plugins.id, assignment.pluginId),
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

  // All device addresses (primary first) so the plugin can reach secondary IPs.
  const secondaryIps = await db.query.deviceIps.findMany({
    where: (rows) => eq(rows.deviceId, device.id),
  });
  const ipAddresses = [
    { address: device.managementAddress, isPrimary: true },
    ...secondaryIps.map((row) => ({ address: row.address, isPrimary: false })),
  ];

  try {
    // The secrets provider plugin owns the crypto; the broker fetches the
    // decrypted secret on our behalf. Secrets are typed: `fields` holds the
    // decrypted values. For backward compatibility we also pass the legacy
    // `apiKey`/`apiSecret` keys when the secret is of type `apiKey`.
    // FRESH (uncached) — a config change must apply with current credentials.
    const decrypted = assignment.secretId ? await getSecretFresh(assignment.secretId) : null;
    const credentials = withSlots(
      decrypted?.fields ?? {},
      await decryptCredentialSlots(parseExtraCredentials(assignment.extraCredentials), { fresh: true })
    );

    // Inject the plugin's effective settings (device override ⊕ global ⊕
    // defaults) so the plugin can read its options without storing them itself.
    const headers = await settingsHeaders(plugin.id, device.id).catch(() => ({}));

    const response = await axios.post<ConfigResponse>(
      `${plugin.endpoint.replace(/\/$/, '')}/config`,
      {
        deviceId: device.id,
        // The UNM display name — plugins use it to label artifacts they create
        // (e.g. config backups stored in the central file repo).
        deviceName: device.name,
        managementAddress: device.managementAddress,
        ipAddresses,
        credentials,
        ...(decrypted?.type === 'apiKey'
          ? { apiKey: credentials.apiKey, apiSecret: credentials.apiSecret }
          : {}),
        action: job.action,
        payload: JSON.parse(job.payload),
      },
      { timeout: 15_000, headers }
    );

    const status = response.data?.success === false ? 'failed' : 'succeeded';
    await db.update(schema.configJobs)
      .set({ 
        status, 
        result: JSON.stringify(response.data?.result ?? response.data ?? {}), 
        finishedAt: new Date().toISOString() 
      })
      .where(eq(schema.configJobs.id, jobId));
    if (status === 'failed') {
      await notifyConfigJobFailure(jobId, device.name, job.action, JSON.stringify(response.data?.result ?? response.data ?? {}));
    }
  } catch (err) {
    await db.update(schema.configJobs)
      .set({ 
        status: 'failed', 
        result: JSON.stringify({ error: (err as Error).message }), 
        finishedAt: new Date().toISOString() 
      })
      .where(eq(schema.configJobs.id, jobId));
    await notifyConfigJobFailure(jobId, device.name, job.action, (err as Error).message);
  }
}

/** Mirror a failed config job into the notification center (one-shot per job). */
async function notifyConfigJobFailure(
  jobId: string,
  deviceName: string,
  action: string,
  detail: string
): Promise<void> {
  try {
    await emitNotification({
      severity: 'warning',
      source: 'system',
      title: `Config job failed on ${deviceName}`,
      message: `${action}: ${String(detail).slice(0, 500)}`,
      dedupeKey: `config-job:${jobId}`,
      context: { jobId, action },
    });
  } catch {
    // Best-effort by contract.
  }
}

/**
 * Starts the config job processing loop. Every `PROCESS_INTERVAL_MS`, any
 * jobs drained from the in-process queue are dispatched to their device's
 * plugin `/config` endpoint and the resulting status is persisted.
 */
export function startConfigJobWorker(): NodeJS.Timeout {
  initWorker('configJob', -1); // not leader-gated — every replica drains its own queue
  // eslint-disable-next-line no-console
  console.log(`[configJob] worker started, processing every ${PROCESS_INTERVAL_MS / 1000}s`);
  return setInterval(() => {
    const jobs = configJobQueue.drain();
    for (const job of jobs) {
      void trackBeat('configJob', () => processJob(job.data.jobId)).catch((err) => {
        // eslint-disable-next-line no-console
        console.error(`[configJob] failed processing job ${job.data.jobId}:`, err);
      });
    }
  }, PROCESS_INTERVAL_MS);
}
