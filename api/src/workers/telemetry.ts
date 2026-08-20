import axios from 'axios';
import { v4 as uuidv4 } from 'uuid';
import { db } from '../db';
import { eq, inArray } from 'drizzle-orm';
import * as schema from '../db/schema';
import { getSecret } from '../secretsProvider';
import { settingsHeaders } from '../pluginSettings';

const POLL_INTERVAL_MS = 30_000;

interface MonitoringResponse {
  health?: string;
  metrics?: Record<string, unknown>;
  metricDescriptors?: unknown[];
}

/** A device address as presented to plugins (primary flag included). */
interface DeviceAddressView {
  address: string;
  isPrimary: boolean;
}

/** One plugin's view of a device (assignment + its plugin row). */
interface AssignmentTarget {
  deviceId: string;
  managementAddress: string;
  /** All device addresses, primary first. Lets plugins reach secondary IPs. */
  ipAddresses: DeviceAddressView[];
  pluginId: string;
  secretId: string | null;
  endpoint: string;
}

async function pollAssignment(target: AssignmentTarget): Promise<string> {
  try {
    // The secrets provider plugin owns the crypto; the broker fetches the
    // decrypted secret on our behalf. Secrets are typed: `fields` holds the
    // decrypted values. For backward compatibility we also pass the legacy
    // `apiKey`/`apiSecret` keys when the secret is of type `apiKey`.
    const decrypted = target.secretId ? await getSecret(target.secretId) : null;
    const credentials = decrypted?.fields ?? {};

    // Per-device settings overrides are resolved for THIS assignment scope.
    const headers = await settingsHeaders(target.pluginId, target.deviceId).catch(() => ({}));

    const response = await axios.post<MonitoringResponse>(
      `${target.endpoint.replace(/\/$/, '')}/monitoring`,
      {
        deviceId: target.deviceId,
        managementAddress: target.managementAddress,
        ipAddresses: target.ipAddresses,
        credentials,
        ...(decrypted?.type === 'apiKey'
          ? { apiKey: credentials.apiKey, apiSecret: credentials.apiSecret }
          : {})
      },
      { timeout: 10_000, headers }
    );

    const health = response.data?.health ?? 'unknown';
    const metrics = response.data?.metrics ?? {};
    const metricDescriptors = response.data?.metricDescriptors;
    const collectedAt = new Date().toISOString();

    await db.insert(schema.telemetry).values({
      id: uuidv4(),
      deviceId: target.deviceId,
      pluginId: target.pluginId,
      collectedAt,
      health,
      metrics: JSON.stringify(metrics),
      metricDescriptors: metricDescriptors ? JSON.stringify(metricDescriptors) : null,
    });

    return health;
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(
      `[telemetry] failed to poll device ${target.deviceId} via plugin ${target.pluginId}:`,
      (err as Error).message
    );
    return 'unknown';
  }
}

/**
 * Overall device status from per-assignment health — worst-wins:
 *   any critical → offline; all ok → online; otherwise degraded.
 */
function deriveDeviceStatus(healths: string[]): string {
  if (healths.length === 0) return 'unknown';
  if (healths.some((h) => h === 'critical')) return 'offline';
  if (healths.every((h) => h === 'ok')) return 'online';
  return 'degraded';
}

async function pollAllDevices(): Promise<void> {
  const devices = await db.query.devices.findMany();
  if (devices.length === 0) return;

  // Load every assignment with its plugin endpoint in one pass.
  const assignments = await db.query.devicePlugins.findMany({});
  const pluginsById = new Map(
    (await db.query.plugins.findMany()).map((p) => [p.id, p] as const)
  );

  // Secondary IPs per device (primary is always managementAddress). Batched.
  const deviceIds = devices.map((d) => d.id);
  const secondaryIps =
    deviceIds.length > 0
      ? await db.query.deviceIps.findMany({ where: inArray(schema.deviceIps.deviceId, deviceIds) })
      : [];
  const ipsByDevice = new Map<string, string[]>();
  for (const row of secondaryIps) {
    const list = ipsByDevice.get(row.deviceId) ?? [];
    list.push(row.address);
    ipsByDevice.set(row.deviceId, list);
  }

  const targetsByDevice = new Map<string, AssignmentTarget[]>();
  for (const a of assignments) {
    const device = devices.find((d) => d.id === a.deviceId);
    const plugin = pluginsById.get(a.pluginId);
    if (!device || !plugin) continue; // stale assignment or unknown plugin: skip
    const ipAddresses: DeviceAddressView[] = [
      { address: device.managementAddress, isPrimary: true },
      ...(ipsByDevice.get(device.id) ?? []).map((address) => ({ address, isPrimary: false })),
    ];
    const list = targetsByDevice.get(device.id) ?? [];
    list.push({
      deviceId: device.id,
      managementAddress: device.managementAddress,
      ipAddresses,
      pluginId: a.pluginId,
      secretId: a.secretId,
      endpoint: plugin.endpoint,
    });
    targetsByDevice.set(device.id, list);
  }

  // Poll every assignment independently — one dead plugin must not take the
  // whole device down. Device status is derived worst-wins afterwards.
  await Promise.all(
    Array.from(targetsByDevice.entries()).map(async ([deviceId, targets]) => {
      const healths = await Promise.all(targets.map((t) => pollAssignment(t)));
      const status = deriveDeviceStatus(healths);
      await db.update(schema.devices).set({ status }).where(eq(schema.devices.id, deviceId));
    })
  );
}

/**
 * Starts the telemetry polling loop. Every `POLL_INTERVAL_MS`, each device's
 * assigned plugins are asked for a monitoring snapshot which is normalized and
 * persisted to the `telemetry` table (one row per plugin per cycle).
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
