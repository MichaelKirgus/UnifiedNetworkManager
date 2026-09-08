import axios from 'axios';
import { and, eq } from 'drizzle-orm';
import { db } from './db';
import * as schema from './db/schema';
import { getSecretFresh } from './secretsProvider';
import { settingsHeaders } from './pluginSettings';
import { parseExtraCredentials } from './types/credentialSlots';
import { decryptCredentialSlots, withSlots } from './utils/slotCredentials';

/**
 * Device-probe broker.
 *
 * Short-cycle LIVE telemetry: the webapp polls on demand (1–5 s cadence) for
 * data that is too slow or too heavy for the background /monitoring worker —
 * e.g. per-container CPU/RAM/I-O from `docker stats` over SSH. Plugins opt in
 * by advertising the 'probe' capability and serving POST /probe; they own what
 * each probe key means (the caller selects keys via ?keys=a,b so a page only
 * pays for what it renders). This broker is deliberately GENERIC — same shape
 * as deviceState.ts: resolve assignment + fresh credentials, forward to the
 * plugin, return the response verbatim. It never interprets metric content and
 * writes NOTHING to the DB (a live read path, not a telemetry cycle).
 */

/** One address of the device as presented to plugins (primary flag included). */
interface DeviceAddressView {
  address: string;
  isPrimary: boolean;
}

/** The probe snapshot a plugin returns — mirrored from @unm/plugin-sdk types. */
export interface ProbeResult {
  collectedAt: string;
  metrics: Record<string, unknown>;
}

/** Error carrying an HTTP status so routes can map it directly. */
export class DeviceProbeError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

/**
 * Fetches a live probe snapshot for one (device, plugin) assignment from the
 * plugin's POST /probe endpoint. Credentials are fetched FRESH (uncached) —
 * the same rule as plan steps and device state: a live call must use current
 * secrets. `keys` is forwarded verbatim; an empty/absent list means "the
 * plugin's default set". `names` optionally restricts collection to a subset
 * of containers (state-style keys); absent = full collection.
 */
export async function fetchDeviceProbe(
  deviceId: string,
  pluginId: string,
  keys?: string[],
  names?: string[]
): Promise<{ pluginId: string; probe: ProbeResult }> {
  const device = await db.query.devices.findFirst({ where: eq(schema.devices.id, deviceId) });
  if (!device) throw new DeviceProbeError(404, 'Device not found');

  const assignment = await db.query.devicePlugins.findFirst({
    where: and(eq(schema.devicePlugins.deviceId, deviceId), eq(schema.devicePlugins.pluginId, pluginId)),
  });
  if (!assignment) {
    throw new DeviceProbeError(400, `Plugin ${pluginId} is not assigned to this device`);
  }

  const plugin = await db.query.plugins.findFirst({ where: eq(schema.plugins.id, pluginId) });
  if (!plugin || !plugin.endpoint) {
    throw new DeviceProbeError(404, 'Assigned plugin has no reachable endpoint');
  }

  // Capability gate — a stale webapp must get a clean 501, not a transport error.
  const capabilities: string[] = typeof plugin.capabilities === 'string' ? JSON.parse(plugin.capabilities) : (plugin.capabilities ?? []);
  if (!capabilities.includes('probe')) {
    throw new DeviceProbeError(501, 'This plugin does not support probing');
  }

  // Secondary IPs (primary is always managementAddress).
  const secondaryIps = await db.query.deviceIps.findMany({ where: eq(schema.deviceIps.deviceId, deviceId) });
  const ipAddresses: DeviceAddressView[] = [
    { address: device.managementAddress, isPrimary: true },
    ...secondaryIps.map((row) => ({ address: row.address, isPrimary: false })),
  ];

  // Fresh credentials + bound slots (same merge as the plan executor).
  const decrypted = assignment.secretId ? await getSecretFresh(assignment.secretId) : null;
  const credentials = withSlots(
    decrypted?.fields ?? {},
    await decryptCredentialSlots(parseExtraCredentials(assignment.extraCredentials), { fresh: true })
  );

  // Per-device settings overrides for THIS assignment scope.
  const headers = await settingsHeaders(pluginId, deviceId).catch(() => ({}));

  let response;
  try {
    response = await axios.post<ProbeResult>(
      `${plugin.endpoint.replace(/\/$/, '')}/probe`,
      {
        deviceId,
        managementAddress: device.managementAddress,
        ipAddresses,
        model: device.model ?? null,
        firmwareVersion: device.firmwareVersion ?? null,
        credentials,
        ...(keys && keys.length > 0 ? { keys } : {}),
        ...(names && names.length > 0 ? { names } : {}),
        ...(decrypted?.type === 'apiKey' ? { apiKey: credentials.apiKey, apiSecret: credentials.apiSecret } : {})
      },
      // Short-cycle path — the webapp polls every few seconds, so keep the
      // budget tight; a slow probe should fail fast and let the UI fall back.
      { timeout: 8_000, headers }
    );
  } catch (err) {
    const e = err as { response?: { status?: number; data?: { error?: string } }; message?: string };
    if (e.response?.status === 404) {
      throw new DeviceProbeError(501, 'This plugin does not support probing');
    }
    const upstream = e.response?.data?.error ?? e.message ?? 'Failed to probe device';
    throw new DeviceProbeError(502, `Plugin failed to report probe data: ${upstream}`);
  }

  const probe = response.data;
  if (!probe || typeof probe !== 'object' || !probe.metrics || typeof probe.metrics !== 'object') {
    // metrics must be an object (possibly empty) — validate shape, keep content.
    throw new DeviceProbeError(502, 'Malformed probe response from plugin');
  }

  return { pluginId, probe: { collectedAt: String(probe.collectedAt ?? new Date().toISOString()), metrics: probe.metrics as Record<string, unknown> } };
}
