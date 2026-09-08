import axios from 'axios';
import { and, eq } from 'drizzle-orm';
import { db } from './db';
import * as schema from './db/schema';
import { getSecretFresh } from './secretsProvider';
import { settingsHeaders } from './pluginSettings';
import { parseExtraCredentials } from './types/credentialSlots';
import { decryptCredentialSlots, withSlots } from './utils/slotCredentials';

/**
 * Device-filesystem broker.
 *
 * A generic, root-scoped file manager over SFTP: the webapp's Storage page browses a
 * dataset's contents and the Containers page browses a container volume mount — both
 * drive ONE plugin endpoint (POST /filesystem, capability 'filesystem') through this
 * broker. The caller passes an `op` + `path` + `context`; the plugin maps `context`
 * onto an SFTP root and confines every path to it (so a webapp-supplied relative path
 * can never walk out of the scoped tree). This broker is deliberately GENERIC — same
 * shape as deviceProbe.ts: resolve assignment + fresh credentials, forward to the
 * plugin, return the response verbatim. It never interprets file content and writes
 * NOTHING to the DB (a live read/write path, not a telemetry cycle).
 */

/** The file operation to perform (mirrors @unm/plugin-sdk FilesystemOp). */
export type FilesystemOp = 'list' | 'read' | 'stat' | 'write' | 'mkdir' | 'rmdir' | 'unlink' | 'rename';

/** One address of the device as presented to plugins (primary flag included). */
interface DeviceAddressView {
  address: string;
  isPrimary: boolean;
}

/** The filesystem response a plugin returns — mirrored from @unm/plugin-sdk types. */
export interface FilesystemResult {
  collectedAt: string;
  path?: string;
  entries?: Array<{ name: string; isDirectory: boolean; sizeBytes: number | null; mtimeMs: number | null }>;
  contentBase64?: string;
  sizeBytes?: number | null;
  mtimeMs?: number | null;
  isDirectory?: boolean;
}

/** Error carrying an HTTP status so routes can map it directly. */
export class DeviceFilesystemError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

const VALID_OPS: FilesystemOp[] = ['list', 'read', 'stat', 'write', 'mkdir', 'rmdir', 'unlink', 'rename'];

/**
 * Performs one filesystem operation for a (device, plugin) assignment by forwarding to
 * the plugin's POST /filesystem endpoint. Credentials are fetched FRESH (uncached) —
 * the same rule as plan steps and device state: a live call must use current secrets.
 * `context` is forwarded verbatim (the plugin owns its meaning); `op`/`path`/etc. map
 * 1:1 onto the SDK's FilesystemRequestBody.
 */
export async function performFilesystemOp(
  deviceId: string,
  pluginId: string,
  op: FilesystemOp,
  params: { path?: string; targetPath?: string; contentBase64?: string; parents?: boolean; context?: Record<string, unknown> }
): Promise<{ pluginId: string; result: FilesystemResult }> {
  if (!VALID_OPS.includes(op)) throw new DeviceFilesystemError(400, `Unsupported filesystem op "${op}"`);

  const device = await db.query.devices.findFirst({ where: eq(schema.devices.id, deviceId) });
  if (!device) throw new DeviceFilesystemError(404, 'Device not found');

  const assignment = await db.query.devicePlugins.findFirst({
    where: and(eq(schema.devicePlugins.deviceId, deviceId), eq(schema.devicePlugins.pluginId, pluginId)),
  });
  if (!assignment) {
    throw new DeviceFilesystemError(400, `Plugin ${pluginId} is not assigned to this device`);
  }

  const plugin = await db.query.plugins.findFirst({ where: eq(schema.plugins.id, pluginId) });
  if (!plugin || !plugin.endpoint) {
    throw new DeviceFilesystemError(404, 'Assigned plugin has no reachable endpoint');
  }

  // Capability gate — a stale webapp must get a clean 501, not a transport error.
  const capabilities: string[] = typeof plugin.capabilities === 'string' ? JSON.parse(plugin.capabilities) : (plugin.capabilities ?? []);
  if (!capabilities.includes('filesystem')) {
    throw new DeviceFilesystemError(501, 'This plugin does not support filesystem browsing');
  }

  // Secondary IPs (primary is always managementAddress).
  const secondaryIps = await db.query.deviceIps.findMany({ where: eq(schema.deviceIps.deviceId, deviceId) });
  const ipAddresses: DeviceAddressView[] = [
    { address: device.managementAddress, isPrimary: true },
    ...secondaryIps.map((row) => ({ address: row.address, isPrimary: false })),
  ];

  // Fresh credentials + bound slots (same merge as the plan executor). The ssh slot
  // (when bound) is what the plugin uses for SFTP; the primary secret is used to
  // resolve dataset mountpoints over the appliance RPC.
  const decrypted = assignment.secretId ? await getSecretFresh(assignment.secretId) : null;
  const credentials = withSlots(
    decrypted?.fields ?? {},
    await decryptCredentialSlots(parseExtraCredentials(assignment.extraCredentials), { fresh: true })
  );

  // Per-device settings overrides for THIS assignment scope.
  const headers = await settingsHeaders(pluginId, deviceId).catch(() => ({}));

  let response;
  try {
    response = await axios.post<FilesystemResult>(
      `${plugin.endpoint.replace(/\/$/, '')}/filesystem`,
      {
        deviceId,
        managementAddress: device.managementAddress,
        ipAddresses,
        model: device.model ?? null,
        firmwareVersion: device.firmwareVersion ?? null,
        credentials,
        op,
        ...(params.path !== undefined ? { path: params.path } : {}),
        ...(params.targetPath !== undefined ? { targetPath: params.targetPath } : {}),
        ...(params.contentBase64 !== undefined ? { contentBase64: params.contentBase64 } : {}),
        ...(params.parents !== undefined ? { parents: params.parents } : {}),
        ...(params.context && Object.keys(params.context).length > 0 ? { context: params.context } : {}),
      },
      // File ops can be slow (large reads/writes, mountpoint resolution) — give a
      // generous budget; the webapp shows a spinner while waiting.
      { timeout: 60_000, headers, maxBodyLength: 12 * 1024 * 1024 }
    );
  } catch (err) {
    const e = err as { response?: { status?: number; data?: { error?: string } }; message?: string };
    if (e.response?.status === 404) {
      throw new DeviceFilesystemError(501, 'This plugin does not support filesystem browsing');
    }
    const upstream = e.response?.data?.error ?? e.message ?? 'Failed to reach the device';
    throw new DeviceFilesystemError(502, `Plugin failed to perform the file operation: ${upstream}`);
  }

  const result = response.data;
  if (!result || typeof result !== 'object') {
    throw new DeviceFilesystemError(502, 'Malformed filesystem response from plugin');
  }

  return { pluginId, result: { ...result, collectedAt: String(result.collectedAt ?? new Date().toISOString()) } };
}
