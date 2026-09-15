import { and, eq } from 'drizzle-orm';
import { db } from './db';
import * as schema from './db/schema';
import { getSecretFresh } from './secretsProvider';
import { parseExtraCredentials } from './types/credentialSlots';
import { decryptCredentialSlots, withSlots } from './utils/slotCredentials';
import { getEffectiveSettings } from './pluginSettings';

/**
 * Device-console broker (capability 'sshConsole').
 *
 * Resolves everything the WebSocket proxy needs to open a console: the assigned
 * plugin's endpoint + the device's addresses + FRESH decrypted credentials. The
 * actual byte-pumping lives in routes/devices.ts (the /console/ws upgrade path) —
 * this module only answers "who do we connect to, and with what credentials?".
 *
 * Credentials are fetched UNCACHED (getSecretFresh), same rule as plan steps and
 * device state: a live interactive session must use current secrets. The ssh slot
 * (when bound) is what the plugin uses for the PTY; it rides `credentials.slots.ssh`
 * exactly like every other SSH data path in this codebase.
 */

/** One address of the device as presented to plugins (primary flag included). */
export interface DeviceAddressView {
  address: string;
  isPrimary: boolean;
}

/** The resolved console target — everything the WS proxy needs for one connection. */
export interface ConsoleTarget {
  pluginId: string;
  /** The plugin's HTTP endpoint (the WS URL derives from it). */
  endpoint: string;
  managementAddress: string;
  ipAddresses: DeviceAddressView[];
  /** Fresh decrypted credentials (primary + bound slots) — same shape as /monitoring. */
  credentials: Record<string, unknown>;
  /** The assignment's effective plugin settings (defaults ⊕ overrides) — lets the
   *  plugin's console onOpen() resolve per-device options such as a non-default SSH port. */
  settings?: Record<string, unknown>;
}

/** Error carrying an HTTP status so routes can map it directly. */
export class DeviceConsoleError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

/**
 * Resolves the console target for a (device, plugin) assignment. `pluginId` empty
 * = the device's primary assignment. Throws DeviceConsoleError with an HTTP status
 * when anything is missing (no assignment / no endpoint / capability not advertised).
 *
 * `sessionSecretId` — when set (validated upstream by sessionCredentials.ts), its
 * decrypted fields REPLACE whatever is bound to the assignment's `ssh` slot, so a
 * user can open a console with ANY of their eligible personal credentials without
 * changing the device assignment. Plugins are unaffected: they read slots.ssh as before.
 */
export async function resolveConsoleTarget(
  deviceId: string,
  pluginId?: string,
  sessionSecretId?: string
): Promise<ConsoleTarget> {
  const device = await db.query.devices.findFirst({ where: eq(schema.devices.id, deviceId) });
  if (!device) throw new DeviceConsoleError(404, 'Device not found');

  let effectivePluginId = pluginId ?? '';
  if (!effectivePluginId) {
    const assignments = await db.query.devicePlugins.findMany({ where: eq(schema.devicePlugins.deviceId, deviceId) });
    const primary = assignments.find((a) => a.isPrimary) ?? assignments[0];
    if (!primary) throw new DeviceConsoleError(400, 'Device has no plugin assignment');
    effectivePluginId = primary.pluginId;
  }

  const assignment = await db.query.devicePlugins.findFirst({
    where: and(eq(schema.devicePlugins.deviceId, deviceId), eq(schema.devicePlugins.pluginId, effectivePluginId)),
  });
  if (!assignment) {
    throw new DeviceConsoleError(400, `Plugin ${effectivePluginId} is not assigned to this device`);
  }

  const plugin = await db.query.plugins.findFirst({ where: eq(schema.plugins.id, effectivePluginId) });
  if (!plugin || !plugin.endpoint) {
    throw new DeviceConsoleError(404, 'Assigned plugin has no reachable endpoint');
  }

  // Capability gate — a stale webapp must get a clean 501, not a transport error.
  const capabilities: string[] = typeof plugin.capabilities === 'string' ? JSON.parse(plugin.capabilities) : (plugin.capabilities ?? []);
  if (!capabilities.includes('sshConsole')) {
    throw new DeviceConsoleError(501, 'This plugin does not support an SSH console');
  }

  // Secondary IPs (primary is always managementAddress).
  const secondaryIps = await db.query.deviceIps.findMany({ where: eq(schema.deviceIps.deviceId, deviceId) });
  const ipAddresses: DeviceAddressView[] = [
    { address: device.managementAddress, isPrimary: true },
    ...secondaryIps.map((row) => ({ address: row.address, isPrimary: false })),
  ];

  // Fresh credentials + bound slots (same merge as the plan executor). The ssh slot
  // (when bound) is what the plugin uses for the PTY session. A validated
  // `sessionSecretId` OVERRIDES that slot — the user's chosen personal credential
  // rides in exactly like a bound one, so plugins need no changes.
  const decrypted = assignment.secretId ? await getSecretFresh(assignment.secretId) : null;
  let slots = await decryptCredentialSlots(parseExtraCredentials(assignment.extraCredentials), { fresh: true });
  if (sessionSecretId) {
    try {
      const sessionSecret = await getSecretFresh(sessionSecretId);
      slots = { ...slots, ssh: sessionSecret.fields };
    } catch (err) {
      throw new DeviceConsoleError(502, `Failed to load the selected SSH credential: ${(err as Error).message}`);
    }
  }
  const credentials = withSlots(decrypted?.fields ?? {}, slots);

  // Effective plugin settings (best-effort) — the console hello carries them so a
  // non-default SSH port configured per device is honored by the PTY session.
  let settings: Record<string, unknown> | undefined;
  try {
    const s = await getEffectiveSettings(effectivePluginId, deviceId);
    if (s && Object.keys(s).length > 0) settings = s;
  } catch {
    // Unknown plugin/assignment — the plugin falls back to its own defaults.
  }

  return {
    pluginId: effectivePluginId,
    endpoint: plugin.endpoint,
    managementAddress: device.managementAddress,
    ipAddresses,
    credentials,
    ...(settings ? { settings } : {}),
  };
}
