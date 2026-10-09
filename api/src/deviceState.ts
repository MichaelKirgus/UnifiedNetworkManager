import { pluginAxios } from './utils/pluginHttp';
import { and, eq } from 'drizzle-orm';
import { db } from './db';
import * as schema from './db/schema';
import { getSecretFresh } from './secretsProvider';
import { settingsHeaders } from './pluginSettings';
import { parseExtraCredentials } from './types/credentialSlots';
import type { DeviceAddressView } from './types/deviceAddressView';
import { decryptCredentialSlots, withSlots } from './utils/slotCredentials';

/**
 * Device-state broker.
 *
 * The webapp's per-device Config page renders a DYNAMIC device state document
 * (ports with live states + per-port MACs, interfaces, ZFS pools, system info)
 * plus context-aware action references. Plugins own the shape — they serve it
 * from their `GET /state` endpoint (capability 'deviceState'). This broker is
 * deliberately GENERIC: it resolves the assignment + credentials, forwards them
 * to the plugin, and validates that every advertised action id exists in the
 * plugin's persisted action catalog. It never interprets section/item content —
 * new device kinds (file systems, ZFS pools, …) cost zero API changes.
 */

// DeviceAddressView comes from types/deviceAddressView (shared).

/** The state document a plugin returns — mirrored from @unm/plugin-sdk types. */
export interface StateActionRef {
  actionId: string;
  prefill?: Record<string, unknown>;
}
export interface StateItem {
  key: string;
  title: string;
  subtitle?: string | null;
  status?: string | null;
  /** Display values — arrays render as chip lists (e.g. per-port MACs). */
  fields: Record<string, string | number | null | unknown[]>;
  actions?: StateActionRef[];
}
export interface StateSection {
  id: string;
  label: string;
  description?: string | null;
  items?: StateItem[];
  actions?: StateActionRef[];
}
export interface DeviceStateResponse {
  collectedAt: string;
  sections: StateSection[];
}

/** Error carrying an HTTP status so routes can map it directly. */
export class DeviceStateError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

/**
 * Fetches the live device state for one (device, plugin) assignment from the
 * plugin's `GET /state` endpoint. Credentials are fetched FRESH (uncached) —
 * the same rule as plan steps: a config-capable call must use current secrets.
 * Advertised action refs whose id is not in the plugin's persisted catalog are
 * stripped (a stale state document must never surface an unexecutable button).
 */
export async function fetchDeviceState(
  deviceId: string,
  pluginId: string
): Promise<{ pluginId: string; state: DeviceStateResponse }> {
  const device = await db.query.devices.findFirst({ where: eq(schema.devices.id, deviceId) });
  if (!device) throw new DeviceStateError(404, 'Device not found');

  const assignment = await db.query.devicePlugins.findFirst({
    where: and(eq(schema.devicePlugins.deviceId, deviceId), eq(schema.devicePlugins.pluginId, pluginId)),
  });
  if (!assignment) {
    throw new DeviceStateError(400, `Plugin ${pluginId} is not assigned to this device`);
  }

  const plugin = await db.query.plugins.findFirst({ where: eq(schema.plugins.id, pluginId) });
  if (!plugin || !plugin.endpoint) {
    throw new DeviceStateError(404, 'Assigned plugin has no reachable endpoint');
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
    response = await pluginAxios(plugin.endpoint).post<DeviceStateResponse>(
      '/state',
      {
        deviceId,
        managementAddress: device.managementAddress,
        ipAddresses,
        model: device.model ?? null,
        firmwareVersion: device.firmwareVersion ?? null,
        credentials,
        ...(decrypted?.type === 'apiKey' ? { apiKey: credentials.apiKey, apiSecret: credentials.apiSecret } : {})
      },
      { timeout: 10_000, headers }
    );
  } catch (err) {
    const e = err as { response?: { status?: number; data?: { error?: string } }; message?: string };
    if (e.response?.status === 404) {
      throw new DeviceStateError(501, 'This plugin does not support device state');
    }
    const upstream = e.response?.data?.error ?? e.message ?? 'Failed to fetch device state';
    throw new DeviceStateError(502, `Plugin failed to report device state: ${upstream}`);
  }

  const state = response.data;
  if (!state || !Array.isArray(state.sections)) {
    throw new DeviceStateError(502, 'Malformed device-state response from plugin');
  }

  // Validate advertised action ids against the persisted catalog — strip any
  // that are not single-device actions of this plugin.
  const validActionIds = await loadSingleDeviceActionIds(pluginId);
  if (validActionIds !== null) {
    state.sections = state.sections.map((section) => ({
      ...section,
      ...(section.actions ? { actions: section.actions.filter((a) => a && validActionIds.has(a.actionId)) } : {}),
      items: section.items?.map((item) =>
        item.actions ? { ...item, actions: item.actions.filter((a) => a && validActionIds.has(a.actionId)) } : item
      ),
    }));
  }

  return { pluginId, state };
}

/**
 * Loads the set of single-device action ids persisted for a plugin from its
 * /discover catalog. Returns null when the plugin has NO catalog at all (in
 * which case nothing is validated — a brand-new plugin may advertise state
 * before its first discovery poll).
 */
async function loadSingleDeviceActionIds(pluginId: string): Promise<Set<string> | null> {
  const plugin = await db.query.plugins.findFirst({ where: eq(schema.plugins.id, pluginId) });
  if (!plugin?.actionDescriptors) return null;
  let actions: unknown[] = [];
  try {
    const parsed = JSON.parse(plugin.actionDescriptors);
    actions = Array.isArray(parsed) ? parsed : [];
  } catch {
    return null;
  }
  const ids = new Set<string>();
  for (const a of actions) {
    if (!a || typeof a !== 'object') continue;
    const entry = a as Record<string, unknown>;
    if (typeof entry.id === 'string' && entry.deviceCount === 1) ids.add(entry.id);
  }
  return ids;
}
