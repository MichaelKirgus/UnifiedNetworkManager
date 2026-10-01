import { pluginAxios } from './utils/pluginHttp';
import { and, eq } from 'drizzle-orm';
import { db } from './db';
import * as schema from './db/schema';
import { settingsHeaders } from './pluginSettings';

/**
 * Device quick-action broker.
 *
 * The Devices page "Device Actions" column renders one-click shortcuts that a
 * plugin propagates via /discover `quickActions`. This broker handles the
 * kind:'url' entries: it resolves the device + assignment, forwards the click to
 * the plugin's POST /quick-action endpoint (capability 'quickActions') and hands
 * back the URL verbatim. The PLUGIN owns all web-UI knowledge — scheme, path and
 * the configured `webUiPort` option ride in via the x-unm-settings header — so
 * neither the API nor the webapp ever assembles appliance URLs themselves.
 *
 * kind:'shell'/'files'/'action' entries need NO broker: the webapp reuses the
 * existing console/filesystem dialogs and the plan workflow directly (they are
 * capability-gated on 'sshConsole'/'filesystem' and risk-gated by the catalog).
 */

/** Error carrying an HTTP status so routes can map it directly. */
export class DeviceQuickActionError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

/** The URL a plugin resolves for a kind:'url' quick action. */
export interface QuickActionResult {
  url: string;
}

/**
 * Resolves one kind:'url' quick action for a (device, plugin) assignment by
 * calling the plugin's POST /quick-action endpoint. Per-device settings
 * overrides are forwarded so the plugin resolves its `webUiPort` option in the
 * device → global → default order. Never throws — returns { ok:false, error }.
 */
export async function resolveDeviceQuickActionUrl(
  deviceId: string,
  pluginId: string,
  actionId: string
): Promise<{ ok: boolean; url?: string; error?: string }> {
  const device = await db.query.devices.findFirst({ where: eq(schema.devices.id, deviceId) });
  if (!device) return { ok: false, error: 'Device not found' };

  const assignment = await db.query.devicePlugins.findFirst({
    where: and(eq(schema.devicePlugins.deviceId, deviceId), eq(schema.devicePlugins.pluginId, pluginId)),
  });
  if (!assignment) return { ok: false, error: `Plugin ${pluginId} is not assigned to this device` };

  const plugin = await db.query.plugins.findFirst({ where: eq(schema.plugins.id, pluginId) });
  if (!plugin || !plugin.endpoint) return { ok: false, error: 'Assigned plugin has no reachable endpoint' };

  // Capability gate — a stale webapp must get a clean 501, not a transport error.
  let capabilities: string[] = [];
  try {
    const parsed = JSON.parse(plugin.capabilities ?? '[]');
    capabilities = Array.isArray(parsed) ? (parsed as unknown[]).filter((c): c is string => typeof c === 'string') : [];
  } catch {
    /* malformed cache — treat as no capability */
  }
  if (!capabilities.includes('quickActions')) {
    return { ok: false, error: 'This plugin does not support quick actions' };
  }

  // Per-device settings overrides (device → global → default) so the plugin's
  // webUiPort option resolves for THIS device. No credentials are needed — URL
  // resolution is credential-free by design.
  const headers = await settingsHeaders(pluginId, deviceId).catch(() => ({}));

  try {
    const response = await pluginAxios(plugin.endpoint).post<QuickActionResult>(
      '/quick-action',
      { deviceId: device.id, managementAddress: device.managementAddress, actionId },
      // URL resolution is a local computation inside the plugin — no appliance
      // round-trip. A short budget keeps a wedged plugin from stalling the click.
      { timeout: 5_000, headers }
    );
    const url = response.data?.url;
    if (typeof url !== 'string' || !/^https?:\/\//i.test(url)) {
      return { ok: false, error: 'Plugin returned an invalid URL for the quick action' };
    }
    return { ok: true, url };
  } catch (err) {
    const e = err as { response?: { status?: number; data?: { error?: string } }; message?: string };
    if (e.response?.data?.error) return { ok: false, error: e.response.data.error };
    return { ok: false, error: `Quick-action resolution failed: ${e.message ?? 'unreachable'}` };
  }
}
