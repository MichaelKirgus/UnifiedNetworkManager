import { pluginAxios } from './pluginHttp';
import { db } from '../db';
import * as schema from '../db/schema';
import { getSecretFresh } from '../secretsProvider';
import { settingsHeaders } from '../pluginSettings';
import { parseExtraCredentials } from '../types/credentialSlots';
import { decryptCredentialSlots, withSlots } from './slotCredentials';
import { getEffectiveSettingValue } from '../systemSettings';

/**
 * Dispatch a single-device action to one of the device's plugin assignments —
 * the same credential resolution + POST /config contract the plan executor and
 * config-job worker use, factored out so ad-hoc callers (e.g. notification
 * close → appliance alert dismiss) can reuse it without creating a job row.
 *
 * Returns `{ ok: true, result }` on success or `{ ok: false, error }` when the
 * device/assignment/plugin is missing, credentials fail to resolve, or the
 * plugin reports `success: false`. NEVER throws — callers treat this as
 * best-effort side work.
 */
export interface PluginDispatchResult {
  ok: boolean;
  /** The plugin's ActionResult (`result` field of its /config response). */
  result?: Record<string, unknown>;
  error?: string;
}

export async function dispatchPluginAction(
  deviceId: string,
  pluginId: string,
  actionId: string,
  input: Record<string, unknown>,
  timeoutMs?: number
): Promise<PluginDispatchResult> {
  // Default dispatch timeout is a system setting; callers may override explicitly.
  const effectiveTimeout = timeoutMs ?? (Number(await getEffectiveSettingValue('pluginDispatchTimeoutMs')) || 30_000);
  try {
    const device = await db.query.devices.findFirst({ where: (d, { eq }) => eq(d.id, deviceId) });
    if (!device) return { ok: false, error: 'Device not found' };

    const assignment = await db.query.devicePlugins.findFirst({
      where: (a, { and, eq }) => and(eq(a.deviceId, deviceId), eq(a.pluginId, pluginId)),
    });
    if (!assignment) return { ok: false, error: `Plugin ${pluginId} is not assigned to this device` };

    const plugin = await db.query.plugins.findFirst({ where: (p, { eq }) => eq(p.id, pluginId) });
    if (!plugin || !plugin.endpoint) return { ok: false, error: 'Plugin not found or has no endpoint' };

    // FRESH credentials — the action applies to live appliance state.
    let credentials: Record<string, unknown> = {};
    try {
      const decrypted = assignment.secretId ? await getSecretFresh(assignment.secretId) : null;
      if (decrypted?.fields) credentials = { ...decrypted.fields };
      // Bound credential slots (e.g. an API key or SSH slot distinct from the primary secret).
      credentials = withSlots(credentials, await decryptCredentialSlots(parseExtraCredentials(assignment.extraCredentials), { fresh: true }));
    } catch (err) {
      return { ok: false, error: `Credential resolution failed: ${(err as Error).message}` };
    }

    const headers = await settingsHeaders(plugin.id, device.id).catch(() => ({}));

    const response = await pluginAxios(plugin.endpoint).post(
      '/config',
      { deviceId: device.id, managementAddress: device.managementAddress, credentials, actionId, input },
      { timeout: effectiveTimeout, headers }
    );
    const body = (response.data ?? {}) as { success?: boolean; result?: Record<string, unknown> };
    if (body.success === false) return { ok: false, error: String(body.result?.error ?? 'Plugin reported failure'), result: body.result };
    return { ok: true, result: body.result ?? {} };
  } catch (err) {
    const e = err as { response?: { status?: number; data?: { error?: string } }; message?: string };
    if (e.response?.status === 400 && e.response.data?.error) return { ok: false, error: e.response.data.error };
    return { ok: false, error: `Dispatch failed: ${e.message ?? 'unreachable'}` };
  }
}
