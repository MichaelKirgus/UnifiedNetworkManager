/**
 * Shelly action catalog — plan-executable operations against one device.
 *
 * Two actions ship in v1:
 *   shelly.firmware.update  (dangerous) — triggers the vendor update flow:
 *       Gen1  : GET /ota?update=true            (stable track only)
 *       Gen2+ : Shelly.Update {stage, url?}     (classic fw 1.x)
 *               Firmware.Update {stage, url?}   (modern fw 2.x+)
 *     The device reboots mid-flight and is unreachable for ~1–2 min, so the
 *     action reports "update started" immediately rather than blocking; the
 *     plan appends a settle wait + inventory refresh (see src/plan.ts).
 *   shelly.reboot           (write) — Gen1 POST /reboot; Gen2+ Shelly.Reboot
 *     (classic) / Sys.Reboot (modern).
 *   shelly.setRelay         (write) — sets a relay's state (the wall-switch
 *     use case): Gen1 POST /relay/{id}?turn=on|off; Gen2+ (both namespaces)
 *     Switch.Set {id, on} — the Switch component is stable across firmware.
 */

import { ActionResult, ActionDescriptor, createRegistry } from '@unm/plugin-sdk';
import { gen1Get, gen1Post, rpc, type ShellyAuth, type ShellyClientOptions } from './client';
import type { DeviceProfile } from './detect';

/** Executor context bound per device by the plugin's /config route. */
export interface ShellyActionContext {
  client: ShellyClientOptions;
  profile: DeviceProfile;
  auth?: ShellyAuth;
}

const str = (input: Record<string, unknown>, key: string): string | undefined => {
  const v = input[key];
  return typeof v === 'string' && v.trim() !== '' ? v.trim() : undefined;
};

/** The firmware update action — the headline feature. */
const firmwareUpdateAction: ActionDescriptor<ShellyActionContext> = {
  id: 'shelly.firmware.update',
  label: 'Update firmware',
  description:
    "DANGEROUS — starts the vendor firmware update on the device (Gen1: GET /ota?update=true; Gen2+: Shelly.Update/Firmware.Update with `stage`). The device reboots mid-flight and is UNREACHABLE for ~1–2 minutes; this action returns as soon as the device accepts the update. Plans append a settle wait + inventory refresh automatically.",
  module: 'Firmware',
  riskLevel: 'dangerous' as const,
  deviceCount: 1 as const,
  timeoutMs: 60_000, // trigger only — the reboot happens asynchronously
  retryOnDispatchFailure: false, // never blindly re-trigger a flash
  inputSchema: {
    stage: { type: 'string', required: false, enum: ['stable', 'beta'], description: "Firmware track (default \"stable\"). Gen1 devices are stable-only." },
    url: { type: 'string', required: false, minLength: 8, description: "Optional custom firmware URL — Gen2+ only (Gen1 has no custom-URL update path)." },
  },
  async execute(ctx: ShellyActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const stage = str(input, 'stage') ?? 'stable';
    const url = str(input, 'url');

    if (ctx.profile.gen === 1) {
      if (stage !== 'stable') {
        return { success: false, details: { error: `Gen1 devices only support the stable firmware track — got stage "${stage}"` } };
      }
      if (url) {
        return { success: false, details: { error: 'Custom firmware URLs are not supported on Gen1 devices' } };
      }
      const r = await gen1Get(ctx.client, '/ota?update=true', ctx.auth);
      if (!r.ok) {
        return { success: false, details: { error: `Device rejected the update trigger (${r.error ?? `HTTP ${r.status}`})` } };
      }
      return {
        success: true,
        applied: true,
        details: { note: 'Firmware update started — the device will reboot and be unreachable for ~1–2 minutes.' },
      };
    }

    // Gen2+ — method depends on the namespace family detection resolved.
    const method = ctx.profile.ns === 'modern' ? 'Firmware.Update' : 'Shelly.Update';
    const params: Record<string, unknown> = { stage };
    if (url) params.url = url;

    const r = await rpc(ctx.client, [{ method, params }], ctx.auth);
    if (!r.ok) {
      return { success: false, details: { error: `Device rejected the update trigger (${r.error ?? `HTTP ${r.status}`})` } };
    }
    const res = r.results[0];
    if (!res?.ok) {
      return { success: false, details: { error: `${method} failed: ${res?.error?.message ?? 'unknown error'}` } };
    }
    return {
      success: true,
      applied: true,
      details: { note: `Firmware update started (stage: ${stage}) — the device will reboot and be unreachable for ~1–2 minutes.` },
    };
  },
};

/** Reboots the device (needed to verify update recovery; trivial otherwise). */
const rebootAction: ActionDescriptor<ShellyActionContext> = {
  id: 'shelly.reboot',
  label: 'Reboot device',
  description: "Reboots the Shelly (Gen1: POST /reboot; Gen2+: Shelly.Reboot / Sys.Reboot). The device is unreachable for ~30–60 s afterwards.",
  module: 'System',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 30_000,
  retryOnDispatchFailure: false,
  inputSchema: {},
  async execute(ctx: ShellyActionContext): Promise<ActionResult> {
    if (ctx.profile.gen === 1) {
      const r = await gen1Post(ctx.client, '/reboot', ctx.auth);
      if (!r.ok) return { success: false, details: { error: `Device rejected the reboot (${r.error ?? `HTTP ${r.status}`})` } };
    } else {
      const method = ctx.profile.ns === 'modern' ? 'Sys.Reboot' : 'Shelly.Reboot';
      const r = await rpc(ctx.client, [{ method }], ctx.auth);
      if (!r.ok) return { success: false, details: { error: `Device rejected the reboot (${r.error ?? `HTTP ${r.status}`})` } };
      const res = r.results[0];
      if (!res?.ok) return { success: false, details: { error: `${method} failed: ${res?.error?.message ?? 'unknown error'}` } };
    }
    return { success: true, applied: true, details: { note: 'Reboot started — the device will be back within a minute.' } };
  },
};

/** Sets a relay's state — the wall-switch / inline-relay use case. */
const setRelayAction: ActionDescriptor<ShellyActionContext> = {
  id: 'shelly.setRelay',
  label: 'Set relay state',
  description:
    "Sets a relay's target state (Gen1: POST /relay/{id}?turn=on|off; Gen2+ both namespaces: Switch.Set {id, on}). Idempotent — safe to re-dispatch. Relay 0 by default; multi-relay models (Shelly 2, Plus 2PM, Pro 4) expose relays 0–3.",
  module: 'Relays',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 15_000,
  retryOnDispatchFailure: true, // idempotent set — re-dispatching is harmless
  inputSchema: {
    on: { type: 'boolean', required: true, description: 'Target state of the relay.' },
    relayId: { type: 'number', required: false, min: 0, max: 8, description: 'Relay index (default 0).' },
  },
  async execute(ctx: ShellyActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const on = input.on as boolean; // validated: required boolean
    const relayId = input.relayId === undefined || input.relayId === null ? 0 : (input.relayId as number);

    if (ctx.profile.gen === 1) {
      const r = await gen1Post(ctx.client, `/relay/${relayId}?turn=${on ? 'on' : 'off'}`, ctx.auth);
      if (!r.ok) {
        return { success: false, details: { error: `Device rejected the relay set (${r.error ?? `HTTP ${r.status}`})` } };
      }
    } else {
      // Gen2+ (classic AND modern namespaces): the Switch component is stable
      // across firmware versions — Switch.Set {id, on} works on fw 1.x and 2.x+.
      const r = await rpc(ctx.client, [{ method: 'Switch.Set', params: { id: relayId, on } }], ctx.auth);
      if (!r.ok) {
        return { success: false, details: { error: `Device rejected the relay set (${r.error ?? `HTTP ${r.status}`})` } };
      }
      const res = r.results[0];
      if (!res?.ok) {
        return { success: false, details: { error: `Switch.Set failed: ${res?.error?.message ?? 'unknown error'}` } };
      }
    }
    return { success: true, applied: true, details: { note: `Relay ${relayId} set to ${on ? 'ON' : 'OFF'}.` } };
  },
};

/** The full Shelly action registry. */
export const shellyActions = createRegistry<ShellyActionContext>([firmwareUpdateAction, rebootAction, setRelayAction]);
