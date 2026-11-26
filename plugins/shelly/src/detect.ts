/**
 * Runtime device detection — figure out which Shelly generation (and, for
 * Gen2+, which JSON-RPC namespace family) a device is, with NO per-device
 * configuration.
 *
 * Probe chain (cheapest/most specific first):
 *   1. GET /shelly            → 200 with `type` ⇒ Gen1 (legacy REST).
 *                               Auth-free on real devices even when local login
 *                               is enabled (it exposes no secrets).
 *   2. POST /rpc Shelly.GetDeviceInfo  ⇒ success ⇒ Gen2+, CLASSIC namespaces
 *                               (fw 1.x: Plus/Pro/Wave — Shelly.*, WiFi.*, Firmware.*).
 *   3. POST /rpc Sys.GetDeviceInfo     ⇒ success ⇒ Gen2+, MODERN namespaces
 *                               (fw 2.x+: Gen3/Gen4 — Sys.*, Wifi.*).
 *   4. nothing answered        → DetectionError with the last failure reason.
 *
 * What answered is remembered per device+address in a TtlCache for 15 minutes,
 * so the probe chain runs at most once per inventory window — steady-state
 * polling never re-probes.
 */

import { TtlCache } from '@unm/plugin-sdk';
import { gen1Get, rpc, type ShellyAuth, type ShellyClientOptions } from './client';

/** One detected device profile. */
export interface DeviceProfile {
  /** 1 = legacy REST (ESP8266); 2 = JSON-RPC (Plus/Pro/Wave/Gen3/Gen4). */
  gen: 1 | 2;
  /** Gen2+ namespace family — undefined for Gen1. */
  ns?: 'classic' | 'modern';
  /** Model code, e.g. `SHPLG-1` (Gen1 `type`) or `SWN-1PM` (Gen2 `id`). */
  model?: string;
  /** Human name as configured on the device. */
  name?: string;
  /** MAC address (hex, no separators). */
  mac?: string;
  /** Firmware version reported at detection time. */
  fw?: string;
}

/** Thrown when no probe answered — message carries the last failure reason. */
export class DetectionError extends Error {}

/** Profiles are good for one inventory window (device generation never changes). */
export const DETECT_TTL_MS = 15 * 60_000;

const profiles = new TtlCache<DeviceProfile>({ isFresh: (v) => Boolean(v) });

/** Cache key — stable per assignment address + bound user. */
export function detectKey(address: string, username?: string): string {
  return `${address}|${username ?? ''}`;
}

function asRecord(v: unknown): Record<string, unknown> | null {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

/**
 * Detects the device profile. Cached per address+user for DETECT_TTL_MS.
 * Throws DetectionError when the device answers none of the probes.
 */
export async function detectDevice(
  opts: ShellyClientOptions,
  auth?: ShellyAuth,
  keyOverride?: string,
): Promise<DeviceProfile> {
  const key = keyOverride ?? opts.address;

  const cached = profiles.get(key, DETECT_TTL_MS);
  if (cached) return cached;

  // 1. Gen1 probe — GET /shelly is the auth-free fingerprint of an ESP8266 device.
  const shelly = await gen1Get<Record<string, unknown>>(opts, '/shelly', auth);
  const shellyData = asRecord(shelly.data);
  if (shelly.ok && typeof shellyData?.type === 'string') {
    const profile: DeviceProfile = {
      gen: 1,
      model: shellyData.type as string,
      name: typeof shellyData.name === 'string' ? shellyData.name : undefined,
      mac: typeof shellyData.mac === 'string' ? shellyData.mac : undefined,
      fw: typeof shellyData.fw === 'string' ? shellyData.fw : undefined,
    };
    profiles.set(key, profile);
    return profile;
  }

  // 2. Gen2+ classic namespace (fw 1.x).
  const classic = await rpc(opts, [{ method: 'Shelly.GetDeviceInfo' }], auth);
  const classicData = asRecord(classic.results[0]?.result);
  if (classic.ok && classic.results[0]?.ok && classicData) {
    const profile: DeviceProfile = {
      gen: 2,
      ns: 'classic',
      model: typeof classicData.id === 'string' ? classicData.id : undefined,
      name: typeof classicData.name === 'string' ? classicData.name : undefined,
      mac: typeof classicData.mac === 'string' ? classicData.mac : undefined,
      fw: typeof classicData.fw_version === 'string' ? classicData.fw_version : undefined,
    };
    profiles.set(key, profile);
    return profile;
  }

  // 3. Gen2+ modern namespace (fw 2.x+).
  const modern = await rpc(opts, [{ method: 'Sys.GetDeviceInfo' }], auth);
  const modernData = asRecord(modern.results[0]?.result);
  if (modern.ok && modern.results[0]?.ok && modernData) {
    const profile: DeviceProfile = {
      gen: 2,
      ns: 'modern',
      model: typeof modernData.id === 'string' ? modernData.id : undefined,
      name: typeof modernData.name === 'string' ? modernData.name : undefined,
      mac: typeof modernData.mac === 'string' ? modernData.mac : undefined,
      fw: typeof modernData.fw_version === 'string' ? modernData.fw_version : undefined,
    };
    profiles.set(key, profile);
    return profile;
  }

  // 4. Nothing answered — surface the most informative failure we saw.
  const reason =
    shelly.errorKind === 'auth-rejected'
      ? `GET /shelly rejected authentication (${shelly.status})`
      : classic.results[0]?.error?.message ?? modern.results[0]?.error?.message ?? shelly.error ?? 'no probe answered';
  throw new DetectionError(`could not detect Shelly generation (last failure: ${reason})`);
}

/** Test hook — drop the detection cache. */
export function clearDetectCache(): void {
  profiles.clear();
}
