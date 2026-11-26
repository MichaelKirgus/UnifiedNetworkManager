/**
 * Firmware update rows — the Updates page integration.
 *
 * Both generations expose the same three facts (current version, available
 * version, has-update flag) — via different transports:
 *   Gen1  : GET /ota                      → { ota, has_update, new_version, old_version }
 *   Gen2+ : POST /rpc [Firmware.GetStatus] → { has_update, new_version, old_version }
 *
 * Emission contract (canonical): an empty array is AUTHORITATIVE ("checked,
 * nothing available") and wipes the stored row; a transport failure THROWS so
 * the caller OMITS the `updates` key entirely — previously stored rows survive
 * outages instead of being wiped by a transient network error.
 */

import { firmwareRow } from '@unm/plugin-sdk';
import type { UpdateRow } from '@unm/plugin-sdk';
import { gen1Get, rpc, type ShellyAuth, type ShellyClientOptions } from './client';
import type { DeviceProfile } from './detect';

/** Action id the Updates page row points at (see src/actions.ts). */
export const FIRMWARE_UPDATE_ACTION_ID = 'shelly.firmware.update';

/** Gen1 GET /ota payload (firmware status; model-independent core fields). */
export interface Gen1Ota {
  ota?: 'idle' | 'pending' | 'updating';
  has_update?: boolean;
  new_version?: string;
  old_version?: string;
}

/** Gen2+ Firmware.GetStatus payload. */
export interface FwStatus {
  has_update?: boolean;
  new_version?: string;
  old_version?: string;
}

function toRow(fw: { has_update?: boolean; new_version?: string; old_version?: string }, note?: string): UpdateRow[] {
  const current = typeof fw.old_version === 'string' && fw.old_version ? fw.old_version : null;
  const latest = typeof fw.new_version === 'string' && fw.new_version ? fw.new_version : null;

  // The device's own has_update flag is authoritative — only emit a row when
  // it says an update exists AND we know the target version.
  if (!fw.has_update || !latest) return [];

  return [
    firmwareRow(current, latest, {
      rebootRequired: true, // firmware update reboots the device mid-flight
      applyActionId: FIRMWARE_UPDATE_ACTION_ID,
      note,
    }),
  ];
}

/**
 * Fetches the Updates-page rows for one device. THROWS on transport failure
 * (unreachable / auth-rejected) — callers must omit the `updates` key in that
 * case, never emit an empty array.
 */
export async function getShellyUpdateRows(
  opts: ShellyClientOptions,
  profile: DeviceProfile,
  auth?: ShellyAuth,
): Promise<UpdateRow[]> {
  if (profile.gen === 1) {
    const r = await gen1Get<Gen1Ota>(opts, '/ota', auth);
    if (!r.ok) throw new Error(r.errorKind === 'auth-rejected' ? `authentication rejected by device (HTTP ${r.status})` : r.error ?? `device answered HTTP ${r.status}`);
    const ota = r.data ?? {};
    const note = ota.ota && ota.ota !== 'idle' ? `update in progress (${ota.ota})` : undefined;
    return toRow(ota, note);
  }

  const r = await rpc(opts, [{ method: 'Firmware.GetStatus' }], auth);
  if (!r.ok) throw new Error(r.errorKind === 'auth-rejected' ? `authentication rejected by device (HTTP ${r.status})` : r.error ?? `device answered HTTP ${r.status}`);
  const res = r.results[0];
  if (!res?.ok || !res.result) {
    // Per-method RPC error — treat as "no data this cycle" (omit), not a wipe.
    throw new Error(`Firmware.GetStatus failed: ${res?.error ?? 'unknown error'}`);
  }
  return toRow(res.result as FwStatus);
}
