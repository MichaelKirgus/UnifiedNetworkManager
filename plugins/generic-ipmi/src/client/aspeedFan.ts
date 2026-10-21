/**
 * Aspeed BMC (AST2600 / AST2500) OEM fan control — the interface used by most
 * ASRock Rack server mainboards. There is no standard IPMI "set fan speed"
 * command; these boards expose an OEM netfn 0x3a with per-channel mode + duty
 * commands (community-documented, verified against working daemons for
 * B650D4U-2L2T/BCM fw 5.02 and ROMED8-2T variants).
 *
 * AST2600 (current boards) — subcommands under the 0xd0 prefix:
 *   read mode : raw 0x3a 0xd0 0x12            → 16 bytes, one per channel
 *   set mode  : raw 0x3a 0xd0 0x11 <16 ch>    (0=disabled, 1=auto, 2=manual)
 *   read duty : raw 0x3a 0xd0 0x0f            → 16 bytes, percent 0..100
 *   set duty  : raw 0x3a 0xd0 0x0e <16 ch>    (percent; ONLY effective in manual mode)
 *
 * AST2500 (older boards) — legacy layout:
 *   read mode : raw 0x3a 0xd7                 → per-channel mode bytes
 *   set mode  : raw 0x3a 0xd8 <16 ch>         (0=auto, 1=manual)
 *   read duty : raw 0x3a 0xda                 → per-channel percent bytes
 *   set duty  : raw 0x3a 0x01 <8 ch>          (percent; applies directly)
 *
 * Gotchas (documented by the community daemons):
 *   - AST2600: duty writes are IGNORED while a channel is in auto mode — switch
 *     to manual first. The BMC rejects duty below ~20% ("Invalid data field").
 *   - All commands require 16 channel values even though boards usually have
 *     only 7 physical headers (FAN1..FAN7); unused channels are padded.
 *   - Manual mode + duty do NOT persist across a BMC reboot / AC power cycle —
 *     the BMC returns to auto fan control on its own.
 *   - The BMC may override manual settings when critical temperatures are hit.
 */

import { IpmiClient, IpmiError } from './ipmiClient';

/** OEM netfn used by Aspeed BMCs for fan control (ASRock Rack boards). */
const NETFN_OEM_FAN = 0x3a;

export type AspeedVariant = 'ast2600' | 'ast2500';

/** One fan channel's state. */
export interface AspeedFanChannel {
  /** 0-based channel index (FAN1 = 0). */
  index: number;
  /** Mode as reported by the BMC: auto / manual / disabled (AST2600) or auto/manual (AST2500). */
  mode: 'auto' | 'manual' | 'disabled';
  /** Current duty percent 0..100 (null when the BMC does not report it). */
  dutyPercent: number | null;
}

export interface AspeedFanState {
  variant: AspeedVariant;
  channels: AspeedFanChannel[];
}

// --- AST2600 command ids -----------------------------------------------------------
// All AST2600 fan commands use cmd byte 0xd0; the subcommand is data[0].

const A26_CMD = 0xd0;
const A26_SUB_READ_MODE = 0x12;
const A26_SUB_SET_MODE = 0x11;
const A26_SUB_READ_DUTY = 0x0f;
const A26_SUB_SET_DUTY = 0x0e;

// --- AST2500 command ids -----------------------------------------------------------
// Legacy layout: the subcommand IS the cmd byte, no prefix.

const A25_CMD_READ_MODE = 0xd7;
const A25_CMD_SET_MODE = 0xd8;
const A25_CMD_READ_DUTY = 0xda;
const A25_CMD_SET_DUTY_8CH = 0x01;

/** Number of channel values every Aspeed fan command requires. */
export const ASPEED_CHANNEL_COUNT = 16;

function modeByteToLabel(variant: AspeedVariant, b: number): 'auto' | 'manual' | 'disabled' {
  if (variant === 'ast2600') return b === 0x02 ? 'manual' : b === 0x01 ? 'auto' : 'disabled';
  // AST2500: 0=auto, 1=manual.
  return b === 0x01 ? 'manual' : 'auto';
}

function labelToModeByte(variant: AspeedVariant, mode: 'auto' | 'manual'): number {
  if (variant === 'ast2600') return mode === 'manual' ? 0x02 : 0x01;
  return mode === 'manual' ? 0x01 : 0x00;
}

/** Reads the current fan mode + duty of every channel. Throws IpmiError when the
 *  BMC does not answer with a well-formed payload (e.g. non-Aspeed board). */
export async function readAspeedFanState(client: IpmiClient, variant: AspeedVariant): Promise<AspeedFanState> {
  const modeData =
    variant === 'ast2600'
      ? await client.sendCommand(NETFN_OEM_FAN, A26_CMD, Buffer.from([A26_SUB_READ_MODE]))
      : await client.sendCommand(NETFN_OEM_FAN, A25_CMD_READ_MODE);
  const dutyData =
    variant === 'ast2600'
      ? await client.sendCommand(NETFN_OEM_FAN, A26_CMD, Buffer.from([A26_SUB_READ_DUTY]))
      : await client.sendCommand(NETFN_OEM_FAN, A25_CMD_READ_DUTY);

  const count = Math.min(ASPEED_CHANNEL_COUNT, modeData.length);
  if (count < 8) throw new IpmiError(`Aspeed fan read returned too few channels (${modeData.length})`, 'protocol');
  const channels: AspeedFanChannel[] = [];
  for (let i = 0; i < count; ++i) {
    channels.push({
      index: i,
      mode: modeByteToLabel(variant, modeData[i]),
      dutyPercent: i < dutyData.length ? dutyData[i] : null,
    });
  }
  return { variant, channels };
}

/** Sets the fan MODE of every channel (auto or manual). */
export async function setAspeedFanMode(client: IpmiClient, variant: AspeedVariant, mode: 'auto' | 'manual'): Promise<void> {
  const bytes = Buffer.alloc(ASPEED_CHANNEL_COUNT);
  for (let i = 0; i < ASPEED_CHANNEL_COUNT; ++i) bytes[i] = labelToModeByte(variant, mode);
  if (variant === 'ast2600') await client.sendCommand(NETFN_OEM_FAN, A26_CMD, Buffer.concat([Buffer.from([A26_SUB_SET_MODE]), bytes]));
  else await client.sendCommand(NETFN_OEM_FAN, A25_CMD_SET_MODE, bytes);
}

/** Sets the DUTY percent of every channel. On AST2600 this first switches all
 *  channels to manual mode (duty writes are ignored in auto mode). */
export async function setAspeedFanDuty(client: IpmiClient, variant: AspeedVariant, dutyPercent: number): Promise<void> {
  const pct = Math.max(0, Math.min(100, Math.round(dutyPercent)));
  if (variant === 'ast2600') {
    await setAspeedFanMode(client, 'ast2600', 'manual');
    const bytes = Buffer.alloc(ASPEED_CHANNEL_COUNT, pct);
    await client.sendCommand(NETFN_OEM_FAN, A26_CMD, Buffer.concat([Buffer.from([A26_SUB_SET_DUTY]), bytes]));
  } else {
    // AST2500: the legacy set-duty command takes 8 channel values and applies directly.
    const bytes = Buffer.alloc(8, pct);
    await client.sendCommand(NETFN_OEM_FAN, A25_CMD_SET_DUTY_8CH, bytes);
  }
}

/** Restores BMC auto fan control on every channel (the safe default). */
export async function restoreAspeedAutoMode(client: IpmiClient, variant: AspeedVariant): Promise<void> {
  await setAspeedFanMode(client, variant, 'auto');
}

/** Auto-detects the Aspeed variant by probing read-mode commands. Returns null when
 *  neither command is answered with a plausible payload (non-Aspeed BMC). */
export async function detectAspeedVariant(client: IpmiClient): Promise<AspeedVariant | null> {
  try {
    const state = await readAspeedFanState(client, 'ast2600');
    if (state.channels.length >= 8) return 'ast2600';
  } catch {
    /* not AST2600 — fall through */
  }
  try {
    const state = await readAspeedFanState(client, 'ast2500');
    if (state.channels.length >= 8) return 'ast2500';
  } catch {
    /* not Aspeed at all */
  }
  return null;
}
