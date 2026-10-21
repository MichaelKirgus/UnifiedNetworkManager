/**
 * The generic IPMI action registry — plan-gated writes served to UNM's plans system.
 *
 * Modules:
 *   - Power    : on / soft-off (ACPI) / hard-off / reset  (dangerous, verified by re-read)
 *   - Boot     : set boot options (service partition selector + flags)
 *   - SEL      : clear the System Event Log (dangerous — destroys history)
 *   - LED      : pulse the diagnostic interrupt (NMI) — write, for debugging hangs
 *   - LAN      : set IP address / subnet mask / default gateway on the BMC's LAN channel
 *
 * Conventions (mirrors netcup-scp):
 *   - An IpmiError with kind 'comcode' means the BMC ANSWERED and rejected — hard/final
 *     failure. Transport/protocol errors are marked retryable so the plan executor
 *     re-dispatches per policy.
 *   - Power actions set retryOnDispatchFailure:false (flapping guard) and verify by
 *     RE-READING chassis status afterwards (pollUntil).
 */

import { ActionDescriptor, ActionResult, createRegistry, isTransientTransportError, pollUntil } from '@unm/plugin-sdk';
import type { IpmiClient } from './client/ipmiClient';
import { IpmiError } from './client/ipmiClient';
import { getChassisStatus, setSystemPower, setBootOptions, clearSel, setLanParam } from './client/ipmiCommands';

/** Executor context for one /config step — the client is already connected + authenticated. */
export interface IpmiActionContext {
  client: IpmiClient;
  /** Effective plugin settings (defaults ⊕ per-device overrides). */
  settings: Record<string, unknown>;
}

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/** Classifies a failure into an ActionResult — BMC comcode errors are final, transport errors retryable. */
function failureResult(err: unknown): ActionResult {
  const isComCode = err instanceof IpmiError && (err.kind === 'comcode' || err.kind === 'auth');
  const retryable = !isComCode && isTransientTransportError(err);
  return { success: false, error: errMsg(err), ...(retryable ? { retryable: true } : {}) };
}

/** Parses an IPv4 dotted quad into a 4-byte Buffer (null when invalid). */
function ipv4ToBytes(ip: string): Buffer | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  const bytes = parts.map((p) => {
    if (!/^\d{1,3}$/.test(p)) return -1;
    const n = parseInt(p, 10);
    return n > 255 ? -1 : n;
  });
  if (bytes.some((b) => b < 0)) return null;
  return Buffer.from(bytes);
}

// --- Power ---------------------------------------------------------------------

const powerOnAction: ActionDescriptor<IpmiActionContext> = {
  id: 'power.on',
  label: 'Power on server',
  description: 'Sends IPMI chassis "Power Up" (code 1). Verified by polling until the chassis reports powered-on.',
  module: 'Power',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  retryOnDispatchFailure: false,
  timeoutMs: 300_000,
  inputSchema: {},
  async execute(ctx) {
    try {
      const before = await getChassisStatus(ctx.client).catch(() => null);
      if (before?.poweredOn) return { success: true, applied: false, verified: true, details: { note: 'Server already powered on' } };
      await setSystemPower(ctx.client, 'on');
      const wait = await pollUntil(
        async () => (await getChassisStatus(ctx.client)).poweredOn,
        (on) => on === true,
        { timeoutMs: 240_000, intervalMs: 5_000 },
      );
      return { success: true, applied: true, verified: wait.ok, details: { before: before?.poweredOn ?? null, after: wait.value ?? null } };
    } catch (err) {
      return failureResult(err);
    }
  },
};

const powerSoftOffAction: ActionDescriptor<IpmiActionContext> = {
  id: 'power.soft-off',
  label: 'Power off server (ACPI soft off)',
  description: 'Sends IPMI chassis "ACPI Power Down" (code 5) — a graceful shutdown request the OS must honor. Verified by polling until powered-off. DANGEROUS for workloads.',
  module: 'Power',
  riskLevel: 'dangerous' as const,
  deviceCount: 1 as const,
  retryOnDispatchFailure: false,
  timeoutMs: 300_000,
  inputSchema: {},
  async execute(ctx) {
    try {
      const before = await getChassisStatus(ctx.client).catch(() => null);
      if (!before?.poweredOn) return { success: true, applied: false, verified: true, details: { note: 'Server already powered off' } };
      await setSystemPower(ctx.client, 'soft-off');
      const wait = await pollUntil(
        async () => (await getChassisStatus(ctx.client)).poweredOn,
        (on) => on === false,
        { timeoutMs: 240_000, intervalMs: 5_000 },
      );
      return { success: true, applied: true, verified: wait.ok, details: { before: before?.poweredOn ?? null, after: wait.value ?? null } };
    } catch (err) {
      return failureResult(err);
    }
  },
};

const powerHardOffAction: ActionDescriptor<IpmiActionContext> = {
  id: 'power.hard-off',
  label: 'Power off server (hard)',
  description: 'Sends IPMI chassis "Power Down" (code 0) — an immediate, ungraceful cut of power. Verified by polling until powered-off. DANGEROUS — data loss risk.',
  module: 'Power',
  riskLevel: 'dangerous' as const,
  deviceCount: 1 as const,
  retryOnDispatchFailure: false,
  timeoutMs: 300_000,
  inputSchema: {},
  async execute(ctx) {
    try {
      const before = await getChassisStatus(ctx.client).catch(() => null);
      if (!before?.poweredOn) return { success: true, applied: false, verified: true, details: { note: 'Server already powered off' } };
      await setSystemPower(ctx.client, 'hard-off');
      const wait = await pollUntil(
        async () => (await getChassisStatus(ctx.client)).poweredOn,
        (on) => on === false,
        { timeoutMs: 240_000, intervalMs: 5_000 },
      );
      return { success: true, applied: true, verified: wait.ok, details: { before: before?.poweredOn ?? null, after: wait.value ?? null } };
    } catch (err) {
      return failureResult(err);
    }
  },
};

const powerResetAction: ActionDescriptor<IpmiActionContext> = {
  id: 'power.reset',
  label: 'Hard reset server',
  description: 'Sends IPMI chassis "Hard Reset" (code 3) — an ungraceful reboot. Verified by polling until powered-on again. DANGEROUS for workloads.',
  module: 'Power',
  riskLevel: 'dangerous' as const,
  deviceCount: 1 as const,
  retryOnDispatchFailure: false,
  timeoutMs: 300_000,
  inputSchema: {},
  async execute(ctx) {
    try {
      await setSystemPower(ctx.client, 'reset');
      // After a hard reset the BMC itself may be briefly unreachable — poll tolerates that.
      const wait = await pollUntil(
        async () => (await getChassisStatus(ctx.client)).poweredOn,
        (on) => on === true,
        { timeoutMs: 240_000, intervalMs: 5_000 },
      );
      return { success: true, applied: true, verified: wait.ok, details: { after: wait.value ?? null } };
    } catch (err) {
      return failureResult(err);
    }
  },
};

// --- Boot ---------------------------------------------------------------------

const bootSetAction: ActionDescriptor<IpmiActionContext> = {
  id: 'boot.device.set',
  label: 'Set boot options',
  description: 'Sets the chassis system boot options (service partition selector + boot flags) via Set System Boot Options. Use to force a one-time PXE/BIOS/network boot.',
  module: 'Boot',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  inputSchema: {
    servicePartitionSelector: { type: 'number', required: false, min: 0, max: 15, default: 1, description: 'Service partition selector (0=BIOS, 1=primary OS/HDD, 2=PXE/network, …)' },
    bootFlags: { type: 'number', required: false, min: 0, max: 255, default: 0, description: 'Boot flags byte (bit 4 = force BIOS setup, bit 6 = one-time boot)' },
  },
  async execute(ctx, input) {
    const selector = typeof input['servicePartitionSelector'] === 'number' ? (input['servicePartitionSelector'] as number) : 1;
    const flags = typeof input['bootFlags'] === 'number' ? (input['bootFlags'] as number) : 0;
    try {
      await setBootOptions(ctx.client, { servicePartitionSelector: selector, bootFlags: flags });
      return { success: true, applied: true, verified: false, details: { servicePartitionSelector: selector, bootFlags: flags } };
    } catch (err) {
      return failureResult(err);
    }
  },
};

// --- SEL ---------------------------------------------------------------------

const selClearAction: ActionDescriptor<IpmiActionContext> = {
  id: 'sel.clear',
  label: 'Clear System Event Log',
  description: 'Deletes ALL entries from the BMC\'s System Event Log (Get SEL Info → record count must drop to 0). DANGEROUS — destroys event history.',
  module: 'SEL',
  riskLevel: 'dangerous' as const,
  deviceCount: 1 as const,
  inputSchema: {},
  async execute(ctx) {
    try {
      await clearSel(ctx.client);
      // Verify by re-reading the SEL info — record count should be 0.
      const wait = await pollUntil(
        async () => {
          const info = await ctx.client.sendCommand(0x0a, 0x40); // Get SEL Info (netfn STORAGE)
          return info.length >= 3 ? info[1] | (info[2] << 8) : -1; // count is u16 LE at [1..2]
        },
        (count) => count === 0,
        { timeoutMs: 30_000, intervalMs: 2_000 },
      );
      return { success: true, applied: true, verified: wait.ok, details: { remainingRecords: wait.value ?? null } };
    } catch (err) {
      return failureResult(err);
    }
  },
};

// --- LED / diagnostics ---------------------------------------------------------------------

const ledPulseDiagAction: ActionDescriptor<IpmiActionContext> = {
  id: 'led.pulse-diag',
  label: 'Pulse diagnostic interrupt (NMI)',
  description: 'Sends IPMI chassis "Pulse Diagnostic Interrupt" (code 4) — an NMI to the host CPU. Use only for kernel debugging on a hung system.',
  module: 'Diagnostics',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  inputSchema: {},
  async execute(ctx) {
    try {
      await ctx.client.sendCommand(0x00, 0x06, Buffer.from([0x04])); // System Power Control code 4
      return { success: true, applied: true, verified: false, details: { note: 'NMI pulse sent — check the host kernel log for the diagnostic interrupt' } };
    } catch (err) {
      return failureResult(err);
    }
  },
};

// --- LAN config ---------------------------------------------------------------------

const lanIpSetAction: ActionDescriptor<IpmiActionContext> = {
  id: 'lan.ip.set',
  label: 'Set BMC IP address',
  description: 'Writes the static IPv4 address of the BMC\'s LAN channel (param 1). Verified by re-reading the parameter. WARNING: a wrong value can make the BMC unreachable.',
  module: 'LAN',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  inputSchema: {
    ipAddress: { type: 'string', required: true, pattern: '^\\d{1,3}(\\.\\d{1,3}){3}$', description: 'New static IPv4 address (dotted quad)' },
  },
  async execute(ctx, input) {
    const ip = String(input['ipAddress']);
    const bytes = ipv4ToBytes(ip);
    if (!bytes) return { success: false, error: `Invalid IPv4 address "${ip}"` };
    try {
      await setLanParam(ctx.client, 1, 0x0001, bytes);
      const wait = await pollUntil(
        async () => {
          const rsp = await ctx.client.sendCommand(0x0c, 0x52, Buffer.from([1, 0x01, 0x00])); // Get LAN Config param 1
          return rsp.length >= 4 ? [...rsp.subarray(0, 4)].map((b) => b.toString()).join('.') : '';
        },
        (v) => v === ip,
        { timeoutMs: 30_000, intervalMs: 2_000 },
      );
      return { success: true, applied: true, verified: wait.ok, details: { ipAddress: ip } };
    } catch (err) {
      return failureResult(err);
    }
  },
};

const lanMaskSetAction: ActionDescriptor<IpmiActionContext> = {
  id: 'lan.mask.set',
  label: 'Set BMC subnet mask',
  description: 'Writes the IPv4 subnet mask of the BMC\'s LAN channel (param 2). Verified by re-reading the parameter.',
  module: 'LAN',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  inputSchema: {
    subnetMask: { type: 'string', required: true, pattern: '^\\d{1,3}(\\.\\d{1,3}){3}$', description: 'New subnet mask (dotted quad)' },
  },
  async execute(ctx, input) {
    const mask = String(input['subnetMask']);
    const bytes = ipv4ToBytes(mask);
    if (!bytes) return { success: false, error: `Invalid subnet mask "${mask}"` };
    try {
      await setLanParam(ctx.client, 1, 0x0002, bytes);
      const wait = await pollUntil(
        async () => {
          const rsp = await ctx.client.sendCommand(0x0c, 0x52, Buffer.from([1, 0x02, 0x00])); // Get LAN Config param 2
          return rsp.length >= 4 ? [...rsp.subarray(0, 4)].map((b) => b.toString()).join('.') : '';
        },
        (v) => v === mask,
        { timeoutMs: 30_000, intervalMs: 2_000 },
      );
      return { success: true, applied: true, verified: wait.ok, details: { subnetMask: mask } };
    } catch (err) {
      return failureResult(err);
    }
  },
};

const lanGatewaySetAction: ActionDescriptor<IpmiActionContext> = {
  id: 'lan.gateway.set',
  label: 'Set BMC default gateway',
  description: 'Writes the IPv4 default gateway of the BMC\'s LAN channel (param 3). Verified by re-reading the parameter.',
  module: 'LAN',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  inputSchema: {
    gateway: { type: 'string', required: true, pattern: '^\\d{1,3}(\\.\\d{1,3}){3}$', description: 'New default gateway (dotted quad)' },
  },
  async execute(ctx, input) {
    const gw = String(input['gateway']);
    const bytes = ipv4ToBytes(gw);
    if (!bytes) return { success: false, error: `Invalid gateway "${gw}"` };
    try {
      await setLanParam(ctx.client, 1, 0x0003, bytes);
      const wait = await pollUntil(
        async () => {
          const rsp = await ctx.client.sendCommand(0x0c, 0x52, Buffer.from([1, 0x03, 0x00])); // Get LAN Config param 3
          return rsp.length >= 4 ? [...rsp.subarray(0, 4)].map((b) => b.toString()).join('.') : '';
        },
        (v) => v === gw,
        { timeoutMs: 30_000, intervalMs: 2_000 },
      );
      return { success: true, applied: true, verified: wait.ok, details: { gateway: gw } };
    } catch (err) {
      return failureResult(err);
    }
  },
};

// --- Registry ---------------------------------------------------------------------

export const registry = createRegistry<IpmiActionContext>([
  powerOnAction,
  powerSoftOffAction,
  powerHardOffAction,
  powerResetAction,
  bootSetAction,
  selClearAction,
  ledPulseDiagAction,
  lanIpSetAction,
  lanMaskSetAction,
  lanGatewaySetAction,
]);
