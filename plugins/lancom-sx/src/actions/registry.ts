/**
 * The LANCOM SX-Series switch action registry — single source of truth for
 * everything this plugin can do. Serves three entry points (same contract as
 * the other plugins):
 *  - /discover → listCatalog() (the catalog the API persists + validates)
 *  - /plan     → buildPlan() fans out single-device actions per device
 *  - /config   → getAction(step.actionId).execute(ctx, input) runs one step
 *
 * Write semantics: every SNMP-SET action follows read → set → re-read-verify.
 * Actions are VARIANT-AWARE: PoE/LACP/VLAN objects only exist in the unified
 * 4.x tree — on a legacy GS-2310 (3.x) device they fail with a clear error
 * instead of touching an OID that doesn't exist there.
 */

import { createRegistry, ianaZoneToOffsetMinutes } from '@unm/plugin-sdk';
import { snmpGet, snmpSet, snmpWalk, SnmpValue } from '@unm/snmp-client';
import { SX4_PORT_CONF, SX4_POE_CONF, SX4_LACP_CONF, SX4_VLAN, SX3_PORT_CONF, SX4_TIMEZONE, SX3_TIME } from '../sxOids';
import { detectVariant, SxOptions } from '../sxClient';
import { ActionContext, ActionDescriptor } from './types';

// --- Small helpers --------------------------------------------------------------------

function str(input: Record<string, unknown>, key: string): string | undefined {
  const v = input[key];
  return typeof v === 'string' && v.length > 0 ? v : undefined;
}

/** Resolves the transport options for SNMP calls from the action context. */
function sxOpts(ctx: ActionContext): SxOptions {
  // Actions never take the slow inventory path — TTL 0 + no FDB enrichment.
  return { ...ctx.opts, inventoryTtlMs: 0, enrichHostPorts: false };
}

/** Reads one scalar OID and returns its typed value (or null when absent). */
async function readScalar(ctx: ActionContext, oid: string): Promise<SnmpValue | null> {
  try {
    const m = await snmpGet(ctx.host, ctx.credentials.snmp, [oid], ctx.opts);
    return m.get(oid) ?? null;
  } catch {
    return null;
  }
}

/** Resolves the device's firmware line, or fails with a clear error. */
async function requireVariant(ctx: ActionContext): Promise<'sx4' | 'sx3'> {
  const det = await detectVariant(ctx.host, ctx.credentials.snmp, sxOpts(ctx));
  if (!det.variant) throw new Error(det.error ?? 'Could not determine the device firmware line.');
  return det.variant;
}

/** Validates a 1-based panel port number. */
function parsePort(input: Record<string, unknown>): { port?: number; error?: string } {
  const raw = input.port;
  if (typeof raw !== 'number' || !Number.isInteger(raw) || raw < 1 || raw > 52) {
    return { error: `Invalid port ${String(input.port)} (expected an integer 1..52)` };
  }
  return { port: raw };
}

// --- Actions ----------------------------------------------------------------------------

/** Set a port's speed/duplex mode — including shutdown (mode 0). */
const portSpeedModeSet: ActionDescriptor = {
  id: 'port.speedMode.set',
  label: 'Set port speed / duplex (or shut down)',
  description:
    "Sets the configured speed/duplex mode of one switch port via SNMP SET (lcsPortConfSpeedMode on 4.x, gs2310PortConfSpeed on 3.x). Mode 0 DISABLES the port — use it to administratively shut a port down; set any other mode to bring it back. Re-reads to verify.",
  module: 'Ports',
  riskLevel: 'dangerous',
  deviceCount: 1,
  inputSchema: {
    port: { type: 'number', required: true, min: 1, max: 52, description: 'Panel port number (1-based)' },
    mode: {
      type: 'number',
      required: true,
      enum: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24],
      description: 'Speed mode: 0=disable (shutdown), 1=auto, 2..6=10M/100M/1G fixed, 7..24=SFP/2.5G/5G/10G/25G modes (see MIB)',
    },
  },
  async execute(ctx, input) {
    const { port, error } = parsePort(input);
    if (error || !port) return { success: false, error };
    const mode = typeof input.mode === 'number' ? Math.floor(input.mode) : NaN;
    if (!Number.isInteger(mode)) return { success: false, error: `Invalid mode ${String(input.mode)} (expected an integer)` };

    const variant = await requireVariant(ctx);
    const oid = variant === 'sx4'
      ? `${SX4_PORT_CONF.base}.1.${SX4_PORT_CONF.COL_SPEED_MODE}.${port}`
      : `${SX3_PORT_CONF.base}.1.${SX3_PORT_CONF.COL_SPEED}.${port}`;

    const before = await readScalar(ctx, oid);
    if (before === null) return { success: false, error: `Port ${port} does not expose a speed-mode object on this device.` };
    if (Number(before) === mode) {
      // Already in the requested state — idempotent no-op.
      return { success: true, applied: false, verified: true, details: { port, mode, alreadySet: true } };
    }

    await snmpSet(ctx.host, ctx.credentials.snmp, oid, 'i', mode, ctx.opts);
    const got = await readScalar(ctx, oid);
    const verified = got !== null && Number(got) === mode;
    return {
      success: verified,
      applied: true,
      verified,
      details: { port, mode, before: String(before), after: got ?? null },
    };
  },
};

/** Set the PoE operating mode of one port (4.x only). */
const poeModeSet: ActionDescriptor = {
  id: 'poe.mode.set',
  label: 'Set PoE mode on a port',
  description:
    "Sets the PoE operating mode of one port via lcsPoeConfigurationPortTable column .2 (SNMP SET, unified 4.x tree only). Modes: 0=disable, 1=poe (802.3af/at), 2=4-pair 60W, 3=4-pair 90W, 4=802.3bt, 10/11=802.3bt 30W/60W. Re-reads to verify.",
  module: 'PoE',
  riskLevel: 'write',
  deviceCount: 1,
  inputSchema: {
    port: { type: 'number', required: true, min: 1, max: 52, description: 'Panel port number (1-based)' },
    mode: { type: 'number', required: true, enum: [0, 1, 2, 3, 4, 10, 11], description: 'PoE mode (see action description)' },
  },
  async execute(ctx, input) {
    const variant = await requireVariant(ctx);
    if (variant !== 'sx4') return { success: false, error: 'PoE configuration is only available on the unified 4.x firmware line.' };

    const { port, error } = parsePort(input);
    if (error || !port) return { success: false, error };
    const mode = typeof input.mode === 'number' ? Math.floor(input.mode) : NaN;
    if (!Number.isInteger(mode)) return { success: false, error: `Invalid PoE mode ${String(input.mode)} (expected an integer)` };

    const oid = `${SX4_POE_CONF.base}.1.${SX4_POE_CONF.COL_POE_MODE}.${port}`;
    const before = await readScalar(ctx, oid);
    if (before === null) return { success: false, error: `Port ${port} does not expose a PoE mode object on this device.` };
    if (Number(before) === mode) {
      return { success: true, applied: false, verified: true, details: { port, mode, alreadySet: true } };
    }

    await snmpSet(ctx.host, ctx.credentials.snmp, oid, 'i', mode, ctx.opts);
    const got = await readScalar(ctx, oid);
    const verified = got !== null && Number(got) === mode;
    return { success: verified, applied: true, verified, details: { port, mode, before: String(before), after: got ?? null } };
  },
};

/** Set the PoE power priority of one port (4.x only). */
const poePrioritySet: ActionDescriptor = {
  id: 'poe.priority.set',
  label: 'Set PoE power priority on a port',
  description:
    "Sets the PoE power priority of one port via lcsPoeConfigurationPortTable column .3 (SNMP SET, unified 4.x tree only). Priorities decide which PDs keep power when the budget is exhausted. Re-reads to verify.",
  module: 'PoE',
  riskLevel: 'write',
  deviceCount: 1,
  inputSchema: {
    port: { type: 'number', required: true, min: 1, max: 52, description: 'Panel port number (1-based)' },
    priority: { type: 'string', required: true, enum: ['low', 'high', 'critical'], description: 'PoE power priority' },
  },
  async execute(ctx, input) {
    const variant = await requireVariant(ctx);
    if (variant !== 'sx4') return { success: false, error: 'PoE configuration is only available on the unified 4.x firmware line.' };

    const { port, error } = parsePort(input);
    if (error || !port) return { success: false, error };
    const prioLabel = str(input, 'priority');
    const prioValue: number | null = prioLabel === 'low' ? 0 : prioLabel === 'high' ? 1 : prioLabel === 'critical' ? 2 : null;
    if (prioValue === null) return { success: false, error: `Invalid priority ${String(input.priority)} (expected low|high|critical)` };

    const oid = `${SX4_POE_CONF.base}.1.${SX4_POE_CONF.COL_PRIORITY}.${port}`;
    const before = await readScalar(ctx, oid);
    if (before === null) return { success: false, error: `Port ${port} does not expose a PoE priority object on this device.` };
    if (Number(before) === prioValue) {
      return { success: true, applied: false, verified: true, details: { port, priority: prioLabel, alreadySet: true } };
    }

    await snmpSet(ctx.host, ctx.credentials.snmp, oid, 'i', prioValue, ctx.opts);
    const got = await readScalar(ctx, oid);
    const verified = got !== null && Number(got) === prioValue;
    return { success: verified, applied: true, verified, details: { port, priority: prioLabel, before: String(before), after: got ?? null } };
  },
};

/** Configure LACP on one port (4.x only). */
const lacpPortSet: ActionDescriptor = {
  id: 'lacp.port.set',
  label: 'Configure LACP on a port',
  description:
    "Enables/disables LACP on one port and sets its aggregation key, activity role and timeout via lcsLACPPortConfigTable (SNMP SET, unified 4.x tree only). Changing the key of an active member moves it between aggregation groups — verify the partner side first. Re-reads to verify.",
  module: 'LAG',
  riskLevel: 'dangerous',
  deviceCount: 1,
  inputSchema: {
    port: { type: 'number', required: true, min: 1, max: 52, description: 'Panel port number (1-based)' },
    enabled: { type: 'boolean', required: true, description: 'Enable (true) or disable (false) LACP on the port' },
    key: { type: 'number', min: 1, max: 65535, description: 'Aggregation group key (required when enabling)' },
    role: { type: 'string', enum: ['passive', 'active'], default: 'passive', description: 'LACP activity mode' },
    timeout: { type: 'string', enum: ['slow', 'fast'], default: 'slow', description: 'BPDU transmission period' },
  },
  async execute(ctx, input) {
    const variant = await requireVariant(ctx);
    if (variant !== 'sx4') return { success: false, error: 'LACP configuration is only available on the unified 4.x firmware line.' };

    const { port, error } = parsePort(input);
    if (error || !port) return { success: false, error };
    const enabled = typeof input.enabled === 'boolean' ? input.enabled : true;
    const roleValue = str(input, 'role') === 'active' ? 1 : 0;
    const timeoutValue = str(input, 'timeout') === 'fast' ? 1 : 0;

    const enabledOid = `${SX4_LACP_CONF.base}.1.${SX4_LACP_CONF.COL_ENABLED}.${port}`;
    const beforeEnabled = await readScalar(ctx, enabledOid);
    if (beforeEnabled === null) return { success: false, error: `Port ${port} does not expose a LACP config object on this device.` };

    // 1. Enable/disable flag first — the other columns only matter when enabled.
    await snmpSet(ctx.host, ctx.credentials.snmp, enabledOid, 'i', enabled ? 1 : 0, ctx.opts);

    if (enabled) {
      const key = typeof input.key === 'number' && Number.isInteger(input.key) ? Math.floor(input.key) : null;
      if (key === null || key < 1 || key > 65535) return { success: false, error: 'A valid aggregation key (1..65535) is required when enabling LACP.' };
      await snmpSet(ctx.host, ctx.credentials.snmp, `${SX4_LACP_CONF.base}.1.${SX4_LACP_CONF.COL_KEY}.${port}`, 'i', key, ctx.opts);
      await snmpSet(ctx.host, ctx.credentials.snmp, `${SX4_LACP_CONF.base}.1.${SX4_LACP_CONF.COL_ROLE}.${port}`, 'i', roleValue, ctx.opts);
      await snmpSet(ctx.host, ctx.credentials.snmp, `${SX4_LACP_CONF.base}.1.${SX4_LACP_CONF.COL_TIMEOUT}.${port}`, 'i', timeoutValue, ctx.opts);
    }

    // 2. Re-read to verify.
    const ge = await readScalar(ctx, enabledOid);
    const gotEnabled = ge !== null && Number(ge) === (enabled ? 1 : 0);
    let verified = gotEnabled;
    if (enabled) {
      const key = Math.floor(input.key as number);
      const gotKey = await readScalar(ctx, `${SX4_LACP_CONF.base}.1.${SX4_LACP_CONF.COL_KEY}.${port}`);
      const gotRole = await readScalar(ctx, `${SX4_LACP_CONF.base}.1.${SX4_LACP_CONF.COL_ROLE}.${port}`);
      verified = gotEnabled && (gotKey !== null && Number(gotKey) === key) && (gotRole !== null && Number(gotRole) === roleValue);
    }
    return { success: verified, applied: true, verified, details: { port, enabled, beforeEnabled: String(beforeEnabled) } };
  },
};

/** Set the PVID (access VLAN) of one port (4.x only). */
const vlanPvidSet: ActionDescriptor = {
  id: 'vlan.pvid.set',
  label: 'Move a port to another VLAN (PVID)',
  description:
    "Sets the port's PVID via lcsVlanTable column .3 (SNMP SET, unified 4.x tree only). On access ports this moves the port between VLANs — traffic on that port changes destination immediately. Re-reads to verify.",
  module: 'VLAN',
  riskLevel: 'dangerous',
  deviceCount: 1,
  inputSchema: {
    port: { type: 'number', required: true, min: 1, max: 52, description: 'Panel port number (1-based)' },
    pvid: { type: 'number', required: true, min: 1, max: 4094, description: 'Target VLAN ID' },
  },
  async execute(ctx, input) {
    const variant = await requireVariant(ctx);
    if (variant !== 'sx4') return { success: false, error: 'VLAN configuration is only available on the unified 4.x firmware line.' };

    const { port, error } = parsePort(input);
    if (error || !port) return { success: false, error };
    const pvid = typeof input.pvid === 'number' && Number.isInteger(input.pvid) ? Math.floor(input.pvid) : NaN;
    if (!Number.isInteger(pvid) || pvid < 1 || pvid > 4094) return { success: false, error: `Invalid PVID ${String(input.pvid)} (expected an integer 1..4094)` };

    const oid = `${SX4_VLAN.base}.1.${SX4_VLAN.COL_PVID}.${port}`;
    const before = await readScalar(ctx, oid);
    if (before === null) return { success: false, error: `Port ${port} does not expose a VLAN PVID object on this device.` };
    if (Number(before) === pvid) {
      return { success: true, applied: false, verified: true, details: { port, pvid, alreadySet: true } };
    }

    await snmpSet(ctx.host, ctx.credentials.snmp, oid, 'i', pvid, ctx.opts);
    const got = await readScalar(ctx, oid);
    const verified = got !== null && Number(got) === pvid;
    return { success: verified, applied: true, verified, details: { port, pvid, before: String(before), after: got ?? null } };
  },
};

/** Set the VLAN mode (access/trunk/hybrid) of one port (4.x only). */
const vlanModeSet: ActionDescriptor = {
  id: 'vlan.mode.set',
  label: 'Set port VLAN mode (access / trunk / hybrid)',
  description:
    "Sets the port's fundamental VLAN behavior via lcsVlanTable column .2 (SNMP SET, unified 4.x tree only). Changing an access port to trunk alters how ALL its traffic is tagged — verify the uplink partner first. Re-reads to verify.",
  module: 'VLAN',
  riskLevel: 'dangerous',
  deviceCount: 1,
  inputSchema: {
    port: { type: 'number', required: true, min: 1, max: 52, description: 'Panel port number (1-based)' },
    mode: { type: 'string', required: true, enum: ['access', 'trunk', 'hybrid'], description: 'Port VLAN mode' },
  },
  async execute(ctx, input) {
    const variant = await requireVariant(ctx);
    if (variant !== 'sx4') return { success: false, error: 'VLAN configuration is only available on the unified 4.x firmware line.' };

    const { port, error } = parsePort(input);
    if (error || !port) return { success: false, error };
    const modeLabel = str(input, 'mode');
    const modeValue: number | null = modeLabel === 'access' ? 0 : modeLabel === 'trunk' ? 1 : modeLabel === 'hybrid' ? 2 : null;
    if (modeValue === null) return { success: false, error: `Invalid VLAN mode ${String(input.mode)} (expected access|trunk|hybrid)` };

    const oid = `${SX4_VLAN.base}.1.${SX4_VLAN.COL_MODE}.${port}`;
    const before = await readScalar(ctx, oid);
    if (before === null) return { success: false, error: `Port ${port} does not expose a VLAN mode object on this device.` };
    if (Number(before) === modeValue) {
      return { success: true, applied: false, verified: true, details: { port, mode: modeLabel, alreadySet: true } };
    }

    await snmpSet(ctx.host, ctx.credentials.snmp, oid, 'i', modeValue, ctx.opts);
    const got = await readScalar(ctx, oid);
    const verified = got !== null && Number(got) === modeValue;
    return { success: verified, applied: true, verified, details: { port, mode: modeLabel, before: String(before), after: got ?? null } };
  },
};

/** Read the current port/PoE/LACP state (read-only diagnostics). */
const portsStateRead: ActionDescriptor = {
  id: 'ports.state.read',
  label: 'Read port / PoE / LACP state',
  description:
    "Walks the port configuration table (link state + speed) and, on the unified 4.x line, the PoE status and LACP status tables. Read-only — useful as a plan pre-check before risky changes.",
  module: 'System',
  riskLevel: 'read',
  deviceCount: 1,
  inputSchema: {},
  async execute(ctx) {
    const variant = await requireVariant(ctx);

    // Port link/speed states — walk the config table's link + speed columns.
    const portBase = variant === 'sx4' ? SX4_PORT_CONF.base : SX3_PORT_CONF.base;
    const linkCol = variant === 'sx4' ? SX4_PORT_CONF.COL_LINK : SX3_PORT_CONF.COL_LINK;
    const speedCol = variant === 'sx4' ? SX4_PORT_CONF.COL_SPEED_STATUS : SX3_PORT_CONF.COL_CURRENT_SPEED;
    const ports: Record<string, { link: string; speed: string }> = {};
    try {
      const m = await snmpWalk(ctx.host, ctx.credentials.snmp, [portBase], ctx.opts);
      for (const [oid, value] of m) {
        if (!oid.startsWith(`${portBase}.1.`)) continue;
        const parts = oid.slice(`${portBase}.1.`.length).split('.');
        if (parts.length < 2) continue;
        const col = Number(parts[0]);
        const port = parts.slice(1).join('.');
        if (!/^\d+$/.test(port)) continue;
        const entry = ports[port] ?? (ports[port] = { link: '', speed: '' });
        if (col === linkCol) entry.link = String(value).trim();
        else if (col === speedCol) entry.speed = String(value).trim();
      }
    } catch {
      // best-effort — the port table is the core of this action, but a partial
      // read still returns whatever was collected.
    }

    const details: Record<string, unknown> = { variant, ports };

    if (variant === 'sx4') {
      try {
        const poe = await snmpWalk(ctx.host, ctx.credentials.snmp, [`${SX4_POE_CONF.base}.1.${SX4_POE_CONF.COL_POE_MODE}`], ctx.opts);
        const poeModes: Record<string, string> = {};
        for (const [oid] of poe) {
          const tail = oid.split('.').pop();
          if (tail && /^\d+$/.test(tail)) poeModes[`P${tail}`] = String(Number(tail));
        }
        details.poeModes = poeModes;
      } catch { /* non-PoE model — no PoE table */ }

      try {
        const lacp = await snmpWalk(ctx.host, ctx.credentials.snmp, [`${SX4_LACP_CONF.base}.1.${SX4_LACP_CONF.COL_ENABLED}`], ctx.opts);
        const lacpEnabled: Record<string, boolean> = {};
        for (const [oid, value] of lacp) {
          const tail = oid.split('.').pop();
          if (tail && /^\d+$/.test(tail)) lacpEnabled[`P${tail}`] = Number(value) === 1;
        }
        details.lacpEnabled = lacpEnabled;
      } catch { /* no LACP configured */ }
    }

    return { success: true, details };
  },
};

// IANA zone → UTC-offset-minutes resolution comes from the shared SDK
// (ianaZoneToOffsetMinutes) — previously a local copy of the same Intl logic.

/** Set the switch's timezone — a UTC offset in minutes over SNMP SET. */
const systemTimezoneSet: ActionDescriptor = {
  id: 'system.timezone.set',
  label: 'Set device timezone (UTC offset)',
  description:
    "Sets the switch's timezone as a fixed UTC offset via SNMP SET (lcsSystemTimeZoneConf on 4.x, gs2310SystemTimeManualTimeZoneOffset on 3.x). Pass an IANA zone name (resolved to its current offset) or explicit minutes. Re-reads to verify.",
  module: 'System',
  riskLevel: 'write',
  deviceCount: 1,
  timeoutMs: 30_000,
  inputSchema: {
    timezone: { type: 'string', required: false, description: 'IANA zone (e.g. "Europe/Berlin") — resolved to its current UTC offset' },
    utcOffsetMinutes: { type: 'number', required: false, min: -7200, max: 780, description: 'Explicit UTC offset in minutes (wins over timezone)' },
  },
  async execute(ctx, input) {
    const variant = await requireVariant(ctx);
    // Resolve the target offset: explicit minutes win; else resolve the IANA zone.
    let minutes: number | null = null;
    if (typeof input.utcOffsetMinutes === 'number' && Number.isFinite(input.utcOffsetMinutes)) {
      minutes = Math.round(input.utcOffsetMinutes as number);
    } else if (str(input, 'timezone')) {
      minutes = ianaZoneToOffsetMinutes(str(input, 'timezone')!);
      if (minutes === null) return { success: false, error: `Unknown IANA timezone "${str(input, 'timezone')}".` };
    } else {
      return { success: false, error: 'Provide either "timezone" or "utcOffsetMinutes".' };
    }

    const oid = variant === 'sx4' ? SX4_TIMEZONE.conf : SX3_TIME.timezoneOffset;
    // 3.x range is narrower (-720..780) than 4.x (-7200..7201).
    if (variant === 'sx3' && (minutes < -720 || minutes > 780)) {
      return { success: false, error: `Offset ${minutes}m out of range for this firmware line (-720..780).` };
    }

    const before = await readScalar(ctx, oid);
    if (before !== null && Number(before) === minutes) {
      return { success: true, applied: false, verified: true, details: { timezoneMinutes: minutes, note: 'Already set — no change.' } };
    }
    await snmpSet(ctx.host, ctx.credentials.snmp, oid, 'i', minutes, sxOpts(ctx));
    const after = await readScalar(ctx, oid);
    const verified = after !== null && Number(after) === minutes;
    return { success: verified, applied: true, verified, details: { timezoneMinutes: minutes, before: before === null ? null : String(before), after: after === null ? null : String(after) } };
  },
};

// --- Registry ---------------------------------------------------------------------------

const ALL_ACTIONS: ActionDescriptor[] = [portSpeedModeSet, poeModeSet, poePrioritySet, lacpPortSet, vlanPvidSet, vlanModeSet, portsStateRead, systemTimezoneSet];

/** The shared registry factory (@unm/plugin-sdk) — one source for /discover, /plan and /config. */
export const registry = createRegistry(ALL_ACTIONS);

/** Returns the action for an id, or undefined. */
export function getAction(id: string): ActionDescriptor | undefined {
  return registry.getAction(id);
}

/** All actions (the full catalog). */
export function listActions(): ActionDescriptor[] {
  return registry.listActions();
}

/** Distinct module names, for catalog grouping in the webapp. */
export function listModules(): string[] {
  return registry.listModules();
}

/** The full action catalog (single-device actions only in v1). */
export function listCatalog() {
  return registry.listCatalog();
}
