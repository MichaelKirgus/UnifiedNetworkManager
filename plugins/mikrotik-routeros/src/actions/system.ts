/**
 * System-module actions for RouterOS (verified live on 7.21 LTS).
 *
 * REST semantics used here:
 *  - /system/resource, /system/identity — singleton tables served as one-element arrays.
 *  - /user — named table; PUT creates, PATCH /user/<name> updates, DELETE removes.
 *    GET rows do NOT include the password field (RouterOS never returns it).
 *  - /ip/service — named table (one row per service name); start/stop is the
 *    `disabled` flag — RouterOS has no separate "restart" for services over REST.
 *  - /system/script, /system/scheduler — named tables with full CRUD.
 *  - Reboot/halt are command words: POST /system/reboot {} and POST /system/shutdown {}.
 */

import { rosNumber, rosString } from '../routerosClient';
import type { ActionContext, ActionDescriptor } from './types';

type Row = Record<string, unknown>;

/** Singleton tables may answer as a bare object OR a one-element array — normalize. */
function firstRow(raw: unknown): Row | null {
  if (Array.isArray(raw)) return raw[0] && typeof raw[0] === 'object' ? (raw[0] as Row) : null;
  return raw && typeof raw === 'object' ? (raw as Row) : null;
}

/** Parses a RouterOS uptime string ("2d4h3m1s" / "59s") into seconds. */
function parseUptimeSeconds(raw: string | undefined): number | null {
  if (!raw) return null;
  let total = 0;
  const re = /(\d+)([dwms])/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(raw)) !== null) {
    const n = Number(m[1]);
    switch (m[2]) {
      case 'w': total += n * 7 * 86_400; break;
      case 'd': total += n * 86_400; break;
      case 'h': total += n * 3_600; break;
      case 'm': total += n * 60; break;
      case 's': total += n; break;
    }
  }
  return raw.trim() === '' ? null : total;
}

/** RouterOS user groups (7.x). */
const USER_GROUPS = ['read', 'write', 'full'] as const;

// --- system.info.read ---------------------------------------------------------------

export const systemInfoReadAction: ActionDescriptor = {
  id: 'system.info.read',
  label: 'Read system information',
  description: "Static identity of the router — RouterOS version, build time, CPU architecture, board name and hostname (from /system/resource + /system/identity).",
  module: 'System',
  riskLevel: 'read',
  deviceCount: 1,
  inputSchema: {},
  execute: async (ctx) => {
    const [resourceRaw, identityRaw] = await Promise.all([
      ctx.client.get<unknown>('/system/resource').catch(() => null),
      ctx.client.get<unknown>('/system/identity').catch(() => null),
    ]);
    const resource = firstRow(resourceRaw) ?? {};
    const identity = firstRow(identityRaw) ?? {};
    return {
      success: true,
      details: {
        version: rosString(resource, ['version']) ?? null,
        buildTime: rosString(resource, ['build-time']) ?? null,
        platform: rosString(resource, ['architecture-name', 'cpu']) ?? null,
        boardName: rosString(resource, ['board-name']) ?? null,
        hostname: rosString(identity, ['name']) ?? null,
      },
    };
  },
};

// --- system.status.read ---------------------------------------------------------------

export const systemStatusReadAction: ActionDescriptor = {
  id: 'system.status.read',
  label: 'Read system status',
  description: "Live health of the router — CPU load, free/total memory and disk, uptime (from /system/resource).",
  module: 'System',
  riskLevel: 'read',
  deviceCount: 1,
  inputSchema: {},
  execute: async (ctx) => {
    const raw = await ctx.client.get<unknown>('/system/resource').catch(() => null);
    const resource = firstRow(raw);
    if (!resource) return { success: false, error: 'Could not read /system/resource.' };
    const cpuLoadRaw = rosNumber(resource, ['cpu-load']);
    return {
      success: true,
      details: {
        cpuLoadPercent: cpuLoadRaw !== undefined && Number.isFinite(cpuLoadRaw) ? Math.round(cpuLoadRaw * 10) / 10 : null,
        freeMemoryBytes: rosNumber(resource, ['free-memory']) ?? null,
        totalMemoryBytes: rosNumber(resource, ['total-memory']) ?? null,
        freeDiskBytes: rosNumber(resource, ['free-disk-space', 'free-disk']) ?? null,
        totalDiskBytes: rosNumber(resource, ['total-disk-space', 'total-disk']) ?? null,
        uptimeSeconds: parseUptimeSeconds(rosString(resource, ['uptime'])),
      },
    };
  },
};

// --- system.identity.set ---------------------------------------------------------------

export const systemIdentitySetAction: ActionDescriptor = {
  id: 'system.identity.set',
  label: 'Set hostname (identity)',
  description: "Sets the router's identity/hostname via POST /system/identity/set. Idempotent — an unchanged name is a no-op.",
  module: 'System',
  riskLevel: 'write',
  deviceCount: 1,
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, maxLength: 64, description: 'New hostname (e.g. router-01)' },
  },
  execute: async (ctx, input) => {
    const name = String(input.name ?? '').trim();
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(name)) {
      return { success: false, error: `Invalid hostname "${name}" — letters, digits, dots and dashes only (must start alphanumeric).` };
    }

    const before = firstRow(await ctx.client.get<unknown>('/system/identity').catch(() => null));
    if (rosString(before ?? {}, ['name']) === name) {
      return { success: true, applied: false, details: { skipped: `hostname already "${name}"` } };
    }

    try {
      await ctx.client.post('/system/identity/set', { name });
    } catch (e) {
      return { success: false, error: `Setting identity failed: ${e instanceof Error ? e.message : String(e)}` };
    }

    const after = firstRow(await ctx.client.get<unknown>('/system/identity').catch(() => null));
    if (rosString(after ?? {}, ['name']) !== name) {
      return { success: false, error: `Verification failed — identity is "${rosString(after ?? {}, ['name'])}" after set.` };
    }
    return { success: true, applied: true, details: { before: rosString(before ?? {}, ['name']) ?? null, after: name } };
  },
};

// --- system.users.read -----------------------------------------------------------------

export const systemUsersReadAction: ActionDescriptor = {
  id: 'system.users.read',
  label: 'Read local users',
  description: "Lists the router's local user accounts (/user) — name, group, disabled/expired state and last login. Passwords are never returned by RouterOS REST.",
  module: 'System',
  riskLevel: 'read',
  deviceCount: 1,
  inputSchema: {},
  execute: async (ctx) => {
    const rows = await ctx.client.get<Row[]>('/user').catch(() => [] as Row[]);
    return {
      success: true,
      details: {
        users: rows.map((u) => ({
          name: rosString(u, ['name']) ?? null,
          group: rosString(u, ['group']) ?? null,
          disabled: rosString(u, ['disabled']) === 'true',
          expired: rosString(u, ['expired']) === 'true',
          inactivityPolicy: rosString(u, ['inactivity-policy']) ?? null,
          lastLoggedIn: rosString(u, ['last-logged-in']) ?? null,
        })),
      },
    };
  },
};

// --- system.user.add --------------------------------------------------------------------

export const systemUserAddAction: ActionDescriptor = {
  id: 'system.user.add',
  label: 'Create or update a local user',
  description: "Creates a local user (/user) — idempotent by name: an existing user is updated in place (password/group/disabled). Use to provision per-admin accounts instead of sharing the default admin.",
  module: 'System',
  riskLevel: 'write',
  deviceCount: 1,
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, maxLength: 64, description: 'Username' },
    password: { type: 'string', required: true, minLength: 1, maxLength: 256, description: 'Password (set on create; re-set on update when provided)' },
    group: { type: 'string', enum: [...USER_GROUPS], description: "User group — read | write | full (default: read)" },
    disabled: { type: 'boolean', description: 'Create the user in a disabled state' },
  },
  execute: async (ctx, input) => {
    const name = String(input.name ?? '').trim();
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(name)) return { success: false, error: `Invalid username "${name}".` };
    const password = String(input.password ?? '');
    const group = typeof input.group === 'string' && input.group ? input.group : 'read';

    const rows = await ctx.client.get<Row[]>('/user').catch(() => [] as Row[]);
    const existing = rows.find((u) => rosString(u, ['name']) === name);

    if (existing) {
      // Update in place — PATCH by name.
      try {
        await ctx.client.patch(`/user/${encodeURIComponent(name)}`, { password, group });
      } catch (e) {
        return { success: false, error: `Updating user "${name}" failed: ${e instanceof Error ? e.message : String(e)}` };
      }
      const after = (await ctx.client.get<Row[]>('/user').catch(() => [] as Row[])).find((u) => rosString(u, ['name']) === name);
      if (!after || rosString(after, ['group']) !== group) {
        return { success: false, error: `Verification failed — user "${name}" not updated.` };
      }
      return { success: true, applied: true, details: { updated: name, group } };
    }

    const body: Record<string, unknown> = { name, password, group };
    if (input.disabled === true) body['disabled'] = true;
    try {
      await ctx.client.put('/user', body);
    } catch (e) {
      return { success: false, error: `Creating user "${name}" failed: ${e instanceof Error ? e.message : String(e)}` };
    }

    const after = (await ctx.client.get<Row[]>('/user').catch(() => [] as Row[])).find((u) => rosString(u, ['name']) === name);
    if (!after) return { success: false, error: `Verification failed — user "${name}" not present after create.` };
    return { success: true, applied: true, details: { created: name, group } };
  },
};

// --- system.user.delete ------------------------------------------------------------------

export const systemUserDeleteAction: ActionDescriptor = {
  id: 'system.user.delete',
  label: 'Delete a local user',
  description: "Removes a local user by name (/user). Idempotent — an unknown name is a no-op. Refuses to delete the only enabled `full`-group account (that would lock you out).",
  module: 'System',
  riskLevel: 'write',
  deviceCount: 1,
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, maxLength: 64, description: 'Username to remove' },
  },
  execute: async (ctx, input) => {
    const name = String(input.name ?? '').trim();
    const rows = await ctx.client.get<Row[]>('/user').catch(() => [] as Row[]);
    const target = rows.find((u) => rosString(u, ['name']) === name);
    if (!target) return { success: true, applied: false, details: { skipped: `no user named "${name}"` } };

    // Lockout guard — never remove the last enabled full-access account.
    const otherFull = rows.filter((u) => rosString(u, ['group']) === 'full' && rosString(u, ['disabled']) !== 'true' && rosString(u, ['name']) !== name);
    if (rosString(target, ['group']) === 'full' && otherFull.length === 0) {
      return { success: false, error: `Refusing to delete "${name}" — it is the only enabled full-access account. Create another admin first.` };
    }

    const id = rosString(target, ['.id']);
    if (!id) return { success: false, error: `User "${name}" has no .id — cannot remove it.` };
    try {
      await ctx.client.delete(`/user/${id}`);
    } catch (e) {
      return { success: false, error: `Deleting user "${name}" failed: ${e instanceof Error ? e.message : String(e)}` };
    }

    const after = (await ctx.client.get<Row[]>('/user').catch(() => [] as Row[])).find((u) => rosString(u, ['name']) === name);
    if (after) return { success: false, error: `Verification failed — user "${name}" still present.` };
    return { success: true, applied: true, details: { deleted: name } };
  },
};

// --- system.services.read ------------------------------------------------------------------

export const systemServicesReadAction: ActionDescriptor = {
  id: 'system.services.read',
  label: 'Read management services',
  description: "Lists the router's management services (/ip/service) — name, port, protocol, bound address and enabled state. This is what the Security page checks for exposure.",
  module: 'System',
  riskLevel: 'read',
  deviceCount: 1,
  inputSchema: {},
  execute: async (ctx) => {
    const rows = await ctx.client.get<Row[]>('/ip/service').catch(() => [] as Row[]);
    return {
      success: true,
      details: {
        services: rows.map((s) => ({
          name: rosString(s, ['name']) ?? null,
          port: rosNumber(s, ['port']),
          proto: rosString(s, ['proto']) ?? null,
          address: rosString(s, ['address']) ?? '', // empty = all interfaces
          disabled: rosString(s, ['disabled']) === 'true',
        })),
      },
    };
  },
};

// --- service lifecycle (start/stop/restart) -------------------------------------------------

/** Patches the `disabled` flag of one /ip/service row by name. */
async function setServiceEnabled(ctx: ActionContext, serviceName: string, enabled: boolean): Promise<{ ok: boolean; error?: string }> {
  const rows = await ctx.client.get<Row[]>('/ip/service').catch(() => [] as Row[]);
  const target = rows.find((s) => rosString(s, ['name']) === serviceName);
  if (!target) return { ok: false, error: `No service named "${serviceName}" on this router.` };

  try {
    await ctx.client.patch(`/ip/service/${encodeURIComponent(serviceName)}`, { disabled: !enabled });
  } catch (e) {
    return { ok: false, error: `${enabled ? 'Enabling' : 'Disabling'} service "${serviceName}" failed: ${e instanceof Error ? e.message : String(e)}` };
  }

  const after = (await ctx.client.get<Row[]>('/ip/service').catch(() => [] as Row[])).find((s) => rosString(s, ['name']) === serviceName);
  const stillDisabled = !after || rosString(after, ['disabled']) === 'true';
  if (stillDisabled !== !enabled) {
    return { ok: false, error: `Verification failed — service "${serviceName}" state unchanged.` };
  }
  return { ok: true };
}

function serviceLifecycleAction(id: string, label: string, verb: 'start' | 'stop' | 'restart'): ActionDescriptor {
  const enabled = verb !== 'stop';
  return {
    id,
    label,
    description:
      verb === 'restart'
        ? `Toggles the service off and on (RouterOS has no native restart over REST — a stop+start cycle is the closest equivalent).`
        : `${verb === 'start' ? 'Enables' : 'Disables'} the named management service (/ip/service \`disabled\` flag). Idempotent.`,
    module: 'Services',
    riskLevel: 'write',
    deviceCount: 1,
    inputSchema: { name: { type: 'string', required: true, description: `Service name (e.g. ssh, www-ssl, telnet, winbox) — see system.services.read` } },
    execute: async (ctx, input) => {
      const serviceName = String(input.name ?? '').trim();

      if (verb === 'restart') {
        const off = await setServiceEnabled(ctx, serviceName, false);
        if (!off.ok) return { success: false, error: off.error };
        const on = await setServiceEnabled(ctx, serviceName, true);
        if (!on.ok) return { success: false, error: on.error };
        return { success: true, applied: true, details: { service: serviceName, restarted: true } };
      }

      // Idempotency — already in the desired state.
      const rows = await ctx.client.get<Row[]>('/ip/service').catch(() => [] as Row[]);
      const target = rows.find((s) => rosString(s, ['name']) === serviceName);
      if (!target) return { success: false, error: `No service named "${serviceName}" on this router.` };
      const currentlyDisabled = rosString(target, ['disabled']) === 'true';
      if (currentlyDisabled === !enabled) {
        return { success: true, applied: false, details: { skipped: `service "${serviceName}" already ${enabled ? 'enabled' : 'disabled'}` } };
      }

      const res = await setServiceEnabled(ctx, serviceName, enabled);
      if (!res.ok) return { success: false, error: res.error };
      return { success: true, applied: true, details: { service: serviceName, [verb]: true } };
    },
  };
}

export const servicesStartAction = serviceLifecycleAction('services.start', 'Start a service', 'start');
export const servicesStopAction = serviceLifecycleAction('services.stop', 'Stop a service', 'stop');
export const servicesRestartAction = serviceLifecycleAction('services.restart', 'Restart a service', 'restart');
/** Canonical alias (OPNsense-compatible id) — same executor as services.restart. */
export const systemServiceRestartAction: ActionDescriptor = { ...servicesRestartAction, id: 'system.service.restart' };

// --- system.reboot / system.halt -------------------------------------------------------------

export const systemRebootAction: ActionDescriptor = {
  id: 'system.reboot',
  label: 'Reboot router',
  description: "Reboots the router (POST /system/reboot). The REST connection drops mid-response — that is EXPECTED and reported as success. Use only in a maintenance window.",
  module: 'System',
  riskLevel: 'dangerous',
  deviceCount: 1,
  timeoutMs: 30_000,
  retryOnDispatchFailure: false, // flapping guard — never re-dispatch a power cycle
  inputSchema: {},
  execute: async (ctx) => {
    try {
      await ctx.client.post('/system/reboot', {});
      return { success: true, applied: true, details: { note: 'Reboot command accepted.' } };
    } catch (e) {
      // A dropped connection right after the POST means the router is already going down.
      const msg = e instanceof Error ? e.message : String(e);
      if (/unreachable|timeout|socket|ECONNRESET/i.test(msg)) {
        return { success: true, applied: true, details: { note: 'Reboot command accepted (connection dropped as the router went down).' } };
      }
      return { success: false, error: `Reboot failed: ${msg}` };
    }
  },
};

export const systemHaltAction: ActionDescriptor = {
  id: 'system.halt',
  label: 'Shut down router',
  description: "Shuts the router down (POST /system/shutdown) — it will NOT power back on by itself. The REST connection drops mid-response; that is EXPECTED.",
  module: 'System',
  riskLevel: 'dangerous',
  deviceCount: 1,
  timeoutMs: 30_000,
  retryOnDispatchFailure: false,
  inputSchema: {},
  execute: async (ctx) => {
    try {
      await ctx.client.post('/system/shutdown', {});
      return { success: true, applied: true, details: { note: 'Shutdown command accepted.' } };
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      if (/unreachable|timeout|socket|ECONNRESET/i.test(msg)) {
        return { success: true, applied: true, details: { note: 'Shutdown command accepted (connection dropped as the router went down).' } };
      }
      return { success: false, error: `Shutdown failed: ${msg}` };
    }
  },
};

// --- system.script.* ---------------------------------------------------------------------------

export const systemScriptsReadAction: ActionDescriptor = {
  id: 'system.scripts.read',
  label: 'Read user scripts',
  description: "Lists the router's user-defined scripts (/system/script) — name, owner and source.",
  module: 'System',
  riskLevel: 'read',
  deviceCount: 1,
  inputSchema: {},
  execute: async (ctx) => {
    const rows = await ctx.client.get<Row[]>('/system/script').catch(() => [] as Row[]);
    return {
      success: true,
      details: { scripts: rows.map((s) => ({ name: rosString(s, ['name']) ?? null, owner: rosString(s, ['owner']) ?? null, source: rosString(s, ['source']) ?? '' })) },
    };
  },
};

export const systemScriptAddAction: ActionDescriptor = {
  id: 'system.script.add',
  label: 'Create or update a user script',
  description: "Creates (or updates in place) a RouterOS user script (/system/script). The source is raw RouterOS CLI — e.g. `put log info \"hello\"`. Idempotent by name.",
  module: 'System',
  riskLevel: 'write',
  deviceCount: 1,
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, maxLength: 64, description: 'Script name' },
    source: { type: 'string', required: true, minLength: 1, description: 'RouterOS CLI script body (may span multiple lines)' },
  },
  execute: async (ctx, input) => {
    const name = String(input.name ?? '').trim();
    const source = String(input.source ?? '');

    const rows = await ctx.client.get<Row[]>('/system/script').catch(() => [] as Row[]);
    const existing = rows.find((s) => rosString(s, ['name']) === name);
    if (existing && rosString(existing, ['source']) === source) {
      return { success: true, applied: false, details: { skipped: `script "${name}" already has this source` } };
    }

    try {
      if (existing) await ctx.client.patch(`/system/script/${encodeURIComponent(name)}`, { source });
      else await ctx.client.put('/system/script', { name, source });
    } catch (e) {
      return { success: false, error: `${existing ? 'Updating' : 'Creating'} script "${name}" failed: ${e instanceof Error ? e.message : String(e)}` };
    }

    const after = (await ctx.client.get<Row[]>('/system/script').catch(() => [] as Row[])).find((s) => rosString(s, ['name']) === name);
    if (!after || rosString(after, ['source']) !== source) {
      return { success: false, error: `Verification failed — script "${name}" not stored correctly.` };
    }
    return { success: true, applied: true, details: { [existing ? 'updated' : 'created']: name } };
  },
};

export const systemScriptDeleteAction: ActionDescriptor = {
  id: 'system.script.delete',
  label: 'Delete a user script',
  description: "Removes a RouterOS user script by name. Idempotent — an unknown name is a no-op.",
  module: 'System',
  riskLevel: 'write',
  deviceCount: 1,
  inputSchema: { name: { type: 'string', required: true, minLength: 1, maxLength: 64, description: 'Script name to remove' } },
  execute: async (ctx, input) => {
    const name = String(input.name ?? '').trim();
    const rows = await ctx.client.get<Row[]>('/system/script').catch(() => [] as Row[]);
    const target = rows.find((s) => rosString(s, ['name']) === name);
    if (!target) return { success: true, applied: false, details: { skipped: `no script named "${name}"` } };

    const id = rosString(target, ['.id']);
    if (!id) return { success: false, error: `Script "${name}" has no .id — cannot remove it.` };
    try {
      await ctx.client.delete(`/system/script/${id}`);
    } catch (e) {
      return { success: false, error: `Deleting script "${name}" failed: ${e instanceof Error ? e.message : String(e)}` };
    }

    const after = (await ctx.client.get<Row[]>('/system/script').catch(() => [] as Row[])).find((s) => rosString(s, ['name']) === name);
    if (after) return { success: false, error: `Verification failed — script "${name}" still present.` };
    return { success: true, applied: true, details: { deleted: name } };
  },
};

// --- system.scheduler.* --------------------------------------------------------------------------

export const systemSchedulerReadAction: ActionDescriptor = {
  id: 'system.scheduler.read',
  label: 'Read scheduled jobs',
  description: "Lists the router's scheduler entries (/system/scheduler) — name, interval/start time, on-event script and enabled state.",
  module: 'System',
  riskLevel: 'read',
  deviceCount: 1,
  inputSchema: {},
  execute: async (ctx) => {
    const rows = await ctx.client.get<Row[]>('/system/scheduler').catch(() => [] as Row[]);
    return {
      success: true,
      details: {
        jobs: rows.map((s) => ({
          name: rosString(s, ['name']) ?? null,
          interval: rosString(s, ['interval']) ?? null,
          startDate: rosString(s, ['start-date']) ?? null,
          startTime: rosString(s, ['start-time']) ?? null,
          onEvent: rosString(s, ['on-event']) ?? '',
          disabled: rosString(s, ['disabled']) === 'true',
        })),
      },
    };
  },
};

export const systemSchedulerAddAction: ActionDescriptor = {
  id: 'system.scheduler.add',
  label: 'Create or update a scheduled job',
  description: "Creates (or updates in place) a scheduler entry (/system/scheduler). `onEvent` is the script NAME to run (create it first with system.script.add). Idempotent by name.",
  module: 'System',
  riskLevel: 'write',
  deviceCount: 1,
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, maxLength: 64, description: 'Job name' },
    onEvent: { type: 'string', required: true, minLength: 1, description: "Script name to execute (e.g. `system script run my-script` or just the script name)" },
    interval: { type: 'string', description: "Repeat interval — e.g. 1h, 30m, 2d (omit for a one-shot job at startDate/startTime)" },
    startTime: { type: 'string', description: "Start time of day, HH:MM[:SS] (default 00:00:00)" },
    disabled: { type: 'boolean', description: 'Create the job in a disabled state' },
  },
  execute: async (ctx, input) => {
    const name = String(input.name ?? '').trim();
    const onEvent = String(input.onEvent ?? '').trim();

    const rows = await ctx.client.get<Row[]>('/system/scheduler').catch(() => [] as Row[]);
    const existing = rows.find((s) => rosString(s, ['name']) === name);

    const body: Record<string, unknown> = { 'on-event': onEvent };
    if (typeof input.interval === 'string' && input.interval.trim()) body['interval'] = input.interval.trim();
    if (typeof input.startTime === 'string' && input.startTime.trim()) body['start-time'] = input.startTime.trim();
    if (input.disabled === true) body['disabled'] = true;

    try {
      if (existing) await ctx.client.patch(`/system/scheduler/${encodeURIComponent(name)}`, body);
      else await ctx.client.put('/system/scheduler', { name, ...body });
    } catch (e) {
      return { success: false, error: `${existing ? 'Updating' : 'Creating'} scheduler job "${name}" failed: ${e instanceof Error ? e.message : String(e)}` };
    }

    const after = (await ctx.client.get<Row[]>('/system/scheduler').catch(() => [] as Row[])).find((s) => rosString(s, ['name']) === name);
    if (!after || rosString(after, ['on-event']) !== onEvent) {
      return { success: false, error: `Verification failed — scheduler job "${name}" not stored correctly.` };
    }
    return { success: true, applied: true, details: { [existing ? 'updated' : 'created']: name } };
  },
};

export const systemSchedulerDeleteAction: ActionDescriptor = {
  id: 'system.scheduler.delete',
  label: 'Delete a scheduled job',
  description: "Removes a scheduler entry by name. Idempotent — an unknown name is a no-op.",
  module: 'System',
  riskLevel: 'write',
  deviceCount: 1,
  inputSchema: { name: { type: 'string', required: true, minLength: 1, maxLength: 64, description: 'Job name to remove' } },
  execute: async (ctx, input) => {
    const name = String(input.name ?? '').trim();
    const rows = await ctx.client.get<Row[]>('/system/scheduler').catch(() => [] as Row[]);
    const target = rows.find((s) => rosString(s, ['name']) === name);
    if (!target) return { success: true, applied: false, details: { skipped: `no scheduler job named "${name}"` } };

    const id = rosString(target, ['.id']);
    if (!id) return { success: false, error: `Scheduler job "${name}" has no .id — cannot remove it.` };
    try {
      await ctx.client.delete(`/system/scheduler/${id}`);
    } catch (e) {
      return { success: false, error: `Deleting scheduler job "${name}" failed: ${e instanceof Error ? e.message : String(e)}` };
    }

    const after = (await ctx.client.get<Row[]>('/system/scheduler').catch(() => [] as Row[])).find((s) => rosString(s, ['name']) === name);
    if (after) return { success: false, error: `Verification failed — scheduler job "${name}" still present.` };
    return { success: true, applied: true, details: { deleted: name } };
  },
};

// --- system.logging.read ---------------------------------------------------------------------------

export const systemLoggingReadAction: ActionDescriptor = {
  id: 'system.logging.read',
  label: 'Read logging configuration',
  description: "Shows the router's log output destinations (/system/logging) — which topics go to memory/echo/disk and at what level.",
  module: 'System',
  riskLevel: 'read',
  deviceCount: 1,
  inputSchema: {},
  execute: async (ctx) => {
    const rows = await ctx.client.get<Row[]>('/system/logging').catch(() => [] as Row[]);
    return {
      success: true,
      details: {
        destinations: rows.map((l) => ({
          topics: rosString(l, ['topics']) ?? null,
          action: rosString(l, ['action']) ?? null, // memory | echo | disk | remote
          prefix: rosString(l, ['prefix']) ?? '',
          disabled: rosString(l, ['disabled']) === 'true',
        })),
      },
    };
  },
};

export const systemActions: ActionDescriptor[] = [
  systemInfoReadAction,
  systemStatusReadAction,
  systemIdentitySetAction,
  systemUsersReadAction,
  systemUserAddAction,
  systemUserDeleteAction,
  systemServicesReadAction,
  servicesStartAction,
  servicesStopAction,
  servicesRestartAction,
  systemServiceRestartAction,
  systemRebootAction,
  systemHaltAction,
  systemScriptsReadAction,
  systemScriptAddAction,
  systemScriptDeleteAction,
  systemSchedulerReadAction,
  systemSchedulerAddAction,
  systemSchedulerDeleteAction,
  systemLoggingReadAction,
];
