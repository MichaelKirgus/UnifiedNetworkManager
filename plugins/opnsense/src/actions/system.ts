import * as sys from '../client/system';
import * as backup from '../client/backup';
import * as firmware from '../client/firmware';
import * as ntpd from '../client/ntpd';
import { ActionDescriptor, ActionResult } from './types';

/**
 * System + snapshot actions. Snapshots are the appliance's native rollback
 * primitive: `snapshot.create` is auto-prepended to dangerous/staged plans so a
 * later `snapshot.restore` can undo them (the created uuid travels in the step
 * result for output-ref substitution).
 */

// Extracts the response body object when the call succeeded.
function dataOf(res: { ok: boolean; status: number; data: unknown }): Record<string, unknown> | undefined {
  return res.ok && res.data !== null && typeof res.data === 'object' ? (res.data as Record<string, unknown>) : undefined;
}

export const systemActions: ActionDescriptor[] = [
  {
    id: 'system.status.read',
    label: 'Read system status',
    module: 'System',
    riskLevel: 'read',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const res = await sys.getSystemStatus(ctx.client);
      return { success: res.ok, details: dataOf(res) ?? { status: res.status } };
    },
  },
  {
    id: 'system.info.read',
    label: 'Read system information',
    module: 'System',
    riskLevel: 'read',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const res = await sys.getSystemInformation(ctx.client);
      return { success: res.ok, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'system.services.read',
    label: 'Read services + running state',
    module: 'System',
    riskLevel: 'read',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const res = await sys.searchServices(ctx.client);
      return { success: res.ok, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'system.service.restart',
    label: 'Restart a service',
    module: 'System',
    riskLevel: 'write',
    deviceCount: 1,
    inputSchema: { name: { type: 'string', required: true, description: 'Service name (e.g. pf, unbound, dnsmasq)' } },
    execute: async (ctx, input) => {
      const res = await sys.restartService(ctx.client, String(input.name));
      return { success: res.ok, applied: res.ok, details: dataOf(res) ?? {} };
    },
  },
  // --- Unified service lifecycle (Services page — catalog-driven buttons) -----

  {
    id: 'services.start',
    label: 'Start a service',
    module: 'Services',
    riskLevel: 'write',
    deviceCount: 1,
    inputSchema: { name: { type: 'string', required: true, description: 'Service name (e.g. pf, unbound, dnsmasq)' } },
    execute: async (ctx, input) => {
      const res = await sys.startService(ctx.client, String(input.name));
      return { success: res.ok, applied: res.ok, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'services.stop',
    label: 'Stop a service',
    module: 'Services',
    riskLevel: 'write',
    deviceCount: 1,
    inputSchema: { name: { type: 'string', required: true, description: 'Service name (e.g. pf, unbound, dnsmasq)' } },
    execute: async (ctx, input) => {
      const res = await sys.stopService(ctx.client, String(input.name));
      return { success: res.ok, applied: res.ok, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'services.restart',
    label: 'Restart a service',
    module: 'Services',
    riskLevel: 'write',
    deviceCount: 1,
    inputSchema: { name: { type: 'string', required: true, description: 'Service name (e.g. pf, unbound, dnsmasq)' } },
    execute: async (ctx, input) => {
      const res = await sys.restartService(ctx.client, String(input.name));
      return { success: res.ok, applied: res.ok, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'system.reboot',
    label: 'Reboot appliance',
    module: 'System',
    riskLevel: 'dangerous',
    deviceCount: 1,
    timeoutMs: 30_000,
    // Flapping guard — a failed reboot must never be re-dispatched (it would
    // power-cycle the gateway again).
    retryOnDispatchFailure: false,
    inputSchema: {},
    execute: async (ctx) => {
      const res = await sys.reboot(ctx.client);
      return { success: res.ok, applied: res.ok, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'system.halt',
    label: 'Power off appliance',
    module: 'System',
    riskLevel: 'dangerous',
    deviceCount: 1,
    timeoutMs: 30_000,
    // Flapping guard — a failed halt must never be re-dispatched.
    retryOnDispatchFailure: false,
    inputSchema: {},
    execute: async (ctx) => {
      const res = await sys.halt(ctx.client);
      return { success: res.ok, applied: res.ok, details: dataOf(res) ?? {} };
    },
  },
  // --- Snapshots / backups -----------------------------------------------------

  {
    id: 'snapshot.create',
    label: 'Create config snapshot (rollback point)',
    module: 'System',
    riskLevel: 'write',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const supported = await backup.snapshotsSupported(ctx.client);
      if (!supported.ok || !supported.data) {
        return { success: false, error: `Snapshots not available on this appliance (HTTP ${supported.status})` };
      }
      const res = await backup.addSnapshot(ctx.client);
      const d = dataOf(res);
      const uuid = typeof d?.['uuid'] === 'string' ? (d['uuid'] as string) : undefined;
      return { success: res.ok, applied: res.ok, details: { snapshotUuid: uuid ?? null } };
    },
  },
  {
    id: 'snapshot.restore',
    label: 'Restore config snapshot',
    module: 'System',
    riskLevel: 'dangerous',
    deviceCount: 1,
    timeoutMs: 60_000,
    // Flapping guard — a failed restore must never be re-dispatched (it would
    // overwrite the config again).
    retryOnDispatchFailure: false,
    inputSchema: { snapshotUuid: { type: 'string', required: true, description: 'Snapshot uuid (e.g. from a prior snapshot.create step)' } },
    execute: async (ctx, input) => {
      const res = await backup.activateSnapshot(ctx.client, String(input.snapshotUuid));
      return { success: res.ok, applied: res.ok, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'snapshot.list',
    label: 'List config snapshots',
    module: 'System',
    riskLevel: 'read',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const res = await backup.searchSnapshots(ctx.client);
      return { success: res.ok, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'backup.list',
    label: 'List backups',
    module: 'System',
    riskLevel: 'read',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const res = await backup.listBackups(ctx.client);
      return { success: res.ok, details: dataOf(res) ?? {} };
    },
  },

  // --- Firmware updates --------------------------------------------------------
  // The appliance's own update surface (System → Updates in the web UI):
  //   check     — force a fresh probe against pkg.opnsense.org (slow, sync)
  //   status    — read the cached check result (fast)
  //   update    — MINOR: point release within the current series + packages
  //   upgrade   — MAJOR: new release line (reboots into it)
  // Both apply actions are ASYNC configd jobs: they return a job uuid and the
  // progress is tracked via `firmware.upgradestatus` (the Updates page polls it
  // through the plan's verified flag once the row disappears on the next poll).

  {
    id: 'firmware.status.read',
    label: 'Read firmware update status',
    description:
      'Returns the appliance\'s CACHED update check (fast): current version, pending package upgrades and whether a major release line is available. Use `firmware.check` to force a fresh probe first.',
    module: 'System',
    riskLevel: 'read',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const res = await firmware.getFirmwareStatus(ctx.client);
      if (!res.ok || !res.data) return { success: false, error: `firmware status failed (HTTP ${res.status})` };
      const st = firmware.parseFirmwareStatus(res.data);
      return { success: true, details: { ...st, raw: dataOf(res) ?? {} } as Record<string, unknown> };
    },
  },
  {
    id: 'firmware.check',
    label: 'Check for updates (fresh probe)',
    description:
      'Forces the appliance to re-probe its configured mirror synchronously and returns the fresh result. Can take up to ~2 minutes against pkg.opnsense.org.',
    module: 'System',
    riskLevel: 'read',
    deviceCount: 1,
    timeoutMs: 150_000,
    inputSchema: {},
    execute: async (ctx) => {
      const res = await firmware.checkForUpdates(ctx.client);
      if (!res.ok || !res.data) return { success: false, error: `firmware check failed (HTTP ${res.status})` };
      const st = firmware.parseFirmwareStatus(res.data);
      return { success: true, details: { ...st } as Record<string, unknown> };
    },
  },
  {
    id: 'firmware.update',
    label: 'Update system + packages (minor)',
    description:
      'Applies the appliance\'s MINOR update job: point release within the current series plus all pending package upgrades. Runs as an async configd job — the appliance stays up unless a reboot is required, in which case it reboots itself when done. DANGEROUS on a production gateway.',
    module: 'System',
    riskLevel: 'dangerous',
    deviceCount: 1,
    timeoutMs: 60_000,
    // Flapping guard — a failed firmware update must never be re-dispatched
    // (it would start the update job again).
    retryOnDispatchFailure: false,
    inputSchema: {},
    execute: async (ctx) => {
      // Guard: only start the job when there is actually something to update.
      const st = firmware.parseFirmwareStatus((await firmware.getFirmwareStatus(ctx.client)).data ?? {});
      if (!st.checked || (st.packages.length === 0 && st.majorSets.length === 0)) {
        return { success: false, error: 'No updates pending — run `firmware.check` first to force a fresh probe.' };
      }
      const res = await firmware.runFirmwareUpdate(ctx.client);
      if (!res.ok) return { success: false, error: `firmware update job failed to start (HTTP ${res.status})` };
      const d = dataOf(res) ?? {};
      return {
        success: true,
        applied: true,
        details: {
          msgUuid: typeof d['msg_uuid'] === 'string' ? d['msg_uuid'] : null,
          needsReboot: st.needsReboot,
          packages: st.packages.map((p) => p.name),
          note: 'Async job started — track progress via `firmware.upgradestatus`.',
        },
      };
    },
  },
  {
    id: 'firmware.upgrade',
    label: 'Upgrade to new release line (major)',
    description:
      'Applies the appliance\'s MAJOR upgrade job: moves to a newer release line (e.g. 26.4 → 26.7). The appliance REBOOTS into the new boot environment when done — expect downtime. DANGEROUS.',
    module: 'System',
    riskLevel: 'dangerous',
    deviceCount: 1,
    timeoutMs: 60_000,
    // Flapping guard — a failed major upgrade must never be re-dispatched
    // (it would start the upgrade job again).
    retryOnDispatchFailure: false,
    inputSchema: {},
    execute: async (ctx) => {
      const st = firmware.parseFirmwareStatus((await firmware.getFirmwareStatus(ctx.client)).data ?? {});
      if (!st.checked || st.majorSets.length === 0) {
        return { success: false, error: 'No major release line available — only minor updates are pending (use `firmware.update`).' };
      }
      const res = await firmware.runFirmwareUpgrade(ctx.client);
      if (!res.ok) return { success: false, error: `firmware upgrade job failed to start (HTTP ${res.status})` };
      const d = dataOf(res) ?? {};
      return {
        success: true,
        applied: true,
        details: {
          msgUuid: typeof d['msg_uuid'] === 'string' ? d['msg_uuid'] : null,
          targetSeries: st.nextSeries ?? null,
          note: 'Async job started — the appliance reboots into the new release when done.',
        },
      };
    },
  },
  {
    id: 'firmware.upgradestatus',
    label: 'Read firmware update progress',
    description:
      'Returns the progress of a running firmware update/upgrade job (status running/done/reboot + the job log tail).',
    module: 'System',
    riskLevel: 'read',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const res = await firmware.getFirmwareUpgradeStatus(ctx.client);
      if (!res.ok || !res.data) return { success: false, error: `upgradestatus failed (HTTP ${res.status})` };
      const d = dataOf(res) ?? {};
      const log = typeof d['log'] === 'string' ? d['log'].slice(-2000) : null;
      return { success: true, details: { status: d['status'] ?? null, log } };
    },
  },
  // --- Fleet clock re-sync (Time page "Re-sync devices") ----------------------
  // Canonical action id shared across plugins — deviceCount 'N' fans out one step
  // per device via plan.ts; the API treats non-1 counts as multi-device intents.
  {
    id: 'system.clock.sync',
    label: 'Sync or set device clock',
    description:
      "Re-syncs the firewall to its configured NTP source (mode='sync') and/or sets the IANA timezone (mode='set'). Fleet-wide intent — fans out one step per device. 'sync' restarts ntpd so it re-polls its configured servers. NOTE: OPNsense's REST API has no wall-clock setter, so mode='set' only supports the timezone field.",
    module: 'System',
    riskLevel: 'write',
    deviceCount: 'N',
    timeoutMs: 60_000,
    inputSchema: {
      mode: { type: 'string', required: true, enum: ['sync', 'set'], description: "'sync' = re-trigger native NTP; 'set' = manual wall-clock and/or timezone" },
      timeUtc: { type: 'string', description: "ISO-8601 UTC instant for mode='set' (e.g. 2026-10-02T14:30:00Z)" },
      timezone: { type: 'string', description: "IANA zone for mode='set' (e.g. Europe/Berlin); independent of timeUtc" },
    },
    execute: async (ctx, input) => {
      const mode = String(input.mode ?? '').trim();
      if (!['sync', 'set'].includes(mode)) return { success: false, error: "mode must be 'sync' or 'set'." };

      // --- sync: re-trigger native NTP ---------------------------------------
      if (mode === 'sync') {
        const res = await ntpd.restartService(ctx.client);
        if (!res.ok) return { success: false, error: `ntpd restart failed (HTTP ${res.status})` };
        // Best-effort read of the current wall clock for the result details.
        const t = await sys.getSystemTime(ctx.client).catch(() => null);
        const d = t ? dataOf(t) ?? {} : {};
        return { success: true, applied: true, details: { mode: 'sync', note: 'ntpd restarted — re-syncing to configured servers.', systemTime: d['system_time'] ?? d['time'] ?? null } };
      }

      // --- set: timezone (wall-clock NOT available over OPNsense REST) --------
      const timeUtc = typeof input.timeUtc === 'string' && input.timeUtc.trim() ? input.timeUtc.trim() : undefined;
      const tz = typeof input.timezone === 'string' && input.timezone.trim() ? input.timezone.trim() : undefined;
      if (!timeUtc && !tz) return { success: false, error: "mode 'set' requires at least one of timeUtc or timezone." };
      if (timeUtc && !tz) {
        return { success: false, error: "OPNsense's REST API has no wall-clock setter — only the timezone can be set. Use mode='sync' to re-sync via NTP instead." };
      }
      // IANA identifiers are [A-Za-z0-9_+-/]; reject anything else before it hits the API.
      if (!tz || !/^[A-Za-z][A-Za-z0-9_+-]*(\/[A-Za-z0-9_+-]+)*$/.test(tz)) return { success: false, error: 'Invalid timezone identifier.' };

      const res = await sys.setSystemTimezone(ctx.client, tz);
      if (!res.ok) return { success: false, error: `Setting timezone failed (HTTP ${res.status})` };
      // Verify by re-reading the configured zone.
      const check = await sys.getSystemTimezone(ctx.client).catch(() => null);
      const cd = check ? dataOf(check) ?? {} : {};
      return { success: true, applied: true, verified: String(cd['timezone'] ?? '') === tz, details: { mode: 'set', timezone: tz, reported: cd['timezone'] ?? null } };
    },
  },
];
