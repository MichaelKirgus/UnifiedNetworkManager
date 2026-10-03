/**
 * The TrueNAS action registry — first config-capable release of this plugin.
 * Serves two entry points (same contract as the other plugins):
 *  - /discover → listCatalog() (the catalog the API persists + validates)
 *  - /config   → getAction(step.actionId).execute(ctx, input) runs one step
 *
 * All methods are documented TrueNAS JSON-RPC calls (api.truenas.com /
 * middleware source): system.info, pool.query, interface.query for reads;
 * system.reboot(reason, {delay}) and system.shutdown(reason, {delay}) for the
 * DANGEROUS power actions — both FULL_ADMIN jobs that drop our socket as the
 * appliance goes down (a job id or a transport error after dispatch both mean
 * "initiated").
 */

import { randomBytes } from 'node:crypto';
import { ActionDescriptor, ActionResult, compareVersions, configBackupFileName, createFileRepoClient, createRegistry, dynamicSshHostVerifier, FileRepoClient, INTENT_L2_TOPOLOGY_READ, INTENT_NETWORK_CREATE, INTENT_NETWORK_DELETE, L2Topology, pickNumber, pickString, pollUntil, PreflightResult, resolveSshCredentials, SshError } from '@unm/plugin-sdk';
import { TruenasClient, TruenasCredentials, TruenasRpcError } from './client/truenasClient';
import { hostSshPort, normalizeVmDevice, sshPool } from './enrich';
import { fsSftpPool } from './index';

/** Executor context for one /config step. */
export interface TruenasActionContext {
  client: TruenasClient;
  creds: TruenasCredentials;
  /** The device management address (host[:port]) — needed by actions that reach the appliance over a different channel than the RPC socket (e.g. SSH for container logs). */
  host?: string;
  /** UNM's device id for this step — recorded in audit trails (e.g. file-repo usage rows). */
  deviceId?: string | null;
  /** UNM's device display name (sent by the API on /config) — labels artifacts like config backups. */
  deviceName?: string | null;
  /** The request's raw `credentials` body (primary secret + bound slots) — needed by actions that use a slot distinct from the primary (e.g. SSH for container logs). */
  rawCredentials?: Record<string, unknown> | null;
  /** Plugin option `uploadViaSftp` (default true) — stream file-repo uploads over SFTP instead of /_upload when an ssh slot is bound. */
  uploadViaSftp?: boolean;
}

function str(input: Record<string, unknown>, key: string): string | undefined {
  const v = input[key];
  return typeof v === 'string' && v.length > 0 ? v : undefined;
}

/** TrueNAS job methods (reboot/shutdown) resolve to a JOB ID — the work runs server-side. */
function describeJobResult(result: unknown): Record<string, unknown> {
  if (typeof result === 'number') return { jobId: result, note: 'Accepted as an asynchronous job — the appliance will go down shortly.' };
  if (result && typeof result === 'object' && typeof (result as Record<string, unknown>)['id'] === 'number') {
    const r = result as Record<string, unknown>;
    return { jobId: r['id'], note: 'Accepted as an asynchronous job — the appliance will go down shortly.' };
  }
  return {};
}

/**
 * Stable dedupe key for one alert (class + subject) — shared by index.ts (which
 * mirrors active alerts into the UNM notification center, where the API prefixes
 * it with `plugin:<uuid>:`) and the `alerts.dismiss` action below (which matches
 * UNM rows back to appliance alerts). Args are usually `[diskName]` or
 * `{name: ...}` — take the first string-ish piece as the subject so e.g.
 * "SMART uncorrected errors on da0" dedupes per disk.
 */
export function alertDedupeKey(klass: string, argsRaw: unknown): string {
  let subject = '';
  if (Array.isArray(argsRaw) && argsRaw.length > 0) {
    const first = argsRaw[0];
    subject = typeof first === 'string' ? first : pickString((first ?? {}) as Record<string, unknown>, ['name', 'disk']) ?? '';
  } else if (argsRaw && typeof argsRaw === 'object') {
    subject = pickString(argsRaw as Record<string, unknown>, ['name', 'disk']) ?? '';
  }
  return `alert:${klass}:${subject}`.toLowerCase();
}

const systemInfoAction: ActionDescriptor<TruenasActionContext> = {
  id: 'system.info.read',
  label: 'Read system information',
  description: 'Fetches hostname, version, CPU load, memory and uptime from system.info.',
  module: 'System',
  riskLevel: 'read' as const,
  deviceCount: 1 as const,
  inputSchema: {},
  async execute(ctx: TruenasActionContext): Promise<ActionResult> {
    const si = await ctx.client.call<Record<string, unknown>>('system.info', [], ctx.creds);
    return { success: true, details: { systemInfo: si } };
  },
};

const poolsReadAction: ActionDescriptor<TruenasActionContext> = {
  id: 'pools.read',
  label: 'Read ZFS pool status',
  description: 'Fetches all pools with size/used/free and scrub state from pool.query.',
  module: 'Storage',
  riskLevel: 'read' as const,
  deviceCount: 1 as const,
  inputSchema: {},
  async execute(ctx: TruenasActionContext): Promise<ActionResult> {
    const pools = await ctx.client.call<Record<string, unknown>[]>('pool.query', [], ctx.creds);
    return { success: true, details: { poolCount: pools.length } };
  },
};

const interfacesReadAction: ActionDescriptor<TruenasActionContext> = {
  id: 'interfaces.read',
  label: 'Read network interfaces',
  description: 'Fetches all interfaces with link state, MAC and IP aliases from interface.query.',
  module: 'Network',
  riskLevel: 'read' as const,
  deviceCount: 1 as const,
  inputSchema: {},
  async execute(ctx: TruenasActionContext): Promise<ActionResult> {
    const ifaces = await ctx.client.call<Record<string, unknown>[]>('interface.query', [], ctx.creds);
    return { success: true, details: { interfaceCount: ifaces.length } };
  },
};

const systemRebootAction: ActionDescriptor<TruenasActionContext> = {
  id: 'system.reboot',
  label: 'Reboot the appliance',
  description:
    'Gracefully reboots TrueNAS (documented `system.reboot` job, FULL_ADMIN). The WebSocket drops as the box goes down — a job id or a transport error after dispatch both mean "initiated".',
  module: 'System',
  riskLevel: 'dangerous' as const,
  deviceCount: 1 as const,
  timeoutMs: 60_000,
  // Flapping guard — a failed reboot must never be re-dispatched (it would
  // power-cycle the appliance again). The socket drop on success is expected.
  retryOnDispatchFailure: false,
  inputSchema: {
    reason: { type: 'string', required: true, minLength: 3, maxLength: 200, description: 'Reason recorded in the appliance audit log' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const reason = str(input, 'reason') ?? 'Reboot initiated from Unified Network Manager';
    try {
      const result = await ctx.client.call<unknown>('system.reboot', [reason, {}], ctx.creds);
      return { success: true, applied: true, details: describeJobResult(result) };
    } catch (e) {
      // The socket dies mid-job when the appliance powers off — that is EXPECTED.
      if (e instanceof TruenasRpcError && /timed out|closed|unresponsive/i.test(e.message)) {
        return { success: true, applied: true, details: { note: 'Reboot initiated — connection lost as expected while the appliance went down.' } };
      }
      throw e;
    }
  },
};

const systemTimezoneReadAction: ActionDescriptor<TruenasActionContext> = {
  id: 'system.timezone.read',
  label: 'Read timezone + NTP servers',
  description: 'Fetches the configured IANA timezone (system.general.config) and active NTP servers for the Time page.',
  module: 'System',
  riskLevel: 'read' as const,
  deviceCount: 1 as const,
  inputSchema: {},
  async execute(ctx: TruenasActionContext): Promise<ActionResult> {
    const [general, ntp] = await Promise.all([
      ctx.client.call<Record<string, unknown>>('system.general.config', [], ctx.creds),
      ctx.client.call<unknown>('system.ntpserver.get_config', [], ctx.creds).catch(() => null),
    ]);
    return { success: true, details: { timezone: pickString(general as Record<string, unknown>, ['timezone']) ?? null, ntp } };
  },
};

const systemTimezoneSetAction: ActionDescriptor<TruenasActionContext> = {
  id: 'system.timezone.set',
  label: 'Set device timezone',
  description:
    'Changes the appliance IANA timezone via `system.general.update` (e.g. "Europe/Berlin"). Reversible; does NOT force UTC — it sets whatever zone you choose.',
  module: 'System',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 30_000,
  inputSchema: {
    timezone: { type: 'string', required: true, minLength: 2, maxLength: 64, description: 'IANA timezone identifier (e.g. "Europe/Berlin", "UTC")' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const tz = str(input, 'timezone');
    if (!tz) throw new Error('timezone is required');
    // system.general.update takes a PARTIAL object — only the fields we change.
    // Transport-tolerant — a lost response is confirmed by re-reading the config (the zone must match).
    const dr = await dispatchWrite(ctx, 'system.general.update', [{ timezone: tz }], {
      verify: async () => {
        try {
          const general = await ctx.client.call<Record<string, unknown>>('system.general.config', [], ctx.creds);
          return pickString(general as Record<string, unknown>, ['timezone']) === tz; // matches — applied
        } catch {
          return null;
        }
      },
    });
    return { success: true, applied: true, details: { timezone: tz, ...(dr.note ? { transportNote: dr.note } : {}) } };
  },
};

/**
 * Fleet clock re-sync — canonical id shared across plugins. TrueNAS specifics
 * (verified against truenas/middleware source):
 *  - mode='sync' : ensure the requested NTP servers are configured
 *    (`system.ntpserver.create` for missing ones) and RESTART ntpd via
 *    `service.control RESTART ntpd` — chrony re-reads its config and re-syncs.
 *    Every write is PERSISTED in the middleware DB (survives reboot).
 *  - mode='set'  : timezone only (`system.general.update {timezone}` — persisted,
 *    applied via timedatectl + timeservices reload). The public API has NO
 *    wall-clock setter: chrony owns the clock, and a raw `date -s` over SSH is
 *    not saved by the middleware (it gets clobbered on the next sync/reboot).
 */
const systemClockSyncAction: ActionDescriptor<TruenasActionContext> = {
  id: 'system.clock.sync',
  label: 'Sync or set device clock',
  description:
    "Re-syncs the appliance to its NTP source (mode='sync') and/or sets the IANA timezone (mode='set'). Fleet-wide intent — fans out one step per device. NOTE: TrueNAS's public API has no wall-clock setter, so mode='set' only supports the timezone field.",
  module: 'System',
  riskLevel: 'write' as const,
  deviceCount: 'N' as const,
  timeoutMs: 120_000,
  inputSchema: {
    mode: { type: 'string', required: true, enum: ['sync', 'set'], description: "'sync' = re-trigger native NTP; 'set' = manual wall-clock and/or timezone" },
    timeUtc: { type: 'string', description: "ISO-8601 UTC instant for mode='set' (e.g. 2026-10-02T14:30:00Z)" },
    timezone: { type: 'string', description: "IANA zone for mode='set' (e.g. Europe/Berlin); independent of timeUtc" },
    servers: { type: 'array', items: { type: 'string' }, description: "Optional NTP server list for mode='sync' — missing ones are added to the appliance's NTP config" },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const mode = str(input, 'mode')?.trim();
    if (!['sync', 'set'].includes(mode ?? '')) return { success: false, details: { error: "mode must be 'sync' or 'set'" } };

    // --- sync: ensure NTP servers + restart ntpd (chrony re-syncs) -------------
    if (mode === 'sync') {
      const servers = Array.isArray(input.servers) ? input.servers.map((s) => String(s).trim()).filter(Boolean) : [];

      let created: string[] = [];
      if (servers.length > 0) {
        // Read the current config — shape is `{ enable, servers: [{id, address, ...}] }`.
        const cfg = await ctx.client.call<Record<string, unknown>>('system.ntpserver.get_config', [], ctx.creds);
        const existing = Array.isArray(cfg?.['servers']) ? (cfg['servers'] as Record<string, unknown>[]) : [];
        for (const addr of servers) {
          if (existing.some((s) => pickString(s, ['address']) === addr)) continue;
          // create is a transport-tolerant write — idempotent enough to re-dispatch on drop.
          await dispatchWrite(ctx, 'system.ntpserver.create', [{ address: addr }], { idempotentRetry: true });
          created.push(addr);
        }
      }

      // Restart ntpd so chrony re-reads its config and re-syncs NOW (job-based).
      const notes: string[] = [];
      let jobId: number | null = null;
      try {
        const dr = await dispatchWrite(ctx, 'service.control', ['RESTART', 'ntpd'], {
          verify: async () => {
            try { return !!(await ctx.client.call<boolean>('service.started', ['ntpd'], ctx.creds)); } catch { return null; }
          },
        });
        if (dr.note) notes.push(dr.note);
        const r = dr.value;
        if (typeof r === 'number') jobId = r;
        else if (r && typeof r === 'object' && typeof (r as Record<string, unknown>)['id'] === 'number') {
          jobId = (r as Record<string, unknown>)['id'] as number;
        }
      } catch (e) {
        return { success: false, details: { error: `ntpd restart failed: ${e instanceof Error ? e.message : String(e)}` } };
      }

      let waitState = 'UNKNOWN';
      if (jobId !== null) {
        const wait = await waitForJob(ctx, jobId, 90_000);
        waitState = wait.state;
        if (wait.state === 'RUNNING') {
          return { success: true, applied: true, details: { mode: 'sync', note: 'ntpd restart job still running — check the appliance shortly.', created } };
        }
        if (wait.state !== 'SUCCESS' && wait.state !== 'FINISHED') {
          return { success: false, details: { mode: 'sync', error: `ntpd restart job ended in state ${waitState}`, jobId, waitError: wait.error ?? undefined } };
        }
      }

      let verified = false;
      try { verified = !!(await ctx.client.call<boolean>('service.started', ['ntpd'], ctx.creds)); } catch { /* best-effort */ }
      const note = created.length > 0 ? `Added ${created.length} NTP server(s); ntpd restarted — re-syncing.` : 'ntpd restarted — re-syncing to its configured servers.';
      return { success: true, applied: true, verified, details: { mode: 'sync', note, created, jobId, state: waitState, ...(notes.length > 0 ? { notes } : {}) } };
    }

    // --- set: timezone only (NO wall-clock setter in the public API) -----------
    const timeUtc = str(input, 'timeUtc');
    const tz = str(input, 'timezone');
    if (!timeUtc && !tz) return { success: false, details: { error: "mode 'set' requires at least one of timeUtc or timezone" } };
    if (timeUtc && !tz) {
      return { success: false, details: { error: "TrueNAS's public API has no wall-clock setter — only the timezone can be set. Use mode='sync' to re-sync via NTP instead." } };
    }

    const dr = await dispatchWrite(ctx, 'system.general.update', [{ timezone: tz! }], {
      verify: async () => {
        try {
          const general = await ctx.client.call<Record<string, unknown>>('system.general.config', [], ctx.creds);
          return pickString(general as Record<string, unknown>, ['timezone']) === tz; // matches — applied
        } catch {
          return null;
        }
      },
    });
    const notes: string[] = [];
    if (dr.note) notes.push(dr.note);
    return { success: true, applied: true, verified: !dr.unconfirmed, details: { mode: 'set', timezone: tz, ...(notes.length > 0 ? { notes } : {}) } };
  },
};

const systemShutdownAction: ActionDescriptor<TruenasActionContext> = {
  id: 'system.shutdown',
  label: 'Shut down the appliance',
  description:
    'Gracefully powers off TrueNAS (documented `system.shutdown` job, FULL_ADMIN). The WebSocket drops as the box goes down — a job id or a transport error after dispatch both mean "initiated".',
  module: 'System',
  riskLevel: 'dangerous' as const,
  deviceCount: 1 as const,
  timeoutMs: 60_000,
  // Flapping guard — a failed shutdown must never be re-dispatched.
  retryOnDispatchFailure: false,
  inputSchema: {
    reason: { type: 'string', required: true, minLength: 3, maxLength: 200, description: 'Reason recorded in the appliance audit log' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const reason = str(input, 'reason') ?? 'Shutdown initiated from Unified Network Manager';
    try {
      const result = await ctx.client.call<unknown>('system.shutdown', [reason, {}], ctx.creds);
      return { success: true, applied: true, details: describeJobResult(result) };
    } catch (e) {
      if (e instanceof TruenasRpcError && /timed out|closed|unresponsive/i.test(e.message)) {
        return { success: true, applied: true, details: { note: 'Shutdown initiated — connection lost as expected while the appliance went down.' } };
      }
      throw e;
    }
  },
};

/**
 * Firmware update (TrueNAS `update.run` job — FULL_ADMIN). Downloads the target
 * release (if not already cached) and applies it as a NEW boot environment; the
 * appliance reboots into it at the end of the job. The WebSocket drops when the
 * box goes down — same "initiated" convention as system.reboot: a job id or a
 * transport error after dispatch both mean success. Post-apply verification is
 * impossible from this side (the connection dies with the old OS), so `verified`
 * stays undefined and the plan reports it unverified-by-design; the next
 * inventory poll re-reads system.info + update.available_versions, and once the
 * box is back on the new version the Updates-page row disappears.
 */
const systemFirmwareUpdateAction: ActionDescriptor<TruenasActionContext> = {
  id: 'system.firmware.update',
  label: 'Update firmware (OS)',
  description:
    "Downloads and applies a TrueNAS OS update via `update.run` (FULL_ADMIN job). The appliance reboots into the new boot environment when done — expect downtime. Omit version to use the newest release matching the box's configured update profile.",
  module: 'System',
  riskLevel: 'dangerous' as const,
  deviceCount: 1 as const,
  timeoutMs: 3_600_000, // multi-GB downloads + install can exceed an hour on slow links
  // Flapping guard — a failed firmware update must never be re-dispatched (it
  // would flash the OS again). The socket drop on success is expected.
  retryOnDispatchFailure: false,
  inputSchema: {
    version: { type: 'string', required: false, minLength: 2, description: 'Target release (e.g. "25.10.1"); omit for the newest matching the configured update profile' },
    train: { type: 'string', required: false, minLength: 2, description: "Update train override (e.g. \"TrueNAS-26-BETA\"); omit to keep the box's configured profile" },
    // TrueNAS's UpdateRunAttrs.reboot DEFAULTS TO FALSE — without it the job
    // downloads + installs a new boot environment and then just… stops, leaving
    // the appliance running the old OS (observed live on SRV03 25.10.4: update.run
    // [{}] → jobId accepted, box never rebooted). The Web UI always reboots after
    // an update, so we do too by default; set false to install-only.
    reboot: { type: 'boolean', required: false, default: true, description: 'Reboot into the new boot environment when the update is applied (TrueNAS default is NO — this must be passed explicitly)' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const version = str(input, 'version');
    const train = str(input, 'train');
    // Default TRUE — see the schema note: TrueNAS's own default is false, which
    // silently leaves the box on the old OS after a successful install.
    const reboot = input['reboot'] !== false;

    // Idempotency guard — already on the requested release (or newer) → no-op.
    // Older releases prefix system.info's version with "SCALE "/"CORE ".
    let current: string | undefined;
    try {
      const si = await ctx.client.call<Record<string, unknown>>('system.info', [], ctx.creds);
      current = pickString(si, ['version'])?.replace(/^(scale|core)\s+/i, '').trim();
    } catch { /* best-effort guard — update.run will reject a no-op anyway */ }
    if (current && version && compareVersions(current, version) >= 0) {
      return { success: true, applied: false, verified: true, details: { note: `Already on ${version} (or newer) — nothing to do.`, currentVersion: current } };
    }

    const options: Record<string, unknown> = { reboot }; // REQUIRED — TrueNAS defaults it to false (install-only)
    if (train) options['train'] = train;
    if (version) options['version'] = version;

    // Second idempotency layer — the one that hid SRV03's stuck state (2026-10-03):
    // a boot environment for the target version may ALREADY EXIST (an earlier
    // install-only run, or an update.run whose reboot leg never fired). Re-running
    // update.run then fails INSIDE the appliance job ("already installed") AFTER we
    // have already returned success with a jobId — invisible to UNM. So: skip the
    // download/install entirely and just (re)activate + boot into what's there.
    if (version) {
      let beq: { rows: BootEnvRow[]; namespace: string } | null = null;
      try {
        beq = await queryBootEnvs(ctx); // best-effort pre-check — a failure falls through to update.run
      } catch { /* pre-check only */ }
      const existing = beq?.rows.find((r) => r.id === version);
      if (beq && existing) {
        if (!reboot) {
          return { success: true, applied: false, verified: true, details: { note: `Boot environment ${version} is already installed — nothing to install. Reboot the box to enter it (or use bootenv.activate).`, currentVersion: current } };
        }
        // REAL errors from here on must surface — do NOT fall through to update.run.
        // Re-activating an already-activated BE is a no-op (25.10.x answers EINVAL for it).
        try {
          await ctx.client.call<unknown>(`${beq.namespace}.activate`, [{ id: version }], ctx.creds);
        } catch (e3) {
          if (!(e3 instanceof TruenasRpcError && /already activated/i.test(e3.message))) throw e3;
        }
        try {
          const rb = await ctx.client.call<unknown>('system.reboot', ['System upgrade (UNM — boot environment already installed)', {}], ctx.creds);
          return { success: true, applied: true, details: { note: `Boot environment ${version} was already installed — activated and rebooting into it. Unreachable while down; verification is impossible by design.` }, ...(describeJobResult(rb) as Record<string, unknown>) };
        } catch (e2) {
          if (e2 instanceof TruenasRpcError && /timed out|closed|unresponsive/i.test(e2.message)) {
            return { success: true, applied: true, details: { note: `Boot environment ${version} was already installed — reboot initiated; connection lost as expected while the appliance went down.` } };
          }
          throw e2;
        }
      }
    }

    try {
      const result = await ctx.client.call<unknown>('update.run', [options], ctx.creds);
      if (reboot) {
        // The appliance reboots itself inside the job — we cannot observe its outcome.
        return { success: true, applied: true, details: describeJobResult(result) };
      }
      // Install-only: WAIT for the real job outcome so a failed install is reported as
      // FAILURE (SRV03 incident 2026-10-03: jobId accepted, the job died ~20 min later
      // on an already-installed BE, and the plan still said "succeeded").
      const jid = typeof result === 'number' ? result : (result && typeof result === 'object' && typeof (result as Record<string, unknown>)['id'] === 'number') ? ((result as Record<string, unknown>)['id'] as number) : null;
      if (jid !== null) {
        const wait = await waitForJob(ctx, jid, 3_500_000);
        if (wait.state === 'RUNNING') return { success: true, applied: true, details: { jobId: jid, note: wait.error ?? 'Update job still in progress on the appliance.' } };
        if (wait.state !== 'SUCCESS' && wait.state !== 'FINISHED') return { success: false, details: { jobId: jid, error: wait.error ?? `Job ended in state ${wait.state}` } };
      }
      // Confirm the new BE actually exists when we know its name.
      let verified = false;
      if (version) {
        try { verified = (await queryBootEnvs(ctx)).rows.some((r) => r.id === version); } catch { /* best-effort */ }
      }
      return { success: true, applied: true, verified, details: { ...(jid !== null ? { jobId: jid } : {}), note: 'Update installed — NO reboot performed (install-only). The new boot environment is active at the next manual reboot.' } };
    } catch (e) {
      // The socket dies when the appliance reboots into the new boot environment — EXPECTED.
      if (e instanceof TruenasRpcError && /timed out|closed|unresponsive/i.test(e.message)) {
        return { success: true, applied: true, details: { note: 'Update initiated — connection lost as expected while the appliance rebooted.' } };
      }
      throw e;
    }
  },
};

// ---------------------------------------------------------------------------
// Configuration backup / restore — TrueNAS's own "Manage Configuration" feature
// (System → Advanced in the Web UI), exposed as plan actions so UNM can take a
// rollback point before risky changes and restore from one later. The file does
// NOT travel over JSON-RPC: it goes through middlewared's HTTP FileApplication
// endpoints on the same port as /api/current (verified against truenas/middleware
// source — apps/file_app.py + api/v26_0_0/config.py):
//   backup  = `config.save` job → mint single-use token for that job → GET
//             /_download/{jobId}?auth_token=… → raw bytes
//   restore = multipart POST /_upload — part 1 MUST be field "data" carrying
//             {"method":"config.upload","params":[]}, part 2 MUST be file field
//             "file" → {job_id}. Replaces the ENTIRE configuration database.
// The Web UI reboots after a successful upload (it navigates to the restart
// page) — we do the same via system.reboot so the restored config takes effect.

/** Decodes a base64 file payload from plan input (same contract as the SwOS plugin's file actions). */
function decodeFilePayload(input: Record<string, unknown>, maxBytes = 512 * 1024 * 1024): { data: Buffer; fileName: string } | { error: string } {
  const b64 = input['fileBase64'];
  if (typeof b64 !== 'string' || b64.length === 0) return { error: 'fileBase64 is required — the file content as base64' };
  let data: Buffer;
  try {
    data = Buffer.from(b64, 'base64');
  } catch (e) {
    return { error: `Invalid base64 in fileBase64: ${e instanceof Error ? e.message : String(e)}` };
  }
  if (data.length === 0) return { error: 'fileBase64 decoded to an empty file' };
  if (data.length > maxBytes) return { error: `File is ${(data.length / 1024 / 1024).toFixed(1)} MB — exceeds the ${maxBytes / 1024 / 1024} MB limit` };
  const fileName = typeof input['fileName'] === 'string' && (input['fileName'] as string).length > 0 ? (input['fileName'] as string) : 'config-backup';
  return { data, fileName };
}

const configBackupDownloadAction: ActionDescriptor<TruenasActionContext> = {
  id: 'config.backup.download',
  label: 'Download configuration backup',
  description:
    "Creates a full configuration backup on the appliance (TrueNAS `config.save` job — the same file the Web UI's System → Advanced → Manage Configuration downloads) and returns it base64-encoded in details. Read-only on the device; use as a rollback point before risky changes or to clone a config.",
  module: 'System',
  riskLevel: 'read' as const,
  deviceCount: 1 as const,
  timeoutMs: 300_000, // config.save is an appliance job — large configs can take a while
  inputSchema: {
    secretseed: { type: 'boolean', required: false, default: false, description: "Include the system's secret seed in the backup" },
    pool_keys: { type: 'boolean', required: false, default: false, description: 'Include ZFS pool encryption keys (needed to restore encrypted pools on another box)' },
    root_authorized_keys: { type: 'boolean', required: false, default: false, description: "Include root's SSH authorized_keys in the backup" },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const options: Record<string, unknown> = {};
    for (const k of ['secretseed', 'pool_keys', 'root_authorized_keys'] as const) {
      if (input[k] === true) options[k] = true; // defaults are false — only send explicit trues
    }

    // 1. Start the backup via core.download — on TrueNAS 25.10+ (v26 API) a plain
    //    JSON-RPC call to config.save fails with "Pipe 'output' is not open" because
    //    it is a pipe job; core.download OPENS the output pipe and returns
    //    [jobId, "/_download/{id}?auth_token=…"] (the same path the Web UI uses).
    //    buffered=true: the job's output is spooled in RAM until completion and the
    //    URL stays valid for 3600s — with the default (buffered=false) the job BLOCKS
    //    until a client downloads or 60s elapse, so waiting for the job first would
    //    deadlock it into "[Errno 32] Broken pipe".
    let jobId: number | null = null;
    let downloadPath: string | null = null;
    try {
      const r = await ctx.client.call<unknown>('core.download', ['config.save', [options], 'truenas-config-backup', true], ctx.creds);
      if (Array.isArray(r) && typeof r[0] === 'number' && typeof r[1] === 'string') {
        jobId = r[0];
        downloadPath = r[1];
      } else {
        throw new Error('core.download did not return [jobId, url]');
      }
    } catch (e) {
      // Legacy fallback (pre-25.10): config.save as a plain job + minted token.
      try {
        const r = await ctx.client.call<unknown>('config.save', [options], ctx.creds);
        if (typeof r === 'number') jobId = r;
        else if (r && typeof r === 'object' && typeof (r as Record<string, unknown>)['id'] === 'number') jobId = (r as Record<string, unknown>)['id'] as number;
      } catch (e2) {
        return { success: false, details: { error: `Could not start config.save: ${e2 instanceof Error ? e2.message : String(e2)} (core.download: ${e instanceof Error ? e.message : String(e)})` } };
      }
    }
    if (jobId === null) return { success: false, details: { error: 'config.save did not return a job id' } };

    // 2. Wait for the job to settle — middlewared buffers the pipe output until it is downloaded.
    const wait = await waitForJob(ctx, jobId, 180_000);
    if (wait.state === 'RUNNING') return { success: false, details: { jobId, error: `config.save job still running after ${Math.round(180_000 / 1000)}s` } };
    if (wait.state !== 'SUCCESS' && wait.state !== 'FINISHED') return { success: false, details: { jobId, error: wait.error ?? `Job ended in state ${wait.state}` } };

    // 3. Fetch the file over HTTP — core.download's URL already carries a single-use
    //    token; on the legacy path mint one via auth.generate_token.
    let data: Buffer;
    try {
      if (downloadPath) {
        data = await ctx.client.downloadAtPath(downloadPath);
      } else {
        const t = await ctx.client.call<unknown>('auth.generate_token', [null, { job: jobId, filename: 'config-backup' }], ctx.creds);
        if (typeof t !== 'string' || t.length === 0) throw new Error('auth.generate_token returned no token');
        data = await ctx.client.downloadJobFile(jobId, t);
      }
    } catch (e) {
      return { success: false, details: { jobId, error: e instanceof Error ? e.message : String(e) } };
    }
    if (data.length === 0) return { success: false, details: { jobId, error: 'Appliance returned an empty backup file' } };

    // Store the backup in UNM's central file repository so it is downloadable /
    // archivable from the Files page — no more base64 blobs buried in step results.
    // Named with the shared SDK convention (<device>__config-backup-<UTC-ts>.db).
    const fileName = configBackupFileName({ device: ctx.deviceName, host: ctx.host, ext: 'db' });
    let repoFileId: string | null = null;
    try {
      const entry = await fileRepo().upload(data, { name: fileName, category: 'config-backup' }, 120_000);
      repoFileId = entry.id;
      void fileRepo().recordUse(entry.id, { deviceId: ctx.deviceId ?? undefined, note: `config backup of ${ctx.host ?? 'appliance'} (config.save)` }).catch(() => undefined);
    } catch (e) {
      // The repo is a convenience — a failed store must not fail the backup itself.
      return {
        success: true,
        verified: true,
        details: {
          sizeBytes: data.length,
          fileName,
          options,
          warning: `Backup downloaded but could NOT be stored in the UNM file repository: ${e instanceof Error ? e.message : String(e)}`,
          // Fallback so a restore can still reference the bytes (legacy contract).
          backupBase64: data.toString('base64'),
        },
      };
    }

    return {
      success: true,
      verified: true,
      details: {
        sizeBytes: data.length,
        fileName,
        options,
        // Reference the stored backup by repo id — restore it with config.restore {repoFileId}.
        repoFileId,
      },
    };
  },
};

const configRestoreAction: ActionDescriptor<TruenasActionContext> = {
  id: 'config.restore',
  label: 'Restore configuration from backup file',
  description:
    "DANGEROUS — replaces the appliance's ENTIRE configuration database with the given backup file (TrueNAS `config.upload` via the /_upload multipart endpoint, exactly what the Web UI's Manage Configuration → Upload does). The box reboots into the restored configuration afterwards. Pair with config.backup.download as a rollback point. Source: a UNM file-repo id in `repoFileId` (preferred — e.g. ${steps[N].result.details.repoFileId} from an earlier backup step) or raw base64 in `fileBase64`. The appliance is unreachable while it reboots — verification is impossible by design.",
  module: 'System',
  riskLevel: 'dangerous' as const,
  deviceCount: 1 as const,
  timeoutMs: 300_000, // upload + config swap; the box then reboots on its own
  // Flapping guard — a failed restore must never be re-dispatched (it would
  // overwrite the config DB again and reboot). The socket drop is expected.
  retryOnDispatchFailure: false,
  inputSchema: {
    repoFileId: { type: 'string', required: false, minLength: 1, description: 'UNM file-repo id of a backup (e.g. from config.backup.download details.repoFileId) — preferred over fileBase64' },
    fileBase64: { type: 'string', required: false, minLength: 8, description: 'The configuration backup file as base64 (legacy path; use repoFileId when the file is in the UNM repository)' },
    fileName: { type: 'string', required: false, maxLength: 200, description: 'Original file name (informational only)' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    // Preferred source: a backup already in UNM's central file repository.
    const repoFileId = str(input, 'repoFileId');
    let payload: { data: Buffer; fileName: string };
    if (repoFileId) {
      try {
        const meta = await fileRepo().getMeta(repoFileId);
        if (!meta) return { success: false, details: { error: `Unknown file-repo id ${repoFileId}` } };
        payload = { data: await fileRepo().get(repoFileId), fileName: str(input, 'fileName') ?? meta.name };
      } catch (e) {
        return { success: false, details: { error: `Could not fetch repo file ${repoFileId}: ${e instanceof Error ? e.message : String(e)}` } };
      }
    } else {
      const b64 = typeof input.fileBase64 === 'string' ? (input.fileBase64 as string) : '';
      if (!b64.trim()) return { success: false, details: { error: 'Either repoFileId or fileBase64 is required' } };
      const decoded = decodeFilePayload(input);
      if ('error' in decoded) return { success: false, details: { error: decoded.error } };
      payload = decoded;
    }

    let jobId: number | null = null;
    try {
      // Primary path: HTTP Basic auth (username/password credentials). On
      // OTP-enabled appliances the appliance rejects Basic — fall back to a
      // minted single-use token in that case.
      // API-key credentials mint a session token inside uploadFile (never Bearer —
      // TrueNAS 26+ would revoke the key on such an HTTP login); username/password
      // uses Basic, which OTP-enabled appliances reject.
      const r = await ctx.client.uploadFile(ctx.creds, 'config.upload', payload.data, payload.fileName);
      if (typeof r['job_id'] === 'number') jobId = r['job_id'];
    } catch (e) {
      return { success: false, details: { error: `config.upload failed: ${e instanceof Error ? e.message : String(e)}` } };
    }
    if (jobId === null) return { success: false, details: { error: 'config.upload did not return a job id' } };

    // The upload job streams the file into config.upload's input pipe — wait for it to settle.
    const wait = await waitForJob(ctx, jobId, 180_000);
    if (wait.state === 'RUNNING') {
      return { success: true, applied: true, details: { jobId, note: 'Restore job still in progress on the appliance — it will reboot into the restored configuration.' } };
    }
    if (wait.state !== 'SUCCESS' && wait.state !== 'FINISHED') {
      return { success: false, details: { jobId, error: wait.error ?? `Job ended in state ${wait.state}` } };
    }

    // The Web UI reboots after a successful upload — do the same so the restored
    // configuration actually takes effect. Transport errors here are EXPECTED (the box goes down).
    try {
      await ctx.client.call<unknown>('system.reboot', ['Configuration restore from Unified Network Manager', {}], ctx.creds);
    } catch (e) {
      if (!(e instanceof TruenasRpcError && /timed out|closed|unresponsive/i.test(e.message))) throw e;
    }

    return {
      success: true,
      applied: true,
      details: { jobId, fileName: payload.fileName, note: 'Configuration restored — the appliance is rebooting into it. Unreachable while down; verification is impossible by design.' },
    };
  },
};

const configResetAction: ActionDescriptor<TruenasActionContext> = {
  id: 'config.reset',
  label: 'Factory-reset configuration',
  description:
    "DANGEROUS — resets the appliance's configuration to factory defaults (TrueNAS `config.reset` job) and reboots it. All settings, shares, users and app definitions are LOST; ZFS pool data is untouched but pools may need re-importing. Take a config.backup.download first if you want a rollback point.",
  module: 'System',
  riskLevel: 'dangerous' as const,
  deviceCount: 1 as const,
  timeoutMs: 300_000,
  // Flapping guard — a failed factory reset must never be re-dispatched (it
  // would wipe the config again and reboot). The socket drop is expected.
  retryOnDispatchFailure: false,
  inputSchema: {
    reboot: { type: 'boolean', required: false, default: true, description: 'Reboot after the reset (TrueNAS default)' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const reboot = input['reboot'] !== false; // default true — matches TrueNAS's own default
    try {
      const result = await ctx.client.call<unknown>('config.reset', [{ reboot }], ctx.creds);
      return { success: true, applied: true, details: describeJobResult(result) };
    } catch (e) {
      // The socket dies when the appliance reboots — EXPECTED.
      if (e instanceof TruenasRpcError && /timed out|closed|unresponsive/i.test(e.message)) {
        return { success: true, applied: true, details: { note: 'Reset initiated — connection lost as expected while the appliance rebooted.' } };
      }
      throw e;
    }
  },
};

// ---------------------------------------------------------------------------
// Update branch + firmware update from file — TrueNAS's "System → Update" page
// as plan actions (verified against truenas/middleware plugins/update_/ and the
// Web UI's manual-update-form.component.ts):
//   branch  = the appliance's configured UPDATE PROFILE: `update.config` reads
//             it, `update.update {profile}` changes it. Profiles are an ordered
//             enum (profile_.py UpdateProfiles) DEVELOPER < EARLY_ADOPTER <
//             GENERAL < MISSION_CRITICAL; which ones a box OFFERS is
//             license/entitlement-gated → the live choice list comes from
//             `update.profile_choices`. Changing it needs no reboot — it only
//             changes which releases future updates target.
//   file    = manual update: either `path` at an .update file already on the box
//             (`update.manual {path}` job) or base64 content uploaded via /_upload
//             running `update.file [{destination?}]` (same FileApplication endpoint
//             as config.upload; destination = pool mountpoint, null → :temp:).
// Both can fail with the appliance's RESUMABLE [EAGAIN] warning ("an upgrade can
// be performed with a warning and that warning is accepted") — the Web UI shows
// a confirm dialog and re-runs with {resume:true}; we accept it automatically.

/** TrueNAS update profiles, weakest → strongest (profile_.py UpdateProfiles). */
const UPDATE_PROFILES = ['DEVELOPER', 'EARLY_ADOPTER', 'GENERAL', 'MISSION_CRITICAL'] as const;

/** Extracts a job id from an RPC result that may be a bare number or {id}. */
function jobIdOf(result: unknown): number | null {
  if (typeof result === 'number') return result;
  if (result && typeof result === 'object' && typeof (result as Record<string, unknown>)['id'] === 'number') {
    return (result as Record<string, unknown>)['id'] as number;
  }
  return null;
}

/**
 * Starts an update job and waits for it to settle. When the job fails with the
 * appliance's resumable [EAGAIN] warning ("an upgrade can be performed with a
 * warning"), accepts it by re-running `resumeMethod` with `resumeParams` —
 * exactly what the Web UI's confirm-and-continue dialog does (one resume only).
 */
async function runUpdateJobWithResume(
  ctx: TruenasActionContext,
  start: () => Promise<number | null>,
  resumeMethod: string,
  resumeParams: unknown[],
  budgetMs: number,
): Promise<{ jobId: number; state: string; error?: string }> {
  let jobId = await start();
  if (jobId === null) throw new Error('update job did not return a job id');
  let wait = await waitForJob(ctx, jobId, budgetMs);
  const resumable = (wait.state !== 'SUCCESS' && wait.state !== 'FINISHED') && /\[EAGAIN\]/.test(wait.error ?? '');
  if (resumable) {
    const r = await ctx.client.call<unknown>(resumeMethod, resumeParams, ctx.creds);
    const jobId2 = jobIdOf(r);
    if (jobId2 !== null) {
      jobId = jobId2;
      wait = await waitForJob(ctx, jobId, budgetMs);
    }
  }
  return { jobId, state: wait.state, ...(wait.error ? { error: wait.error } : {}) };
}

const updateProfileReadAction: ActionDescriptor<TruenasActionContext> = {
  id: 'update.profile.read',
  label: 'Read update branch (profile)',
  description:
    "Fetches the appliance's configured update profile/branch (`update.config`) plus the profiles it currently offers (`update.profile_choices` — availability is license-gated). Read-only.",
  module: 'System',
  riskLevel: 'read' as const,
  deviceCount: 1 as const,
  inputSchema: {},
  async execute(ctx: TruenasActionContext): Promise<ActionResult> {
    const [cfgRes, choicesRes] = await Promise.allSettled([
      ctx.client.call<Record<string, unknown>>('update.config', [], ctx.creds),
      ctx.client.call<Record<string, Record<string, unknown>>>('update.profile_choices', [], ctx.creds),
    ]);
    if (cfgRes.status !== 'fulfilled') {
      return { success: false, details: { error: cfgRes.reason instanceof Error ? cfgRes.reason.message : String(cfgRes.reason) } };
    }
    const profile = pickString(cfgRes.value, ['profile']);
    const autocheck = typeof cfgRes.value['autocheck'] === 'boolean' ? (cfgRes.value['autocheck'] as boolean) : null;
    let choices: Record<string, unknown>[] | undefined;
    if (choicesRes.status === 'fulfilled' && choicesRes.value && typeof choicesRes.value === 'object') {
      choices = Object.entries(choicesRes.value).map(([name, c]) => ({ name, ...(c as Record<string, unknown>) }));
    }
    return { success: true, details: { profile, autocheck, choices } };
  },
};

const updateProfileSetAction: ActionDescriptor<TruenasActionContext> = {
  id: 'update.profile.set',
  label: 'Change update branch (profile)',
  description:
    "Changes the appliance's configured update profile/branch via `update.update` — the same control as System → Update in the Web UI. Profiles are ordered DEVELOPER < EARLY_ADOPTER < GENERAL < MISSION_CRITICAL; only profiles the box currently offers are accepted (availability is license-gated — check update.profile.read first). No reboot: it changes which releases future updates target.",
  module: 'System',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 30_000,
  inputSchema: {
    profile: { type: 'string', required: true, enum: [...UPDATE_PROFILES], description: "Target update branch (the box's current choice list comes from update.profile.read)" },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const raw = str(input, 'profile');
    if (!raw) return { success: false, details: { error: 'profile is required' } };
    const profile = UPDATE_PROFILES.find((p) => p.toLowerCase() === raw.toLowerCase());
    if (!profile) return { success: false, details: { error: `Unknown profile "${raw}" — expected one of ${UPDATE_PROFILES.join(', ')}` } };
    try {
      // update.update takes a PARTIAL object — only the fields we change.
      // Transport-tolerant — a lost response is confirmed by re-reading the config (the profile must match).
      const dr = await dispatchWrite(ctx, 'update.update', [{ profile }], {
        verify: async () => {
          try {
            const cfg = await ctx.client.call<Record<string, unknown>>('update.config', [], ctx.creds);
            return pickString(cfg, ['profile']) === profile; // matches — applied
          } catch {
            return null;
          }
        },
      });
      const updated = dr.value as Record<string, unknown> | undefined;
      return { success: true, applied: true, details: { profile: pickString(updated ?? {}, ['profile']) ?? profile, note: 'Update branch changed — future updates now target this track. No reboot required.', ...(dr.note ? { transportNote: dr.note } : {}) } };
    } catch (e) {
      // The appliance rejects profiles it does not offer ("Invalid profile." /
      // "This profile is unavailable.") — surface verbatim with a hint.
      return { success: false, details: { error: e instanceof Error ? e.message : String(e), hint: 'Check update.profile.read for the branches this box currently offers (availability is license-gated).' } };
    }
  },
};

const firmwareUpdateFileAction: ActionDescriptor<TruenasActionContext> = {
  id: 'system.firmware.update-file',
  label: 'Update firmware from file',
  description:
    "DANGEROUS — installs a TrueNAS update from an explicit FILE instead of the appliance's update feed (the Web UI's System → Update manual-update flow). Either point `path` at an .update file already on the box (`update.manual {path}` job) or pass the content as base64 in `fileBase64` — it is uploaded via /_upload running `update.file`, staged in `destination` (a pool mountpoint like /mnt/tank; omit for :temp:). The appliance reboots into the new boot environment when done. A resumable [EAGAIN] warning is accepted automatically (one resume), mirroring the Web UI's confirm dialog.",
  module: 'System',
  riskLevel: 'dangerous' as const,
  deviceCount: 1 as const,
  timeoutMs: 7_200_000, // multi-GB update files + install can exceed an hour on slow links
  // Flapping guard — a failed firmware-from-file update must never be re-dispatched.
  retryOnDispatchFailure: false,
  inputSchema: {
    path: { type: 'string', required: false, minLength: 2, description: "Absolute path of an .update file ALREADY on the appliance (e.g. /mnt/tank/TrueNAS-25.10.1.update); omit when passing fileBase64" },
    destination: { type: 'string', required: false, maxLength: 200, description: "Pool mountpoint to stage the uploaded file in (e.g. /mnt/tank); omit for :temp: — only used with fileBase64" },
    fileBase64: { type: 'string', required: false, minLength: 8, description: "The .update file content as base64 (uploaded via the appliance's /_upload endpoint)" },
    fileName: { type: 'string', required: false, maxLength: 200, description: "Original file name (e.g. TrueNAS-25.10.1.update) — used for the upload; defaults to update-file" },
    // The update.manual / update.file jobs have NO reboot parameter — they only
    // install a new boot environment and stop (TrueNAS's own Web UI issues a
    // separate system.reboot afterwards). We mirror that: default true reboots
    // into the new BE once the job succeeds; set false to install-only.
    reboot: { type: 'boolean', required: false, default: true, description: 'Reboot into the new boot environment after the update is installed (the update jobs themselves never reboot)' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const path = str(input, 'path');
    const b64 = typeof input['fileBase64'] === 'string' && (input['fileBase64'] as string).length > 0 ? (input['fileBase64'] as string) : undefined;
    if (!path && !b64) return { success: false, details: { error: 'Either path (a file already on the appliance) or fileBase64 (uploaded content) is required' } };
    // Default TRUE — see schema note: the update jobs never reboot on their own.
    const reboot = input['reboot'] !== false;

    /** Reboots into the new boot environment after a successful install job. */
    const finishWithReboot = async (details: Record<string, unknown>): Promise<ActionResult> => {
      if (!reboot) {
        return { success: true, applied: true, details: { ...details, note: 'Update installed — NO reboot performed (install-only). The new boot environment is active at the next manual reboot.' } };
      }
      try {
        const r = await ctx.client.call<unknown>('system.reboot', ['System upgrade (UNM firmware update from file)', {}], ctx.creds);
        return { success: true, applied: true, details: { ...details, note: 'Update installed — reboot initiated into the new boot environment. Unreachable while down; verification is impossible by design.' }, ...(describeJobResult(r) as Record<string, unknown>) };
      } catch (e) {
        // The socket dies when the appliance reboots — EXPECTED.
        if (e instanceof TruenasRpcError && /timed out|closed|unresponsive/i.test(e.message)) {
          return { success: true, applied: true, details: { ...details, note: 'Update installed — reboot initiated; connection lost as expected while the appliance went down.' } };
        }
        throw e;
      }
    };

    // Idempotency guard — already at/above the target version named in the file
    // ("TrueNAS-25.10.1.update" → 25.10.1). Best-effort only.
    let current: string | undefined;
    try {
      const si = await ctx.client.call<Record<string, unknown>>('system.info', [], ctx.creds);
      current = pickString(si, ['version'])?.replace(/^(scale|core)\s+/i, '').trim();
    } catch { /* best-effort guard */ }
    if (current) {
      const name = str(input, 'fileName') ?? path?.split('/').pop() ?? '';
      const m = name.match(/(\d+\.\d+(?:\.\d+)?)/);
      if (m && compareVersions(current, m[1]) >= 0) {
        return { success: true, applied: false, verified: true, details: { note: `Already on ${current} — the file targets ${m[1]} (or older), nothing to do.` } };
      }
    }

    if (path) {
      // File already lives on the appliance → update.manual job.
      const r = await runUpdateJobWithResume(ctx, async () => jobIdOf(await ctx.client.call<unknown>('update.manual', [{ path }])), 'update.manual', [{ path, resume: true }], 3_600_000);
      if (r.state === 'RUNNING') return { success: true, applied: true, details: { jobId: r.jobId, note: reboot ? 'Update job still in progress on the appliance — once it finishes, REBOOT the box to enter the new boot environment (the update jobs never reboot by themselves).' : 'Update job still in progress on the appliance (install-only; no reboot will be performed).' } };
      if (r.state !== 'SUCCESS' && r.state !== 'FINISHED') return { success: false, details: { jobId: r.jobId, error: r.error ?? `Job ended in state ${r.state}` } };
      return finishWithReboot({ jobId: r.jobId });
    }

    // Content passed as base64 → upload via /_upload running update.file.
    const payload = decodeFilePayload(input);
    if ('error' in payload) return { success: false, details: { error: payload.error } };
    const destination = str(input, 'destination');
    const fileParams = [{ ...(destination ? { destination } : {}) }];
    const startUpload = async (): Promise<number | null> => {
      // API-key credentials mint a session token inside uploadFile (never Bearer —
      // TrueNAS 26+ would revoke the key on such an HTTP login).
      const r = await ctx.client.uploadFile(ctx.creds, 'update.file', payload.data, payload.fileName || 'update-file', undefined, fileParams);
      return typeof r['job_id'] === 'number' ? (r['job_id'] as number) : null;
    };

    const r2 = await runUpdateJobWithResume(ctx, startUpload, 'update.file', [{ resume: true }], 3_600_000);
    if (r2.state === 'RUNNING') return { success: true, applied: true, details: { jobId: r2.jobId, fileName: payload.fileName, note: reboot ? 'Update job still in progress on the appliance — once it finishes, REBOOT the box to enter the new boot environment (the update jobs never reboot by themselves).' : 'Update job still in progress on the appliance (install-only; no reboot will be performed).' } };
    if (r2.state !== 'SUCCESS' && r2.state !== 'FINISHED') return { success: false, details: { jobId: r2.jobId, fileName: payload.fileName, error: r2.error ?? `Job ended in state ${r2.state}` } };
    // Install confirmed — now the reboot (finishWithReboot swallows its own expected
    // disconnect; a transport error anywhere else here is a REAL failure).
    return await finishWithReboot({ jobId: r2.jobId, fileName: payload.fileName });
  },
};

// ---------------------------------------------------------------------------
// Boot environments (SCALE) — the same data TrueNAS's Web UI shows under
// System → Boot Environments, exposed as plan actions so UNM can see what an
// upgrade actually installed and ROLL BACK to a previous OS version. Verified
// against truenas/middleware source: plugins/boot_environment/ + api/v25_10_x/
// boot_environments.py — namespace `boot.environment` (roles BOOT_ENV_*), entry
// fields {id, dataset, active, activated, created, used_bytes, used, keep,
// can_activate}. Pre-25.04 appliances expose the legacy `bootenv.*` namespace
// with positional args and no keep/can_activate — queryBootEnvs falls back to
// it automatically (JSON-RPC -32601).
// ---------------------------------------------------------------------------

export interface BootEnvRow { id: string; dataset?: string; active?: boolean; activated?: boolean; created?: unknown; usedBytes?: number; used?: string; keep?: boolean; canActivate?: boolean; }

/** Queries the appliance's boot environments, normalizing both namespaces. Exported so index.ts can reuse it for the Storage page's BE rows (same normalization, one code path). */
export async function queryBootEnvs(ctx: TruenasActionContext): Promise<{ rows: BootEnvRow[]; namespace: 'boot.environment' | 'bootenv' }> {
  const normalize = (raw: unknown[]): BootEnvRow[] => raw.map((r) => {
    const o = r as Record<string, unknown>;
    return { id: String(o['id'] ?? ''), dataset: typeof o['dataset'] === 'string' ? o['dataset'] : undefined, active: o['active'] === true || (typeof o['active'] === 'string' && /^R/.test(o['active'])), activated: o['activated'] === true || (typeof o['activated'] === 'string' && /N/.test(o['activated'])), created: o['created'], usedBytes: typeof o['used_bytes'] === 'number' ? o['used_bytes'] : undefined, used: typeof o['used'] === 'string' ? o['used'] : undefined, keep: typeof o['keep'] === 'boolean' ? o['keep'] : undefined, canActivate: typeof o['can_activate'] === 'boolean' ? o['can_activate'] : undefined };
  });
  try {
    const rows = await ctx.client.call<unknown[]>('boot.environment.query', [[], {}], ctx.creds);
    return { rows: normalize(Array.isArray(rows) ? rows : []), namespace: 'boot.environment' };
  } catch (e) {
    if (!(e instanceof TruenasRpcError && e.code === -32601)) throw e; // legacy appliance — try the old namespace
    const rows = await ctx.client.call<unknown[]>('bootenv.query', [[], {}], ctx.creds);
    return { rows: normalize(Array.isArray(rows) ? rows : []), namespace: 'bootenv' };
  }
}

// ---------------------------------------------------------------------------
// Boot-pool guards — shared by the storage actions below. The OS boot pool
// (`boot-pool` on modern releases, `freenas-boot` on legacy ones) holds the
// appliance's own datasets (one per boot environment). It is NOT a data pool:
//   - it never appears in pool.query / pool.dataset.query results (middleware
//     excludes it from discovery and filters internal datasets server-side), so
//     the generic storage actions can only reach it through names we surface on
//     the Storage page — those must be refused here, not "not found";
//   - scrubbing it is a DIFFERENT RPC (`boot.scrub`, role BOOT_ENV_WRITE) than
//     pool.scrub, so the boot-pool row gets its own storage.boot-scrub action.
// ---------------------------------------------------------------------------

/** The appliance's OS boot pool name — `boot-pool` (25.x/26), `freenas-boot` (legacy). */
export function bootPoolName(): string {
  return 'boot-pool';
}

const BOOT_POOL_NAMES = new Set(['boot-pool', 'freenas-boot']);

/** True for the OS boot pool itself or any dataset under it (e.g. `boot-pool/ROOT/25.10.7`). */
export function isBootPoolName(name: string): boolean {
  return BOOT_POOL_NAMES.has(name) || name.startsWith('boot-pool/') || name.startsWith('freenas-boot/');
}

const bootEnvReadAction: ActionDescriptor<TruenasActionContext> = {
  id: 'bootenv.read',
  label: 'List boot environments',
  description:
    "Lists the appliance's OS boot environments (TrueNAS `boot.environment.query` — the same data as System → Boot Environments in the Web UI). Shows which version is currently running (`active`) and which one will be booted next (`activated`). Use after a firmware upgrade to confirm what got installed, or before rolling back.",
  module: 'System',
  riskLevel: 'read' as const,
  deviceCount: 1 as const,
  inputSchema: {},
  async execute(ctx: TruenasActionContext): Promise<ActionResult> {
    const { rows } = await queryBootEnvs(ctx);
    return { success: true, details: { count: rows.length, bootEnvironments: rows } };
  },
};

const bootEnvActivateAction: ActionDescriptor<TruenasActionContext> = {
  id: 'bootenv.activate',
  label: 'Boot into a boot environment (rollback / forward-boot)',
  description:
    "Activates the named boot environment so it becomes the default at the NEXT reboot (TrueNAS `boot.environment.activate`) — this is how you roll back to an older OS version after a bad upgrade, or finish an install-only update. The currently running OS is untouched until the box reboots; set reboot=true (default) to reboot immediately.",
  module: 'System',
  riskLevel: 'dangerous' as const,
  deviceCount: 1 as const,
  timeoutMs: 60_000, // activate regenerates the boot menu — quick; the optional reboot drops the socket
  retryOnDispatchFailure: false,
  inputSchema: {
    id: { type: 'string', required: true, minLength: 2, description: 'Boot environment name (usually the version, e.g. "25.10.4") — see bootenv.read' },
    reboot: { type: 'boolean', required: false, default: true, description: 'Reboot immediately so the selected boot environment takes effect now (default). Set false to only arm it for the next manual reboot.' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const id = str(input, 'id');
    if (!id) return { success: false, details: { error: 'id (boot environment name) is required' } };
    const reboot = input['reboot'] !== false;

    // Resolve the namespace + confirm the BE exists BEFORE mutating anything.
    const beq = await queryBootEnvs(ctx);
    const target = beq.rows.find((r) => r.id === id);
    if (!target) return { success: false, details: { error: `No boot environment named "${id}" on this appliance`, available: beq.rows.map((r) => r.id) } };

    // activate: re-activating an already-activated BE is a no-op — some releases
    // (25.10.x observed live on SRV03) answer EINVAL "already activated" instead of
    // regenerating the menu; treat that as success, everything else must surface.
    try {
      await ctx.client.call<unknown>(`${beq.namespace}.activate`, [{ id }], ctx.creds);
    } catch (e) {
      if (!(e instanceof TruenasRpcError && /already activated/i.test(e.message))) throw e;
    }

    if (!reboot) {
      return { success: true, applied: true, details: { bootEnvironment: id, note: `Boot environment ${id} is armed for the next reboot — the currently running OS stays active until then.` } };
    }
    try {
      const rb = await ctx.client.call<unknown>('system.reboot', [`UNM boot environment switch → ${id}`, {}], ctx.creds);
      return { success: true, applied: true, details: { bootEnvironment: id, note: `Rebooting into ${id}. Unreachable while down; verification is impossible by design.` }, ...(describeJobResult(rb) as Record<string, unknown>) };
    } catch (e) {
      if (e instanceof TruenasRpcError && /timed out|closed|unresponsive/i.test(e.message)) {
        return { success: true, applied: true, details: { bootEnvironment: id, note: `Reboot into ${id} initiated; connection lost as expected while the appliance went down.` } };
      }
      throw e;
    }
  },
};

const bootEnvDestroyAction: ActionDescriptor<TruenasActionContext> = {
  id: 'bootenv.destroy',
  label: 'Delete a boot environment',
  description:
    "Permanently deletes the named boot environment (TrueNAS `boot.environment.destroy`), freeing its space. The appliance refuses to delete the currently running (`active`) or next-boot (`activated`) one — those guards are enforced on the appliance side.",
  module: 'System',
  riskLevel: 'dangerous' as const,
  deviceCount: 1 as const,
  timeoutMs: 300_000, // destroy + boot-menu regeneration can take a while for large BEs
  retryOnDispatchFailure: false,
  inputSchema: {
    id: { type: 'string', required: true, minLength: 2, description: 'Boot environment name to delete (e.g. "25.10.4") — see bootenv.read' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const id = str(input, 'id');
    if (!id) return { success: false, details: { error: 'id (boot environment name) is required' } };
    const beq = await queryBootEnvs(ctx);
    const target = beq.rows.find((r) => r.id === id);
    if (!target) return { success: false, details: { error: `No boot environment named "${id}" on this appliance — nothing to delete.`, available: beq.rows.map((r) => r.id) } };
    await ctx.client.call<unknown>(`${beq.namespace}.destroy`, [{ id }], ctx.creds); // active/activated are refused by the appliance itself
    return { success: true, applied: true, details: { bootEnvironment: id, note: `Boot environment ${id} deleted.` } };
  },
};

const bootEnvKeepAction: ActionDescriptor<TruenasActionContext> = {
  id: 'bootenv.keep',
  label: 'Protect a boot environment from auto-deletion',
  description:
    "Sets or clears the keep flag on a boot environment (TrueNAS `boot.environment.keep`). When true, the updater will NOT delete this BE when it needs space for an update — useful to pin a known-good version as your rollback target. Requires TrueNAS 25.04+ (the legacy bootenv namespace has no keep flag).",
  module: 'System',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  inputSchema: {
    id: { type: 'string', required: true, minLength: 2, description: 'Boot environment name (e.g. "25.10.4") — see bootenv.read' },
    value: { type: 'boolean', required: true, description: 'true = protect from updater auto-deletion; false = allow it' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const id = str(input, 'id');
    if (!id) return { success: false, details: { error: 'id (boot environment name) is required' } };
    if (typeof input['value'] !== 'boolean') return { success: false, details: { error: 'value must be a boolean' } };
    const value = input['value'] as boolean;
    const beq = await queryBootEnvs(ctx);
    if (!beq.rows.some((r) => r.id === id)) return { success: false, details: { error: `No boot environment named "${id}" on this appliance`, available: beq.rows.map((r) => r.id) } };
    try {
      await ctx.client.call<unknown>('boot.environment.keep', [{ id, value }], ctx.creds);
    } catch (e) {
      if (e instanceof TruenasRpcError && e.code === -32601) return { success: false, details: { error: 'This appliance predates the keep flag (pre-25.04 `bootenv` namespace) — nothing to set.' } };
      throw e;
    }
    return { success: true, applied: true, verified: true, details: { bootEnvironment: id, keep: value, note: value ? `Boot environment ${id} is now protected from updater auto-deletion.` : `Boot environment ${id} may be deleted by the updater when it needs space.` } };
  },
};

/**
 * Dismiss active alerts on the appliance (TrueNAS `alert.dismiss` RPC). The API
 * calls this when a user closes TrueNAS alert notifications in UNM so the
 * acknowledgment reaches the box itself — dismissed alerts stop driving health
 * and are skipped by the plugin's alert mirroring. Matching is by dedupe key
 * (class + subject, see alertDedupeKey): it survives re-polls even when the
 * appliance regenerates alert UUIDs. `alert.dismiss` on an already-dismissed or
 * gone alert raises a method error — treated as "already handled", not failure.
 */
const alertsDismissAction: ActionDescriptor<TruenasActionContext> = {
  id: 'alerts.dismiss',
  label: 'Dismiss appliance alerts',
  description:
    'Dismissing TrueNAS alerts (alert.dismiss) for the given dedupe keys — used when a user closes alert notifications in UNM so the acknowledgment reaches the appliance.',
  module: 'Alerts',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  inputSchema: {
    keys: { type: 'array', required: true, items: { type: 'string', minLength: 3 } },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const keys = Array.isArray(input.keys) ? (input.keys as unknown[]).filter((k): k is string => typeof k === 'string' && k.length > 0) : [];
    if (keys.length === 0) return { success: false, details: { error: 'No alert keys provided' } };

    const alerts = await ctx.client.call<Record<string, unknown>[]>('alert.list', [], ctx.creds);
    // One UNM row can aggregate several appliance alerts of the same class+subject.
    const byKey = new Map<string, string[]>();
    for (const a of alerts) {
      if ((a['dismissed'] as boolean | undefined) === true) continue;
      const uuid = pickString(a, ['id', 'uuid']);
      if (!uuid) continue;
      const k = alertDedupeKey(pickString(a, ['klass']) ?? '', a['args']);
      const list = byKey.get(k) ?? [];
      list.push(uuid);
      byKey.set(k, list);
    }

    let dismissed = 0;
    let unconfirmed = 0;
    const notes: string[] = [];
    const missing: string[] = [];
    for (const k of keys) {
      const uuids = byKey.get(k);
      if (!uuids || uuids.length === 0) {
        missing.push(k); // already gone or already dismissed — nothing to do
        continue;
      }
      for (const uuid of uuids) {
        try {
          // Transport-tolerant — a lost response is confirmed by re-reading alert.list (dismissed flag).
          const r = await dispatchWrite(ctx, 'alert.dismiss', [uuid], {
            verify: async () => {
              try {
                const rows = await ctx.client.call<Record<string, unknown>[]>('alert.list', [], ctx.creds);
                const row = (rows ?? []).find((a) => pickString(a, ['id', 'uuid']) === uuid);
                if (!row) return true; // gone — applied
                return (row['dismissed'] as boolean | undefined) === true ? true : false; // dismissed — applied; still active — not applied
              } catch {
                return null;
              }
            },
          });
          if (r.note) notes.push(r.note);
          if (r.unconfirmed) unconfirmed++; // response lost AND state unreadable — not proven applied
          dismissed++;
        } catch (e) {
          if (!(e instanceof TruenasRpcError)) throw e; // non-RPC error — surface it
          // Method error = alert vanished or was dismissed in the meantime.
        }
      }
    }
    return { success: unconfirmed === 0, details: { dismissed, missing, ...(notes.length > 0 ? { notes } : {}) } };
  },
};

/**
 * Re-enable previously dismissed alerts (TrueNAS `alert.undismiss` RPC) — the
 * inverse of alerts.dismiss, used when a user re-opens a closed alert in UNM.
 */
const alertsUndismissAction: ActionDescriptor<TruenasActionContext> = {
  id: 'alerts.undismiss',
  label: 'Re-enable appliance alerts',
  description:
    'Re-enables previously dismissed TrueNAS alerts (alert.undismiss) for the given dedupe keys — used when a user re-opens closed alert notifications in UNM.',
  module: 'Alerts',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  inputSchema: {
    keys: { type: 'array', required: true, items: { type: 'string', minLength: 3 } },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const keys = Array.isArray(input.keys) ? (input.keys as unknown[]).filter((k): k is string => typeof k === 'string' && k.length > 0) : [];
    if (keys.length === 0) return { success: false, details: { error: 'No alert keys provided' } };

    const alerts = await ctx.client.call<Record<string, unknown>[]>('alert.list', [], ctx.creds);
    // Undismiss targets DISMISSED alerts — the inverse of alerts.dismiss.
    const byKey = new Map<string, string[]>();
    for (const a of alerts) {
      if ((a['dismissed'] as boolean | undefined) !== true) continue;
      const uuid = pickString(a, ['id', 'uuid']);
      if (!uuid) continue;
      const k = alertDedupeKey(pickString(a, ['klass']) ?? '', a['args']);
      const list = byKey.get(k) ?? [];
      list.push(uuid);
      byKey.set(k, list);
    }

    let undismissed = 0;
    let unconfirmed = 0;
    const notes: string[] = [];
    const missing: string[] = [];
    for (const k of keys) {
      const uuids = byKey.get(k);
      if (!uuids || uuids.length === 0) {
        missing.push(k); // never dismissed or already gone — nothing to do
        continue;
      }
      for (const uuid of uuids) {
        try {
          // Transport-tolerant — a lost response is confirmed by re-reading alert.list (dismissed flag).
          const r = await dispatchWrite(ctx, 'alert.undismiss', [uuid], {
            verify: async () => {
              try {
                const rows = await ctx.client.call<Record<string, unknown>[]>('alert.list', [], ctx.creds);
                const row = (rows ?? []).find((a) => pickString(a, ['id', 'uuid']) === uuid);
                if (!row) return null; // gone — can't confirm either way
                return (row['dismissed'] as boolean | undefined) !== true ? true : false; // active again — applied; still dismissed — not applied
              } catch {
                return null;
              }
            },
          });
          if (r.note) notes.push(r.note);
          if (r.unconfirmed) unconfirmed++; // response lost AND state unreadable — not proven applied
          undismissed++;
        } catch (e) {
          if (!(e instanceof TruenasRpcError)) throw e; // non-RPC error — surface it
          // Method error = alert vanished or was re-enabled in the meantime.
        }
      }
    }
    return { success: unconfirmed === 0, details: { undismissed, missing, ...(notes.length > 0 ? { notes } : {}) } };
  },
};

// ---------------------------------------------------------------------------
// Container / image lifecycle actions (Containers page bulk actions).
//
// These are GENERIC single-device actions: the UNM webapp's Containers page
// offers them as bulk operations and fans one step out per selected app/image.
// Any future vendor plugin that manages docker workloads can expose the same
// action ids so the UI stays identical across vendors. All of them target the
// TrueNAS SCALE `app.*` / `app.image.*` JSON-RPC methods (documented in the
// middleware source). The mutating ones are @job methods — the RPC resolves to
// a JOB ID immediately and the work runs server-side, so each step returns fast
// ("accepted") rather than blocking until the workload settles.
// ---------------------------------------------------------------------------

/** Reads a non-empty string array from an action input (defensive). */
function strArray(input: Record<string, unknown>, key: string): string[] {
  const v = input[key];
  if (!Array.isArray(v)) return [];
  return v.filter((x): x is string => typeof x === 'string' && x.length > 0);
}

/** One app row as returned by `app.query` (only the fields we need). */
interface AppRow {
  name: string;
  state?: string | null;
  upgrade_available?: boolean | null;
  custom_app?: boolean | null;
}

/**
 * One JSON-RPC call with a single retry on timeout. Bulk reads (app.query /
 * app.image.query) can exceed the client's default per-call budget when the
 * appliance is busy — e.g. right after a bulk stop/start of several apps, or on
 * fleets with hundreds of apps/images. The retry uses a 15s round-trip budget;
 * non-timeout errors (auth, method errors) are surfaced immediately.
 */
async function callWithRetry<T>(ctx: TruenasActionContext, method: string, params: unknown[]): Promise<T> {
  try {
    return await ctx.client.call<T>(method, params, ctx.creds);
  } catch (e) {
    if (!isTransportError(e)) throw e;
    return await ctx.client.call<T>(method, params, ctx.creds, 15_000);
  }
}

/** True when an error is a TRANSPORT-level failure (dropped WebSocket session or per-call timeout) rather than an appliance-side method error. On such errors the write may have been applied even though we lost the response — callers must re-read state before declaring failure. */
function isTransportError(e: unknown): boolean {
  return e instanceof TruenasRpcError && /unresponsive|timed out/i.test(e.message);
}

/** Outcome of a transport-tolerant write dispatch (see dispatchWrite). `value` is undefined when the call's response was lost and the effect was confirmed by re-reading state instead. `unconfirmed` marks the one case where neither confirmation nor re-dispatch happened — callers must treat it as "not proven applied" (typically: fail unless a later state check confirms it). */
interface DispatchResult<T> { value: T; note?: string; unconfirmed?: boolean }

/**
 * Dispatches a WRITE RPC tolerating ONE transport-level failure. When the socket
 * drops mid-call ("unresponsive — reconnecting" / per-call timeout) the appliance
 * may have applied it anyway, so before giving up we re-read state via `verify`:
 *   - verify → true  : the effect is already visible → success (no re-dispatch).
 *   - verify → false : it demonstrably did NOT apply → retry once on the fresh session.
 *   - verify → null  : state unreadable → do NOT blindly re-dispatch (destructive ops
 *                      must not be doubled) — report applied-but-unconfirmed instead.
 * `idempotentRetry` skips verification and simply re-dispatches — for full-replacement
 * writes where a second identical call is harmless. Non-transport errors are thrown
 * for the caller's existing handling (already-in-state / already-exists mappings).
 */
/** Default round-trip budget for a WRITE dispatch. The client's own default is the device setting `timeoutMs` (5 s) — far too short for appliance writes on a busy box: a healthy-but-slow `vm.device.delete` then "times out" at 5 s, the response is lost, and the action has to fall back to state re-reads. 30 s covers every observed write; call sites that are genuinely heavier pass their own budget. */
const WRITE_DISPATCH_TIMEOUT_MS = 30_000;

async function dispatchWrite<T>(
  ctx: TruenasActionContext,
  method: string,
  params: unknown[],
  opts?: { timeoutMs?: number; verify?: () => Promise<boolean | null>; idempotentRetry?: boolean },
): Promise<DispatchResult<T>> {
  const effTimeout = opts?.timeoutMs ?? WRITE_DISPATCH_TIMEOUT_MS;
  try {
    return { value: await ctx.client.call<T>(method, params, ctx.creds, effTimeout) };
  } catch (e) {
    if (!isTransportError(e)) throw e;
  }
  // Transport dropped mid-call — did the appliance apply it anyway?
  if (opts?.idempotentRetry) {
    return { value: await ctx.client.call<T>(method, params, ctx.creds, effTimeout), note: 'Response lost to a transport drop — re-dispatched (idempotent write).' };
  }
  const seen = opts?.verify ? await opts.verify() : null;
  if (seen === true) {
    return { value: undefined as T, note: 'Response lost to a transport drop — verified applied on re-read.' };
  }
  if (seen !== false) {
    return { value: undefined as T, unconfirmed: true, note: 'Response lost to a transport drop and state could not be confirmed — check the appliance.' };
  }
  return { value: await ctx.client.call<T>(method, params, ctx.creds, effTimeout), note: 'Response lost to a transport drop — re-dispatched after confirming it had not applied.' };
}

/** Builds a VM-state verify for dispatchWrite: true when in `applied`, false when in `notApplied`, null (unknown/transitioning) otherwise. */
function vmStateVerify(ctx: TruenasActionContext, name: string, applied: Set<string>, notApplied: Set<string>): () => Promise<boolean | null> {
  return async () => {
    const s = await readVmStates(ctx, [name]);
    if (s === null) return null;
    const st = s[name];
    if (applied.has(st)) return true;
    if (notApplied.has(st)) return false;
    return null; // transitioning / gone — don't guess
  };
}

/** Builds an app-state verify for dispatchWrite (same contract as vmStateVerify). */
function appStateVerify(ctx: TruenasActionContext, name: string, applied: Set<string>, notApplied: Set<string>): () => Promise<boolean | null> {
  return async () => {
    const s = await readAppStates(ctx, [name]);
    if (s === null) return null;
    const st = s[name];
    if (applied.has(st)) return true;
    if (notApplied.has(st)) return false;
    return null;
  };
}

/** Fetches all installed apps with their current state. */
async function listApps(ctx: TruenasActionContext): Promise<AppRow[]> {
  const rows = await callWithRetry<Record<string, unknown>[]>(ctx, 'app.query', []);
  return (rows ?? []).map((r) => ({
    name: pickString(r, ['name']) ?? '',
    state: pickString(r, ['state']),
    upgrade_available: typeof r['upgrade_available'] === 'boolean' ? (r['upgrade_available'] as boolean) : null,
    custom_app: typeof r['custom_app'] === 'boolean' ? (r['custom_app'] as boolean) : null,
  }));
}

/** Normalizes an app state to uppercase (SCALE emits e.g. RUNNING/STOPPED). */
function normState(s: string | null | undefined): string {
  return (s ?? '').toUpperCase();
}

/**
 * Builds the per-name outcome for a lifecycle action. `target` is the set of
 * states that mean "already done" (idempotent skip); apps in those states are
 * reported as skipped, not failed — so re-running a bulk stop/start is safe.
 */
function planAppOutcomes(
  names: string[],
  apps: AppRow[],
  target: Set<string>,
): { toRun: string[]; skipped: Record<string, string>; missing: string[] } {
  const byName = new Map(apps.map((a) => [a.name, a]));
  const toRun: string[] = [];
  const skipped: Record<string, string> = {};
  const missing: string[] = [];
  for (const n of names) {
    const app = byName.get(n);
    if (!app) {
      missing.push(n); // already gone — nothing to do
      continue;
    }
    if (target.has(normState(app.state))) skipped[n] = normState(app.state).toLowerCase();
    else toRun.push(n);
  }
  return { toRun, skipped, missing };
}

/** True when a JSON-RPC error means "the app is already in the target state". */
function isAlreadyInState(e: unknown): boolean {
  if (!(e instanceof TruenasRpcError)) return false;
  return /already|not (running|stopped)|in an invalid state/i.test(e.message);
}

// --- Post-apply state verification ---------------------------------------------
// UNM marks a plan step "verified" only when the plugin RE-READS appliance state
// after applying and confirms the target was reached (ActionResult.verified).
// TrueNAS `app.*` methods are @job — the RPC resolves to a JOB ID immediately
// while the work runs server-side, so an acknowledged stop/start is NOT done.
// These helpers poll app.query / vm.query until every driven name reaches its
// target state (or disappears, for deletes), bounded so a stuck workload
// surfaces as "unverified" instead of blocking forever.

/** Re-reads current app states by name ('gone' when absent). Null on read failure — the caller retries. */
async function readAppStates(ctx: TruenasActionContext, names: string[]): Promise<Record<string, string> | null> {
  try {
    const apps = await listApps(ctx);
    const out: Record<string, string> = {};
    for (const n of names) {
      const app = apps.find((a) => a.name === n);
      out[n] = app ? normState(app.state) : 'gone';
    }
    return out;
  } catch {
    return null; // transient RPC failure — pollUntil keeps probing until the deadline
  }
}

/** Waits until every name is in one of `want` states. */
async function verifyAppStates(ctx: TruenasActionContext, names: string[], want: Set<string>): Promise<boolean> {
  if (names.length === 0) return true;
  const wait = await pollUntil(
    () => readAppStates(ctx, names),
    (states) => states !== null && names.every((n) => want.has(states[n])),
    { timeoutMs: 60_000, intervalMs: 3_000 },
  );
  return wait.ok;
}

/** Re-reads current VM states by name ('gone' when absent). Null on read failure. */
async function readVmStates(ctx: TruenasActionContext, names: string[]): Promise<Record<string, string> | null> {
  try {
    const vms = await listVms(ctx);
    const out: Record<string, string> = {};
    for (const n of names) {
      const vm = vms.find((v) => v.name === n);
      out[n] = vm ? normState(vm.state) : 'gone';
    }
    return out;
  } catch {
    return null;
  }
}

/** Waits until every VM name is in one of `want` states. */
async function verifyVmStates(ctx: TruenasActionContext, names: string[], want: Set<string>): Promise<boolean> {
  if (names.length === 0) return true;
  const wait = await pollUntil(
    () => readVmStates(ctx, names),
    (states) => states !== null && names.every((n) => want.has(states[n])),
    { timeoutMs: 60_000, intervalMs: 3_000 },
  );
  return wait.ok;
}

/** Waits until a NIC with the given MAC is (present=true) / gone (present=false) on the VM. */
async function verifyVmNic(ctx: TruenasActionContext, vmName: string, mac: string, present: boolean): Promise<boolean> {
  const wait = await pollUntil(
    async () => {
      try {
        const vms = await listVms(ctx);
        const vm = vms.find((v) => v.name === vmName);
        if (!vm) return null; // VM vanished mid-flight — keep probing (delete race)
        for (const d of vm.devices) {
          const dev = normalizeVmDevice(d);
          if (!dev || dev.dtype !== 'NIC') continue;
          const dmac = pickString(dev.attrs, ['mac']);
          if (dmac && dmac.toLowerCase() === mac.toLowerCase()) return present;
        }
        return !present; // NIC absent — done when we expected it gone
      } catch {
        return null;
      }
    },
    (found) => found === true,
    { timeoutMs: 30_000, intervalMs: 2_000 },
  );
  return wait.ok;
}

/** Describes a job-method result (job id = accepted, work runs server-side). */
function describeAccepted(result: unknown): Record<string, unknown> {
  if (typeof result === 'number') return { jobId: result, note: 'Accepted as an asynchronous appliance job.' };
  if (result && typeof result === 'object' && typeof (result as Record<string, unknown>)['id'] === 'number') {
    return { jobId: (result as Record<string, unknown>)['id'], note: 'Accepted as an asynchronous appliance job.' };
  }
  return {};
}

const containersStopAction: ActionDescriptor<TruenasActionContext> = {
  id: 'containers.stop',
  label: 'Stop container(s)',
  description: 'Stops the selected apps (app.stop). Apps already stopped are skipped, not failed.',
  module: 'Containers',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 120_000,
  inputSchema: {
    names: { type: 'array', required: true, items: { type: 'string', minLength: 1 }, description: 'App names to stop' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const names = strArray(input, 'names');
    if (names.length === 0) return { success: false, details: { error: 'No app names provided' } };
    const apps = await listApps(ctx);
    const { toRun, skipped, missing } = planAppOutcomes(names, apps, new Set(['STOPPED', 'STOPPING']));

    let stopped = 0;
    let unconfirmed = 0;
    const notes: Record<string, string> = {};
    const errors: Record<string, string> = {};
    for (const n of toRun) {
      try {
        // Transport-tolerant — a lost response is confirmed by re-reading the state.
        const r = await dispatchWrite(ctx, 'app.stop', [n], { verify: appStateVerify(ctx, n, new Set(['STOPPED', 'STOPPING']), new Set(['RUNNING'])) });
        if (r.note) notes[n] = r.note;
        if (r.unconfirmed) unconfirmed++; // response lost AND state unreadable — not proven applied
        stopped++;
      } catch (e) {
        if (isAlreadyInState(e)) skipped[n] = 'already stopped';
        else errors[n] = e instanceof Error ? e.message : String(e);
      }
    }
    // Verify: app.stop is a server-side job — every driven app must actually
    // reach STOPPED for this step to count as verified.
    const verified = Object.keys(errors).length === 0 && unconfirmed === 0 && (await verifyAppStates(ctx, toRun, new Set(['STOPPED'])));
    return { success: Object.keys(errors).length === 0 && unconfirmed === 0, applied: true, verified, details: { stopped, skipped, missing, ...(Object.keys(notes).length ? { notes } : {}), ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

const containersStartAction: ActionDescriptor<TruenasActionContext> = {
  id: 'containers.start',
  label: 'Start container(s)',
  description: 'Starts the selected apps (app.start). Apps already running are skipped, not failed.',
  module: 'Containers',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 120_000,
  inputSchema: {
    names: { type: 'array', required: true, items: { type: 'string', minLength: 1 }, description: 'App names to start' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const names = strArray(input, 'names');
    if (names.length === 0) return { success: false, details: { error: 'No app names provided' } };
    const apps = await listApps(ctx);
    const { toRun, skipped, missing } = planAppOutcomes(names, apps, new Set(['RUNNING', 'DEPLOYING']));

    let started = 0;
    let unconfirmed = 0;
    const notes: Record<string, string> = {};
    const errors: Record<string, string> = {};
    for (const n of toRun) {
      try {
        // Transport-tolerant — a lost response is confirmed by re-reading the state.
        const r = await dispatchWrite(ctx, 'app.start', [n], { verify: appStateVerify(ctx, n, new Set(['RUNNING', 'DEPLOYING']), new Set(['STOPPED'])) });
        if (r.note) notes[n] = r.note;
        if (r.unconfirmed) unconfirmed++; // response lost AND state unreadable — not proven applied
        started++;
      } catch (e) {
        if (isAlreadyInState(e)) skipped[n] = 'already running';
        else errors[n] = e instanceof Error ? e.message : String(e);
      }
    }
    // Verify: every driven app must actually reach RUNNING.
    const verified = Object.keys(errors).length === 0 && unconfirmed === 0 && (await verifyAppStates(ctx, toRun, new Set(['RUNNING'])));
    return { success: Object.keys(errors).length === 0 && unconfirmed === 0, applied: true, verified, details: { started, skipped, missing, ...(Object.keys(notes).length ? { notes } : {}), ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

const containersRestartAction: ActionDescriptor<TruenasActionContext> = {
  id: 'containers.restart',
  label: 'Restart container(s)',
  description: 'Restarts the selected apps (app.stop then app.start). Apps already stopped are started directly.',
  module: 'Containers',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 300_000,
  inputSchema: {
    names: { type: 'array', required: true, items: { type: 'string', minLength: 1 }, description: 'App names to restart' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const names = strArray(input, 'names');
    if (names.length === 0) return { success: false, details: { error: 'No app names provided' } };
    const apps = await listApps(ctx);
    const byName = new Map(apps.map((a) => [a.name, a]));

    let restarted = 0;
    let unconfirmed = 0;
    const notes: Record<string, string> = {};
    const missing: string[] = [];
    const errors: Record<string, string> = {};
    for (const n of names) {
      const app = byName.get(n);
      if (!app) {
        missing.push(n); // already gone — nothing to do
        continue;
      }
      try {
        // Stop first unless it is not running, then start. Both dispatches are
        // transport-tolerant — a lost response is confirmed by re-reading the state.
        if (normState(app.state) !== 'STOPPED') {
          const r0 = await dispatchWrite(ctx, 'app.stop', [n], { verify: appStateVerify(ctx, n, new Set(['STOPPED']), new Set(['RUNNING'])) });
          if (r0.note) notes[n] = r0.note;
          if (r0.unconfirmed) {
            // Stop response lost AND state unreadable — don't start on top of an unknown state.
            errors[n] = 'Stop before restart could not be confirmed (transport drop, state unreadable) — re-run the step';
            continue;
          }
        }
        const r1 = await dispatchWrite(ctx, 'app.start', [n], { verify: appStateVerify(ctx, n, new Set(['RUNNING', 'DEPLOYING']), new Set(['STOPPED'])) });
        if (r1.note) notes[n] = r1.note;
        if (r1.unconfirmed) unconfirmed++; // response lost AND state unreadable — not proven applied
        restarted++;
      } catch (e) {
        errors[n] = e instanceof Error ? e.message : String(e);
      }
    }
    // Verify: a restart is only done when every driven app is RUNNING again.
    const verified = Object.keys(errors).length === 0 && unconfirmed === 0 && (await verifyAppStates(ctx, names.filter((n) => byName.has(n)), new Set(['RUNNING'])));
    return { success: Object.keys(errors).length === 0 && unconfirmed === 0, applied: true, verified, details: { restarted, missing, ...(Object.keys(notes).length ? { notes } : {}), ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

const containersUpgradeAction: ActionDescriptor<TruenasActionContext> = {
  id: 'containers.upgrade',
  label: 'Update container(s)',
  description:
    'Upgrades the selected apps to their latest version (app.upgrade). Apps with no update available are skipped, not failed.',
  module: 'Containers',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 300_000,
  inputSchema: {
    names: { type: 'array', required: true, items: { type: 'string', minLength: 1 }, description: 'App names to update' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const names = strArray(input, 'names');
    if (names.length === 0) return { success: false, details: { error: 'No app names provided' } };
    const apps = await listApps(ctx);
    const byName = new Map(apps.map((a) => [a.name, a]));

    let upgraded = 0;
    let unconfirmed = 0;
    const notes: Record<string, string> = {};
    const skipped: Record<string, string> = {};
    const missing: string[] = [];
    const errors: Record<string, string> = {};
    for (const n of names) {
      const app = byName.get(n);
      if (!app) {
        missing.push(n);
        continue;
      }
      // Only upgrade when the appliance reports an update — otherwise skip.
      if (app.upgrade_available !== true) {
        skipped[n] = 'no update available';
        continue;
      }
      try {
        // Transport-tolerant — a lost response is confirmed by re-reading: the app must settle into a stable state AND no longer flag an available upgrade.
        const r = await dispatchWrite(ctx, 'app.upgrade', [n, { app_version: 'latest' }], {
          timeoutMs: 60_000,
          verify: async () => {
            try {
              const apps = await listApps(ctx);
              const row = apps.find((a) => a.name === n);
              if (!row) return null; // gone / unreadable — don't guess
              const st = normState(row.state);
              if (st !== 'RUNNING' && st !== 'STOPPED') return null; // still DEPLOYING — not settled yet
              return row.upgrade_available === false ? true : null; // stable + no pending update → applied; still flagged → unknown (may be mid-redeploy)
            } catch {
              return null;
            }
          },
        });
        if (r.note) notes[n] = r.note;
        if (r.unconfirmed) unconfirmed++; // response lost AND state unreadable — not proven applied
        upgraded++;
      } catch (e) {
        errors[n] = e instanceof Error ? e.message : String(e);
      }
    }
    // Verify: an upgrade redeploys the app server-side — every driven app must
    // settle back into a stable state (RUNNING or STOPPED), not stay DEPLOYING.
    const upgradedNames = names.filter((n) => byName.has(n) && !skipped[n]);
    const verified = Object.keys(errors).length === 0 && unconfirmed === 0 && (await verifyAppStates(ctx, upgradedNames, new Set(['RUNNING', 'STOPPED'])));
    return { success: Object.keys(errors).length === 0 && unconfirmed === 0, applied: true, verified, details: { upgraded, skipped, missing, ...(Object.keys(notes).length ? { notes } : {}), ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

const containersDeleteAction: ActionDescriptor<TruenasActionContext> = {
  id: 'containers.delete',
  label: 'Delete container(s)',
  description:
    'DELETES the selected apps and their docker resources (app.delete, remove_images). This is destructive — data in app-managed volumes is removed.',
  module: 'Containers',
  riskLevel: 'dangerous' as const,
  deviceCount: 1 as const,
  timeoutMs: 300_000,
  inputSchema: {
    names: { type: 'array', required: true, items: { type: 'string', minLength: 1 }, description: 'App names to delete' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const names = strArray(input, 'names');
    if (names.length === 0) return { success: false, details: { error: 'No app names provided' } };
    const apps = await listApps(ctx);
    const byName = new Map(apps.map((a) => [a.name, a]));

    let deleted = 0;
    const notes: Record<string, string> = {};
    const missing: string[] = [];
    const errors: Record<string, string> = {};
    for (const n of names) {
      if (!byName.has(n)) {
        missing.push(n); // already gone — nothing to do
        continue;
      }
      try {
        // Transport-tolerant — a lost response is confirmed by re-reading (the app must be GONE).
        const r = await dispatchWrite(ctx, 'app.delete', [n, { remove_images: true, force_remove_custom_app: true }], { verify: appStateVerify(ctx, n, new Set(['gone']), new Set()) });
        if (r.note) notes[n] = r.note;
        if (r.unconfirmed) errors[n] = 'Delete could not be confirmed (transport drop, state unreadable) — re-run the step'; // destructive: never assume applied
        else deleted++;
      } catch (e) {
        errors[n] = e instanceof Error ? e.message : String(e);
      }
    }
    // Verify: every driven app must be gone from app.query.
    const verified = Object.keys(errors).length === 0 && (await verifyAppStates(ctx, names.filter((n) => byName.has(n)), new Set(['gone'])));
    return { success: Object.keys(errors).length === 0, applied: true, verified, details: { deleted, missing, ...(Object.keys(notes).length ? { notes } : {}), ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

// ---------------------------------------------------------------------------
// VM lifecycle + NIC actions (VMs page) — a GENERIC contract any hypervisor
// plugin can implement: input is always guest NAMES (`names[]` for bulk, `name`
// for single-VM ops), each action resolves them to appliance ids via vm.query
// and reports per-name outcomes, so re-running a bulk start/stop is idempotent
// (already in the target state = skipped, not failed). TrueNAS mapping:
//   vms.start    → vm.start(id)            immediate
//   vms.stop     → vm.stop(id)             JOB — ACPI powerdown, bounded by the
//                                           appliance's shutdown timeout
//   vms.kill     → vm.poweroff(id)         hard kill for unresponsive guests
//   vms.restart  → vm.restart(id)          JOB — stop + start server-side
//   vms.suspend  → vm.suspend(id)          freeze RAM state (guest must run)
//   vms.resume   → vm.resume(id)           unfreeze SUSPENDED/PAUSED guests
//   vms.delete   → vm.delete(id,{zvols})   destructive; zvols removes storage
/**
 * True when the appliance speaks the v26+ VM device API (TrueNAS 25.10 and up):
 * `vm.device.create` takes a single { vm, attributes } object — the legacy
 * { id, attributes } shape is rejected with "Extra inputs are not permitted" —
 * and NIC devices carry the MODEL as `type` (E1000/VIRTIO) while bridge-vs-
 * macvlan is inferred from nic_attach. Older releases keep the legacy shape,
 * where `type` was the attachment kind (BRIDGE/MACVLAN).
 */
async function usesV26VmDeviceApi(ctx: TruenasActionContext): Promise<boolean> {
  try {
    const si = await ctx.client.call<Record<string, unknown>>('system.info', [], ctx.creds);
    const v = (pickString(si, ['version']) ?? '').replace(/^(scale|core)\s+/i, '').trim();
    const m = v.match(/^(\d+)\.(\d+)/);
    if (!m) return true; // unknown version — assume modern
    const major = Number(m[1]);
    return major > 25 || (major === 25 && Number(m[2]) >= 10);
  } catch {
    return true; // can't determine — assume modern
  }
}

/** Builds the vm.device.create argument for the appliance's API generation. */
function vmDeviceCreateArg(v26: boolean, vmId: number, attributes: Record<string, unknown>): Record<string, unknown> {
  return v26 ? { vm: vmId, attributes } : { id: vmId, attributes };
}

// ---------------------------------------------------------------------------
// NICs are VM devices: attach = vm.device.create({vm|id, attributes:{dtype:'NIC',…}}),
// detach = vm.device.delete(deviceId) — the integer device id is resolved from
// the NIC's MAC via vm.query. `vms.nic-choices` (read-only) feeds the webapp's
// attach dialog with the appliance's bridges + MACVLANs.
// ---------------------------------------------------------------------------

/** One VM as returned by `vm.query` (only the fields these actions need). */
interface VmInfo {
  id: number;
  name: string;
  /** Normalized uppercase libvirt state (RUNNING / STOPPED / SUSPENDED / …). */
  state: string;
  /** Raw devices[] entries — NIC detach resolves its integer device id from here. */
  devices: Record<string, unknown>[];
}

/** Fetches all VMs with their current state (vm.query). */
async function listVms(ctx: TruenasActionContext): Promise<VmInfo[]> {
  const rows = await callWithRetry<Record<string, unknown>[]>(ctx, 'vm.query', []);
  const out: VmInfo[] = [];
  for (const r of rows ?? []) {
    if (!r || typeof r !== 'object') continue;
    const name = pickString(r, ['name']);
    if (!name) continue;
    const status = (r['status'] ?? {}) as Record<string, unknown>;
    out.push({
      id: typeof r['id'] === 'number' ? (r['id'] as number) : -1,
      name,
      state: normState(pickString(status, ['state'])),
      devices: Array.isArray(r['devices']) ? (r['devices'] as Record<string, unknown>[]) : [],
    });
  }
  return out;
}

/** Resolves guest names to VMs — the per-name outcome for a lifecycle action. */
function planVmOutcomes(
  names: string[],
  vms: VmInfo[],
  target: Set<string>,
): { toRun: VmInfo[]; skipped: Record<string, string>; missing: string[] } {
  const byName = new Map(vms.map((v) => [v.name, v]));
  const toRun: VmInfo[] = [];
  const skipped: Record<string, string> = {};
  const missing: string[] = [];
  for (const n of names) {
    const vm = byName.get(n);
    if (!vm) {
      missing.push(n); // already gone — nothing to do
      continue;
    }
    if (target.has(vm.state)) skipped[n] = vm.state.toLowerCase();
    else toRun.push(vm);
  }
  return { toRun, skipped, missing };
}

const vmsStartAction: ActionDescriptor<TruenasActionContext> = {
  id: 'vms.start',
  label: 'Start VM(s)',
  description: 'Starts the selected VMs (vm.start). VMs already running are skipped, not failed.',
  module: 'VMs',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 120_000,
  inputSchema: {
    names: { type: 'array', required: true, items: { type: 'string', minLength: 1 }, description: 'VM names to start' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const names = strArray(input, 'names');
    if (names.length === 0) return { success: false, details: { error: 'No VM names provided' } };
    const vms = await listVms(ctx);
    const { toRun, skipped, missing } = planVmOutcomes(names, vms, new Set(['RUNNING']));

    let started = 0;
    let unconfirmed = 0;
    const notes: Record<string, string> = {};
    const errors: Record<string, string> = {};
    for (const vm of toRun) {
      try {
        // Transport-tolerant: a dropped socket may have lost the response even
        // though the VM is starting — re-read state before retrying.
        const r = await dispatchWrite(ctx, 'vm.start', [vm.id], { verify: vmStateVerify(ctx, vm.name, new Set(['RUNNING']), new Set(['STOPPED', 'SUSPENDED', 'PAUSED'])) });
        if (r.note) notes[vm.name] = r.note;
        if (r.unconfirmed) unconfirmed++; // response lost AND state unreadable — not proven applied
        started++;
      } catch (e) {
        if (isAlreadyInState(e)) skipped[vm.name] = 'already running';
        else errors[vm.name] = e instanceof Error ? e.message : String(e);
      }
    }
    // Verify: every driven VM must actually reach RUNNING. An unconfirmed dispatch
    // (response lost AND state unreadable) is not proven applied → fail the step.
    const verified = Object.keys(errors).length === 0 && unconfirmed === 0 && (await verifyVmStates(ctx, toRun.map((v) => v.name), new Set(['RUNNING'])));
    return { success: Object.keys(errors).length === 0 && unconfirmed === 0, applied: true, verified, details: { started, skipped, missing, ...(Object.keys(notes).length ? { notes } : {}), ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

const vmsStopAction: ActionDescriptor<TruenasActionContext> = {
  id: 'vms.stop',
  label: 'Stop VM(s)',
  description:
    'Gracefully stops the selected VMs (vm.stop — ACPI powerdown, an appliance job). The step waits for each stop job to settle; a guest that ignores the shutdown is reported per-VM so it can be killed. VMs already stopped are skipped.',
  module: 'VMs',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 300_000,
  inputSchema: {
    names: { type: 'array', required: true, items: { type: 'string', minLength: 1 }, description: 'VM names to stop' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const names = strArray(input, 'names');
    if (names.length === 0) return { success: false, details: { error: 'No VM names provided' } };
    const vms = await listVms(ctx);
    const { toRun, skipped, missing } = planVmOutcomes(names, vms, new Set(['STOPPED']));

    let stopped = 0;
    let unconfirmed = 0;
    const notes: Record<string, string> = {};
    const errors: Record<string, string> = {};
    for (const vm of toRun) {
      try {
        // vm.stop is a JOB method — the ACPI powerdown runs server-side and the
        // job settles when the guest acks or its shutdown timeout elapses. Wait
        // with a bounded budget so an unresponsive guest surfaces as a per-VM
        // error (the user can then Kill it) instead of a silent "accepted".
        const dr = await dispatchWrite(ctx, 'vm.stop', [vm.id], { verify: vmStateVerify(ctx, vm.name, new Set(['STOPPED']), new Set(['RUNNING'])) });
        if (dr.note) notes[vm.name] = dr.note; // response lost — state already confirmed on re-read
        if (dr.unconfirmed) unconfirmed++; // response lost AND state unreadable — not proven applied
        const job = describeAccepted(dr.value);
        if (typeof job['jobId'] === 'number') {
          const wait = await waitForJob(ctx, job['jobId'], 150_000);
          if (wait.state === 'RUNNING') {
            notes[vm.name] = 'Stop initiated — still in progress on the appliance';
            stopped++;
            continue;
          }
          if (wait.state !== 'SUCCESS' && wait.state !== 'FINISHED') {
            errors[vm.name] = wait.error ?? `Stop job ended in state ${wait.state}`;
            continue;
          }
        }
        stopped++;
      } catch (e) {
        if (isAlreadyInState(e)) skipped[vm.name] = 'already stopped';
        else errors[vm.name] = e instanceof Error ? e.message : String(e);
      }
    }
    // Verify: the ACPI powerdown job settling is not enough — every driven VM
    // must actually be STOPPED. A guest still shutting down stays "unverified".
    const verified = Object.keys(errors).length === 0 && unconfirmed === 0 && (await verifyVmStates(ctx, toRun.map((v) => v.name), new Set(['STOPPED'])));
    return { success: Object.keys(errors).length === 0 && unconfirmed === 0, applied: true, verified, details: { stopped, skipped, missing, ...(Object.keys(notes).length ? { notes } : {}), ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

const vmsKillAction: ActionDescriptor<TruenasActionContext> = {
  id: 'vms.kill',
  label: 'Kill VM(s)',
  description:
    'HARD-KILLS the selected VMs (vm.poweroff) — no ACPI handshake, use for guests that are unresponsive to a graceful stop. VMs already stopped are skipped.',
  module: 'VMs',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 120_000,
  inputSchema: {
    names: { type: 'array', required: true, items: { type: 'string', minLength: 1 }, description: 'VM names to kill' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const names = strArray(input, 'names');
    if (names.length === 0) return { success: false, details: { error: 'No VM names provided' } };
    const vms = await listVms(ctx);
    const { toRun, skipped, missing } = planVmOutcomes(names, vms, new Set(['STOPPED']));

    let killed = 0;
    let unconfirmed = 0;
    const notes: Record<string, string> = {};
    const errors: Record<string, string> = {};
    for (const vm of toRun) {
      try {
        // Transport-tolerant — a hard kill that lost its response is confirmed by re-reading the state.
        const r = await dispatchWrite(ctx, 'vm.poweroff', [vm.id], { verify: vmStateVerify(ctx, vm.name, new Set(['STOPPED']), new Set(['RUNNING'])) });
        if (r.note) notes[vm.name] = r.note;
        if (r.unconfirmed) unconfirmed++; // response lost AND state unreadable — not proven applied
        killed++;
      } catch (e) {
        if (isAlreadyInState(e)) skipped[vm.name] = 'already stopped';
        else errors[vm.name] = e instanceof Error ? e.message : String(e);
      }
    }
    // Verify: a hard kill must leave every driven VM STOPPED.
    const verified = Object.keys(errors).length === 0 && unconfirmed === 0 && (await verifyVmStates(ctx, toRun.map((v) => v.name), new Set(['STOPPED'])));
    return { success: Object.keys(errors).length === 0 && unconfirmed === 0, applied: true, verified, details: { killed, skipped, missing, ...(Object.keys(notes).length ? { notes } : {}), ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

const vmsRestartAction: ActionDescriptor<TruenasActionContext> = {
  id: 'vms.restart',
  label: 'Restart VM(s)',
  description:
    'Restarts the selected VMs (vm.restart — an appliance job). Stopped VMs are started directly. The step waits for each restart job to settle.',
  module: 'VMs',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 300_000,
  inputSchema: {
    names: { type: 'array', required: true, items: { type: 'string', minLength: 1 }, description: 'VM names to restart' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const names = strArray(input, 'names');
    if (names.length === 0) return { success: false, details: { error: 'No VM names provided' } };
    const vms = await listVms(ctx);
    const byName = new Map(vms.map((v) => [v.name, v]));

    let restarted = 0;
    let unconfirmed = 0;
    const notes: Record<string, string> = {};
    const missing: string[] = [];
    const errors: Record<string, string> = {};
    for (const n of names) {
      const vm = byName.get(n);
      if (!vm) {
        missing.push(n); // already gone — nothing to do
        continue;
      }
      try {
        if (vm.state === 'STOPPED') {
          // Transport-tolerant — a lost response is confirmed by re-reading the state.
          const r0 = await dispatchWrite(ctx, 'vm.start', [vm.id], { verify: vmStateVerify(ctx, n, new Set(['RUNNING']), new Set(['STOPPED'])) });
          if (r0.note) notes[n] = r0.note;
          if (r0.unconfirmed) unconfirmed++; // response lost AND state unreadable — not proven applied
        } else {
          // Transport-tolerant — a lost response is confirmed by re-reading the state.
          const dr = await dispatchWrite(ctx, 'vm.restart', [vm.id], { verify: vmStateVerify(ctx, n, new Set(['RUNNING']), new Set(['STOPPED'])) });
          if (dr.note) notes[n] = dr.note; // response lost — state already confirmed on re-read
          if (dr.unconfirmed) unconfirmed++; // response lost AND state unreadable — not proven applied
          const job = describeAccepted(dr.value);
          if (typeof job['jobId'] === 'number') {
            const wait = await waitForJob(ctx, job['jobId'], 150_000);
            if (wait.state === 'RUNNING') {
              notes[n] = 'Restart initiated — still in progress on the appliance';
              restarted++;
              continue;
            }
            if (wait.state !== 'SUCCESS' && wait.state !== 'FINISHED') {
              errors[n] = wait.error ?? `Restart job ended in state ${wait.state}`;
              continue;
            }
          }
        }
        restarted++;
      } catch (e) {
        errors[n] = e instanceof Error ? e.message : String(e);
      }
    }
    // Verify: a restart is only done when every driven VM is RUNNING again.
    const verified = Object.keys(errors).length === 0 && unconfirmed === 0 && (await verifyVmStates(ctx, names.filter((n) => byName.has(n)), new Set(['RUNNING'])));
    return { success: Object.keys(errors).length === 0 && unconfirmed === 0, applied: true, verified, details: { restarted, missing, ...(Object.keys(notes).length ? { notes } : {}), ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

const vmsSuspendAction: ActionDescriptor<TruenasActionContext> = {
  id: 'vms.suspend',
  label: 'Suspend VM(s)',
  description: 'Suspends the selected RUNNING VMs (vm.suspend) — RAM state is frozen, resume continues exactly where it left off.',
  module: 'VMs',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 120_000,
  inputSchema: {
    names: { type: 'array', required: true, items: { type: 'string', minLength: 1 }, description: 'VM names to suspend' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const names = strArray(input, 'names');
    if (names.length === 0) return { success: false, details: { error: 'No VM names provided' } };
    const vms = await listVms(ctx);
    const { toRun, skipped, missing } = planVmOutcomes(names, vms, new Set(['SUSPENDED']));

    let suspended = 0;
    let unconfirmed = 0;
    const notes: Record<string, string> = {};
    const errors: Record<string, string> = {};
    for (const vm of toRun) {
      if (vm.state !== 'RUNNING') {
        skipped[vm.name] = `not running (${vm.state.toLowerCase()})`;
        continue;
      }
      try {
        // Transport-tolerant — a lost response is confirmed by re-reading the state.
        const r = await dispatchWrite(ctx, 'vm.suspend', [vm.id], { verify: vmStateVerify(ctx, vm.name, new Set(['SUSPENDED']), new Set(['RUNNING'])) });
        if (r.note) notes[vm.name] = r.note;
        if (r.unconfirmed) unconfirmed++; // response lost AND state unreadable — not proven applied
        suspended++;
      } catch (e) {
        if (isAlreadyInState(e)) skipped[vm.name] = 'already suspended';
        else errors[vm.name] = e instanceof Error ? e.message : String(e);
      }
    }
    // Verify: every driven VM must actually be SUSPENDED.
    const verified = Object.keys(errors).length === 0 && unconfirmed === 0 && (await verifyVmStates(ctx, toRun.map((v) => v.name), new Set(['SUSPENDED'])));
    return { success: Object.keys(errors).length === 0 && unconfirmed === 0, applied: true, verified, details: { suspended, skipped, missing, ...(Object.keys(notes).length ? { notes } : {}), ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

const vmsResumeAction: ActionDescriptor<TruenasActionContext> = {
  id: 'vms.resume',
  label: 'Resume VM(s)',
  description: 'Resumes the selected SUSPENDED/PAUSED VMs (vm.resume).',
  module: 'VMs',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 120_000,
  inputSchema: {
    names: { type: 'array', required: true, items: { type: 'string', minLength: 1 }, description: 'VM names to resume' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const names = strArray(input, 'names');
    if (names.length === 0) return { success: false, details: { error: 'No VM names provided' } };
    const vms = await listVms(ctx);
    const byName = new Map(vms.map((v) => [v.name, v]));

    let resumed = 0;
    let unconfirmed = 0;
    const skipped: Record<string, string> = {};
    const missing: string[] = [];
    const notes: Record<string, string> = {};
    const errors: Record<string, string> = {};
    for (const n of names) {
      const vm = byName.get(n);
      if (!vm) {
        missing.push(n);
        continue;
      }
      if (vm.state === 'RUNNING') {
        skipped[n] = 'already running';
        continue;
      }
      if (vm.state !== 'SUSPENDED' && vm.state !== 'PAUSED') {
        skipped[n] = `not suspended (${vm.state.toLowerCase()})`;
        continue;
      }
      try {
        // Transport-tolerant — a lost response is confirmed by re-reading the state.
        const r = await dispatchWrite(ctx, 'vm.resume', [vm.id], { verify: vmStateVerify(ctx, n, new Set(['RUNNING']), new Set(['SUSPENDED', 'PAUSED'])) });
        if (r.note) notes[n] = r.note;
        if (r.unconfirmed) unconfirmed++; // response lost AND state unreadable — not proven applied
        resumed++;
      } catch (e) {
        if (isAlreadyInState(e)) skipped[n] = 'already running';
        else errors[n] = e instanceof Error ? e.message : String(e);
      }
    }
    // Verify: every driven VM must actually be RUNNING again.
    const verified = Object.keys(errors).length === 0 && unconfirmed === 0 && (await verifyVmStates(ctx, names.filter((n) => byName.has(n)), new Set(['RUNNING'])));
    return { success: Object.keys(errors).length === 0 && unconfirmed === 0, applied: true, verified, details: { resumed, skipped, missing, ...(Object.keys(notes).length ? { notes } : {}), ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

const vmsDeleteAction: ActionDescriptor<TruenasActionContext> = {
  id: 'vms.delete',
  label: 'Delete VM(s)',
  description:
    'DELETES the selected VMs (vm.delete). Running VMs are stopped first. With removeStorage=true the backing zvols/disks are removed too — this is destructive.',
  module: 'VMs',
  riskLevel: 'dangerous' as const,
  deviceCount: 1 as const,
  timeoutMs: 300_000,
  inputSchema: {
    names: { type: 'array', required: true, items: { type: 'string', minLength: 1 }, description: 'VM names to delete' },
    removeStorage: { type: 'boolean', required: false, default: false, description: 'Also delete the VMs\' backing storage (zvols)' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const names = strArray(input, 'names');
    if (names.length === 0) return { success: false, details: { error: 'No VM names provided' } };
    const removeStorage = input['removeStorage'] === true;
    const vms = await listVms(ctx);
    const byName = new Map(vms.map((v) => [v.name, v]));

    let deleted = 0;
    const missing: string[] = [];
    const notes: Record<string, string> = {};
    const errors: Record<string, string> = {};
    for (const n of names) {
      const vm = byName.get(n);
      if (!vm) {
        missing.push(n); // already gone — nothing to do
        continue;
      }
      try {
        // vm.delete refuses running guests — stop first (bounded job wait).
        if (vm.state === 'RUNNING') {
          const dr = await dispatchWrite(ctx, 'vm.stop', [vm.id], { verify: vmStateVerify(ctx, n, new Set(['STOPPED']), new Set(['RUNNING'])) });
          if (dr.note) notes[n] = dr.note;
          if (dr.unconfirmed) {
            // Stop response lost AND state unreadable — don't delete a possibly-running guest.
            errors[n] = 'Stop before delete could not be confirmed (transport drop, state unreadable) — re-run the step';
            continue;
          }
          const job = describeAccepted(dr.value);
          if (typeof job['jobId'] === 'number') {
            const wait = await waitForJob(ctx, job['jobId'], 150_000);
            if (wait.state !== 'RUNNING' && wait.state !== 'SUCCESS' && wait.state !== 'FINISHED') {
              errors[n] = `Could not stop before delete: ${wait.error ?? `stop job ended in state ${wait.state}`}`;
              continue;
            }
          }
        }
        // Transport-tolerant — a lost response is confirmed by re-reading (the VM must be GONE).
        const dd = await dispatchWrite(ctx, 'vm.delete', [vm.id, removeStorage ? { zvols: true } : {}], { verify: vmStateVerify(ctx, n, new Set(['gone']), new Set()) });
        if (dd.note) notes[n] = dd.note;
        if (dd.unconfirmed) errors[n] = 'Delete response lost and state unreadable — re-run the step to confirm';
        deleted++;
      } catch (e) {
        errors[n] = e instanceof Error ? e.message : String(e);
      }
    }
    // Verify: every driven VM must be gone from vm.query.
    const verified = Object.keys(errors).length === 0 && (await verifyVmStates(ctx, names.filter((n) => byName.has(n)), new Set(['gone'])));
    return { success: Object.keys(errors).length === 0, applied: true, verified, details: { deleted, missing, removeStorage, ...(Object.keys(notes).length ? { notes } : {}), ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

const vmsNicChoicesAction: ActionDescriptor<TruenasActionContext> = {
  id: 'vms.nic-choices',
  label: 'List attachable NIC interfaces',
  description: 'Read-only list of the bridges and MACVLANs this appliance can attach to VMs (vm.device.nic_attach_choices). Feeds the VMs page attach dialog.',
  module: 'VMs',
  riskLevel: 'read' as const,
  deviceCount: 1 as const,
  inputSchema: {},
  async execute(ctx: TruenasActionContext): Promise<ActionResult> {
    const r = await ctx.client.call<{ BRIDGE?: string[]; MACVLAN?: string[] }>('vm.device.nic_attach_choices', [], ctx.creds);
    return {
      success: true,
      details: {
        bridges: Array.isArray(r?.BRIDGE) ? (r.BRIDGE as string[]) : [],
        macvlans: Array.isArray(r?.MACVLAN) ? (r.MACVLAN as string[]) : [],
      },
    };
  },
};

const vmsNicAttachAction: ActionDescriptor<TruenasActionContext> = {
  id: 'vms.nic-attach',
  label: 'Attach NIC to VM',
  description:
    'Attaches a network interface to ONE VM (vm.device.create with dtype NIC). nicAttach is a bridge or MACVLAN from vms.nic-choices; omit mac to let the appliance assign one.',
  module: 'VMs',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 120_000,
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, description: 'VM name' },
    nicAttach: { type: 'string', required: true, minLength: 1, description: 'Bridge or MACVLAN interface to attach (from vms.nic-choices)' },
    type: { type: 'string', required: false, enum: ['BRIDGE', 'MACVLAN'], default: 'BRIDGE', description: 'NIC attachment kind — only honored by pre-25.10 appliances; TrueNAS 25.10+ infers bridge vs MACVLAN from nic_attach' },
    mac: { type: 'string', required: false, pattern: '^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', description: 'Optional fixed MAC (appliance assigns one when omitted)' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const name = str(input, 'name');
    if (!name) return { success: false, details: { error: 'VM name is required' } };
    const nicAttach = str(input, 'nicAttach');
    if (!nicAttach) return { success: false, details: { error: 'nicAttach (bridge/MACVLAN) is required' } };
    const type = (str(input, 'type') ?? 'BRIDGE').toUpperCase();
    if (type !== 'BRIDGE' && type !== 'MACVLAN') return { success: false, details: { error: `Unsupported NIC type "${type}" (expected BRIDGE or MACVLAN)` } };
    const mac = str(input, 'mac');

    const vms = await listVms(ctx);
    const vm = vms.find((v) => v.name === name);
    if (!vm) return { success: false, details: { error: `VM "${name}" not found on this appliance` } };

    try {
      const v26 = await usesV26VmDeviceApi(ctx);
      // v26+: `type` is the NIC MODEL (E1000/VIRTIO) and bridge-vs-macvlan is
      // inferred from nic_attach — so the attachment kind validated above is not
      // sent. Legacy: type = BRIDGE|MACVLAN.
      const attributes: Record<string, unknown> = { dtype: 'NIC', nic_attach: nicAttach };
      if (v26) attributes['type'] = 'VIRTIO'; // appliance default is E1000 — VIRTIO is the expected model
      else attributes['type'] = type;
      if (mac) attributes['mac'] = mac;
      const beforeCount = vm.devices.filter((d) => normalizeVmDevice(d)?.dtype === 'NIC').length;
      // Transport-tolerant: a lost response is confirmed by re-reading — the NIC
      // must show up (by MAC when requested, otherwise as a count increase).
      const r = await dispatchWrite(ctx, 'vm.device.create', [vmDeviceCreateArg(v26, vm.id, attributes)], {
        timeoutMs: 30_000,
        verify: async () => {
          try {
            const vms2 = await listVms(ctx);
            const vm2 = vms2.find((v) => v.name === name);
            if (!vm2) return null;
            if (mac) {
              for (const d of vm2.devices) {
                const dev = normalizeVmDevice(d);
                if (dev?.dtype !== 'NIC') continue;
                const m2 = pickString(dev.attrs, ['mac']);
                if (m2 && m2.toLowerCase() === mac.toLowerCase()) return true;
              }
              return false; // VM exists but no NIC with that MAC — not applied
            }
            const count = vm2.devices.filter((d) => normalizeVmDevice(d)?.dtype === 'NIC').length;
            if (count > beforeCount) return true;
            if (count < beforeCount) return null; // unexpected shrinkage — don't guess
            return false; // unchanged — not applied
          } catch {
            return null;
          }
        },
      });
      // Verify by re-reading the VM's devices. When a MAC was requested it must
      // appear; when omitted the appliance assigns one — then we confirm the NIC
      // count grew instead (the new device is dtype NIC on nicAttach).
      let verified = false;
      if (mac) {
        verified = await verifyVmNic(ctx, name, mac, true);
      } else {
        const wait = await pollUntil(
          async () => {
            try {
              const vms2 = await listVms(ctx);
              const vm2 = vms2.find((v) => v.name === name);
              if (!vm2) return null;
              return vm2.devices.filter((d) => normalizeVmDevice(d)?.dtype === 'NIC').length > beforeCount;
            } catch {
              return null;
            }
          },
          (grew) => grew === true,
          { timeoutMs: 15_000, intervalMs: 2_000 },
        );
        verified = wait.ok;
      }
      return { success: true, applied: true, verified, details: { name, nicAttach, type, ...(mac ? { mac } : {}), ...(r.note ? { note: r.note } : {}) } };
    } catch (e) {
      return { success: false, details: { error: e instanceof Error ? e.message : String(e) } };
    }
  },
};

const vmsNicDetachAction: ActionDescriptor<TruenasActionContext> = {
  id: 'vms.nic-detach',
  label: 'Detach NIC from VM',
  description:
    'Removes ONE network interface from a VM (vm.device.delete). The target NIC is identified by its MAC; the integer device id is resolved via vm.query.',
  module: 'VMs',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 120_000,
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, description: 'VM name' },
    mac: { type: 'string', required: true, pattern: '^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', description: 'MAC of the NIC to remove' },
    force: { type: 'boolean', required: false, default: false, description: 'Force removal even if the appliance would otherwise refuse' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const name = str(input, 'name');
    const mac = (str(input, 'mac') ?? '').toLowerCase();
    if (!name) return { success: false, details: { error: 'VM name is required' } };
    if (!mac) return { success: false, details: { error: 'NIC MAC is required' } };

    const vms = await listVms(ctx);
    const vm = vms.find((v) => v.name === name);
    if (!vm) return { success: false, details: { error: `VM "${name}" not found on this appliance` } };

    // Resolve the integer device id of the NIC with this MAC. The id sits at the
    // entry top level (TrueNAS 26+ nested shape) or flat inside attrs (legacy).
    let deviceId: number | null = null;
    for (const d of vm.devices) {
      const dev = normalizeVmDevice(d);
      if (!dev || dev.dtype !== 'NIC') continue;
      const dmac = pickString(dev.attrs, ['mac']);
      if (!dmac || dmac.toLowerCase() !== mac) continue;
      const raw = d as Record<string, unknown>;
      deviceId = typeof raw['id'] === 'number' ? (raw['id'] as number) : typeof dev.attrs['id'] === 'number' ? (dev.attrs['id'] as number) : null;
      break;
    }
    if (deviceId === null) return { success: false, details: { error: `No NIC with MAC ${mac.toUpperCase()} on VM "${name}"` } };

    try {
      const force = input['force'] === true;
      // Transport-tolerant — a lost response is confirmed by re-reading (the NIC must be GONE).
      const r = await dispatchWrite(ctx, 'vm.device.delete', [deviceId, force ? { force: true } : {}], {
        verify: async () => {
          try {
            const vms2 = await listVms(ctx);
            const vm2 = vms2.find((v) => v.name === name);
            if (!vm2) return null; // VM gone — can't confirm either way
            for (const d of vm2.devices) {
              const dev = normalizeVmDevice(d);
              if (dev?.dtype !== 'NIC') continue;
              const m2 = pickString(dev.attrs, ['mac']);
              if (m2 && m2.toLowerCase() === mac) return false; // still present — not applied
            }
            return true; // gone — applied
          } catch {
            return null;
          }
        },
      });
      // Verify by re-reading the VM's devices — the NIC with this MAC must be gone.
      const verified = await verifyVmNic(ctx, name, mac, false);
      return { success: true, applied: true, verified, details: { name, mac: mac.toUpperCase(), deviceId, ...(r.note ? { note: r.note } : {}) } };
    } catch (e) {
      return { success: false, details: { error: e instanceof Error ? e.message : String(e) } };
    }
  },
};

// ---------------------------------------------------------------------------
// VM creation + ISO / device management (VMs page). GENERIC contract — any
// hypervisor plugin implementing these ids gets the webapp's Create-VM dialog,
// CD-ROM/ISO flow and per-device detach button for free. TrueNAS mapping:
//   vms.create         → vm.create(...) + vm.device.create(DISK|NIC) — vm.create
//                        EXCLUDES devices, they are added separately afterwards.
//                        The DISK abstraction is a fresh ZVOL (create_zvol +
//                        zvol_name + zvol_volsize under the chosen dataset) or an
//                        existing disk path.
//   vms.create-choices → pool.dataset.query — datasets/pools a new zvol may live in
//   vms.iso-upload     → UNM file-repo stream (SDK FileRepoClient.getStream) piped
//                        into the appliance's `filesystem.put` JOB over /_upload —
//                        multi-GB safe, nothing buffered. Records a repo usage row.
//   vms.iso-choices    → filesystem.listdir + stat of a dataset dir (.iso/.img)
//   vms.cdrom-attach   → vm.device.create(dtype CDROM) — or vm.device.update on
//                        the VM's EXISTING CD-ROM, so re-attaching (ISO swap) is
//                        idempotent instead of stacking drives. With repoFileId +
//                        dataset it first ensures the ISO exists at the target path
//                        (reused when already present at matching size — a single
//                        stat, no appliance-wide search; streamed from UNM's file
//                        repo via filesystem.put only when missing), so "install OS
//                        from a repo ISO" is ONE step.
//   vms.device-detach  → vm.device.delete(deviceId, {zvol?, force?}) — integer
//                        device id from the inventory rows; removeStorage=true
//                        destroys a DISK's backing zvol. Requires a STOPPED VM.
//   vms.device-edit    → vm.device.update(deviceId, attributes)
// All of them work with ONLY the primary credential (JSON-RPC) — no SSH needed.
// ---------------------------------------------------------------------------

/** Lazily-built shared UNM file-repo client (the SDK's ONE implementation). */
let repoClient: FileRepoClient | null = null;
function fileRepo(): FileRepoClient {
  if (!repoClient) repoClient = createFileRepoClient();
  return repoClient;
}

/** Reads a finite number from an action input (defensive — schema already validated). */
function num(input: Record<string, unknown>, key: string, fallback: number): number {
  const v = input[key];
  return typeof v === 'number' && Number.isFinite(v) ? v : fallback;
}

/** True for system-managed datasets that must never host VM zvols (mirrors middleware's INTERNAL_DATASETS). */
function isSystemDataset(name: string): boolean {
  if (name === '.system' || name.startsWith('.system/')) return true;
  for (const p of ['ix-applications', 'ix-apps']) {
    if (name === p || name.includes(`/${p}`)) return true;
  }
  for (const bp of ['boot-pool', 'freenas-boot']) {
    if (name === bp || name.startsWith(`${bp}/`)) return true;
  }
  return false;
}

/** Resolves a dataset/pool NAME to its mountpoint (/mnt/…) via pool.dataset.query. */
async function resolveDatasetMount(ctx: TruenasActionContext, dataset: string): Promise<string | null> {
  try {
    const rows = await ctx.client.call<Record<string, unknown>[]>('pool.dataset.query', [], ctx.creds, 20_000);
    for (const r of rows ?? []) {
      if (pickString(r, ['name']) !== dataset) continue;
      const mp = pickString(r, ['mountpoint']);
      return mp && mp !== 'legacy' && mp !== 'unmounted' ? mp : `/mnt/${dataset}`;
    }
  } catch { /* fall through — the pool may not appear in the dataset query */ }
  try {
    const pools = await ctx.client.call<Record<string, unknown>[]>('pool.query', [], ctx.creds);
    if ((pools ?? []).some((p) => pickString(p, ['name']) === dataset)) return `/mnt/${dataset}`;
  } catch { /* ignore */ }
  return null;
}

const vmsCreateChoicesAction: ActionDescriptor<TruenasActionContext> = {
  id: 'vms.create-choices',
  label: 'List VM creation choices',
  description:
    'Read-only list of the datasets (and pools) a new VM disk zvol can live in, with their mountpoints. Feeds the Create-VM dialog\'s dataset picker.',
  module: 'VMs',
  riskLevel: 'read' as const,
  deviceCount: 1 as const,
  inputSchema: {},
  async execute(ctx: TruenasActionContext): Promise<ActionResult> {
    try {
      const rows = await ctx.client.call<Record<string, unknown>[]>('pool.dataset.query', [], ctx.creds, 20_000);
      const out: { name: string; mountpoint: string }[] = [];
      for (const r of rows ?? []) {
        const name = pickString(r, ['name']);
        if (!name || isSystemDataset(name)) continue;
        // Pools (no slash) and FILESYSTEM datasets are valid zvol parents.
        const type = typeof r['type'] === 'string' ? (r['type'] as string).toLowerCase() : '';
        if (name.includes('/') && type !== 'filesystem') continue;
        const mp = pickString(r, ['mountpoint']);
        out.push({ name, mountpoint: mp && mp !== 'legacy' && mp !== 'unmounted' ? mp : `/mnt/${name}` });
      }
      out.sort((a, b) => a.name.localeCompare(b.name));
      return { success: true, details: { datasets: out } };
    } catch (e) {
      return { success: false, details: { error: e instanceof Error ? e.message : String(e) } };
    }
  },
};

const vmsCreateAction: ActionDescriptor<TruenasActionContext> = {
  id: 'vms.create',
  label: 'Create VM',
  description:
    'Creates a NEW VM (vm.create) with an abstracted DISK device — either a fresh ZVOL under the chosen dataset (create_zvol + zvol_name + zvol_volsize, named <dataset>/<zvolName or vm-name>) or an existing disk path — plus an optional NIC. vm.create excludes devices, so each is added via vm.device.create afterwards.',
  module: 'VMs',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 300_000,
  inputSchema: {
    name: { type: 'string', required: true, minLength: 2, maxLength: 64, pattern: '^[A-Za-z][A-Za-z0-9_-]*$', description: 'VM name' },
    description: { type: 'string', required: false, maxLength: 512, description: 'Optional guest description' },
    vcpus: { type: 'number', required: true, min: 1, max: 16, default: 1, description: 'Virtual CPUs (vcpus = cores × threads)' },
    cores: { type: 'number', required: false, min: 1, max: 16, default: 1, description: 'Cores per package' },
    threads: { type: 'number', required: false, min: 1, max: 8, default: 1, description: 'Threads per core (hyperthreading)' },
    memoryMiB: { type: 'number', required: true, min: 20, default: 2048, description: 'RAM in MiB' },
    minMemoryMiB: { type: 'number', required: false, min: 0, description: 'Optional minimum RAM (ballooning) in MiB' },
    bootloader: { type: 'string', required: false, enum: ['UEFI', 'UEFI_CSM'], default: 'UEFI', description: 'Firmware' },
    autostart: { type: 'boolean', required: false, default: false, description: 'Start the VM when the appliance boots' },
    diskMode: { type: 'string', required: true, enum: ['zvol', 'path'], default: 'zvol', description: 'zvol = create a new ZFS volume; path = attach an existing disk' },
    dataset: { type: 'string', required: false, minLength: 1, description: 'Parent dataset for the new zvol (from vms.create-choices) — required when diskMode=zvol' },
    sizeBytes: { type: 'number', required: false, min: 1073741824, description: 'New zvol size in bytes — required when diskMode=zvol' },
    zvolName: { type: 'string', required: false, minLength: 1, maxLength: 64, pattern: '^[a-zA-Z0-9][a-zA-Z0-9_-]*$', description: 'Optional ZVOL leaf name under the chosen dataset (default: VM name; case preserved) — only used when diskMode=zvol' },
    diskPath: { type: 'string', required: false, minLength: 1, pattern: '^/dev/zvol/', description: 'Existing disk path (zvol or raw file) — required when diskMode=path' },
    diskType: { type: 'string', required: false, enum: ['AHCI', 'VIRTIO'], default: 'VIRTIO', description: 'Disk controller interface' },
    nicAttach: { type: 'string', required: false, minLength: 1, description: 'Optional bridge/MACVLAN to attach (from vms.nic-choices)' },
    nicType: { type: 'string', required: false, enum: ['BRIDGE', 'MACVLAN'], default: 'BRIDGE', description: 'NIC attachment kind — only honored by pre-25.10 appliances; TrueNAS 25.10+ infers bridge vs MACVLAN from nic_attach' },
    mac: { type: 'string', required: false, pattern: '^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', description: 'Optional fixed MAC (appliance assigns one when omitted)' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const name = str(input, 'name');
    if (!name) return { success: false, details: { error: 'VM name is required' } };

    // Idempotency guard — a VM with this name already exists.
    let vms: VmInfo[];
    try {
      vms = await listVms(ctx);
    } catch (e) {
      return { success: false, details: { error: `Could not read existing VMs: ${e instanceof Error ? e.message : String(e)}` } };
    }
    if (vms.some((v) => v.name === name)) {
      return { success: false, details: { error: `A VM named "${name}" already exists on this appliance` } };
    }

    const diskMode = strOr(input, 'diskMode', 'zvol');
    const dataset = str(input, 'dataset');
    const sizeBytes = typeof input['sizeBytes'] === 'number' ? (input['sizeBytes'] as number) : undefined;
    const diskPath = str(input, 'diskPath');
    if (diskMode === 'zvol' && (!dataset || !sizeBytes)) {
      return { success: false, details: { error: 'diskMode=zvol requires dataset + sizeBytes' } };
    }
    if (diskMode === 'path' && !diskPath) {
      return { success: false, details: { error: 'diskMode=path requires diskPath' } };
    }

    const create: Record<string, unknown> = {
      name,
      vcpus: num(input, 'vcpus', 1),
      cores: num(input, 'cores', 1),
      threads: num(input, 'threads', 1),
      memory: num(input, 'memoryMiB', 2048), // TrueNAS reports/accepts MiB
      bootloader: strOr(input, 'bootloader', 'UEFI'),
      autostart: input['autostart'] === true,
    };
    const description = str(input, 'description');
    if (description) create['description'] = description;
    if (typeof input['minMemoryMiB'] === 'number') create['min_memory'] = input['minMemoryMiB'];

    let vmId: number | null = null;
    try {
      // Transport-tolerant — a lost response is confirmed by re-reading (the VM must exist);
      // when it does, the id comes from the re-read row. When it demonstrably did NOT apply,
      // dispatchWrite retries once on the fresh session (a duplicate create would just error).
      const dr = await dispatchWrite(ctx, 'vm.create', [create], {
        timeoutMs: 60_000,
        verify: async () => {
          try {
            return (await listVms(ctx)).some((v) => v.name === name); // exists — applied
          } catch {
            return null;
          }
        },
      });
      const created = dr.value as Record<string, unknown> | undefined;
      vmId = typeof created?.['id'] === 'number' ? (created['id'] as number) : null;
      if (vmId === null && dr.note) {
        // Response lost — the verify proved the VM exists; recover its id from the re-read.
        const row = (await listVms(ctx)).find((v) => v.name === name);
        vmId = typeof row?.id === 'number' ? row.id : null;
      }
    } catch (e) {
      return { success: false, details: { error: `vm.create failed: ${e instanceof Error ? e.message : String(e)}` } };
    }
    if (vmId === null) {
      return { success: false, details: { error: 'VM create was accepted but no id came back — check the appliance VM list' } };
    }

    // DISK device — vm.create EXCLUDES devices, so it is added separately.
    const diskAttrs: Record<string, unknown> = { dtype: 'DISK', type: strOr(input, 'diskType', 'VIRTIO') };
    let zvolFullName: string | null = null;
    if (diskMode === 'zvol' && dataset) {
      // The zvol leaf is the user's optional override or the VM name under the
      // chosen parent dataset — e.g. VIRTUALIZATION01/VM/<name>. Case is PRESERVED
      // (ZFS dataset names are case-sensitive and allow uppercase); only characters
      // that are invalid in a dataset name are stripped.
      const requested = str(input, 'zvolName');
      const leaf = (requested || name).replace(/[^a-zA-Z0-9_]/g, '');
      if (!leaf) {
        return { success: false, details: { error: `Invalid zvolName "${requested}" — it must contain at least one letter or digit` } };
      }
      zvolFullName = `${dataset}/${leaf}`;
      Object.assign(diskAttrs, { create_zvol: true, zvol_name: zvolFullName, zvol_volsize: sizeBytes });
    } else if (diskPath) {
      diskAttrs['path'] = diskPath;
    }

    const v26 = await usesV26VmDeviceApi(ctx);
    const errors: string[] = [];
    try {
      // 60s budget — a zvol-backed disk create can exceed the client's 5s default
      // (zvol provisioning + flapping WS sessions), and the NIC attach below is fast.
      // Transport-tolerant — a lost response is confirmed by re-reading the VM's devices.
      const rd = await dispatchWrite(ctx, 'vm.device.create', [vmDeviceCreateArg(v26, vmId, diskAttrs)], {
        timeoutMs: 60_000,
        verify: async () => {
          try {
            const vms2 = await listVms(ctx);
            const vm2 = vms2.find((v) => v.name === name);
            if (!vm2) return null;
            for (const d of vm2.devices) {
              const dev = normalizeVmDevice(d);
              if (dev?.dtype !== 'DISK') continue;
              if (zvolFullName && pickString(dev.attrs, ['path']) === `/dev/zvol/${zvolFullName}`) return true;
              if (!zvolFullName) return true; // path mode — any DISK counts
            }
            return false;
          } catch {
            return null;
          }
        },
      });
      if (rd.note) errors.push(`disk device: ${rd.note}`);
    } catch (e) {
      errors.push(`disk device: ${e instanceof Error ? e.message : String(e)}`);
    }

    // Optional NIC.
    const nicAttach = str(input, 'nicAttach');
    if (nicAttach) {
      // v26+: `type` is the NIC MODEL — send VIRTIO explicitly (the appliance's own
      // default is E1000); bridge-vs-macvlan is inferred from nic_attach.
      // Legacy: type = BRIDGE|MACVLAN.
      const nicAttrs: Record<string, unknown> = { dtype: 'NIC', nic_attach: nicAttach };
      if (v26) nicAttrs['type'] = 'VIRTIO';
      else nicAttrs['type'] = strOr(input, 'nicType', 'BRIDGE');
      const mac = str(input, 'mac');
      if (mac) nicAttrs['mac'] = mac.toUpperCase();
      try {
        // Transport-tolerant — a lost response is confirmed by re-reading the VM's devices.
        const rn = await dispatchWrite(ctx, 'vm.device.create', [vmDeviceCreateArg(v26, vmId, nicAttrs)], {
          timeoutMs: 30_000,
          verify: async () => {
            try {
              const vms2 = await listVms(ctx);
              const vm2 = vms2.find((v) => v.name === name);
              if (!vm2) return null;
              for (const d of vm2.devices) {
                const dev = normalizeVmDevice(d);
                if (dev?.dtype !== 'NIC') continue;
                if (mac && pickString(dev.attrs, ['mac'])?.toLowerCase() === mac.toLowerCase()) return true;
                if (!mac) return true; // any NIC counts — the appliance assigns MACs
              }
              return false;
            } catch {
              return null;
            }
          },
        });
        if (rn.note) errors.push(`NIC device: ${rn.note}`);
      } catch (e) {
        errors.push(`NIC device: ${e instanceof Error ? e.message : String(e)}`);
      }
    }

    // Verify by re-reading the VM — it must exist with its DISK (and NIC).
    const wait = await pollUntil(
      async () => {
        try {
          const vms2 = await listVms(ctx);
          const vm2 = vms2.find((v) => v.name === name);
          if (!vm2) return null;
          let disks = 0;
          let nics = 0;
          for (const d of vm2.devices) {
            const dev = normalizeVmDevice(d);
            if (!dev) continue;
            if (dev.dtype === 'DISK') disks++;
            else if (dev.dtype === 'NIC') nics++;
          }
          return { ok: disks >= 1 && (!nicAttach || nics >= 1), disks, nics };
        } catch {
          return null;
        }
      },
      (r) => r !== null && r.ok,
      { timeoutMs: 60_000, intervalMs: 2_000 },
    );

    // The RPC may have timed out / errored even though the device actually landed
    // (e.g. a slow zvol create that finished just after our client gave up). Trust
    // the re-read: if the DISK (+NIC) are present, report success with a note.
    if (errors.length > 0 && wait.ok) {
      return {
        success: true,
        applied: true,
        verified: true,
        details: { name, vmId, diskMode, ...(zvolFullName ? { zvolName: zvolFullName } : {}), ...(nicAttach ? { nicAttach } : {}), note: `Device RPC reported an error but the device is present on re-read — treated as success. ${errors.join('; ')}` },
      };
    }
    if (errors.length > 0) {
      return {
        success: false,
        applied: true,
        details: {
          error: `VM "${name}" was created but device setup failed — delete it via vms.delete and retry. ${errors.join('; ')}`,
          name, vmId, zvolName: zvolFullName,
        },
      };
    }
    return { success: true, applied: true, verified: wait.ok, details: { name, vmId, diskMode, ...(zvolFullName ? { zvolName: zvolFullName } : {}), ...(nicAttach ? { nicAttach } : {}) } };
  },
};

const vmsIsoUploadAction: ActionDescriptor<TruenasActionContext> = {
  id: 'vms.iso-upload',
  label: 'Upload ISO from file repo to appliance',
  description:
    'Streams a file from UNM\'s central file repository onto the appliance (filesystem.put JOB over /_upload) into the chosen dataset — multi-GB safe, nothing buffered. Skips when the file already exists there at matching size (idempotent), and records a usage row on the repo file.',
  module: 'VMs',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 3_600_000, // multi-GB ISOs over a slow link legitimately take a long time
  inputSchema: {
    dataset: { type: 'string', required: true, minLength: 1, description: 'Target dataset (from vms.create-choices), e.g. VIRTUALIZATION01/ISO' },
    repoFileId: { type: 'string', required: true, minLength: 1, description: 'UNM file-repo id of the ISO to upload' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const dataset = str(input, 'dataset');
    if (!dataset) return { success: false, details: { error: 'Target dataset is required' } };
    const repoFileId = str(input, 'repoFileId');
    if (!repoFileId) return { success: false, details: { error: 'repoFileId (UNM file-repo id) is required' } };

    // Shared with vms.cdrom-attach — streams the repo file onto the appliance
    // (skipping when already present at matching size).
    const ensured = await ensureRepoFileOnAppliance(ctx, dataset, repoFileId);
    if (!ensured.ok) return { success: false, details: { error: ensured.error, retryable: true } };

    // Verify by re-reading the appliance: the file must exist at the expected size.
    let verified = false;
    try {
      const st = await ctx.client.call<Record<string, unknown>>('filesystem.stat', [ensured.path], ctx.creds);
      verified = typeof st['size'] === 'number';
    } catch { /* stat failure → unverified */ }

    return { success: true, applied: true, verified, details: { dataset, path: ensured.path, uploaded: ensured.uploaded } };
  },
};

const vmsIsoChoicesAction: ActionDescriptor<TruenasActionContext> = {
  id: 'vms.iso-choices',
  label: 'List ISOs in a dataset',
  description:
    'Read-only list of the .iso/.img files in one dataset directory (filesystem.listdir + stat). Feeds the CD-ROM attach dialog\'s "existing ISO" picker.',
  module: 'VMs',
  riskLevel: 'read' as const,
  deviceCount: 1 as const,
  inputSchema: {
    dataset: { type: 'string', required: true, minLength: 1, description: 'Dataset to list (from vms.create-choices)' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const dataset = str(input, 'dataset');
    if (!dataset) return { success: false, details: { error: 'Dataset is required' } };
    const mp = await resolveDatasetMount(ctx, dataset);
    if (!mp) return { success: false, details: { error: `Dataset "${dataset}" not found on this appliance` } };

    let entries: Record<string, unknown>[];
    try {
      entries = await ctx.client.call<Record<string, unknown>[]>('filesystem.listdir', [mp], ctx.creds);
    } catch (e) {
      return { success: false, details: { error: `Could not list ${mp}: ${e instanceof Error ? e.message : String(e)}` } };
    }

    const files: { path: string; name: string; sizeBytes: number | null }[] = [];
    for (const en of entries ?? []) {
      const fname = pickString(en, ['name']);
      if (!fname || !/\.(iso|img)$/i.test(fname)) continue;
      let sizeBytes: number | null = null;
      try {
        const st = await ctx.client.call<Record<string, unknown>>('filesystem.stat', [`${mp}/${fname}`], ctx.creds);
        sizeBytes = typeof st['size'] === 'number' ? (st['size'] as number) : null;
      } catch { /* keep the entry without a size */ }
      files.push({ path: `${mp}/${fname}`, name: fname, sizeBytes });
    }
    files.sort((a, b) => a.name.localeCompare(b.name));
    return { success: true, details: { dataset, mountpoint: mp, files } };
  },
};

/**
 * Best-effort context for upload failures: if the dataset's parent POOL is not
 * ONLINE, ZFS writes to it can stall behind a stuck/failing disk (a DEGRADED
 * pool blocks every write until the bad disk responds or gives up) — which is
 * what makes TrueNAS's nginx kill /_upload after 60s of no bytes. Returns a
 * short prefix for error messages, or '' when the pool looks healthy/unknown.
 */
async function poolHealthNote(ctx: TruenasActionContext, dataset: string): Promise<string> {
  try {
    const root = (dataset ?? '').split('/')[0];
    if (!root) return '';
    const pools = await ctx.client.call<Record<string, unknown>[]>('pool.query', [[['name', '=', root]]], ctx.creds);
    const p = (pools ?? [])[0];
    // Same field fallback as parsePool in index.ts (v26 vs legacy naming).
    const status = pickString(p, ['status', 'state']);
    if (status && status !== 'ONLINE') return `Pool ${root} is ${status} — writes to it can stall behind a stuck disk. `;
  } catch { /* best-effort only */ }
  return '';
}

/**
 * Ensures a repo file exists at <mount>/<fileName> on the appliance — reuses it
 * when already present with matching size, otherwise streams it from UNM's file
 * repo into the `filesystem.put` JOB over /_upload (multi-GB safe). Returns the
 * final path + whether an upload happened. Records a repo usage row.
 */
async function ensureRepoFileOnAppliance(
  ctx: TruenasActionContext,
  dataset: string,
  repoFileId: string,
): Promise<{ ok: true; path: string; uploaded: boolean } | { ok: false; error: string }> {
  const mp = await resolveDatasetMount(ctx, dataset);
  if (!mp) return { ok: false, error: `Dataset "${dataset}" not found on this appliance` };

  let meta; // FileRepoEntry | null (inferred — SDK client)
  try {
    meta = await fileRepo().getMeta(repoFileId);
  } catch (e) {
    return { ok: false, error: `Could not reach the UNM file repo: ${e instanceof Error ? e.message : String(e)}` };
  }
  if (!meta) return { ok: false, error: 'Repo file not found — it may have been deleted from the Files page' };

  const targetPath = `${mp}/${meta.name}`;

  // Already there with matching size → reuse (idempotent re-attach / ISO swap).
  try {
    const st = await ctx.client.call<Record<string, unknown>>('filesystem.stat', [targetPath], ctx.creds);
    if (typeof st['size'] === 'number' && (st['size'] as number) === meta.sizeBytes) {
      return { ok: true, path: targetPath, uploaded: false };
    }
  } catch { /* missing → upload below */ }

  // SFTP fallback (plugin option `uploadViaSftp`, default on): stream the file over
  // the bound SSH slot — bypasses middlewared/nginx entirely. On appliances where
  // /_upload stalls (nginx kills it after ~60 s, leaving 0-byte files) this is the
  // reliable path; when SFTP isn't available (no ssh slot / auth failure) we fall
  // through to the HTTP retry loop below.
  let sftpError = ''; // surfaced in the final error when BOTH paths fail
  if (ctx.uploadViaSftp !== false) {
    const sftpResult = await uploadRepoFileViaSftp(ctx, repoFileId, targetPath, meta.sizeBytes);
    if (sftpResult && sftpResult.ok === true) return { ok: true, path: targetPath, uploaded: true };
    if (sftpResult && !sftpResult.ok) sftpError = `SFTP attempt failed (${sftpResult.error}); /_upload attempts: `;
  }

  // TrueNAS's nginx kills /_upload after ~60s without bytes flowing (the location
  // sets no timeout → client_body_timeout default). A ZFS write stall — e.g. a
  // DEGRADED pool whose stuck disk blocks every write to it — fills the put job's
  // input pipe, pauses our send, and nginx answers "socket hang up" mid-transfer,
  // leaving a PARTIAL file at the target (filesystem.put writes in place). Such
  // stalls are often transient → retry the WHOLE upload with backoff: fresh repo
  // stream + fresh session token each attempt. The plan-step budget (1h) bounds it.
  const MAX_UPLOAD_ATTEMPTS = 3;
  let lastError = '';
  for (let attempt = 1; attempt <= MAX_UPLOAD_ATTEMPTS; attempt++) {
    if (attempt > 1) {
      await new Promise((r2) => setTimeout(r2, attempt === 2 ? 5_000 : 15_000));
      // A previous attempt may have left a partial file — filesystem.put rewrites
      // it from byte 0 ('wb+'), so no cleanup needed; just verify the size below.
    }
    let stream;
    try {
      stream = await fileRepo().getStream(repoFileId);
    } catch (e) {
      return { ok: false, error: `Could not open repo file for streaming: ${e instanceof Error ? e.message : String(e)}` };
    }

    let r: Record<string, unknown>;
    try {
      // filesystem.put(path) — the /_upload body IS the job's input pipe; parent dirs are auto-created.
      // API-key credentials mint a session token inside uploadFileStream (never Bearer —
      // TrueNAS 26+ would revoke the key on such an HTTP login).
      r = await ctx.client.uploadFileStream(ctx.creds, 'filesystem.put', stream, meta.name, undefined, [targetPath]);
    } catch (e) {
      lastError = e instanceof Error ? e.message : String(e);
      continue; // transport failure — retry with a fresh stream + token
    }

    const jobId = typeof r['job_id'] === 'number' ? (r['job_id'] as number) : null;
    if (jobId !== null) {
      const w = await waitForJob(ctx, jobId, 3_540_000);
      if (w.state && w.state !== 'SUCCESS' && w.state !== 'FINISHED') {
        return { ok: false, error: `${await poolHealthNote(ctx, dataset)}filesystem.put job ended in state ${w.state}: ${w.error ?? ''}`.trim() };
      }
    }

    // Verify by re-reading — a killed upload leaves a PARTIAL file at the target.
    try {
      const st = await ctx.client.call<Record<string, unknown>>('filesystem.stat', [targetPath], ctx.creds);
      if (typeof st['size'] === 'number' && (st['size'] as number) === meta.sizeBytes) {
        break; // complete — done
      }
      lastError = `file at ${targetPath} is ${(st['size'] as number)} bytes, expected ${meta.sizeBytes} (partial upload)`;
    } catch {
      lastError = 'filesystem.put reported success but the file is missing at the target';
    }
  }
  if (lastError) return { ok: false, error: `${await poolHealthNote(ctx, dataset)}${sftpError}Upload to ${dataset} failed after ${MAX_UPLOAD_ATTEMPTS} /_upload attempts: ${lastError}`.trim() };

  // Audit trail — which file was uploaded where/when (best-effort).
  try {
    await fileRepo().recordUse(repoFileId, { deviceId: ctx.deviceId ?? undefined, note: `uploaded to ${ctx.host ?? 'appliance'} dataset ${dataset} as ${targetPath}` });
  } catch { /* audit only — never fail the step for it */ }

  return { ok: true, path: targetPath, uploaded: true };
}

/**
 * Streams a repo file onto the appliance over SFTP (the bound ssh slot) — the
 * fallback for appliances whose /_upload endpoint stalls. Returns `ok: true`
 * when the transfer completed AND verified at full size; `null` when SFTP is not
 * usable on this device (no ssh slot, no management address) so the caller can
 * fall back to HTTP; `{ ok: false }` when SFTP was attempted and failed.
 */
async function uploadRepoFileViaSftp(
  ctx: TruenasActionContext,
  repoFileId: string,
  targetPath: string,
  expectedBytes: number | null,
): Promise<{ ok: true } | { ok: false; error: string } | null> {
  const sshCreds = resolveSshCredentials(ctx.rawCredentials ?? undefined, { slotOnly: true });
  if (!sshCreds) return null; // no bound ssh slot — HTTP path only

  const host = (ctx.host ?? '').trim().replace(/^https?:\/\//i, '').replace(/\/+$/, '');
  if (!host) return null;

  let stream;
  try {
    stream = await fileRepo().getStream(repoFileId);
  } catch (e) {
    return { ok: false, error: `Could not open repo file for SFTP streaming: ${e instanceof Error ? e.message : String(e)}` };
  }

  try {
    // Rootless session — absolute appliance paths; shares the pool with the Storage
    // page's file browser (same host|port key). The dynamic host-key verifier pins
    // the SSH handshake against UNM's inventory, same as every other SSH channel.
    const session = await fsSftpPool.get(host, hostSshPort(host), sshCreds, {
      timeoutMs: 30_000,
      hostKeyVerifier: dynamicSshHostVerifier(host, hostSshPort(host)),
    });
    // writeStream truncates the target first — a leftover partial/0-byte file from
    // an earlier killed /_upload is simply overwritten.
    await session.writeStream(targetPath, stream, sshCreds);
  } catch (e) {
    return { ok: false, error: `SFTP upload to ${targetPath} failed: ${e instanceof Error ? e.message : String(e)}` };
  }

  // Verify by re-reading — never trust the transport alone.
  try {
    const st = await ctx.client.call<Record<string, unknown>>('filesystem.stat', [targetPath], ctx.creds);
    if (typeof st['size'] === 'number' && (expectedBytes == null || (st['size'] as number) === expectedBytes)) {
      return { ok: true };
    }
    return { ok: false, error: `SFTP upload reported success but the file is ${(st['size'] as number)} bytes, expected ${expectedBytes}` };
  } catch (e) {
    return { ok: false, error: `SFTP upload finished but filesystem.stat failed: ${e instanceof Error ? e.message : String(e)}` };
  }
}

const vmsCdromAttachAction: ActionDescriptor<TruenasActionContext> = {
  id: 'vms.cdrom-attach',
  label: 'Attach CD-ROM (ISO) to VM',
  description:
    'Attaches a CD-ROM drive pointing at an ISO on the appliance (vm.device.create dtype CDROM — path must live under /mnt/). When the VM already has a CD-ROM device it is UPDATED in place, so swapping the installed ISO is idempotent. With repoFileId + dataset the ISO is first checked at its target path and reused when already present at matching size; only when missing is it streamed from UNM\'s file repo — "install OS from a repo ISO" in one step.',
  module: 'VMs',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 3_600_000, // the optional repo→appliance upload dominates for multi-GB ISOs
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, description: 'VM name' },
    path: { type: 'string', required: false, minLength: 1, pattern: '^/mnt/', description: 'ISO path on the appliance (from vms.iso-choices) — omit when using repoFileId' },
    dataset: { type: 'string', required: false, minLength: 1, description: 'Target dataset for a repo upload (from vms.create-choices) — required with repoFileId' },
    repoFileId: { type: 'string', required: false, minLength: 1, description: 'UNM file-repo id of the ISO to attach (uploaded first when missing)' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const name = str(input, 'name');
    if (!name) return { success: false, details: { error: 'VM name is required' } };

    // Resolve the ISO path — either given directly or pulled from UNM's file repo.
    let path = str(input, 'path') ?? '';
    let uploadedFromRepo = false;
    const repoFileId = str(input, 'repoFileId');
    if (!path && repoFileId) {
      const dataset = str(input, 'dataset');
      if (!dataset) return { success: false, details: { error: 'repoFileId requires a target dataset' } };

      // ensureRepoFileOnAppliance stats the exact target path FIRST and reuses an
      // existing copy at matching size — no upload, no appliance-wide search.
      const ensured = await ensureRepoFileOnAppliance(ctx, dataset, repoFileId);
      if (!ensured.ok) return { success: false, details: { error: ensured.error } };
      path = ensured.path;
      uploadedFromRepo = ensured.uploaded;
    }
    if (!path || !path.startsWith('/mnt/')) {
      return { success: false, details: { error: 'Either a /mnt/ ISO path or repoFileId + dataset is required' } };
    }

    // Fail fast when the resolved ISO is missing/empty — vm.device.create would only
    // reject it after ~60s of appliance-side validation.
    try {
      const st = await ctx.client.call<Record<string, unknown>>('filesystem.stat', [path], ctx.creds, 20_000);
      if (typeof st['size'] !== 'number' || (st['size'] as number) === 0) {
        return { success: false, details: { error: `ISO ${path} is missing or empty on the appliance — nothing to attach` } };
      }
    } catch {
      return { success: false, details: { error: `ISO ${path} does not exist on the appliance (filesystem.stat failed)` } };
    }

    const vms = await listVms(ctx);
    const vm = vms.find((v) => v.name === name);
    if (!vm) return { success: false, details: { error: `VM "${name}" not found on this appliance` } };

    // Existing CD-ROM device → update it (ISO swap); otherwise create a new one.
    let cdromId: number | null = null;
    for (const d of vm.devices) {
      const dev = normalizeVmDevice(d);
      if (!dev || dev.dtype !== 'CDROM') continue;
      const raw = d as Record<string, unknown>;
      cdromId = typeof raw['id'] === 'number' ? (raw['id'] as number) : typeof dev.attrs['id'] === 'number' ? (dev.attrs['id'] as number) : null;
      break;
    }

    let rpcError: string | null = null;
    try {
      const v26 = await usesV26VmDeviceApi(ctx);
      // Transport-tolerant (see dispatchWrite): a dropped socket or per-call timeout
      // does NOT mean the device wasn't created — the appliance may simply be slow
      // validating the ISO on a degraded pool. The verify callback re-reads the VM's
      // devices; only when the CDROM is demonstrably absent do we retry/fail below.
      const cdromVerify = async (): Promise<boolean | null> => {
        try {
          const vms2 = await listVms(ctx);
          const vm2 = vms2.find((v) => v.name === name);
          if (!vm2) return null;
          for (const d of vm2.devices) {
            const dev = normalizeVmDevice(d);
            if (dev?.dtype !== 'CDROM') continue;
            if (pickString(dev.attrs, ['path']) === path) return true;
          }
          return false; // VM exists but no CDROM at this path — not applied
        } catch {
          return null;
        }
      };
      if (cdromId !== null) {
        // vm.device.update keeps the [id, {attributes}] shape on both API generations.
        const ru = await dispatchWrite(ctx, 'vm.device.update', [cdromId, { attributes: { dtype: 'CDROM', path } }], { timeoutMs: 120_000, verify: cdromVerify });
        if (ru.note) rpcError = ru.note;
      } else {
        // Observed live (KIRGUSBANDE, 26.0.0-BETA.2): vm.device.create for a CDROM takes
        // ~60s EVEN VIA THE WEB UI — the appliance-side work is just slow there, and the
        // Web UI only survives it because its WS session has no per-call timeout. Give
        // this call 120s of headroom; if it still times out we fall through to re-read.
        const rc = await dispatchWrite(ctx, 'vm.device.create', [vmDeviceCreateArg(v26, vm.id, { dtype: 'CDROM', path })], { timeoutMs: 120_000, verify: cdromVerify });
        if (rc.note) rpcError = rc.note;
      }
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return { success: false, details: { error: `${await poolHealthNote(ctx, path.replace(/^\/mnt\//, ''))}CD-ROM attach failed: ${msg}`.trim() } };
    }

    // Verify by re-reading the VM's devices — a CDROM with this path must exist.
    const wait = await pollUntil(
      async () => {
        try {
          const vms2 = await listVms(ctx);
          const vm2 = vms2.find((v) => v.name === name);
          if (!vm2) return null;
          for (const d of vm2.devices) {
            const dev = normalizeVmDevice(d);
            if (!dev || dev.dtype !== 'CDROM') continue;
            if (pickString(dev.attrs, ['path']) === path) return true;
          }
          return false;
        } catch {
          return null;
        }
      },
      (found) => found === true,
      { timeoutMs: 45_000, intervalMs: 2_000 },
    );
    if (!wait.ok && rpcError !== null) {
      return { success: false, details: { error: `${await poolHealthNote(ctx, path.replace(/^\/mnt\//, ''))}CD-ROM attach timed out and the device is not present on the VM: ${rpcError}`.trim() } };
    }
    return {
      success: true,
      applied: true,
      verified: wait.ok,
      details: {
        name,
        path,
        ...(uploadedFromRepo ? { uploadedFromRepo: true } : {}),
        ...(cdromId !== null ? { updatedDeviceId: cdromId } : {}),
        ...(rpcError !== null ? { note: `The RPC reported "${rpcError}" but the CD-ROM IS attached — the appliance was just slow (likely I/O on a degraded pool).` } : {}),
      },
    };
  },
};

const vmsDeviceDetachAction: ActionDescriptor<TruenasActionContext> = {
  id: 'vms.device-detach',
  label: 'Detach device from VM',
  description:
    'Removes ONE attached device (any dtype — NIC, disk, display, CD-ROM, PCIe, USB) by its integer device id (vm.device.delete). The VM must be STOPPED. With removeStorage=true a DISK\'s backing zvol is destroyed too.',
  module: 'VMs',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 120_000,
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, description: 'VM name (state check + error context)' },
    deviceId: { type: 'number', required: true, min: 1, description: 'Integer device id from the VM inventory row' },
    removeStorage: { type: 'boolean', required: false, default: false, description: 'Also destroy a DISK\'s backing zvol (destructive)' },
    force: { type: 'boolean', required: false, default: false, description: 'Force removal even if the appliance would otherwise refuse' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const name = str(input, 'name');
    const deviceId = num(input, 'deviceId', -1);
    if (!name) return { success: false, details: { error: 'VM name is required' } };
    if (deviceId < 1) return { success: false, details: { error: 'deviceId (integer device id) is required' } };

    const vms = await listVms(ctx);
    const vm = vms.find((v) => v.name === name);
    if (!vm) return { success: false, details: { error: `VM "${name}" not found on this appliance` } };
    if (vm.state !== 'STOPPED') {
      return { success: false, details: { error: `VM "${name}" is ${vm.state.toLowerCase()} — stop it before detaching devices` } };
    }

    const opts: Record<string, unknown> = {};
    if (input['removeStorage'] === true) opts['zvol'] = true;
    if (input['force'] === true) opts['force'] = true;

    // Transport-tolerant — a lost response is confirmed by re-reading (the device must be GONE).
    // Any error here (method error, or a failed post-drop retry) falls through to the
    // verification poll below, which decides success from the appliance's actual state.
    let deleteError: string | null = null;
    let deleteTransportDrop = false; // true when the failure traces to a lost response, not an appliance rejection
    try {
      const dr = await dispatchWrite(ctx, 'vm.device.delete', [deviceId, opts], {
        verify: async () => {
          try {
            const vms2 = await listVms(ctx);
            const vm2 = vms2.find((v) => v.name === name);
            if (!vm2) return true; // VM itself is gone — device certainly is
            for (const d of vm2.devices) {
              const raw = d as Record<string, unknown>;
              const dev = normalizeVmDevice(d);
              const id = typeof raw['id'] === 'number' ? (raw['id'] as number) : typeof dev?.attrs['id'] === 'number' ? (dev.attrs['id'] as number) : null;
              if (id === deviceId) return false; // still present — not applied
            }
            return true;
          } catch {
            return null;
          }
        },
      });
      if (dr.note) { deleteError = dr.note; deleteTransportDrop = true; } // transport drop — verified/retried inside dispatchWrite
    } catch (e) {
      deleteError = e instanceof Error ? e.message : String(e);
      deleteTransportDrop = isTransportError(e);
    }

    // Verify by re-reading the VM's devices — this integer id must be gone.
    const wait = await pollUntil(
      async () => {
        try {
          const vms2 = await listVms(ctx);
          const vm2 = vms2.find((v) => v.name === name);
          if (!vm2) return true; // VM itself is gone — device certainly is
          for (const d of vm2.devices) {
            const raw = d as Record<string, unknown>;
            const dev = normalizeVmDevice(d);
            const id = typeof raw['id'] === 'number' ? (raw['id'] as number) : typeof dev?.attrs['id'] === 'number' ? (dev.attrs['id'] as number) : null;
            if (id === deviceId) return false;
          }
          return true;
        } catch {
          return null;
        }
      },
      (gone) => gone === true,
      { timeoutMs: 30_000, intervalMs: 2_000 },
    );
    // A transport drop only counts as a failure when the device is still there.
    if (deleteError && !wait.ok) {
      // Re-running a lost-response delete is SAFE — if it did apply, the re-read
      // above already failed to confirm it and the next attempt's verify passes on
      // "device gone". Let the plan executor retry per its policy.
      return { success: false, details: { error: `Device detach failed: ${deleteError}`, ...(deleteTransportDrop ? { retryable: true } : {}) } };
    }
    return { success: true, applied: true, verified: wait.ok, details: { name, deviceId, removeStorage: input['removeStorage'] === true } };
  },
};

/**
 * vms.device-update — the GENERIC "edit an attached device" contract. The webapp's
 * Edit-device dialog renders its form from the type descriptor's `editInputSchema`
 * (prefilled via vms.device-get) and submits the changed fields here; this action
 * maps them onto appliance attributes for ONE partial-merge vm.device.update call
 * (TrueNAS merges — verified in middleware source: device_dict['attributes'].update(new_attrs)).
 * Field names are plugin-agnostic (nicAttach, diskType, resolution, …), so a future
 * Proxmox/libvirt plugin implementing the same id + descriptor fields gets the dialog for free.
 */
const vmsDeviceUpdateAction: ActionDescriptor<TruenasActionContext> = {
  id: 'vms.device-update',
  label: 'Edit attached VM device',
  description:
    'Updates ONE already-attached device in place (vm.device.update, partial merge) — e.g. a NIC\'s bridge/MAC, a disk\'s controller model, a display\'s resolution/port/password/web console, a USB controller model, or swapping the ISO on an existing CD-ROM. Only fields named by the type descriptor\'s editInputSchema are accepted; everything else keeps its current value.',
  module: 'VMs',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 300_000, // CDROM ISO validation on the appliance can take ~60 s+
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, description: 'VM name' },
    deviceId: { type: 'number', required: true, min: 1, description: 'Integer device id from the VM inventory row' },
    fields: { type: 'object', required: true, properties: {}, description: 'Changed editable fields (names match the descriptor\'s editInputSchema)' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const name = str(input, 'name');
    if (!name) return { success: false, details: { error: 'VM name is required' } };
    const deviceId = num(input, 'deviceId', -1);
    if (deviceId < 1) return { success: false, details: { error: 'deviceId (integer device id) is required' } };
    const fieldsRaw = input['fields'];
    if (!fieldsRaw || typeof fieldsRaw !== 'object' || Array.isArray(fieldsRaw)) {
      return { success: false, details: { error: 'fields (object) is required' } };
    }
    const fields = fieldsRaw as Record<string, unknown>;

    // Resolve the device on the appliance — dtype + current attrs come from there.
    let vms: VmInfo[];
    try {
      vms = await listVms(ctx);
    } catch (e) {
      return { success: false, details: { error: e instanceof Error ? e.message : String(e) } };
    }
    const vm = vms.find((v) => v.name === name);
    if (!vm) return { success: false, details: { error: `VM "${name}" not found on this appliance` } };

    let dev: { dtype: string; attrs: Record<string, unknown> } | null = null;
    for (const d of vm.devices) {
      const raw = d as Record<string, unknown>;
      if ((typeof raw['id'] === 'number' ? (raw['id'] as number) : undefined) !== deviceId) continue;
      dev = normalizeVmDevice(d);
      break;
    }
    if (!dev) return { success: false, details: { error: `Device ${deviceId} not found on VM "${name}" — it may have been detached` } };

    // Map the generic field names onto appliance attributes (partial merge).
    const patch: Record<string, unknown> = {};
    const updated: string[] = [];
    switch (dev.dtype.toUpperCase()) {
      case 'NIC': {
        if (typeof fields['nicAttach'] === 'string' && fields['nicAttach'] !== '') { patch['nic_attach'] = fields['nicAttach']; updated.push('nicAttach'); }
        if (typeof fields['mac'] === 'string' && fields['mac'] !== '') { patch['mac'] = fields['mac']; updated.push('mac'); }
        break;
      }
      case 'DISK':
      case 'RAW': {
        if (typeof fields['diskType'] === 'string' && fields['diskType'] !== '') { patch['type'] = fields['diskType']; updated.push('diskType'); }
        break;
      }
      case 'DISPLAY': {
        if (typeof fields['resolution'] === 'string' && fields['resolution'] !== '') { patch['resolution'] = fields['resolution']; updated.push('resolution'); }
        if (typeof fields['port'] === 'number') { patch['port'] = fields['port']; updated.push('port'); }
        if (typeof fields['password'] === 'string' && fields['password'] !== '') { patch['password'] = fields['password']; updated.push('password'); }
        // web is a plain boolean — always sent by the form, so honor it as-is.
        if (typeof fields['web'] === 'boolean') { patch['web'] = fields['web']; updated.push('web'); }
        break;
      }
      case 'USB': {
        if (typeof fields['controllerType'] === 'string' && fields['controllerType'] !== '') { patch['controller_type'] = fields['controllerType']; updated.push('controllerType'); }
        break;
      }
      case 'CDROM': {
        // Same ISO-source options as vms.cdrom-attach — the resolved /mnt/ path is what gets written.
        let isoPath = typeof fields['path'] === 'string' ? (fields['path'] as string) : '';
        if (!isoPath && typeof fields['repoFileId'] === 'string' && fields['repoFileId'] !== '') {
          const dataset = typeof fields['dataset'] === 'string' ? (fields['dataset'] as string) : '';
          if (!dataset) return { success: false, details: { error: 'repoFileId requires a target dataset' } };
          const ensured = await ensureRepoFileOnAppliance(ctx, dataset, fields['repoFileId']);
          if (!ensured.ok) return { success: false, details: { error: ensured.error } };
          isoPath = ensured.path;
        }
        if (!isoPath.startsWith('/mnt/')) return { success: false, details: { error: 'Either a /mnt/ ISO path or repoFileId + dataset is required' } };
        patch['path'] = isoPath;
        updated.push('path');
        break;
      }
      default:
        return { success: false, details: { error: `Device type ${dev.dtype} cannot be edited in place — detach and re-attach it instead` } };
    }

    if (updated.length === 0) {
      return { success: true, applied: false, verified: true, details: { name, deviceId, dtype: dev.dtype, updated: [], note: 'No changes to apply' } };
    }

    // Verify predicate — every patched attribute must read back with the new value.
    const expected: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(patch)) {
      if (k === 'mac') expected[k] = String(v).toLowerCase();
      else expected[k] = v;
    }
    const readDevice = async (): Promise<Record<string, unknown> | null> => {
      try {
        const rows = await ctx.client.call<Record<string, unknown>[]>('vm.device.query', [[['id', '=', deviceId]]], ctx.creds);
        return (rows ?? [])[0] ?? null;
      } catch {
        return null;
      }
    };
    const appliedCheck = async (): Promise<boolean | null> => {
      const row = await readDevice();
      if (!row) return null; // device gone — can't confirm either way
      const attrs = (typeof row['attributes'] === 'object' && row['attributes'] ? row['attributes'] : row) as Record<string, unknown>;
      for (const [k, want] of Object.entries(expected)) {
        const got = attrs[k];
        if (got === undefined || got === null) return null; // field not readable yet — unknown
        if (typeof want === 'string') {
          if (String(got).toLowerCase() !== want.toLowerCase()) return false;
        } else if (got !== want) {
          return false;
        }
      }
      return true;
    };

    // Transport-tolerant — a lost response is confirmed by re-reading the attributes.
    let note: string | undefined;
    try {
      const r = await dispatchWrite(ctx, 'vm.device.update', [deviceId, { attributes: patch }], {
        timeoutMs: 120_000,
        verify: appliedCheck,
      });
      note = r.note;
    } catch (e) {
      // A partial merge is IDEMPOTENT — re-sending the same fields is harmless, so a
      // transport-level failure that survived dispatchWrite's own retry is safe to let
      // the plan executor re-dispatch per its retry policy. Method errors stay hard.
      const msg = e instanceof Error ? e.message : String(e);
      return { success: false, details: { error: msg, ...(isTransportError(e) ? { retryable: true } : {}) } };
    }

    // Final arbiter — the appliance may apply the change a moment after the RPC.
    const wait = await pollUntil(appliedCheck, (ok) => ok === true, { timeoutMs: 45_000, intervalMs: 2_000 });
    if (!wait.ok && note) {
      // Unconfirmed after a transport drop — the merge is idempotent, so let the plan
      // executor re-dispatch instead of failing the step outright.
      return { success: false, details: { error: `Device update reported "${note}" and the new values are not visible on the appliance yet — retrying`, retryable: true } };
    }
    return { success: true, applied: true, verified: wait.ok, details: { name, deviceId, dtype: dev.dtype, updated, ...(note ? { note } : {}) } };
  },
};

// ---------------------------------------------------------------------------
// VM device ATTACH — the generic contract for the webapp's "Add device" dialog.
// The plugin is the single source of truth for what this hypervisor can attach:
//   vms.device-types (read) → details.types[] — one entry per attachable type,
//     each carrying its own inputSchema (the form fields), a `requiresStopped`
//     flag and an optional `choicesActionId` pointing at the read-only action
//     that feeds the dialog's pickers. The webapp renders this generically — it
//     has NO knowledge of TrueNAS dtypes, so a future Proxmox plugin with other
//     types/fields/actions gets the same dialog for free.
//   vms.nic-choices / vms.pci-choices / vms.usb-choices (read) → normalized
//     picker lists from vm.device.nic_attach_choices / passthrough_device_choices
//     / usb_passthrough_choices (+ iommu).
// EDITING an attached device is the same generic contract: each descriptor may
//   carry `editInputSchema` (the subset of fields changeable in place — absent =
//   detach + re-attach only), and two actions serve it:
//     vms.device-get    (read)  → current values of those fields for ONE device id
//                                  (prefill; the webapp never parses appliance attrs).
//     vms.device-update (write) → partial-merge vm.device.update with the changed
//                                  fields mapped onto appliance attributes, verified
//                                  by re-reading each patched attribute.
//   vms.disk-attach / vms.display-attach / vms.pci-attach / vms.usb-attach /
//     vms.nic-attach / vms.cdrom-attach (write) → vm.device.create with the
//     dtype-specific attributes:
//       DISK    { path | create_zvol+zvol_name+zvol_volsize, type, iotype }
//                — a zvol disk is hot-pluggable on TrueNAS 26; an existing
//                /dev/zvol/… or raw file requires a STOPPED VM (the appliance
//                enforces it too).
//       DISPLAY { type VNC|SPICE, resolution, port, web_port, bind, wait,
//                password, web } — the appliance auto-assigns free ports when
//                omitted; at most ONE display per VM (appliance rule) → the
//                dialog is hidden once one exists.
//       PCI     { pptdev: 'pci_<dom>_<bus>_<slot>_<func>' } — STOPPED only, and
//                only while IOMMU is enabled on the host.
//       USB     { usb:{vendor_id,product_id}, controller_type } — identified by
//                vendor/product so it survives reboots; hot-pluggable.
// All of them work with ONLY the primary credential (JSON-RPC) — no SSH needed.
// ---------------------------------------------------------------------------

/** One attachable device type as advertised in vms.device-types details.types[]. */
interface VmDeviceTypeDescriptor {
  /** Appliance-native dtype (DISK | DISPLAY | PCI | USB | NIC | CDROM). */
  dtype: string;
  label: string;
  description?: string;
  /** True when the appliance requires a STOPPED VM for this type. */
  requiresStopped: boolean;
  /** Read-only catalog action whose details feed the dialog's pickers (optional). */
  choicesActionId?: string;
  /** The form fields — rendered by the webapp via SchemaForm, validated here on submit. */
  inputSchema: Record<string, { type: 'string' | 'number' | 'boolean'; label?: string; description?: string; required?: boolean; default?: unknown; enum?: (string | number)[]; min?: number; max?: number; pattern?: string }>;
  /**
   * The SUBSET of fields that can be changed on an ALREADY-ATTACHED device
   * (vms.device-update). Absent = nothing is editable in place — the only way
   * to change such a device is detach + re-attach. Field names match inputSchema
   * where they overlap, so the webapp renders both dialogs from one descriptor.
   */
  editInputSchema?: Record<string, { type: 'string' | 'number' | 'boolean'; label?: string; description?: string; required?: boolean; default?: unknown; enum?: (string | number)[]; min?: number; max?: number; pattern?: string }>;
}

/** The full attachable-type catalog for this appliance — static per plugin. */
const VM_DEVICE_TYPES: VmDeviceTypeDescriptor[] = [
  {
    dtype: 'DISK',
    label: 'Disk',
    description: 'Attach a disk drive — either an existing ZVOL/disk image on the appliance or a brand-new ZVOL. New ZVOLs hot-plug; attaching an EXISTING disk requires a stopped VM.',
    requiresStopped: false, // new zvols hot-plug; existing paths need a stopped VM (appliance-enforced)
    choicesActionId: 'vms.disk-choices',
    inputSchema: {
      mode: { type: 'string', label: 'Source', required: true, enum: ['existing', 'new-zvol'], default: 'existing', description: 'Attach an existing disk or create a new ZVOL' },
      path: { type: 'string', label: 'Disk (existing)', required: false, description: 'ZVOL or raw file from the appliance — pick one above; must start with /dev/zvol/' },
      dataset: { type: 'string', label: 'Dataset for new ZVOL', required: false, description: 'Parent dataset (from vms.create-choices)' },
      sizeBytes: { type: 'number', label: 'ZVOL size (bytes)', required: false, min: 1073741824, description: 'Size of the new ZVOL in bytes' },
      zvolName: { type: 'string', label: 'ZVOL name', required: false, description: 'Leaf name under the dataset — defaults to <VM>-diskN' },
      diskType: { type: 'string', label: 'Controller', required: true, enum: ['VIRTIO', 'AHCI'], default: 'VIRTIO', description: 'Disk controller interface' },
    },
    editInputSchema: {
      // The backing path/zvol is NOT editable in place (detach + re-attach); only the
      // controller model can be swapped on an attached disk.
      diskType: { type: 'string', label: 'Controller', required: true, enum: ['VIRTIO', 'AHCI'], default: 'VIRTIO', description: 'Disk controller interface' },
    },
  },
  {
    dtype: 'DISPLAY',
    label: 'Display (console)',
    description: 'Attach a VNC/SPICE display server so the guest console can be viewed from a client. A password is generated when not given — it is reported in the result.',
    requiresStopped: false, // hot-pluggable; at most one per VM (appliance rule)
    inputSchema: {
      type: { type: 'string', label: 'Protocol', required: true, enum: ['VNC', 'SPICE'], default: 'VNC' },
      resolution: { type: 'string', label: 'Resolution', required: false, description: 'e.g. 1024x768 — auto-assigned when empty' },
      port: { type: 'number', label: 'Port', required: false, min: 5900, max: 65535, description: 'VNC/SPICE port — auto-assigned (free) when empty' },
      password: { type: 'string', label: 'Console password', required: false, description: 'Required by the appliance — a random one is generated and reported in the result when left empty' },
      web: { type: 'boolean', label: 'Web console (SPICE only)', default: true, description: 'Expose the display through the appliance web UI — SPICE displays only; automatically disabled for VNC' },
    },
    editInputSchema: {
      // The protocol (VNC/SPICE) is NOT editable in place — detach + re-attach.
      resolution: { type: 'string', label: 'Resolution', required: false, description: 'e.g. 1024x768 — leave empty to keep the current one' },
      port: { type: 'number', label: 'Port', required: false, min: 5900, max: 65535, description: 'VNC/SPICE port — leave empty to keep the current one' },
      password: { type: 'string', label: 'Console password', required: false, description: 'Leave empty to keep the current password' },
      web: { type: 'boolean', label: 'Web console (SPICE only)', default: false, description: 'Expose the display through the appliance web UI — SPICE displays only; automatically disabled for VNC' },
    },
  },
  {
    dtype: 'PCI',
    label: 'PCIe passthrough',
    description: 'Pass a host PCI device (GPU, NIC, …) through to the VM. Requires IOMMU on the host and a STOPPED VM.',
    requiresStopped: true,
    choicesActionId: 'vms.pci-choices',
    inputSchema: {
      pptdev: { type: 'string', label: 'PCI device', required: true, description: 'Host PCI device from the picker above (pci_<domain>_<bus>_<slot>_<function>)' },
    },
  },
  {
    dtype: 'USB',
    label: 'USB passthrough',
    description: 'Pass a host USB device through to the VM, identified by vendor/product so it survives reboots.',
    requiresStopped: false, // hot-pluggable
    choicesActionId: 'vms.usb-choices',
    inputSchema: {
      usbDevice: { type: 'string', label: 'USB device', required: true, description: 'Host USB device from the picker above (usb_<bus>_<device>)' },
      controllerType: { type: 'string', label: 'Controller', required: false, enum: ['nec-xhci', 'qemu-xhci', 'ehci'], default: 'nec-xhci', description: 'Virtual USB controller model' },
    },
    editInputSchema: {
      // The passthrough target itself is NOT editable in place (detach + re-attach);
      // only the virtual controller model can be swapped.
      controllerType: { type: 'string', label: 'Controller', required: true, enum: ['piix3-uhci', 'piix4-uhci', 'ehci', 'ich9-ehci1', 'vt82c686b-uhci', 'pci-ohci', 'nec-xhci', 'qemu-xhci'], default: 'nec-xhci', description: 'Virtual USB controller model' },
    },
  },
  {
    dtype: 'NIC',
    label: 'Network interface',
    description: 'Attach a network interface — pick a bridge or MACVLAN from the appliance; omit the MAC to let it be auto-assigned.',
    requiresStopped: false, // hot-pluggable
    choicesActionId: 'vms.nic-choices',
    inputSchema: {
      nicAttach: { type: 'string', label: 'Interface (bridge / MACVLAN)', required: true, description: 'Bridge or MACVLAN from the picker above' },
      type: { type: 'string', label: 'Attachment kind', required: false, enum: ['BRIDGE', 'MACVLAN'], default: 'BRIDGE', description: 'Auto-set from the picker — only honored by pre-25.10 appliances (newer ones infer it)' },
      mac: { type: 'string', label: 'MAC address (optional)', required: false, pattern: '^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', description: 'Fixed MAC — auto-assigned when empty' },
    },
    editInputSchema: {
      nicAttach: { type: 'string', label: 'Interface (bridge / MACVLAN)', required: true, description: 'Bridge or MACVLAN from the picker above' },
      mac: { type: 'string', label: 'MAC address (optional)', required: false, pattern: '^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', description: 'Fixed MAC — leave empty to keep the current one' },
    },
  },
  {
    dtype: 'CDROM',
    label: 'CD-ROM / ISO',
    description: 'Attach a CD-ROM drive pointing at an ISO — from the UNM file repo, an existing ISO on the appliance, or a manual /mnt/ path. Swaps the ISO in place when the VM already has a CD-ROM.',
    requiresStopped: false, // hot-pluggable; updates the existing device in place
    inputSchema: {
      source: { type: 'string', label: 'ISO source', required: true, enum: ['repo', 'dataset', 'path'], default: 'repo' },
      repoFileId: { type: 'string', label: 'File from repo', required: false, description: 'UNM file-repo ISO (uploaded first when missing)' },
      dataset: { type: 'string', label: 'Dataset', required: false, description: 'Target dataset for a repo upload / parent of an existing ISO' },
      path: { type: 'string', label: 'ISO path (/mnt/…)', required: false, pattern: '^/mnt/', description: 'Existing ISO on the appliance or manual path' },
    },
    editInputSchema: {
      // Swapping the installed ISO is an in-place update (vm.device.update) — same
      // source options as attach.
      source: { type: 'string', label: 'ISO source', required: true, enum: ['repo', 'dataset', 'path'], default: 'path' },
      repoFileId: { type: 'string', label: 'File from repo', required: false, description: 'UNM file-repo ISO (uploaded first when missing)' },
      dataset: { type: 'string', label: 'Dataset', required: false, description: 'Target dataset for a repo upload / parent of an existing ISO' },
      path: { type: 'string', label: 'ISO path (/mnt/…)', required: false, pattern: '^/mnt/', description: 'Existing ISO on the appliance or manual path' },
    },
  },
];

const vmsDeviceTypesAction: ActionDescriptor<TruenasActionContext> = {
  id: 'vms.device-types',
  label: 'List attachable VM device types',
  description:
    'Read-only descriptor of every device type this hypervisor can attach to a VM — dtype, form fields (inputSchema), whether the VM must be stopped and which read-only action feeds the pickers. Drives the webapp\'s generic "Add device" dialog; no appliance round-trip.',
  module: 'VMs',
  riskLevel: 'read' as const,
  deviceCount: 1 as const,
  inputSchema: {},
  async execute(): Promise<ActionResult> {
    return { success: true, details: { types: VM_DEVICE_TYPES } };
  },
};

/**
 * vms.device-get — read the CURRENT values of an attached device's editable
 * fields (the subset named in each type descriptor's `editInputSchema`). The
 * webapp's Edit-device dialog prefills its form from this, so it never has to
 * parse appliance attribute names itself. Field keys match editInputSchema:
 *   NIC     { nicAttach, mac }        DISK  { diskType }
 *   DISPLAY { resolution, port, password, web }
 *   USB     { controllerType }        CDROM { path } (source defaults to 'path')
 */
const vmsDeviceGetAction: ActionDescriptor<TruenasActionContext> = {
  id: 'vms.device-get',
  label: 'Read attached device values',
  description:
    'Read-only — returns the current editable field values of ONE attached VM device (prefill for the Edit-device dialog). Field names match the type descriptor\'s editInputSchema.',
  module: 'VMs',
  riskLevel: 'read' as const,
  deviceCount: 1 as const,
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, description: 'VM name' },
    deviceId: { type: 'number', required: true, min: 1, description: 'Integer device id from the VM inventory row' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const name = str(input, 'name');
    if (!name) return { success: false, details: { error: 'VM name is required' } };
    const deviceId = num(input, 'deviceId', -1);
    if (deviceId < 1) return { success: false, details: { error: 'deviceId (integer device id) is required' } };

    let vms: VmInfo[];
    try {
      vms = await listVms(ctx);
    } catch (e) {
      return { success: false, details: { error: e instanceof Error ? e.message : String(e) } };
    }
    const vm = vms.find((v) => v.name === name);
    if (!vm) return { success: false, details: { error: `VM "${name}" not found on this appliance` } };

    let dev: { dtype: string; attrs: Record<string, unknown> } | null = null;
    for (const d of vm.devices) {
      const raw = d as Record<string, unknown>;
      const id = typeof raw['id'] === 'number' ? (raw['id'] as number) : undefined;
      if (id !== deviceId) continue;
      dev = normalizeVmDevice(d);
      break;
    }
    if (!dev) return { success: false, details: { error: `Device ${deviceId} not found on VM "${name}" — it may have been detached` } };

    const a = dev.attrs;
    switch (dev.dtype.toUpperCase()) {
      case 'NIC':
        return { success: true, details: { deviceId, dtype: dev.dtype, values: { nicAttach: pickString(a, ['nic_attach']), mac: pickString(a, ['mac']) } } };
      case 'DISK':
      case 'RAW':
        return { success: true, details: { deviceId, dtype: dev.dtype, values: { diskType: pickString(a, ['type']) ?? 'VIRTIO' } } };
      case 'DISPLAY': {
        const port = typeof a['port'] === 'number' ? (a['port'] as number) : undefined;
        return { success: true, details: { deviceId, dtype: dev.dtype, values: { resolution: pickString(a, ['resolution']), ...(port !== undefined ? { port } : {}), password: pickString(a, ['password']), web: a['web'] === true } } };
      }
      case 'USB':
        return { success: true, details: { deviceId, dtype: dev.dtype, values: { controllerType: pickString(a, ['controller_type']) ?? 'nec-xhci' } } };
      case 'CDROM':
        // The current ISO already lives on the appliance — prefill the manual-path source.
        return { success: true, details: { deviceId, dtype: dev.dtype, values: { source: 'path', path: pickString(a, ['path']) ?? '' } } };
      default:
        return { success: false, details: { error: `Device type ${dev.dtype} has no editable fields on this appliance` } };
    }
  },
};

// ---------------------------------------------------------------------------
// VM-level EDIT — the generic contract for editing a VM's OWN settings (not its
// attached devices): name/description/autostart/boot method/system clock/NUMA
// node/CPU topology/memory. Same shape as the device edit contract:
//   vms.vm-edit-schema (read) → details.fields[] — one entry per editable field,
//     each carrying its form property + `requiresStopped` (the appliance only
//     allows a NAME change while the VM is inactive; every other field is a
//     datastore write that takes effect at the next boot).
//   vms.vm-get    (read)  → current values of those fields for ONE VM name
//                            (prefill; the webapp never parses appliance attrs).
//   vms.vm-update (write) → partial-merge vm.update with ONLY the changed
//                            fields, verified by re-reading the VM row.
// TrueNAS's vm.update is a PARTIAL MERGE (`new = old.copy(); new.update(data)`
// in middleware plugins/vm/vms.py do_update — verified on 26.0 BETA), so
// untouched attributes are preserved; `devices`/`status` are stripped by the
// appliance itself, never sent here. A future Proxmox plugin implementing the
// same three ids gets the webapp's Edit-VM dialog for free.
// ---------------------------------------------------------------------------

/** One editable VM-level field as advertised in vms.vm-edit-schema details.fields[]. */
interface VmEditField {
  /** Generic field name (matches the keys of vms.vm-get values / vms.vm-update fields). */
  key: string;
  label: string;
  description?: string;
  type: 'string' | 'number' | 'boolean';
  required?: boolean;
  default?: unknown;
  enum?: (string | number)[];
  min?: number;
  max?: number;
  pattern?: string;
  /** True when the appliance only accepts this change while the VM is inactive. */
  requiresStopped: boolean;
  /**
   * True for optional strings where an EMPTY value is a legitimate change
   * (clearing the setting) rather than "keep current" — the webapp renders
   * these as plain inputs that keep '' as a real value and sends it through.
   */
  clearable?: boolean;
}

/** The full editable-VM-settings catalog for this hypervisor — static per plugin. */
const VM_EDIT_FIELDS: VmEditField[] = [
  { key: 'name', label: 'Name', type: 'string', required: true, pattern: '^[a-zA-Z_0-9]+$', description: 'Guest name (alphanumeric + underscore). Renaming requires a STOPPED VM — the appliance enforces it.', requiresStopped: true },
  { key: 'description', label: 'Description', type: 'string', required: false, clearable: true, description: 'Free-text guest description shown on the VMs page. Leave empty to remove it.', requiresStopped: false },
  { key: 'autostart', label: 'Start after boot (autostart)', type: 'boolean', default: false, description: 'Start this VM automatically when the appliance boots.', requiresStopped: false },
  { key: 'bootloader', label: 'Boot method (firmware)', type: 'string', required: true, enum: ['UEFI', 'UEFI_CSM'], default: 'UEFI', description: 'UEFI = modern firmware; UEFI_CSM = legacy BIOS compatibility mode.', requiresStopped: false },
  { key: 'time', label: 'System clock (guest time source)', type: 'string', required: true, enum: ['UTC', 'LOCAL'], default: 'UTC', description: 'UTC — the guest keeps UTC; LOCAL — the appliance passes its local timezone to the guest.', requiresStopped: false },
  { key: 'nodeset', label: 'NUMA node (nodeset)', type: 'string', required: false, clearable: true, pattern: '^\\d+(?:-\\d+)?(?:,\\d+(?:-\\d+)?)?$', description: 'Pin the VM to specific NUMA nodes — e.g. "0", "1" or "0-1". Leave empty for no restriction (appliance default).', requiresStopped: false },
  { key: 'cpuset', label: 'CPU pinning (cpuset)', type: 'string', required: false, clearable: true, pattern: '^\\d+(?:-\\d+)?(?:,\\d+(?:-\\d+)?)?$', description: 'Pin vCPUs to specific host CPUs — e.g. "0-3" or "0,2". Leave empty for no pinning (appliance default).', requiresStopped: false },
  { key: 'cores', label: 'Cores per package', type: 'number', required: true, min: 1, max: 64, description: 'CPU cores per socket. Total vCPUs = sockets × cores × threads.', requiresStopped: false },
  { key: 'threads', label: 'Threads per core', type: 'number', required: true, min: 1, max: 8, description: 'Threads (hyperthreading) per core.', requiresStopped: false },
  { key: 'memoryMiB', label: 'Memory (MiB)', type: 'number', required: true, min: 20, description: 'Maximum guest RAM in MiB. Takes effect at the next boot.', requiresStopped: false },
  { key: 'minMemoryMiB', label: 'Minimum memory (MiB)', type: 'number', required: false, clearable: true, min: 0, description: 'Optional minimum RAM for ballooning — must be ≤ maximum memory. Leave empty to disable.', requiresStopped: false },
  { key: 'pinVcpus', label: 'Pin vCPUs (strict CPU pinning)', type: 'boolean', default: false, description: 'Require the cpuset above to cover exactly one host CPU per vCPU (sockets × cores × threads). The appliance rejects a mismatch.', requiresStopped: false },
  { key: 'shutdownTimeoutSec', label: 'Shutdown timeout (seconds)', type: 'number', required: true, min: 0, max: 3600, description: 'Seconds the appliance waits for a clean guest shutdown before forcing poweroff. Default 90.', requiresStopped: false },
  { key: 'suspendOnSnapshot', label: 'Suspend on snapshot', type: 'boolean', default: false, description: 'Automatically pause (suspend) this VM when a TrueNAS snapshot is taken.', requiresStopped: false },
  { key: 'hideFromMsr', label: 'Hide KVM from MSR discovery', type: 'boolean', default: false, description: 'Hides the KVM hypervisor from standard MSR-based guest discovery (anti-VM-detection).', requiresStopped: false },
  { key: 'ensureDisplayDevice', label: 'Ensure display device', type: 'boolean', default: true, description: 'Guarantees the guest always has a video device even when no console is attached.', requiresStopped: false },
  { key: 'trustedPlatformModule', label: 'Trusted Platform Module (TPM)', type: 'boolean', default: false, description: 'Attach a virtual TPM to this VM. Requires UEFI firmware and a reboot of the guest to use it.', requiresStopped: false },
  { key: 'hypervEnlightenments', label: 'Hyper-V enlightenments', type: 'boolean', default: false, description: 'Enable a subset of predefined Hyper-V enlightenments — recommended for Windows guests.', requiresStopped: false },
  { key: 'cpuMode', label: 'CPU mode', type: 'string', required: true, enum: ['HOST-PASSTHROUGH', 'CUSTOM'], default: 'HOST-PASSTHROUGH', description: 'HOST-PASSTHROUGH exposes the host CPU model to the guest; CUSTOM lets you pick a specific CPU model.', requiresStopped: false },
  { key: 'cpuModel', label: 'CPU model (when mode = CUSTOM)', type: 'string', required: false, clearable: true, description: 'Specific CPU model presented to the guest — only valid when CPU mode is CUSTOM. Leave empty for HOST-PASSTHROUGH.', requiresStopped: false },
  { key: 'commandLineArgs', label: 'Command line arguments (QEMU)', type: 'string', required: false, clearable: true, description: 'Extra raw QEMU command-line arguments appended to the guest launch. Advanced — leave empty unless you know what you are doing.', requiresStopped: false },
];

const vmsVmEditSchemaAction: ActionDescriptor<TruenasActionContext> = {
  id: 'vms.vm-edit-schema',
  label: 'List editable VM settings',
  description:
    'Read-only descriptor of every VM-level setting this hypervisor can edit in place — field name, form property (type/enum/pattern/min/max) and whether the appliance requires a STOPPED VM for it. Drives the webapp\'s generic "Edit VM" dialog; no appliance round-trip.',
  module: 'VMs',
  riskLevel: 'read' as const,
  deviceCount: 1 as const,
  inputSchema: {},
  async execute(): Promise<ActionResult> {
    return { success: true, details: { fields: VM_EDIT_FIELDS } };
  },
};

/**
 * vms.vm-get — read the CURRENT values of a VM's editable settings (the subset
 * named in VM_EDIT_FIELDS). The webapp's Edit-VM dialog prefills its form from
 * this, so it never has to parse appliance attribute names itself. Field keys
 * match VM_EDIT_FIELDS: name/description/autostart/bootloader/time/nodeset/
 * cpuset/cores/threads/memoryMiB/minMemoryMiB/pinVcpus/shutdownTimeoutSec/
 * suspendOnSnapshot/hideFromMsr/ensureDisplayDevice/trustedPlatformModule/
 * hypervEnlightenments/cpuMode/cpuModel/commandLineArgs.
 */
const vmsVmGetAction: ActionDescriptor<TruenasActionContext> = {
  id: 'vms.vm-get',
  label: 'Read VM settings values',
  description:
    'Read-only — returns the current editable setting values of ONE VM (prefill for the Edit-VM dialog). Field names match vms.vm-edit-schema.',
  module: 'VMs',
  riskLevel: 'read' as const,
  deviceCount: 1 as const,
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, description: 'VM name' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const name = str(input, 'name');
    if (!name) return { success: false, details: { error: 'VM name is required' } };

    let vms: VmInfo[];
    try {
      vms = await listVms(ctx);
    } catch (e) {
      return { success: false, details: { error: e instanceof Error ? e.message : String(e) } };
    }
    const vm = vms.find((v) => v.name === name);
    if (!vm) return { success: false, details: { error: `VM "${name}" not found on this appliance` } };

    // Re-read the raw row — listVms normalizes away most of the settings.
    let row: Record<string, unknown> | null = null;
    try {
      const rows = await ctx.client.call<Record<string, unknown>[]>('vm.query', [[['name', '=', name]]], ctx.creds);
      row = (rows ?? [])[0] ?? null;
    } catch { /* fall through — the values below degrade to what listVms knew */ }

    const cores = typeof row?.['cores'] === 'number' ? (row['cores'] as number) : 1;
    const threads = typeof row?.['threads'] === 'number' ? (row['threads'] as number) : 1;
    return {
      success: true,
      details: {
        name,
        state: vm.state,
        values: {
          name: vm.name,
          description: typeof row?.['description'] === 'string' ? (row['description'] as string) : '',
          autostart: row?.['autostart'] === true,
          bootloader: pickString(row ?? {}, ['bootloader']) ?? 'UEFI',
          time: pickString(row ?? {}, ['time']) ?? 'UTC',
          nodeset: typeof row?.['nodeset'] === 'string' ? (row['nodeset'] as string) : '',
          cpuset: typeof row?.['cpuset'] === 'string' ? (row['cpuset'] as string) : '',
          cores,
          threads,
          memoryMiB: typeof row?.['memory'] === 'number' ? (row['memory'] as number) : undefined,
          minMemoryMiB: typeof row?.['min_memory'] === 'number' ? (row['min_memory'] as number) : '',
          pinVcpus: row?.['pin_vcpus'] === true,
          shutdownTimeoutSec: typeof row?.['shutdown_timeout'] === 'number' ? (row['shutdown_timeout'] as number) : 90,
          suspendOnSnapshot: row?.['suspend_on_snapshot'] === true,
          hideFromMsr: row?.['hide_from_msr'] === true,
          ensureDisplayDevice: row?.['ensure_display_device'] !== false, // appliance default is true
          trustedPlatformModule: row?.['trusted_platform_module'] === true,
          hypervEnlightenments: row?.['hyperv_enlightenments'] === true,
          cpuMode: pickString(row ?? {}, ['cpu_mode']) ?? 'HOST-PASSTHROUGH',
          cpuModel: typeof row?.['cpu_model'] === 'string' ? (row['cpu_model'] as string) : '',
          commandLineArgs: typeof row?.['command_line_args'] === 'string' ? (row['command_line_args'] as string) : '',
        },
      },
    };
  },
};

/**
 * vms.vm-update — edit a VM's OWN settings in place. Partial-merge vm.update
 * with ONLY the changed fields (names match VM_EDIT_FIELDS), verified by
 * re-reading the VM row. A name change requires an INACTIVE VM (appliance rule,
 * enforced here pre-RPC); every other field is accepted in any state — most take
 * effect at the guest's next boot.
 */
const vmsVmUpdateAction: ActionDescriptor<TruenasActionContext> = {
  id: 'vms.vm-update',
  label: 'Edit VM settings',
  description:
    'Updates ONE VM\'s own settings in place (vm.update, partial merge) — name/description/autostart/boot method/system clock/NUMA node/CPU pinning + strict vCPU pinning/CPU topology/memory (+ minimum)/shutdown timeout/snapshot suspend/MSR hiding/display guarantee/TPM/Hyper-V enlightenments/CPU mode & model/QEMU command-line args. Only fields named by vms.vm-edit-schema are accepted; everything else keeps its current value. A NAME change requires a STOPPED VM.',
  module: 'VMs',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 300_000,
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, description: 'Current VM name (lookup key)' },
    fields: { type: 'object', required: true, properties: {}, description: 'Changed settings (names match vms.vm-edit-schema; empty string clears cpuset/nodeset/description/cpuModel/commandLineArgs/minMemoryMiB)' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const name = str(input, 'name');
    if (!name) return { success: false, details: { error: 'VM name is required' } };
    const fieldsRaw = input['fields'];
    if (!fieldsRaw || typeof fieldsRaw !== 'object' || Array.isArray(fieldsRaw)) {
      return { success: false, details: { error: 'fields (object) is required' } };
    }
    const fields = fieldsRaw as Record<string, unknown>;

    let vms: VmInfo[];
    try {
      vms = await listVms(ctx);
    } catch (e) {
      return { success: false, details: { error: e instanceof Error ? e.message : String(e) } };
    }
    const vm = vms.find((v) => v.name === name);
    if (!vm) return { success: false, details: { error: `VM "${name}" not found on this appliance` } };

    // Raw row — needed for cross-field validation (cpuset/cpu_mode/memory the
    // normalized VmInfo doesn't carry).
    let row: Record<string, unknown> | null = null;
    try {
      const rows = await ctx.client.call<Record<string, unknown>[]>('vm.query', [[['name', '=', name]]], ctx.creds);
      row = (rows ?? [])[0] ?? null;
    } catch { /* fall through — cross-field checks degrade to patch-only */ }

    // Map the generic field names onto appliance attributes (partial merge).
    const patch: Record<string, unknown> = {};
    const updated: string[] = [];
    for (const f of VM_EDIT_FIELDS) {
      if (!(f.key in fields)) continue;
      switch (f.key) {
        case 'name':
          if (typeof fields['name'] === 'string' && fields['name'] !== '') { patch['name'] = fields['name']; updated.push('name'); }
          break;
        case 'description':
          // Empty string CLEARS the description — a legitimate change.
          if (typeof fields['description'] === 'string') { patch['description'] = fields['description']; updated.push('description'); }
          break;
        case 'autostart':
          if (typeof fields['autostart'] === 'boolean') { patch['autostart'] = fields['autostart']; updated.push('autostart'); }
          break;
        case 'bootloader':
          if (typeof fields['bootloader'] === 'string' && fields['bootloader'] !== '') { patch['bootloader'] = fields['bootloader']; updated.push('bootloader'); }
          break;
        case 'time':
          if (typeof fields['time'] === 'string' && fields['time'] !== '') { patch['time'] = fields['time']; updated.push('time'); }
          break;
        case 'nodeset':
          // Empty string CLEARS the NUMA restriction → null on the appliance.
          if (typeof fields['nodeset'] === 'string') { patch['nodeset'] = fields['nodeset'] === '' ? null : fields['nodeset']; updated.push('nodeset'); }
          break;
        case 'cpuset':
          // Empty string CLEARS the CPU pinning → null on the appliance.
          if (typeof fields['cpuset'] === 'string') { patch['cpuset'] = fields['cpuset'] === '' ? null : fields['cpuset']; updated.push('cpuset'); }
          break;
        case 'cores':
          if (typeof fields['cores'] === 'number' && fields['cores'] >= 1) { patch['cores'] = fields['cores']; updated.push('cores'); }
          break;
        case 'threads':
          if (typeof fields['threads'] === 'number' && fields['threads'] >= 1) { patch['threads'] = fields['threads']; updated.push('threads'); }
          break;
        case 'memoryMiB':
          if (typeof fields['memoryMiB'] === 'number' && fields['memoryMiB'] > 0) { patch['memory'] = fields['memoryMiB']; updated.push('memoryMiB'); }
          break;
        case 'minMemoryMiB':
          // Empty string CLEARS the ballooning floor → null on the appliance.
          if (typeof fields['minMemoryMiB'] === 'string' && fields['minMemoryMiB'] === '') { patch['min_memory'] = null; updated.push('minMemoryMiB'); }
          else if (typeof fields['minMemoryMiB'] === 'number' && fields['minMemoryMiB'] >= 0) { patch['min_memory'] = fields['minMemoryMiB']; updated.push('minMemoryMiB'); }
          break;
        case 'pinVcpus':
          if (typeof fields['pinVcpus'] === 'boolean') { patch['pin_vcpus'] = fields['pinVcpus']; updated.push('pinVcpus'); }
          break;
        case 'shutdownTimeoutSec':
          if (typeof fields['shutdownTimeoutSec'] === 'number' && fields['shutdownTimeoutSec'] >= 0) { patch['shutdown_timeout'] = Math.round(fields['shutdownTimeoutSec']); updated.push('shutdownTimeoutSec'); }
          break;
        case 'suspendOnSnapshot':
          if (typeof fields['suspendOnSnapshot'] === 'boolean') { patch['suspend_on_snapshot'] = fields['suspendOnSnapshot']; updated.push('suspendOnSnapshot'); }
          break;
        case 'hideFromMsr':
          if (typeof fields['hideFromMsr'] === 'boolean') { patch['hide_from_msr'] = fields['hideFromMsr']; updated.push('hideFromMsr'); }
          break;
        case 'ensureDisplayDevice':
          if (typeof fields['ensureDisplayDevice'] === 'boolean') { patch['ensure_display_device'] = fields['ensureDisplayDevice']; updated.push('ensureDisplayDevice'); }
          break;
        case 'trustedPlatformModule':
          if (typeof fields['trustedPlatformModule'] === 'boolean') { patch['trusted_platform_module'] = fields['trustedPlatformModule']; updated.push('trustedPlatformModule'); }
          break;
        case 'hypervEnlightenments':
          if (typeof fields['hypervEnlightenments'] === 'boolean') { patch['hyperv_enlightenments'] = fields['hypervEnlightenments']; updated.push('hypervEnlightenments'); }
          break;
        case 'cpuMode':
          if (typeof fields['cpuMode'] === 'string' && fields['cpuMode'] !== '') { patch['cpu_mode'] = fields['cpuMode']; updated.push('cpuMode'); }
          break;
        case 'cpuModel':
          // Empty string CLEARS the model → null on the appliance.
          if (typeof fields['cpuModel'] === 'string') { patch['cpu_model'] = fields['cpuModel'] === '' ? null : fields['cpuModel']; updated.push('cpuModel'); }
          break;
        case 'commandLineArgs':
          // Empty string is a legitimate value — it clears the extra args.
          if (typeof fields['commandLineArgs'] === 'string') { patch['command_line_args'] = fields['commandLineArgs']; updated.push('commandLineArgs'); }
          break;
      }
    }

    // Cross-field rules the appliance enforces anyway — fail early with a clear message.
    const effectiveMemory = typeof patch['memory'] === 'number' ? (patch['memory'] as number) : (typeof row?.['memory'] === 'number' ? (row['memory'] as number) : null);
    if (typeof patch['min_memory'] === 'number' && effectiveMemory !== null && patch['min_memory'] > effectiveMemory) {
      return { success: false, details: { error: `Minimum memory (${patch['min_memory']} MiB) must not exceed the maximum memory (${effectiveMemory} MiB).` } };
    }
    const effectiveCpuset: string | null = typeof patch['cpuset'] === 'string' || patch['cpuset'] === null
      ? (patch['cpuset'] as string | null)
      : (typeof row?.['cpuset'] === 'string' ? (row['cpuset'] as string) : null);
    if ((patch['pin_vcpus'] ?? false) === true && !effectiveCpuset) {
      return { success: false, details: { error: 'Pin vCPUs requires a CPU pinning (cpuset) — set the cpuset to one host CPU per vCPU first.' } };
    }
    const effectiveCpuMode = typeof patch['cpu_mode'] === 'string' ? (patch['cpu_mode'] as string) : pickString(row ?? {}, ['cpu_mode']) ?? 'HOST-PASSTHROUGH';
    if (effectiveCpuMode !== 'CUSTOM') {
      // The appliance validates the MERGED VM — a leftover cpu_model with a non-CUSTOM
      // mode is rejected, so clear it whenever one is present.
      const currentModel = typeof row?.['cpu_model'] === 'string' ? (row['cpu_model'] as string) : null;
      if (patch['cpu_model']) {
        return { success: false, details: { error: 'CPU model can only be set when CPU mode is CUSTOM — switch the CPU mode first.' } };
      }
      if (currentModel && patch['cpu_model'] !== null) patch['cpu_model'] = null;
    } else if (!patch['cpu_model']) {
      const currentModel = typeof row?.['cpu_model'] === 'string' ? (row['cpu_model'] as string) : null;
      // Only complain when the switch to CUSTOM happens in THIS patch and no model
      // exists yet — an already-CUSTOM VM with a model needs nothing.
      if (!currentModel) {
        return { success: false, details: { error: 'CPU mode CUSTOM requires a CPU model — pick one (or switch back to HOST-PASSTHROUGH).' } };
      }
    }

    if (updated.length === 0) {
      return { success: true, applied: false, verified: true, details: { name, updated: [], note: 'No changes to apply' } };
    }

    // Appliance rule — a NAME change is only allowed while the VM is inactive.
    if (updated.includes('name') && vm.state !== 'STOPPED') {
      return { success: false, details: { error: `Renaming requires a STOPPED VM — "${name}" is ${vm.state.toLowerCase()}. Stop it first, then retry.` } };
    }

    // Verify predicate — every patched attribute must read back with the new value.
    const expected: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(patch)) {
      if (k === 'name') continue; // handled below via the lookup-by-name
      expected[k] = v;
    }
    const newName = typeof patch['name'] === 'string' ? (patch['name'] as string) : null;
    const readVm = async (): Promise<Record<string, unknown> | null> => {
      try {
        // After a rename the OLD name is gone — look up by whichever exists.
        const rows = await ctx.client.call<Record<string, unknown>[]>('vm.query', [], ctx.creds);
        return (rows ?? []).find((r) => r['name'] === newName || r['name'] === name) ?? null;
      } catch {
        return null;
      }
    };
    const appliedCheck = async (): Promise<boolean | null> => {
      const row = await readVm();
      if (!row) return null; // VM gone — can't confirm either way
      if (newName && row['name'] !== newName) return false; // rename not visible yet
      for (const [k, want] of Object.entries(expected)) {
        const got = row[k];
        if (want === null) {
          if (got !== null && got !== undefined) return false;
          continue;
        }
        if (got === undefined || got === null) return null; // field not readable yet — unknown
        if (typeof want === 'string') {
          if (String(got).toLowerCase() !== want.toLowerCase()) return false;
        } else if (got !== want) {
          return false;
        }
      }
      return true;
    };

    // Transport-tolerant — a lost response is confirmed by re-reading the row.
    let note: string | undefined;
    try {
      const r = await dispatchWrite(ctx, 'vm.update', [vm.id, patch], {
        timeoutMs: 60_000,
        verify: appliedCheck,
      });
      note = r.note;
    } catch (e) {
      // A partial merge is IDEMPOTENT — re-sending the same fields is harmless, so a
      // transport-level failure that survived dispatchWrite's own retry is safe to let
      // the plan executor re-dispatch per its retry policy. Method errors stay hard.
      const msg = e instanceof Error ? e.message : String(e);
      return { success: false, details: { error: msg, ...(isTransportError(e) ? { retryable: true } : {}) } };
    }

    // Final arbiter — the appliance may apply the change a moment after the RPC.
    const wait = await pollUntil(appliedCheck, (ok) => ok === true, { timeoutMs: 45_000, intervalMs: 2_000 });
    if (!wait.ok && note) {
      // Unconfirmed after a transport drop — the merge is idempotent, so let the plan
      // executor re-dispatch instead of failing the step outright.
      return { success: false, details: { error: `VM update reported "${note}" and the new values are not visible on the appliance yet — retrying`, retryable: true } };
    }
    return { success: true, applied: true, verified: wait.ok, details: { name, ...(newName ? { newName } : {}), updated, ...(note ? { note } : {}) } };
  },
};

/**
 * vms.serial-consoles — read-only availability list for the webapp's per-row
 * "Serial console" quick action (Guest Actions column on the VMs page). The
 * actual attach rides the generic console chain (capability 'sshConsole',
 * context {kind:'vm-serial', name}) — this action only tells the UI which rows
 * may offer it, so a hypervisor plugin that cannot serve serial consoles simply
 * never advertises the id and the button stays hidden. Every VM is listed with
 * its current state; the webapp decides per-state eligibility (attach works on
 * RUNNING/SUSPENDED guests — a stopped guest has no live PTY to attach to).
 */
const vmsSerialConsolesAction: ActionDescriptor<TruenasActionContext> = {
  id: 'vms.serial-consoles',
  label: 'List VM serial consoles',
  description:
    'Read-only list of the VMs whose guest serial console can be attached to (name + current state). Drives the webapp\'s per-row "Serial console" quick action; the attach itself uses the generic console chain with context {kind:"vm-serial", name}.',
  module: 'VMs',
  riskLevel: 'read' as const,
  deviceCount: 1 as const,
  inputSchema: {},
  async execute(ctx: TruenasActionContext): Promise<ActionResult> {
    let vms: VmInfo[];
    try {
      vms = await listVms(ctx);
    } catch (e) {
      return { success: false, details: { error: e instanceof Error ? e.message : String(e) } };
    }
    return { success: true, details: { consoles: vms.map((v) => ({ name: v.name, state: v.state })) } };
  },
};

const vmsPciChoicesAction: ActionDescriptor<TruenasActionContext> = {
  id: 'vms.pci-choices',
  label: 'List PCIe passthrough devices',
  description:
    'Read-only list of the host PCI devices available for passthrough (vm.device.passthrough_device_choices), normalized to {id, description, available, critical, error} + whether IOMMU is enabled on the host. Feeds the Add-device dialog\'s PCIe picker.',
  module: 'VMs',
  riskLevel: 'read' as const,
  deviceCount: 1 as const,
  timeoutMs: 60_000, // enumerates every PCI device + IOMMU groups — slow on big hosts
  inputSchema: {},
  async execute(ctx: TruenasActionContext): Promise<ActionResult> {
    try {
      let iommu = false;
      try { iommu = (await ctx.client.call<boolean>('vm.device.iommu_enabled', [], ctx.creds)) === true; } catch { /* unknown */ }
      const raw = await ctx.client.call<Record<string, Record<string, unknown>>>('vm.device.passthrough_device_choices', [], ctx.creds);
      const devices: { id: string; description: string; available: boolean; critical: boolean; error?: string | null }[] = [];
      for (const [id, info] of Object.entries(raw ?? {})) {
        if (!info || typeof info !== 'object') continue;
        devices.push({
          id,
          description: pickString(info, ['description']) ?? id,
          available: info['available'] === true,
          critical: info['critical'] === true,
          error: typeof info['error'] === 'string' ? (info['error'] as string) : null,
        });
      }
      // Usable devices first — the dialog's picker should lead with what works.
      devices.sort((a, b) => Number(b.available && !b.critical) - Number(a.available && !a.critical) || a.description.localeCompare(b.description));
      return { success: true, details: { iommuEnabled: iommu, devices } };
    } catch (e) {
      return { success: false, details: { error: e instanceof Error ? e.message : String(e) } };
    }
  },
};

const vmsUsbChoicesAction: ActionDescriptor<TruenasActionContext> = {
  id: 'vms.usb-choices',
  label: 'List USB passthrough devices',
  description:
    'Read-only list of the host USB devices available for passthrough (vm.device.usb_passthrough_choices), normalized to {id, description, vendorId, productId, available}. Feeds the Add-device dialog\'s USB picker.',
  module: 'VMs',
  riskLevel: 'read' as const,
  deviceCount: 1 as const,
  inputSchema: {},
  async execute(ctx: TruenasActionContext): Promise<ActionResult> {
    try {
      const raw = await ctx.client.call<Record<string, Record<string, unknown>>>('vm.device.usb_passthrough_choices', [], ctx.creds);
      const devices: { id: string; description: string; vendorId?: string | null; productId?: string | null; available: boolean }[] = [];
      for (const [id, info] of Object.entries(raw ?? {})) {
        if (!info || typeof info !== 'object') continue;
        const cap = (info['capability'] ?? {}) as Record<string, unknown>;
        devices.push({
          id,
          description: pickString(info, ['description']) ?? id,
          vendorId: pickString(cap, ['vendor_id']),
          productId: pickString(cap, ['product_id']),
          available: info['available'] === true,
        });
      }
      devices.sort((a, b) => Number(b.available) - Number(a.available) || a.description.localeCompare(b.description));
      return { success: true, details: { devices } };
    } catch (e) {
      return { success: false, details: { error: e instanceof Error ? e.message : String(e) } };
    }
  },
};

const vmsDiskChoicesAction: ActionDescriptor<TruenasActionContext> = {
  id: 'vms.disk-choices',
  label: 'List attachable disks',
  description:
    'Read-only list of the appliance\'s ZVOLs (vm.device.disk_choices), normalized to {path, name} and sorted. Feeds the Add-device dialog\'s existing-disk picker for DISK attaches.',
  module: 'VMs',
  riskLevel: 'read' as const,
  deviceCount: 1 as const,
  inputSchema: {},
  async execute(ctx: TruenasActionContext): Promise<ActionResult> {
    try {
      const raw = await ctx.client.call<Record<string, string>>('vm.device.disk_choices', [], ctx.creds);
      const disks: { path: string; name: string }[] = [];
      for (const [path, name] of Object.entries(raw ?? {})) {
        if (!path.startsWith('/dev/zvol/')) continue; // raw files are not hot-pluggable — skip them here
        disks.push({ path, name: typeof name === 'string' && name !== '' ? name : path });
      }
      disks.sort((a, b) => a.name.localeCompare(b.name));
      return { success: true, details: { disks } };
    } catch (e) {
      return { success: false, details: { error: e instanceof Error ? e.message : String(e) } };
    }
  },
};

/** Resolves a VM by name and checks its state against the attach requirements. */
async function resolveVmForAttach(ctx: TruenasActionContext, name: string | undefined): Promise<{ ok: true; vm: VmInfo } | { ok: false; error: string }> {
  if (!name) return { ok: false, error: 'VM name is required' };
  const vms = await listVms(ctx);
  const vm = vms.find((v) => v.name === name);
  if (!vm) return { ok: false, error: `VM "${name}" not found on this appliance` };
  return { ok: true, vm };
}

/** Creates a VM device, tolerating ONE transport-level failure (dropped socket).
 * When the create's response is lost mid-flight ("unresponsive — reconnecting"),
 * the appliance may have applied it anyway — so before retrying we re-read the
 * VM's devices and only retry when the device demonstrably did NOT land. This
 * makes a flaky WebSocket unable to create duplicate devices. */
async function createVmDevice(
  ctx: TruenasActionContext,
  vmId: number,
  attrs: Record<string, unknown>,
  timeoutMs: number,
  landedCheck: (dev: { dtype: string; attrs: Record<string, unknown> }) => boolean,
): Promise<void> {
  const v26 = await usesV26VmDeviceApi(ctx);
  try {
    await ctx.client.call('vm.device.create', [vmDeviceCreateArg(v26, vmId, attrs)], ctx.creds, timeoutMs);
    return;
  } catch (e) {
    if (!(e instanceof TruenasRpcError) || !/unresponsive|timed out/i.test(e.message)) throw e;
  }
  // Transport dropped mid-call — did the appliance apply it anyway?
  const landed = await pollUntil(
    async () => {
      try {
        const vms2 = await listVms(ctx);
        const vm2 = vms2.find((v) => v.id === vmId);
        if (!vm2) return false;
        for (const d of vm2.devices) {
          const dev = normalizeVmDevice(d);
          if (dev && landedCheck(dev)) return true;
        }
        return false;
      } catch {
        return null;
      }
    },
    (found) => found === true,
    { timeoutMs: 10_000, intervalMs: 2_000 },
  );
  if (landed.ok) return; // it landed — nothing to retry
  await ctx.client.call('vm.device.create', [vmDeviceCreateArg(v26, vmId, attrs)], ctx.creds, timeoutMs);
}

/** Verifies a freshly created device is present by re-reading the VM's devices. */
async function verifyVmDevicePresent(ctx: TruenasActionContext, name: string, match: (dev: { dtype: string; attrs: Record<string, unknown> }) => boolean): Promise<boolean> {
  const wait = await pollUntil(
    async () => {
      try {
        const vms2 = await listVms(ctx);
        const vm2 = vms2.find((v) => v.name === name);
        if (!vm2) return false;
        for (const d of vm2.devices) {
          const dev = normalizeVmDevice(d);
          if (dev && match(dev)) return true;
        }
        return false;
      } catch {
        return null;
      }
    },
    (found) => found === true,
    { timeoutMs: 45_000, intervalMs: 2_000 },
  );
  return wait.ok;
}

const vmsDiskAttachAction: ActionDescriptor<TruenasActionContext> = {
  id: 'vms.disk-attach',
  label: 'Attach disk to VM',
  description:
    'Attaches a DISK device (vm.device.create dtype DISK). mode=existing attaches an existing /dev/zvol/… path or raw file (VM must be STOPPED — the appliance enforces it); mode=new-zvol creates a fresh ZVOL under the chosen dataset and hot-plugs it. Verified by re-reading the VM\'s devices.',
  module: 'VMs',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 300_000, // a new zvol can take a while to provision
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, description: 'VM name' },
    mode: { type: 'string', required: true, enum: ['existing', 'new-zvol'], default: 'existing', description: 'existing = attach a disk path; new-zvol = create + attach a fresh ZVOL' },
    path: { type: 'string', required: false, minLength: 1, pattern: '^/dev/zvol/', description: 'Existing ZVOL or raw file (from vms.disk-choices) — required when mode=existing' },
    dataset: { type: 'string', required: false, minLength: 1, description: 'Parent dataset for the new zvol (from vms.create-choices) — required when mode=new-zvol' },
    sizeBytes: { type: 'number', required: false, min: 1073741824, description: 'New zvol size in bytes — required when mode=new-zvol' },
    zvolName: { type: 'string', required: false, minLength: 1, maxLength: 64, pattern: '^[a-zA-Z0-9][a-zA-Z0-9_-]*$', description: 'Optional ZVOL leaf name (default: <VM>-diskN)' },
    diskType: { type: 'string', required: false, enum: ['AHCI', 'VIRTIO'], default: 'VIRTIO', description: 'Disk controller interface' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const name = str(input, 'name');
    const mode = strOr(input, 'mode', 'existing');
    if (mode !== 'existing' && mode !== 'new-zvol') return { success: false, details: { error: `Unsupported disk mode "${mode}"` } };

    const resolved = await resolveVmForAttach(ctx, name);
    if (!resolved.ok) return { success: false, details: { error: resolved.error } };
    const vm = resolved.vm;

    // Existing disks cannot be hot-plugged — the appliance refuses a running VM.
    if (mode === 'existing' && vm.state !== 'STOPPED') {
      return { success: false, details: { error: `VM "${name}" is ${vm.state.toLowerCase()} — stop it before attaching an existing disk` } };
    }

    const attrs: Record<string, unknown> = { dtype: 'DISK', type: strOr(input, 'diskType', 'VIRTIO') };
    let zvolFullName: string | null = null;
    if (mode === 'new-zvol') {
      const dataset = str(input, 'dataset');
      const sizeBytes = typeof input['sizeBytes'] === 'number' ? (input['sizeBytes'] as number) : undefined;
      if (!dataset || !sizeBytes) return { success: false, details: { error: 'mode=new-zvol requires dataset + sizeBytes' } };
      // Default leaf: <VM>-diskN where N is the next free index on this VM.
      const existing = vm.devices.map((d) => normalizeVmDevice(d)).filter((d) => d?.dtype === 'DISK').length;
      const requested = str(input, 'zvolName');
      const leaf = (requested || `${name}-disk${existing + 1}`).replace(/[^a-zA-Z0-9_]/g, '');
      if (!leaf) return { success: false, details: { error: `Invalid zvolName "${requested}" — it must contain at least one letter or digit` } };
      zvolFullName = `${dataset}/${leaf}`;
      Object.assign(attrs, { create_zvol: true, zvol_name: zvolFullName, zvol_volsize: sizeBytes });
    } else {
      const path = str(input, 'path');
      if (!path) return { success: false, details: { error: 'mode=existing requires a disk path' } };
      attrs['path'] = path;
    }

    try {
      await createVmDevice(ctx, vm.id, attrs, 180_000, (dev) => dev.dtype === 'DISK' && (zvolFullName ? pickString(dev.attrs, ['path']) === `/dev/zvol/${zvolFullName}` : true));
    } catch (e) {
      return { success: false, details: { error: `Disk attach failed: ${e instanceof Error ? e.message : String(e)}` } };
    }

    const verified = await verifyVmDevicePresent(ctx, name!, (dev) => dev.dtype === 'DISK' && (zvolFullName ? pickString(dev.attrs, ['path']) === `/dev/zvol/${zvolFullName}` : true));
    return { success: true, applied: true, verified, details: { name, mode, ...(zvolFullName ? { zvolName: zvolFullName } : {}), path: attrs['path'] as string | undefined } };
  },
};

const vmsDisplayAttachAction: ActionDescriptor<TruenasActionContext> = {
  id: 'vms.display-attach',
  label: 'Attach display to VM',
  description:
    'Attaches a DISPLAY device (vm.device.create dtype DISPLAY — VNC or SPICE). The appliance REQUIRES a console password (a random one is generated and reported in the result when not given) and auto-assigns free ports when port/web_port are omitted. `web` (appliance web UI) is only valid for SPICE displays. A VM may have at most ONE display (appliance rule) — the webapp hides this action once one exists.',
  module: 'VMs',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 120_000,
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, description: 'VM name' },
    type: { type: 'string', required: false, enum: ['VNC', 'SPICE'], default: 'VNC', description: 'Display protocol' },
    resolution: { type: 'string', required: false, pattern: '^\\d+x\\d+$', description: 'Resolution like 1024x768 (auto-assigned when omitted)' },
    port: { type: 'number', required: false, min: 5900, max: 65535, description: 'Display port — auto-assigned to a free one when omitted' },
    password: { type: 'string', required: false, minLength: 1, maxLength: 64, description: 'Console password (required by the appliance) — generated + reported in details when omitted' },
    web: { type: 'boolean', required: false, default: true, description: 'Expose the display through the appliance web UI — SPICE only; automatically disabled for VNC' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const name = str(input, 'name');
    const resolved = await resolveVmForAttach(ctx, name);
    if (!resolved.ok) return { success: false, details: { error: resolved.error } };
    const vm = resolved.vm;

    // One display per VM — the appliance enforces it too; fail fast with a clear message.
    for (const d of vm.devices) {
      const dev = normalizeVmDevice(d);
      if (dev?.dtype === 'DISPLAY') return { success: false, details: { error: `VM "${name}" already has a display device — detach it first to change the console` } };
    }

    const type = strOr(input, 'type', 'VNC').toUpperCase();
    // Appliance contract (verified live on 26.0 BETA): a console password is
    // MANDATORY for every display device; `web` (appliance web UI) is only valid
    // for SPICE — and the appliance DEFAULTS it to true before validating, so it
    // must be sent EXPLICITLY false for VNC or creation fails with EINVAL. VNC
    // passwords are capped at 8 characters.
    const attrs: Record<string, unknown> = { dtype: 'DISPLAY', type };
    attrs['web'] = type === 'SPICE' && input['web'] !== false;
    let password = str(input, 'password');
    if (!password) {
      // 8 random alphanumeric chars — fits the VNC cap and is SPICE-safe.
      const alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
      password = Array.from(randomBytes(8), (b) => alphabet[b % alphabet.length]).join('');
    } else if (type === 'VNC' && password.length > 8) {
      return { success: false, details: { error: `VNC console passwords are limited to 8 characters — got ${password.length}` } };
    }
    attrs['password'] = password;
    const resolution = str(input, 'resolution');
    if (resolution) attrs['resolution'] = resolution;
    const port = typeof input['port'] === 'number' ? (input['port'] as number) : undefined;
    if (port !== undefined) attrs['port'] = port;

    try {
      await createVmDevice(ctx, vm.id, attrs, 120_000, (dev) => dev.dtype === 'DISPLAY');
    } catch (e) {
      return { success: false, details: { error: `Display attach failed: ${e instanceof Error ? e.message : String(e)}` } };
    }

    const verified = await verifyVmDevicePresent(ctx, name!, (dev) => dev.dtype === 'DISPLAY');
    // Report the appliance-assigned port so the UI can show where to connect.
    let displayPort: number | undefined;
    try {
      const vms2 = await listVms(ctx);
      for (const d of vms2.find((v) => v.name === name)?.devices ?? []) {
        const dev = normalizeVmDevice(d);
        if (dev?.dtype !== 'DISPLAY') continue;
        displayPort = typeof dev.attrs['port'] === 'number' ? (dev.attrs['port'] as number) : undefined;
        break;
      }
    } catch { /* unverified ports */ }
    return { success: true, applied: true, verified, details: { name, type, password, ...(displayPort !== undefined ? { port: displayPort } : {}) } };
  },
};

const vmsPciAttachAction: ActionDescriptor<TruenasActionContext> = {
  id: 'vms.pci-attach',
  label: 'Attach PCIe device to VM',
  description:
    'Passes a host PCI device through to ONE VM (vm.device.create dtype PCI, pptdev from vms.pci-choices). Requires IOMMU on the host and a STOPPED VM — both are enforced here AND by the appliance.',
  module: 'VMs',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 120_000,
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, description: 'VM name' },
    pptdev: { type: 'string', required: true, pattern: '^pci_[0-9a-f]+_[0-9a-f]+_[0-9a-f]+_[0-9a-f]+$', description: 'Host PCI device id (from vms.pci-choices)' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const name = str(input, 'name');
    const pptdev = str(input, 'pptdev');
    if (!pptdev) return { success: false, details: { error: 'pptdev (PCI device id) is required' } };

    let iommu = true;
    try { iommu = (await ctx.client.call<boolean>('vm.device.iommu_enabled', [], ctx.creds)) === true; } catch { /* unknown — let the appliance decide */ }
    if (!iommu) return { success: false, details: { error: 'IOMMU is not enabled on this host — PCIe passthrough requires it (BIOS setting)' } };

    const resolved = await resolveVmForAttach(ctx, name);
    if (!resolved.ok) return { success: false, details: { error: resolved.error } };
    const vm = resolved.vm;
    if (vm.state !== 'STOPPED') {
      return { success: false, details: { error: `VM "${name}" is ${vm.state.toLowerCase()} — stop it before attaching a PCIe device` } };
    }

    try {
      await createVmDevice(ctx, vm.id, { dtype: 'PCI', pptdev }, 120_000, (dev) => dev.dtype === 'PCI' && pickString(dev.attrs, ['pptdev']) === pptdev);
    } catch (e) {
      return { success: false, details: { error: `PCI attach failed: ${e instanceof Error ? e.message : String(e)}` } };
    }

    const verified = await verifyVmDevicePresent(ctx, name!, (dev) => dev.dtype === 'PCI' && pickString(dev.attrs, ['pptdev']) === pptdev);
    return { success: true, applied: true, verified, details: { name, pptdev } };
  },
};

const vmsUsbAttachAction: ActionDescriptor<TruenasActionContext> = {
  id: 'vms.usb-attach',
  label: 'Attach USB device to VM',
  description:
    'Passes a host USB device through to ONE VM (vm.device.create dtype USB). The device is identified by vendor/product ids (from vms.usb-choices) so the passthrough survives reboots; hot-pluggable on running VMs.',
  module: 'VMs',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 120_000,
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, description: 'VM name' },
    usbDevice: { type: 'string', required: true, pattern: '^usb_[0-9]+_[0-9]+$', description: 'Host USB device id (from vms.usb-choices)' },
    controllerType: { type: 'string', required: false, enum: ['piix3-uhci', 'piix4-uhci', 'ehci', 'ich9-ehci1', 'vt82c686b-uhci', 'pci-ohci', 'nec-xhci', 'qemu-xhci'], default: 'nec-xhci', description: 'Virtual USB controller model' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const name = str(input, 'name');
    const usbDevice = str(input, 'usbDevice');
    if (!usbDevice) return { success: false, details: { error: 'usbDevice (USB device id) is required' } };

    // Resolve the vendor/product ids from the live choices — the appliance keys
    // USB passthrough by those, not by the bus/device address.
    let rawChoices: Record<string, Record<string, unknown>>;
    try {
      rawChoices = await ctx.client.call<Record<string, Record<string, unknown>>>('vm.device.usb_passthrough_choices', [], ctx.creds);
    } catch (e) {
      return { success: false, details: { error: `Could not read USB devices: ${e instanceof Error ? e.message : String(e)}` } };
    }
    const info = rawChoices?.[usbDevice];
    if (!info || typeof info !== 'object') return { success: false, details: { error: `USB device "${usbDevice}" is not present on this host anymore` } };
    const cap = (info['capability'] ?? {}) as Record<string, unknown>;
    const vendorId = pickString(cap, ['vendor_id']);
    const productId = pickString(cap, ['product_id']);
    if (!vendorId || !productId) return { success: false, details: { error: `USB device "${usbDevice}" has no usable vendor/product ids` } };

    const resolved = await resolveVmForAttach(ctx, name);
    if (!resolved.ok) return { success: false, details: { error: resolved.error } };
    const vm = resolved.vm;

    try {
      await createVmDevice(ctx, vm.id, { dtype: 'USB', usb: { vendor_id: vendorId, product_id: productId }, controller_type: strOr(input, 'controllerType', 'nec-xhci') }, 120_000,
        (dev) => dev.dtype === 'USB' && pickString((dev.attrs['usb'] ?? {}) as Record<string, unknown>, ['vendor_id']) === vendorId);
    } catch (e) {
      return { success: false, details: { error: `USB attach failed: ${e instanceof Error ? e.message : String(e)}` } };
    }

    const verified = await verifyVmDevicePresent(ctx, name!, (dev) => dev.dtype === 'USB' && pickString((dev.attrs['usb'] ?? {}) as Record<string, unknown>, ['vendor_id']) === vendorId);
    return { success: true, applied: true, verified, details: { name, usbDevice, vendorId, productId } };
  },
};

// ---------------------------------------------------------------------------
// Storage actions (Storage page) — a GENERIC contract any storage plugin can
// implement. Input is always dataset/pool NAMES (`names[]` for bulk, `name` for
// single ops); each action resolves them against the appliance and reports
// per-name outcomes, so re-running a bulk op is idempotent (already in the
// target state = skipped, not failed). TrueNAS mapping:
//   storage.scrub        → pool.scrub(name)            JOB — full-pool scrub
//   storage.snapshot     → pool.snapshot.create(...)   JOB — timestamped snapshot
//                                            (+ optional retention cleanup of
//                                             prior `unm-*` snapshots)
//   storage.quota-set    → pool.dataset.update(name,{quota})  set/clear quota
//   storage.mount        → pool.dataset.mount(name)
//   storage.unmount      → pool.dataset.unmount(name, {force?})
//   storage.delete       → pool.dataset.delete(name, {recursive?, force?})
// Destructive ops (delete) are `dangerous`; the rest are `write`. A future
// libvirt/Proxmox/storage plugin implementing these ids gets the webapp's row +
// bulk actions for free.
// ---------------------------------------------------------------------------

/** Parses a human size ("10 GB", "512 MB", "1 TB") to bytes; null when unparseable. */
function parseHumanSize(s: string): number | null {
  const m = s.trim().match(/^(\d+(?:\.\d+)?)\s*([KMGTPE]?)(B|I)?$/i);
  if (!m) return null;
  const n = parseFloat(m[1]);
  if (!Number.isFinite(n)) return null;
  const unit = (m[2] ?? '').toUpperCase();
  const mult: Record<string, number> = { '': 1, K: 1024, M: 1024 ** 2, G: 1024 ** 3, T: 1024 ** 4, P: 1024 ** 5, E: 1024 ** 6 };
  return Math.round(n * (mult[unit] ?? 1));
}

/** One ZFS pool as returned by `pool.query` (only the fields these actions need). */
interface PoolInfo {
  name: string;
  /** ONLINE | DEGRADED | OFFLINE | FAULTED | ... — normalized uppercase. */
  status: string;
}

/** Fetches all pools with their current state (pool.query). */
async function listPools(ctx: TruenasActionContext): Promise<PoolInfo[]> {
  const rows = await callWithRetry<Record<string, unknown>[]>(ctx, 'pool.query', []);
  const out: PoolInfo[] = [];
  for (const r of rows ?? []) {
    if (!r || typeof r !== 'object') continue;
    const name = pickString(r, ['name']);
    if (!name) continue;
    out.push({ name, status: normState(pickString(r, ['state'])) });
  }
  return out;
}

const storageScrubAction: ActionDescriptor<TruenasActionContext> = {
  id: 'storage.scrub',
  label: 'Scrub pool(s)',
  description:
    'Starts a full scrub on the selected ZFS pools (pool.scrub — an appliance job). A scrub reads every block and repairs any silently-corrupted data from redundancy. Pools already being scrubbed are skipped, not failed.',
  module: 'Storage',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 120_000,
  inputSchema: {
    names: { type: 'array', required: true, items: { type: 'string', minLength: 1 }, description: 'Pool names to scrub' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const names = strArray(input, 'names');
    if (names.length === 0) return { success: false, details: { error: 'No pool names provided' } };
    const pools = await listPools(ctx);
    const byName = new Map(pools.map((p) => [p.name, p]));

    let started = 0;
    let unconfirmed = 0;
    const notes: Record<string, string> = {};
    const skipped: Record<string, string> = {};
    const missing: string[] = [];
    const errors: Record<string, string> = {};
    for (const n of names) {
      const pool = byName.get(n);
      if (!pool) {
        missing.push(n); // not a pool on this appliance — nothing to do
        continue;
      }
      try {
        // Transport-tolerant — a lost response is confirmed by re-reading the pool's scrub state.
        const r = await dispatchWrite(ctx, 'pool.scrub', [n], {
          verify: async () => {
            try {
              const rows = await ctx.client.call<Record<string, unknown>[]>('pool.query', [[['name', '=', n]]], ctx.creds);
              const p = (rows ?? [])[0];
              if (!p) return null; // pool gone — can't confirm either way
              const st = pickString(p, ['scub_state', 'scrub_state'])?.toUpperCase(); // TrueNAS spells it "scub_state"
              if (st === 'RUNNING' || st === 'WAITING') return true; // scrub active — applied
              if (st === 'STOPPED') return false; // not scrubbing — not applied
              return null; // unknown state — don't guess
            } catch {
              return null;
            }
          },
        });
        if (r.note) notes[n] = r.note;
        if (r.unconfirmed) unconfirmed++;
        started++;
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        if (/already|in progress/i.test(msg)) skipped[n] = 'scrub already in progress'; // idempotent — a scrub is running
        else errors[n] = msg;
      }
    }
    return { success: Object.keys(errors).length === 0 && unconfirmed === 0, applied: true, details: { started, skipped, missing, ...(unconfirmed > 0 ? { unconfirmed } : {}), ...(Object.keys(notes).length ? { notes } : {}), ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

const storageBootScrubAction: ActionDescriptor<TruenasActionContext> = {
  id: 'storage.boot-scrub',
  label: 'Scrub boot pool',
  description:
    "Starts a scrub on the appliance's OS BOOT POOL (TrueNAS `boot.scrub` — an appliance job). The boot pool holds TrueNAS itself and its boot environments; it is invisible to pool.query/pool.scrub, so this dedicated action covers it. A scrub reads every block and repairs silently-corrupted data from redundancy.",
  module: 'Storage',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 120_000,
  inputSchema: {
    names: { type: 'array', required: true, items: { type: 'string', minLength: 1 }, description: "Boot pool name(s) to scrub (e.g. [\"boot-pool\"])" },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const names = strArray(input, 'names');
    if (names.length === 0) return { success: false, details: { error: 'No pool names provided' } };

    // The boot pool is the ONLY valid target — anything else belongs to storage.scrub.
    const nonBoot = names.filter((n) => !isBootPoolName(n));
    if (nonBoot.length > 0) return { success: false, details: { error: `Not a boot pool: ${nonBoot.join(', ')} — use "Scrub pool" for data pools` } };

    // Idempotency pre-check: re-read the boot pool's scan state; an in-flight
    // scrub is skipped, not failed (boot.get_state carries the same `scan` shape
    // as pool.query). Missing method on a legacy release → proceed anyway.
    let alreadyScrubbing = false;
    try {
      const st = await ctx.client.call<Record<string, unknown>>('boot.get_state', [], ctx.creds);
      const scan = (st?.['scan'] ?? {}) as Record<string, unknown>;
      const state = pickString(scan, ['state'])?.toUpperCase();
      if (state === 'RUNNING' || state === 'WAITING') alreadyScrubbing = true;
    } catch { /* best-effort — boot.get_state missing or transient */ }

    try {
      // Transport-tolerant — a lost response is confirmed by re-reading the scan state.
      const r = await dispatchWrite(ctx, 'boot.scrub', [], {
        verify: async () => {
          try {
            const st = await ctx.client.call<Record<string, unknown>>('boot.get_state', [], ctx.creds);
            const scan = (st?.['scan'] ?? {}) as Record<string, unknown>;
            const state = pickString(scan, ['state'])?.toUpperCase();
            if (state === 'RUNNING' || state === 'WAITING') return true; // scrub active — applied
            if (state === 'STOPPED') return false; // not scrubbing — not applied
            return null; // unknown state — don't guess
          } catch {
            return null;
          }
        },
      });
      const jobId = typeof r.value === 'number' ? r.value : undefined;
      if (alreadyScrubbing) {
        return { success: true, applied: false, details: { note: 'Boot pool scrub already in progress — skipped.', ...(jobId !== undefined ? { jobId } : {}) } };
      }
      return { success: !r.unconfirmed, applied: true, details: { started: 1, ...(jobId !== undefined ? { jobId } : {}), ...(r.note ? { note: r.note } : {}) } };
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      if (/already|in progress/i.test(msg)) return { success: true, applied: false, details: { note: 'Boot pool scrub already in progress — skipped.' } };
      return { success: false, details: { error: msg } };
    }
  },
};

const storageSnapshotAction: ActionDescriptor<TruenasActionContext> = {
  id: 'storage.snapshot',
  label: 'Create snapshot(s)',
  description:
    'Creates a timestamped ZFS snapshot on the selected dataset (pool.snapshot.create — an appliance job). With retentionDays set, older `unm-*` snapshots of that dataset are pruned to keep only the newest N days. Snapshots are non-destructive point-in-time copies.',
  module: 'Storage',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 300_000,
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, description: 'Dataset (or pool) to snapshot' },
    retentionDays: { type: 'number', required: false, min: 1, max: 3650, default: 7, description: 'Prune prior `unm-*` snapshots older than this many days (omit to keep all)' },
    recursive: { type: 'boolean', required: false, default: false, description: 'Also snapshot all child datasets' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const name = str(input, 'name');
    if (!name) return { success: false, details: { error: 'Dataset name is required' } };
    // The OS boot pool and its boot-environment datasets are not data storage —
    // snapshots there would bloat the very pool TrueNAS itself runs on. Refuse
    // with a clear pointer instead of letting the appliance decide.
    if (isBootPoolName(name)) return { success: false, details: { error: `"${name}" is part of the OS boot pool — it holds the appliance's own boot environments and cannot be snapshotted from here.` } };
    const recursive = input['recursive'] === true;
    const retentionRaw = typeof input['retentionDays'] === 'number' ? (input['retentionDays'] as number) : undefined;

    // Timestamped snapshot name — sortable, and the `unm-` prefix marks it as
    // ours so the retention cleanup only ever touches snapshots we created.
    const ts = new Date().toISOString().replace(/[-:TZ]/g, '').slice(0, 14); // YYYYMMDDHHmmss
    const snapName = `${name}@unm-${ts}`;

    const notes: string[] = [];
    let unconfirmed = false;
    let jobId: number | null = null;
    try {
      // Transport-tolerant — a lost response is confirmed by re-reading (the snapshot must exist).
      const dr = await dispatchWrite(ctx, 'pool.snapshot.create', [{ dataset: name, snapshot_name: `unm-${ts}`, recursive }], {
        verify: async () => {
          try {
            const rows = await ctx.client.call<Record<string, unknown>[]>('pool.snapshot.query', [[['name', '=', snapName]]], ctx.creds);
            return (rows ?? []).length > 0; // exists — applied
          } catch {
            return null;
          }
        },
      });
      if (dr.note) notes.push(dr.note);
      unconfirmed = dr.unconfirmed === true; // response lost AND state unreadable — not proven created
      const r = dr.value as unknown;
      if (typeof r === 'number') jobId = r;
      else if (r && typeof r === 'object' && typeof (r as Record<string, unknown>)['id'] === 'number') jobId = (r as Record<string, unknown>)['id'] as number;
    } catch (e) {
      return { success: false, details: { error: e instanceof Error ? e.message : String(e), snapshot: snapName } };
    }

    // pool.snapshot.create is a JOB method — wait for it to settle so the
    // retention cleanup below sees the new snapshot. (Skipped when the response
    // was lost but the snapshot's existence was already confirmed on re-read.)
    let note = '';
    if (typeof jobId === 'number') {
      const wait = await waitForJob(ctx, jobId, 240_000);
      if (wait.state === 'RUNNING') note = 'Snapshot job still in progress on the appliance';
      else if (wait.state !== 'SUCCESS' && wait.state !== 'FINISHED') return { success: false, details: { snapshot: snapName, error: wait.error ?? `Job ended in state ${wait.state}` } };
    }

    // Optional retention cleanup — prune prior `unm-*` snapshots older than the
    // requested window. Best-effort: a failure here does NOT fail the create.
    let pruned = 0;
    const pruneErrors: Record<string, string> = {};
    if (typeof retentionRaw === 'number' && Number.isFinite(retentionRaw) && retentionRaw > 0) {
      const cutoffMs = Date.now() - retentionRaw * 86_400_000;
      let snaps: Record<string, unknown>[];
      try {
        snaps = await ctx.client.call<Record<string, unknown>[]>('pool.snapshot.query', [{ dataset: name }], ctx.creds);
      } catch (e) {
        return { success: true, applied: true, details: { snapshot: snapName, note: [note, `Retention cleanup skipped: ${e instanceof Error ? e.message : String(e)}`].filter(Boolean).join('; ') || undefined } };
      }
      for (const s of snaps ?? []) {
        const sn = pickString(s, ['name']); // "dataset@unm-YYYYMMDDHHmmss"
        if (!sn) continue;
        const at = sn.split('@')[1] ?? '';
        if (!at.startsWith('unm-')) continue; // only snapshots WE created
        const digits = at.slice(4);
        if (digits.length < 12) continue;
        const t = Date.parse(`${digits.slice(0, 4)}-${digits.slice(4, 6)}-${digits.slice(6, 8)}T${digits.slice(8, 10)}:${digits.slice(10, 12)}:00Z`);
        if (Number.isNaN(t) || t >= cutoffMs) continue; // keep recent ones
        try {
          await ctx.client.call('pool.snapshot.delete', [sn], ctx.creds);
          pruned++;
        } catch (e) {
          pruneErrors[sn] = e instanceof Error ? e.message : String(e);
        }
      }
    }

    return { success: Object.keys(pruneErrors).length === 0 && !unconfirmed, applied: true, details: { snapshot: snapName, pruned, ...(note ? { note } : {}), ...(notes.length > 0 ? { notes } : {}), ...(Object.keys(pruneErrors).length ? { pruneErrors } : {}) } };
  },
};

const storageQuotaSetAction: ActionDescriptor<TruenasActionContext> = {
  id: 'storage.quota-set',
  label: 'Set dataset quota',
  description:
    'Sets (or clears, with an empty value) the ZFS `quota` property on a dataset (pool.dataset.update). The quota caps how much space the dataset may consume; children are not limited unless they have their own quota.',
  module: 'Storage',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 60_000,
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, description: 'Dataset to update' },
    quota: { type: 'string', required: false, description: 'New quota as bytes (number) or a human size like "10 GB"; empty/omitted clears the quota' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const name = str(input, 'name');
    if (!name) return { success: false, details: { error: 'Dataset name is required' } };
    // Quotas on the OS boot pool would cap TrueNAS's own space — refuse.
    if (isBootPoolName(name)) return { success: false, details: { error: `"${name}" is part of the OS boot pool — quotas there are managed by the appliance itself.` } };
    const raw = typeof input['quota'] === 'string' ? (input['quota'] as string).trim() : '';
    let quota: number | null;
    if (raw === '') quota = null; // clear
    else if (/^\d+$/.test(raw)) quota = parseInt(raw, 10);
    else {
      const parsed = parseHumanSize(raw);
      if (parsed === null) return { success: false, details: { error: `Could not parse quota "${raw}" — use bytes or a size like "10 GB"` } };
      quota = parsed;
    }
    try {
      // Transport-tolerant — setting an exact value is idempotent, so a lost response can be re-dispatched blindly.
      const dr = await dispatchWrite(ctx, 'pool.dataset.update', [name, { quota }], { idempotentRetry: true });
      return { success: true, applied: true, details: { name, quota, note: quota === null ? 'Quota cleared' : `Quota set to ${quota} bytes`, ...(dr.note ? { transportNote: dr.note } : {}) } };
    } catch (e) {
      return { success: false, details: { error: e instanceof Error ? e.message : String(e), name } };
    }
  },
};

/** Re-reads a dataset's mount state after a dropped transport response.
 * wantMounted=true → true when the dataset exists AND is mounted, false when it
 * exists but is unmounted (or is gone — mounting a missing dataset cannot have
 * succeeded). wantMounted=false → true when the dataset is unmounted or already
 * gone, false while still mounted. null = state unreadable. */
async function datasetStateVerify(ctx: TruenasActionContext, name: string, wantMounted: boolean): Promise<boolean | null> {
  try {
    const rows = await ctx.client.call<Record<string, unknown>[]>('pool.dataset.query', [[['name', '=', name]]], ctx.creds);
    const row = (rows ?? [])[0];
    if (!row) return wantMounted ? false : true; // gone: mount impossible / unmount moot
    const mp = pickString(row, ['mountpoint']);
    const mounted = !!mp && mp !== 'unmounted' && mp !== 'legacy';
    return mounted === wantMounted;
  } catch {
    return null;
  }
}

const storageMountAction: ActionDescriptor<TruenasActionContext> = {
  id: 'storage.mount',
  label: 'Mount dataset(s)',
  description: 'Mounts the selected ZFS datasets (pool.dataset.mount). Datasets already mounted are skipped, not failed.',
  module: 'Storage',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 120_000,
  inputSchema: {
    names: { type: 'array', required: true, items: { type: 'string', minLength: 1 }, description: 'Dataset names to mount' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const names = strArray(input, 'names');
    if (names.length === 0) return { success: false, details: { error: 'No dataset names provided' } };
    // The OS boot pool and its BE datasets are managed by the appliance itself —
    // mounting/unmounting them from here would break the running system. Refuse.
    const bootNames = names.filter(isBootPoolName);
    if (bootNames.length > 0) return { success: false, details: { error: `Refusing to mount "${bootNames.join(', ')}" — it is part of the OS boot pool and managed by TrueNAS itself.` } };
    let mounted = 0;
    let unconfirmed = 0;
    const notes: Record<string, string> = {};
    const skipped: Record<string, string> = {};
    const errors: Record<string, string> = {};
    for (const n of names) {
      try {
        // Transport-tolerant — a lost response is confirmed by re-reading the mount state.
        const r = await dispatchWrite(ctx, 'pool.dataset.mount', [n], { verify: () => datasetStateVerify(ctx, n, true) });
        if (r.note) notes[n] = r.note;
        if (r.unconfirmed) unconfirmed++; // response lost AND state unreadable — not proven applied
        mounted++;
      } catch (e) {
        if (/already|mounted/i.test(e instanceof Error ? e.message : String(e))) skipped[n] = 'already mounted';
        else errors[n] = e instanceof Error ? e.message : String(e);
      }
    }
    return { success: Object.keys(errors).length === 0 && unconfirmed === 0, applied: true, details: { mounted, skipped, ...(Object.keys(notes).length ? { notes } : {}), ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

const storageUnmountAction: ActionDescriptor<TruenasActionContext> = {
  id: 'storage.unmount',
  label: 'Unmount dataset(s)',
  description: 'Unmounts the selected ZFS datasets (pool.dataset.unmount). Datasets already unmounted are skipped, not failed. Data remains safe on disk — remount to access it again.',
  module: 'Storage',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 120_000,
  inputSchema: {
    names: { type: 'array', required: true, items: { type: 'string', minLength: 1 }, description: 'Dataset names to unmount' },
    force: { type: 'boolean', required: false, default: false, description: 'Force unmount even if the dataset is busy (may lose in-flight writes)' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const names = strArray(input, 'names');
    if (names.length === 0) return { success: false, details: { error: 'No dataset names provided' } };
    // Unmounting the OS boot pool or a BE dataset would break the running system.
    const bootNames = names.filter(isBootPoolName);
    if (bootNames.length > 0) return { success: false, details: { error: `Refusing to unmount "${bootNames.join(', ')}" — it is part of the OS boot pool and managed by TrueNAS itself.` } };
    const force = input['force'] === true;
    let unmounted = 0;
    let unconfirmed = 0;
    const notes: Record<string, string> = {};
    const skipped: Record<string, string> = {};
    const errors: Record<string, string> = {};
    for (const n of names) {
      try {
        // Transport-tolerant — a lost response is confirmed by re-reading the mount state.
        const r = await dispatchWrite(ctx, 'pool.dataset.unmount', [n, force ? { force: true } : {}], { verify: () => datasetStateVerify(ctx, n, false) });
        if (r.note) notes[n] = r.note;
        if (r.unconfirmed) unconfirmed++; // response lost AND state unreadable — not proven applied
        unmounted++;
      } catch (e) {
        if (/not mounted|unmounted/i.test(e instanceof Error ? e.message : String(e))) skipped[n] = 'already unmounted';
        else errors[n] = e instanceof Error ? e.message : String(e);
      }
    }
    return { success: Object.keys(errors).length === 0 && unconfirmed === 0, applied: true, details: { unmounted, force, skipped, ...(Object.keys(notes).length ? { notes } : {}), ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

const storageDeleteAction: ActionDescriptor<TruenasActionContext> = {
  id: 'storage.delete',
  label: 'Delete dataset(s)',
  description:
    'DELETES the selected ZFS datasets (pool.dataset.delete) — this is destructive and removes all data in them. With recursive=true child datasets are removed too; without it a dataset that has children fails so nothing is lost by accident.',
  module: 'Storage',
  riskLevel: 'dangerous' as const,
  deviceCount: 1 as const,
  timeoutMs: 300_000,
  inputSchema: {
    names: { type: 'array', required: true, items: { type: 'string', minLength: 1 }, description: 'Dataset names to delete' },
    recursive: { type: 'boolean', required: false, default: false, description: 'Also delete all child datasets' },
    force: { type: 'boolean', required: false, default: false, description: 'Force deletion even if the dataset is busy/mounted' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const names = strArray(input, 'names');
    if (names.length === 0) return { success: false, details: { error: 'No dataset names provided' } };
    // The OS boot pool itself can never be deleted from here — it holds the
    // running system. Boot-environment datasets under it are removed via the
    // dedicated `bootenv.destroy` action (the appliance enforces its own guards
    // against active/activated BEs); deleting them as plain datasets would skip
    // those checks and the boot menu bookkeeping.
    const poolNames = names.filter((n) => !n.includes('/'));
    const beCandidates = names.filter((n) => n.includes('/') && isBootPoolName(n));
    if (poolNames.some(isBootPoolName)) {
      return { success: false, details: { error: `Refusing to delete the OS boot pool — it holds TrueNAS itself. Individual boot environments are removed with "Delete a boot environment" (bootenv.destroy).` } };
    }
    if (beCandidates.length > 0) {
      let beIds: string[] = [];
      try {
        const { rows } = await queryBootEnvs(ctx);
        beIds = rows.map((r) => r.id);
      } catch { /* best-effort — the error below still names the datasets */ }
      return { success: false, details: { error: `Refusing to delete "${beCandidates.join(', ')}" as plain datasets — they are boot environments. Use "Delete a boot environment" (bootenv.destroy) instead${beIds.length > 0 ? `; available: ${beIds.join(', ')}` : ''}.` } };
    }
    const recursive = input['recursive'] === true;
    const force = input['force'] === true;

    let deleted = 0;
    const notes: Record<string, string> = {};
    const errors: Record<string, string> = {};
    for (const n of names) {
      try {
        // Transport-tolerant — a lost response is confirmed by re-reading (the dataset must be GONE).
        const r = await dispatchWrite(ctx, 'pool.dataset.delete', [n, recursive || force ? { recursive, force } : {}], {
          timeoutMs: 60_000,
          verify: async () => {
            try {
              const rows = await ctx.client.call<Record<string, unknown>[]>('pool.dataset.query', [[['name', '=', n]]], ctx.creds);
              return (rows ?? []).length === 0; // gone — applied; still present — not applied
            } catch {
              return null;
            }
          },
        });
        if (r.note) notes[n] = r.note;
        if (r.unconfirmed) errors[n] = 'Delete could not be confirmed (transport drop, state unreadable) — re-run the step'; // destructive: never assume applied
        else deleted++;
      } catch (e) {
        errors[n] = e instanceof Error ? e.message : String(e);
      }
    }
    return { success: Object.keys(errors).length === 0, applied: true, details: { deleted, recursive, force, ...(Object.keys(notes).length ? { notes } : {}), ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

// ---------------------------------------------------------------------------
// File-share CRUD actions (Shares page) — a GENERIC contract any storage plugin
// can implement. One action per protocol × operation, so the webapp's Shares page
// offers create/edit/delete for SMB/CIFS, NFS, iSCSI and NVMe-oF shares and fans
// one step out per selected row. All target documented TrueNAS JSON-RPC methods:
//   smb.share.{create,update,delete}      (name-keyed; update needs the id)
//   nfs.shares.{create,update,delete}     (path-keyed; update needs the id)
//   iscsi.target.{create,delete}          (id-keyed delete; LUNs via iscsi.extent)
//   nvmet.subsystem.{create,delete}       (TrueNAS 24.10+; id-keyed delete)
// Mutating methods are @job on some releases — a job id or an immediate result both
// mean "applied". Deletes resolve the appliance id by name/path first so re-running
// is idempotent (already gone = skipped, not failed).
// ---------------------------------------------------------------------------

/** Reads a non-empty string from input. */
function inStr(input: Record<string, unknown>, key: string): string | undefined {
  const v = input[key];
  return typeof v === 'string' && v.trim() !== '' ? v.trim() : undefined;
}

/** Reads an optional boolean (undefined when absent). */
function inBool(input: Record<string, unknown>, key: string): boolean | undefined {
  const v = input[key];
  return typeof v === 'boolean' ? v : undefined;
}

/** Resolves a TrueNAS id from a query result by matching name OR path. Returns the
 * row (with its `id`) or null when not found — callers treat null as "already gone". */
async function findShareId(ctx: TruenasActionContext, method: string, matchName?: string, matchPath?: string): Promise<{ id: number; name?: string } | null> {
  const rows = await callWithRetry<Record<string, unknown>[]>(ctx, method, []);
  for (const r of rows ?? []) {
    if (!r || typeof r !== 'object') continue;
    const id = pickNumber(r, ['id']);
    if (typeof id !== 'number') continue;
    if (matchName && pickString(r, ['name']) === matchName) return { id, name: matchName };
    if (matchPath && pickString(r, ['path']) === matchPath) return { id, name: matchPath };
  }
  return null;
}

/** True when a JSON-RPC error means "already exists" (idempotent create skip). */
function isAlreadyExists(e: unknown): boolean {
  if (!(e instanceof TruenasRpcError)) return false;
  return /already exist|duplicate|unique/i.test(e.message);
}

// --- SMB/CIFS -----------------------------------------------------------------

const smbShareCreateAction: ActionDescriptor<TruenasActionContext> = {
  id: 'shares.smb.create',
  label: 'Create SMB share',
  description: 'Creates a new SMB/CIFS share (sharing.smb.create) exporting the given dataset path.',
  module: 'Shares',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 60_000,
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, description: 'Share name (the \\server\\name clients connect to)' },
    path: { type: 'string', required: true, minLength: 1, description: 'Dataset or mountpoint to export (e.g. /mnt/tank/public)' },
    comment: { type: 'string', required: false, description: 'Optional share comment' },
    home: { type: 'boolean', required: false, default: false, description: 'Expose as a per-user home share' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const name = inStr(input, 'name');
    const path = inStr(input, 'path');
    if (!name || !path) return { success: false, details: { error: 'Both "name" and "path" are required' } };
    const params: Record<string, unknown> = { name, path };
    const comment = inStr(input, 'comment');
    if (comment) params['comment'] = comment;
    // Modern sharing.smb model nests per-user-home under `options` — a top-level
    // `home` key is rejected by the schema's additionalProperties:false.
    const home = inBool(input, 'home');
    if (home !== undefined) params['options'] = { home };
    try {
      // Transport-tolerant — a lost response is confirmed by re-querying (the share must exist).
      const dr = await dispatchWrite(ctx, 'sharing.smb.create', [params], { verify: async () => { try { return findShareId(ctx, 'sharing.smb.query', name) !== null; } catch { return null; } } });
      return { success: true, applied: true, details: { name, path, ...(dr.note ? { transportNote: dr.note } : {}) } };
    } catch (e) {
      if (isAlreadyExists(e)) return { success: true, applied: false, details: { name, note: 'Share already exists' } };
      return { success: false, details: { error: e instanceof Error ? e.message : String(e), name } };
    }
  },
};

const smbShareUpdateAction: ActionDescriptor<TruenasActionContext> = {
  id: 'shares.smb.update',
  label: 'Edit SMB share',
  description: 'Updates an existing SMB/CIFS share (sharing.smb.update) — resolves the appliance id by name first.',
  module: 'Shares',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 60_000,
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, description: 'Share name to update' },
    path: { type: 'string', required: false, description: 'New dataset/mountpoint to export (omit to keep)' },
    comment: { type: 'string', required: false, description: 'New share comment (empty clears it)' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const name = inStr(input, 'name');
    if (!name) return { success: false, details: { error: '"name" is required' } };
    const found = await findShareId(ctx, 'sharing.smb.query', name);
    if (!found) return { success: true, applied: false, details: { name, note: 'Share not found — nothing to update' } };
    // sharing.smb.update takes (id, params) as two positional args.
    const params: Record<string, unknown> = {};
    const path = inStr(input, 'path');
    if (path) params['path'] = path;
    if ('comment' in input) params['comment'] = inStr(input, 'comment') ?? '';
    try {
      // Transport-tolerant — a partial update re-sent with the same values is harmless.
      const dr = await dispatchWrite(ctx, 'sharing.smb.update', [found.id, params], { idempotentRetry: true });
      return { success: true, applied: true, details: { name, ...(dr.note ? { transportNote: dr.note } : {}) } };
    } catch (e) {
      return { success: false, details: { error: e instanceof Error ? e.message : String(e), name } };
    }
  },
};

const smbShareDeleteAction: ActionDescriptor<TruenasActionContext> = {
  id: 'shares.smb.delete',
  label: 'Delete SMB share(s)',
  description: 'DELETES the selected SMB/CIFS shares (sharing.smb.delete). Removes only the export — the underlying dataset and its data are untouched.',
  module: 'Shares',
  riskLevel: 'dangerous' as const,
  deviceCount: 1 as const,
  timeoutMs: 120_000,
  inputSchema: {
    names: { type: 'array', required: true, items: { type: 'string', minLength: 1 }, description: 'Share names to delete' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const names = strArray(input, 'names');
    if (names.length === 0) return { success: false, details: { error: 'No share names provided' } };
    let deleted = 0;
    const notes: Record<string, string> = {};
    const missing: string[] = [];
    const errors: Record<string, string> = {};
    for (const n of names) {
      const found = await findShareId(ctx, 'sharing.smb.query', n);
      if (!found) { missing.push(n); continue; } // already gone — idempotent skip
      try {
        // Transport-tolerant — a lost response is confirmed by re-querying (the share must be GONE).
        const r = await dispatchWrite(ctx, 'sharing.smb.delete', [found.id], { verify: async () => { try { return findShareId(ctx, 'sharing.smb.query', n) === null; } catch { return null; } } });
        if (r.note) notes[n] = r.note;
        if (r.unconfirmed) errors[n] = 'Delete could not be confirmed (transport drop, state unreadable) — re-run the step'; // destructive: never assume applied
        else deleted++;
      } catch (e) {
        errors[n] = e instanceof Error ? e.message : String(e);
      }
    }
    return { success: Object.keys(errors).length === 0, applied: true, details: { deleted, missing, ...(Object.keys(notes).length ? { notes } : {}), ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

// --- NFS ----------------------------------------------------------------------

const nfsShareCreateAction: ActionDescriptor<TruenasActionContext> = {
  id: 'shares.nfs.create',
  label: 'Create NFS share',
  description: 'Creates a new NFS export (sharing.nfs.create) of the given path with host access rules.',
  module: 'Shares',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 60_000,
  inputSchema: {
    path: { type: 'string', required: true, minLength: 1, description: 'Dataset/mountpoint to export (e.g. /mnt/tank/nfs)' },
    hosts: { type: 'array', required: false, items: { type: 'string' }, description: 'Allowed client host/CIDR list (empty = all hosts)' },
    readOnly: { type: 'boolean', required: false, default: false, description: 'Export read-only' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const path = inStr(input, 'path');
    if (!path) return { success: false, details: { error: '"path" is required' } };
    const hostsRaw = Array.isArray(input['hosts']) ? (input['hosts'] as unknown[]) : [];
    const params: Record<string, unknown> = { path, hosts: hostsRaw.filter((h): h is string => typeof h === 'string') };
    if (inBool(input, 'readOnly')) params['ro'] = true;
    try {
      // Transport-tolerant — a lost response is confirmed by re-querying (the export must exist).
      const dr = await dispatchWrite(ctx, 'sharing.nfs.create', [params], { verify: async () => { try { return findShareId(ctx, 'sharing.nfs.query', undefined, path) !== null; } catch { return null; } } });
      return { success: true, applied: true, details: { path, ...(dr.note ? { transportNote: dr.note } : {}) } };
    } catch (e) {
      if (isAlreadyExists(e)) return { success: true, applied: false, details: { path, note: 'NFS export already exists' } };
      return { success: false, details: { error: e instanceof Error ? e.message : String(e), path } };
    }
  },
};

const nfsShareUpdateAction: ActionDescriptor<TruenasActionContext> = {
  id: 'shares.nfs.update',
  label: 'Edit NFS share',
  description: 'Updates an existing NFS export (sharing.nfs.update) — resolves the appliance id by path first.',
  module: 'Shares',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 60_000,
  inputSchema: {
    path: { type: 'string', required: true, minLength: 1, description: 'Exported path to update' },
    hosts: { type: 'array', required: false, items: { type: 'string' }, description: 'New allowed client host/CIDR list (empty = all hosts)' },
    readOnly: { type: 'boolean', required: false, default: false, description: 'Export read-only' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const path = inStr(input, 'path');
    if (!path) return { success: false, details: { error: '"path" is required' } };
    const found = await findShareId(ctx, 'sharing.nfs.query', undefined, path);
    if (!found) return { success: true, applied: false, details: { path, note: 'NFS export not found — nothing to update' } };
    // sharing.nfs.update takes (id, params) as two positional args.
    const hostsRaw = Array.isArray(input['hosts']) ? (input['hosts'] as unknown[]) : [];
    const params: Record<string, unknown> = { path, hosts: hostsRaw.filter((h): h is string => typeof h === 'string') };
    if ('readOnly' in input) params['ro'] = inBool(input, 'readOnly') ?? false;
    try {
      // Transport-tolerant — a partial update re-sent with the same values is harmless.
      const dr = await dispatchWrite(ctx, 'sharing.nfs.update', [found.id, params], { idempotentRetry: true });
      return { success: true, applied: true, details: { path, ...(dr.note ? { transportNote: dr.note } : {}) } };
    } catch (e) {
      return { success: false, details: { error: e instanceof Error ? e.message : String(e), path } };
    }
  },
};

const nfsShareDeleteAction: ActionDescriptor<TruenasActionContext> = {
  id: 'shares.nfs.delete',
  label: 'Delete NFS share(s)',
  description: 'DELETES the selected NFS exports (sharing.nfs.delete). Removes only the export — the underlying dataset and its data are untouched.',
  module: 'Shares',
  riskLevel: 'dangerous' as const,
  deviceCount: 1 as const,
  timeoutMs: 120_000,
  inputSchema: {
    paths: { type: 'array', required: true, items: { type: 'string', minLength: 1 }, description: 'Exported paths to delete' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const paths = strArray(input, 'paths');
    if (paths.length === 0) return { success: false, details: { error: 'No export paths provided' } };
    let deleted = 0;
    const notes: Record<string, string> = {};
    const missing: string[] = [];
    const errors: Record<string, string> = {};
    for (const p of paths) {
      const found = await findShareId(ctx, 'sharing.nfs.query', undefined, p);
      if (!found) { missing.push(p); continue; } // already gone — idempotent skip
      try {
        // Transport-tolerant — a lost response is confirmed by re-querying (the export must be GONE).
        const r = await dispatchWrite(ctx, 'sharing.nfs.delete', [found.id], { verify: async () => { try { return findShareId(ctx, 'sharing.nfs.query', undefined, p) === null; } catch { return null; } } });
        if (r.note) notes[p] = r.note;
        if (r.unconfirmed) errors[p] = 'Delete could not be confirmed (transport drop, state unreadable) — re-run the step'; // destructive: never assume applied
        else deleted++;
      } catch (e) {
        errors[p] = e instanceof Error ? e.message : String(e);
      }
    }
    return { success: Object.keys(errors).length === 0, applied: true, details: { deleted, missing, ...(Object.keys(notes).length ? { notes } : {}), ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

// --- iSCSI --------------------------------------------------------------------

const iscsiTargetCreateAction: ActionDescriptor<TruenasActionContext> = {
  id: 'shares.iscsi.create',
  label: 'Create iSCSI target',
  description: 'Creates a new iSCSI target (iscsi.target.create) with one LUN backed by the given dataset.',
  module: 'Shares',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 60_000,
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, description: 'Target name (e.g. iqn.2024-01.org.unm:tank)' },
    path: { type: 'string', required: false, description: 'Dataset to expose as a LUN (omit for an empty target)' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const name = inStr(input, 'name');
    if (!name) return { success: false, details: { error: '"name" is required' } };
    try {
      // Transport-tolerant — a lost response is confirmed by re-querying (the target must exist).
      const dr = await dispatchWrite(ctx, 'iscsi.target.create', [{ name }], { verify: async () => { try { return findShareId(ctx, 'iscsi.target.query', name) !== null; } catch { return null; } } });
      // Attach a LUN when a backing dataset was given. Modern TrueNAS keeps the
      // target↔extent association in its OWN table (iscsi.targetextent) — extents
      // are created standalone, then linked to the target by id.
      const path = inStr(input, 'path');
      if (path) {
        const target = await findShareId(ctx, 'iscsi.target.query', name);
        if (!target) return { success: true, applied: true, details: { name, note: 'Target created but could not be re-resolved for LUN attach' } };
        try {
          // Reuse an existing extent on the same path (idempotent), else create one.
          let extent = await findShareId(ctx, 'iscsi.extent.query', undefined, path);
          if (!extent) {
            const extentName = path.split('/').filter(Boolean).pop() || `lun-${target.id}`;
            // Transport-tolerant — a lost response is confirmed by re-querying (the extent must exist on the path).
            await dispatchWrite(ctx, 'iscsi.extent.create', [{ name: extentName, type: 'FILE', path }], { verify: async () => { try { return findShareId(ctx, 'iscsi.extent.query', undefined, path) !== null; } catch { return null; } } });
            extent = await findShareId(ctx, 'iscsi.extent.query', undefined, path) ?? (await findShareId(ctx, 'iscsi.extent.query', extentName));
          }
          if (!extent) return { success: true, applied: true, details: { name, note: `Target created but LUN could not be resolved for ${path}` } };
          // Transport-tolerant — a lost response is confirmed by re-querying the target↔extent link.
          await dispatchWrite(ctx, 'iscsi.targetextent.create', [{ target: target.id, extent: extent.id }], {
            verify: async () => {
              try {
                const rows = await ctx.client.call<Record<string, unknown>[]>('iscsi.targetextent.query', [], ctx.creds);
                return (rows ?? []).some((r) => pickNumber(r, ['target']) === target.id && pickNumber(r, ['extent']) === extent.id); // linked — applied
              } catch {
                return null;
              }
            },
          });
        } catch (e) {
          return { success: true, applied: true, details: { name, note: `Target created but LUN attach failed: ${e instanceof Error ? e.message : String(e)}` } };
        }
      }
      return { success: true, applied: true, details: { name, ...(path ? { path } : {}), ...(dr.note ? { transportNote: dr.note } : {}) } };
    } catch (e) {
      if (isAlreadyExists(e)) return { success: true, applied: false, details: { name, note: 'iSCSI target already exists' } };
      return { success: false, details: { error: e instanceof Error ? e.message : String(e), name } };
    }
  },
};

const iscsiTargetDeleteAction: ActionDescriptor<TruenasActionContext> = {
  id: 'shares.iscsi.delete',
  label: 'Delete iSCSI target(s)',
  description: 'DELETES the selected iSCSI targets (iscsi.target.delete). Removes only the target/LUNs — the underlying datasets are untouched.',
  module: 'Shares',
  riskLevel: 'dangerous' as const,
  deviceCount: 1 as const,
  timeoutMs: 120_000,
  inputSchema: {
    names: { type: 'array', required: true, items: { type: 'string', minLength: 1 }, description: 'Target names to delete' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const names = strArray(input, 'names');
    if (names.length === 0) return { success: false, details: { error: 'No target names provided' } };
    let deleted = 0;
    const notes: Record<string, string> = {};
    const missing: string[] = [];
    const errors: Record<string, string> = {};
    for (const n of names) {
      const found = await findShareId(ctx, 'iscsi.target.query', n);
      if (!found) { missing.push(n); continue; } // already gone — idempotent skip
      try {
        // Transport-tolerant — a lost response is confirmed by re-querying (the target must be GONE).
        const r = await dispatchWrite(ctx, 'iscsi.target.delete', [found.id], { verify: async () => { try { return findShareId(ctx, 'iscsi.target.query', n) === null; } catch { return null; } } });
        if (r.note) notes[n] = r.note;
        if (r.unconfirmed) errors[n] = 'Delete could not be confirmed (transport drop, state unreadable) — re-run the step'; // destructive: never assume applied
        else deleted++;
      } catch (e) {
        errors[n] = e instanceof Error ? e.message : String(e);
      }
    }
    return { success: Object.keys(errors).length === 0, applied: true, details: { deleted, missing, ...(Object.keys(notes).length ? { notes } : {}), ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

// --- NVMe-oF (TrueNAS 24.10+) -------------------------------------------------

const nvmeofSubsystemCreateAction: ActionDescriptor<TruenasActionContext> = {
  id: 'shares.nvmeof.create',
  label: 'Create NVMe-oF subsystem',
  description: 'Creates a new NVMe-oF subsystem (nvmet.subsys.create, TrueNAS 24.10+) with one file-based namespace backed by the given dataset.',
  module: 'Shares',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 60_000,
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, description: 'Subsystem NQN (e.g. nqn.2024-01.org.unm:tank)' },
    path: { type: 'string', required: false, description: 'Dataset to expose as a namespace (omit for an empty subsystem)' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const name = inStr(input, 'name');
    if (!name) return { success: false, details: { error: '"name" is required' } };
    try {
      // The subsystem collection is `nvmet.subsys.*` (NOT "subsystem") — verified
      // against the live method catalog on 25.10 + 26 BETA appliances.
      // Transport-tolerant — a lost response is confirmed by re-querying (the subsystem must exist).
      const dr = await dispatchWrite(ctx, 'nvmet.subsys.create', [{ name }], { verify: async () => { try { return findShareId(ctx, 'nvmet.subsys.query', name) !== null; } catch { return null; } } });
      const path = inStr(input, 'path');
      if (path) {
        const found = await findShareId(ctx, 'nvmet.subsys.query', name);
        if (found) {
          try {
            // namespace.create requires subsys_id + device_type + device_path.
            // A dataset-backed namespace is a FILE-type namespace on its mountpoint.
            // Transport-tolerant — a lost response is confirmed by re-querying the namespace list.
            await dispatchWrite(ctx, 'nvmet.namespace.create', [{ subsys_id: found.id, device_type: 'FILE', device_path: path }], {
              verify: async () => {
                try {
                  const rows = await ctx.client.call<Record<string, unknown>[]>('nvmet.namespace.query', [], ctx.creds);
                  return (rows ?? []).some((r) => {
                    const subsysObj = (r['subsys'] ?? {}) as Record<string, unknown>;
                    const sid = pickNumber(subsysObj, ['id']) ?? pickNumber(r, ['subsystem']);
                    return sid === found.id && (pickString(r, ['dataset']) === path || pickString(r, ['device_path']) === path); // present — applied
                  });
                } catch {
                  return null;
                }
              },
            });
          } catch (e) {
            return { success: true, applied: true, details: { name, note: `Subsystem created but namespace attach failed: ${e instanceof Error ? e.message : String(e)}` } };
          }
        }
      }
      return { success: true, applied: true, details: { name, ...(path ? { path } : {}), ...(dr.note ? { transportNote: dr.note } : {}) } };
    } catch (e) {
      if (isAlreadyExists(e)) return { success: true, applied: false, details: { name, note: 'NVMe-oF subsystem already exists' } };
      return { success: false, details: { error: e instanceof Error ? e.message : String(e), name } };
    }
  },
};

const nvmeofSubsystemDeleteAction: ActionDescriptor<TruenasActionContext> = {
  id: 'shares.nvmeof.delete',
  label: 'Delete NVMe-oF subsystem(s)',
  description: 'DELETES the selected NVMe-oF subsystems (nvmet.subsys.delete, TrueNAS 24.10+). Removes only the subsystem/namespaces — the underlying datasets are untouched.',
  module: 'Shares',
  riskLevel: 'dangerous' as const,
  deviceCount: 1 as const,
  timeoutMs: 120_000,
  inputSchema: {
    names: { type: 'array', required: true, items: { type: 'string', minLength: 1 }, description: 'Subsystem NQNs to delete' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const names = strArray(input, 'names');
    if (names.length === 0) return { success: false, details: { error: 'No subsystem NQNs provided' } };
    let deleted = 0;
    const notes: Record<string, string> = {};
    const missing: string[] = [];
    const errors: Record<string, string> = {};
    for (const n of names) {
      const found = await findShareId(ctx, 'nvmet.subsys.query', n);
      if (!found) { missing.push(n); continue; } // already gone — idempotent skip
      try {
        // Transport-tolerant — a lost response is confirmed by re-querying (the subsystem must be GONE).
        const r = await dispatchWrite(ctx, 'nvmet.subsys.delete', [found.id], { verify: async () => { try { return findShareId(ctx, 'nvmet.subsys.query', n) === null; } catch { return null; } } });
        if (r.note) notes[n] = r.note;
        if (r.unconfirmed) errors[n] = 'Delete could not be confirmed (transport drop, state unreadable) — re-run the step'; // destructive: never assume applied
        else deleted++;
      } catch (e) {
        errors[n] = e instanceof Error ? e.message : String(e);
      }
    }
    return { success: Object.keys(errors).length === 0, applied: true, details: { deleted, missing, ...(Object.keys(notes).length ? { notes } : {}), ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

const imagesDeleteAction: ActionDescriptor<TruenasActionContext> = {
  id: 'images.delete',
  label: 'Delete image(s)',
  description:
    'DELETES the selected docker images from the appliance (app.image.delete). Images still in use by a running app may fail; dangling/unused ones are removed.',
  module: 'Containers',
  riskLevel: 'dangerous' as const,
  deviceCount: 1 as const,
  timeoutMs: 300_000,
  inputSchema: {
    ids: { type: 'array', required: true, items: { type: 'string', minLength: 1 }, description: 'Image ids or tag references to delete' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const ids = strArray(input, 'ids');
    if (ids.length === 0) return { success: false, details: { error: 'No image ids provided' } };

    // Build the set of known images (id + every tag/digest) so we can tell
    // "already gone" from a real failure, plus a map from any reference to its
    // sha256 id — app.image.delete only accepts ids, not tags.
    const rows = await callWithRetry<Record<string, unknown>[]>(ctx, 'app.image.query', []);
    const known = new Set<string>();
    const idByRef = new Map<string, string>();
    for (const r of rows ?? []) {
      const id = pickString(r, ['id']);
      if (!id) continue;
      known.add(id);
      idByRef.set(id, id);
      for (const t of Array.isArray(r['repo_tags']) ? (r['repo_tags'] as unknown[]) : []) {
        if (typeof t === 'string') {
          known.add(t);
          idByRef.set(t, id);
        }
      }
    }

    let deleted = 0;
    const notes: Record<string, string> = {};
    const missing: string[] = [];
    const errors: Record<string, string> = {};
    const doneIds = new Set<string>(); // several tags can share one image id — delete it once
    for (const ref of ids) {
      if (!known.has(ref)) {
        missing.push(ref); // already gone — nothing to do
        continue;
      }
      const target = idByRef.get(ref)!;
      if (doneIds.has(target)) continue;
      doneIds.add(target);
      try {
        // Transport-tolerant — a lost response is confirmed by re-querying (the image must be GONE).
        const r = await dispatchWrite(ctx, 'app.image.delete', [target, { force: false }], {
          verify: async () => {
            try {
              const after = await ctx.client.call<Record<string, unknown>[]>('app.image.query', [], ctx.creds);
              return !(after ?? []).some((row) => pickString(row, ['id']) === target); // gone — applied; still present — not applied
            } catch {
              return null;
            }
          },
        });
        if (r.note) notes[ref] = r.note;
        if (r.unconfirmed) errors[ref] = 'Delete could not be confirmed (transport drop, state unreadable) — re-run the step'; // destructive: never assume applied
        else deleted++;
      } catch (e) {
        errors[ref] = e instanceof Error ? e.message : String(e);
      }
    }
    return { success: Object.keys(errors).length === 0, applied: true, details: { deleted, missing, ...(Object.keys(notes).length ? { notes } : {}), ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

// --- Generic docker image management contract ---------------------------------
// Same action ids + input shapes as the generic-ssh (docker CLI) and Docker
// plugin (Engine API) implementations, so the Containers page's image panel —
// per-row Pull/Update/Delete buttons, bulk actions and the "Pull image" dialog
// — works identically on TrueNAS hosts. Native middleware methods used:
//   app.image.pull({image})  — pulls ANY ref (job; falls back to saved registry creds)
//   app.redeploy(name)       — stop + pull latest images + start ONE app (job)
//   app.image.query / delete — image inventory + removal (force=false, so docker's
//                              own in-use protection still applies on the appliance)

/** Pulls one ref via the `app.image.pull` job and waits for it to settle. */
async function pullImageRef(ctx: TruenasActionContext, ref: string): Promise<{ ok: boolean; note?: string; error?: string }> {
  try {
    // app.image.pull is a JOB method — it returns the job id immediately.
    // Transport-tolerant — re-pulling an image whose digest already matches upstream is a no-op, so a lost response can be re-dispatched blindly (the pull itself proves the outcome).
    const dr = await dispatchWrite(ctx, 'app.image.pull', [{ image: ref }], { idempotentRetry: true });
    let jobId: number | undefined;
    const r = dr.value;
    if (typeof r === 'number') jobId = r;
    else if (r && typeof r === 'object' && typeof (r as Record<string, unknown>)['id'] === 'number') jobId = (r as Record<string, unknown>)['id'] as number;
    if (jobId !== undefined) {
      const wait = await waitForJob(ctx, jobId, 840_000);
      if (wait.state !== 'SUCCESS' && wait.state !== 'FINISHED') return { ok: false, note: dr.note, error: wait.error ?? `Pull job ended in state ${wait.state}` };
    }
    return { ok: true, ...(dr.note ? { note: dr.note } : {}) };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}

const imagesPullAction: ActionDescriptor<TruenasActionContext> = {
  id: 'images.pull',
  label: 'Pull image(s)',
  description:
    'Pulls docker image references into the appliance (app.image.pull, one job per ref). Works for refs that are NOT in the local store yet — new images are downloaded, existing tags refreshed to the registry version. Saved registry credentials are used automatically when available.',
  module: 'Containers',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 900_000, // large image pulls dominate — give the plan executor a 15-min budget
  inputSchema: {
    refs: { type: 'array', required: true, items: { type: 'string', minLength: 2 }, description: 'Image references to pull (e.g. "nginx:latest", "ghcr.io/org/app:v1")' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const refs = strArray(input, 'refs');
    if (refs.length === 0) return { success: false, details: { error: 'No image references provided' } };

    // One pull per ref — sequential so a single huge image cannot starve the rest.
    const pulled: string[] = [];
    const notes: Record<string, string> = {};
    const errors: Record<string, string> = {};
    for (const ref of refs) {
      const r = await pullImageRef(ctx, ref);
      if (r.note) notes[ref] = r.note;
      if (!r.ok) errors[ref] = r.error ?? 'pull failed';
      else pulled.push(ref);
    }

    // Verify: re-query the image store — every pulled ref must now exist locally.
    let verified: boolean | undefined;
    if (Object.keys(errors).length === 0 && pulled.length > 0) {
      try {
        const after = await callWithRetry<Record<string, unknown>[]>(ctx, 'app.image.query', []);
        const localRefs = new Set<string>();
        for (const row of after ?? []) {
          for (const t of Array.isArray(row['repo_tags']) ? (row['repo_tags'] as unknown[]) : []) {
            if (typeof t === 'string' && t.length > 0) localRefs.add(t);
          }
        }
        verified = refs.every((ref) => localRefs.has(ref));
      } catch { /* verification is best-effort — the pull jobs themselves succeeded */ }
    }

    return { success: Object.keys(errors).length === 0, applied: true, verified, details: { pulled, ...(Object.keys(notes).length ? { notes } : {}), ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

const imagesUpdateAction: ActionDescriptor<TruenasActionContext> = {
  id: 'images.update',
  label: 'Update image(s)',
  description:
    'Re-pulls the given image references (app.image.pull, one job per ref) and — by default — REDEPLOYS every RUNNING app that has a container using one of those refs so it picks up the new version (app.redeploy = stop + pull + start). Stopped apps are NOT started as a side effect. Set restart=false to only refresh the local store.',
  module: 'Containers',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 1_800_000, // pulls + per-app redeploy jobs — give the plan executor a 30-min budget
  inputSchema: {
    refs: { type: 'array', required: true, items: { type: 'string', minLength: 2 }, description: 'Image references to update (e.g. "nginx:latest")' },
    restart: { type: 'boolean', required: false, default: true, description: 'Redeploy running apps that use the updated images (default true)' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const refs = strArray(input, 'refs');
    if (refs.length === 0) return { success: false, details: { error: 'No image references provided' } };
    const restart = input['restart'] !== false; // default true

    // 1) Refresh the local store.
    const pulled: string[] = [];
    const notes: Record<string, string> = {};
    const errors: Record<string, string> = {};
    for (const ref of refs) {
      const r = await pullImageRef(ctx, ref);
      if (r.note) notes[ref] = r.note;
      if (!r.ok) errors[ref] = r.error ?? 'pull failed';
      else pulled.push(ref);
    }

    if (!restart || Object.keys(errors).length > 0) {
      return { success: Object.keys(errors).length === 0, applied: true, verified: Object.keys(errors).length === 0, details: { updated: pulled, restarted: [], ...(Object.keys(notes).length ? { notes } : {}), ...(Object.keys(errors).length ? { errors } : {}) } };
    }

    // 2) Find every app that has a container using one of the refs. ONE pass over
    // app.query — each row's container_details[].image is exactly the ref string
    // used at creation, so a tag update ("nginx:latest") matches containers started
    // from that same ref. Digest-pinned / short-id creations are not matched (same
    // documented limitation as the other two implementations).
    const apps = await callWithRetry<Record<string, unknown>[]>(ctx, 'app.query', []);
    const byName = new Map<string, Record<string, unknown>>();
    for (const a of apps ?? []) {
      const n = pickString(a, ['name']);
      if (n) byName.set(n, a);
    }
    const usingApps = new Set<string>();
    for (const [name, a] of byName) {
      const details = Array.isArray(a['container_details']) ? (a['container_details'] as Record<string, unknown>[]) : [];
      if (details.some((d) => { const img = pickString(d, ['image']); return typeof img === 'string' && refs.includes(img); })) usingApps.add(name);
    }

    // 3) Redeploy the RUNNING ones — app.redeploy is a job; stopped apps are
    // skipped (redeploy would START them, which is not what "update" means here).
    const restarted: string[] = [];
    const skipped: Record<string, string> = {};
    for (const name of Array.from(usingApps).sort()) {
      const st = normState(pickString(byName.get(name) ?? {}, ['state']));
      if (st !== 'RUNNING') { skipped[name] = st.toLowerCase() || 'unknown'; continue; }
      try {
        const dr = await dispatchWrite(ctx, 'app.redeploy', [name], { verify: appStateVerify(ctx, name, new Set(['RUNNING']), new Set()) });
        if (dr.note) notes[name] = dr.note;
        let jobId: number | undefined;
        const r = dr.value;
        if (typeof r === 'number') jobId = r;
        else if (r && typeof r === 'object' && typeof (r as Record<string, unknown>)['id'] === 'number') jobId = (r as Record<string, unknown>)['id'] as number;
        if (jobId !== undefined) {
          const wait = await waitForJob(ctx, jobId, 600_000);
          if (wait.state !== 'SUCCESS' && wait.state !== 'FINISHED') { errors[name] = wait.error ?? `Redeploy job ended in state ${wait.state}`; continue; }
        } else if (dr.unconfirmed) {
          errors[name] = 'Redeploy could not be confirmed (transport drop, state unreadable) — re-run the step';
          continue;
        }
        restarted.push(name);
      } catch (e) {
        errors[name] = e instanceof Error ? e.message : String(e);
      }
    }

    // Verify: every redeployed app must be RUNNING again.
    let verified: boolean | undefined;
    if (Object.keys(errors).length === 0 && restarted.length > 0) {
      try { verified = await verifyAppStates(ctx, restarted, new Set(['RUNNING'])); } catch { /* best-effort */ }
    } else if (Object.keys(errors).length === 0) {
      verified = true; // nothing to restart — the pulls are the whole job
    }

    return { success: Object.keys(errors).length === 0, applied: true, verified, details: { updated: pulled, restarted, ...(Object.keys(skipped).length ? { skipped } : {}), ...(Object.keys(notes).length ? { notes } : {}), ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

const imagesPruneAction: ActionDescriptor<TruenasActionContext> = {
  id: 'images.prune',
  label: 'Prune unused images',
  description:
    'Removes UNUSED docker images from the appliance (app.image.delete, force=false). With all=false only dangling (<none>) images are removed; with all=true every image no installed app references is removed — including stopped apps\' images. Docker\'s own in-use protection still applies on the appliance, so an image a container actually needs cannot be deleted.',
  module: 'Containers',
  riskLevel: 'dangerous' as const,
  deviceCount: 1 as const,
  timeoutMs: 600_000,
  inputSchema: {
    all: { type: 'boolean', required: false, default: false, description: 'Prune ALL unused images (not just dangling). Default false.' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const all = input['all'] === true;

    // Which refs are in use by any container of an installed app? ONE pass over
    // app.query — container_details covers every state (a stopped app still
    // references its images). Images used by containers OUTSIDE the app system
    // are invisible here, but force=false below makes docker refuse to delete them.
    const inUse = new Set<string>();
    if (all) {
      const apps = await callWithRetry<Record<string, unknown>[]>(ctx, 'app.query', []);
      for (const a of apps ?? []) {
        const details = Array.isArray(a['container_details']) ? (a['container_details'] as Record<string, unknown>[]) : [];
        for (const d of details) {
          const img = pickString(d, ['image']);
          if (img) inUse.add(img);
        }
      }
    }

    // Walk the image store and delete what is unused.
    const rows = await callWithRetry<Record<string, unknown>[]>(ctx, 'app.image.query', []);
    let deleted = 0;
    let freedBytes = 0;
    const errors: Record<string, string> = {};
    for (const r of rows ?? []) {
      const id = pickString(r, ['id']);
      if (!id) continue;
      const tags = Array.isArray(r['repo_tags']) ? (r['repo_tags'] as unknown[]).filter((t): t is string => typeof t === 'string' && t !== '<none>:<none>') : [];
      const dangling = r['dangling'] === true || tags.length === 0;
      if (!all && !dangling) continue; // dangling-only mode keeps everything tagged
      if (all && !dangling && tags.some((t) => inUse.has(t))) continue; // referenced by an app container

      const label = tags[0] ?? id.slice(0, 12);
      try {
        // Same transport-tolerant delete as images.delete — a lost response is
        // confirmed by re-querying (the image must be GONE).
        const dr = await dispatchWrite(ctx, 'app.image.delete', [id, { force: false }], {
          verify: async () => {
            try {
              const after = await ctx.client.call<Record<string, unknown>[]>('app.image.query', [], ctx.creds);
              return !(after ?? []).some((row) => pickString(row, ['id']) === id); // gone — applied; still present — not applied
            } catch {
              return null;
            }
          },
        });
        if (dr.unconfirmed) errors[label] = 'Delete could not be confirmed (transport drop, state unreadable)';
        else {
          deleted++;
          const size = typeof r['size'] === 'number' ? (r['size'] as number) : 0;
          freedBytes += size > 0 ? size : 0;
        }
      } catch (e) {
        errors[label] = e instanceof Error ? e.message : String(e); // e.g. "image is in use" — docker protected it
      }
    }

    return { success: Object.keys(errors).length === 0, applied: true, verified: true, details: { all, deleted, freedBytes, ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

/** Quote a YAML scalar when it could be misread (leading indicator chars,
 * trailing space, colon-space, or looking like a number/bool/null). */
function yamlScalar(v: string): string {
  if (v === '') return "''";
  const risky = /^[\s#&*!|>%@`"'{}\[\],-]/.test(v) || /[:\s]$/.test(v) || /:\s/.test(v);
  if (!risky && !/^[0-9]+(\.[0-9]+)?$/.test(v) && !/^(true|false|null|yes|no|on|off)$/i.test(v)) return v;
  const escaped = v.replace(/\\/g, '\\\\').replace(/'/g, "''");
  return `'${escaped}'`;
}

/** Serializes a TrueNAS app config object (the structured `services`/`networks`
 * map of a custom app) into Docker Compose YAML. TrueNAS 26 does NOT store the
 * original compose string for custom apps — only this structured form — so the
 * clone/duplicate flow reconstructs an editable YAML from it. Keys are sorted
 * alphabetically (compose is order-insensitive); values keep their native types.
 */
function serializeComposeYaml(cfg: Record<string, unknown>): string {
  const TOP_KEYS = ['networks', 'services', 'volumes', 'configs', 'secrets'];
  const lines: string[] = [];
  for (const key of TOP_KEYS) {
    if (!(key in cfg)) continue;
    const v = cfg[key];
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      lines.push(`${key}:`);
      for (const [name, def] of Object.entries(v as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b))) {
        const d = def;
        if (d && typeof d === 'object' && !Array.isArray(d)) {
          lines.push(`  ${name}:`);
          for (const [fk, fv] of Object.entries(d as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b))) {
            const ind = '    ';
            if (fv && typeof fv === 'object' && !Array.isArray(fv)) {
              lines.push(`${ind}${fk}:`);
              for (const [gk, gv] of Object.entries(fv as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b))) {
                if (gv && typeof gv === 'object' && !Array.isArray(gv)) {
                  lines.push(`${ind}  ${gk}:`);
                  for (const [hk, hv] of Object.entries(gv as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b))) {
                    if (hv && typeof hv === 'object') lines.push(`${ind}    ${hk}: ${JSON.stringify(hv)}`);
                    else if (typeof hv === 'string') lines.push(`${ind}    ${hk}: ${yamlScalar(hv)}`);
                    else lines.push(`${ind}    ${hk}: ${String(hv ?? '')}`);
                  }
                } else if (Array.isArray(gv)) {
                  if (gv.length === 0) { lines.push(`${ind}  ${gk}: []`); continue; }
                  lines.push(`${ind}  ${gk}:`);
                  for (const item of gv) lines.push(`${ind}    - ${typeof item === 'string' ? yamlScalar(item) : JSON.stringify(item)}`);
                } else if (typeof gv === 'string') lines.push(`${ind}  ${gk}: ${yamlScalar(gv)}`);
                else lines.push(`${ind}  ${gk}: ${String(gv ?? '')}`);
              }
            } else if (Array.isArray(fv)) {
              if (fv.length === 0) { lines.push(`${ind}${fk}: []`); continue; }
              lines.push(`${ind}${fk}:`);
              for (const item of fv) lines.push(`${ind}  - ${typeof item === 'string' ? yamlScalar(item) : JSON.stringify(item)}`);
            } else if (typeof fv === 'string') lines.push(`${ind}${fk}: ${yamlScalar(fv)}`);
            else lines.push(`${ind}${fk}: ${String(fv ?? '')}`);
          }
        } else {
          lines.push(`  ${name}: ${JSON.stringify(d)}`);
        }
      }
    } else if (Array.isArray(v)) {
      if (v.length === 0) { lines.push(`${key}: []`); continue; }
      lines.push(`${key}:`);
      for (const item of v) lines.push(`  - ${typeof item === 'string' ? yamlScalar(item) : JSON.stringify(item)}`);
    } else if (typeof v === 'string') {
      lines.push(`${key}: ${yamlScalar(v)}`);
    }
  }
  return lines.join('\n');
}

/**
 * Reads the current compose YAML of a custom app. The webapp's Containers page
 * uses this to pre-fill its YAML editor (and the Create-app dialog's duplicate
 * flow). TrueNAS 26 stores custom apps as a STRUCTURED config ({networks,
 * services}) — there is no original compose string — so it is reconstructed as
 * editable YAML. Catalog apps return their template identity + saved values
 * instead, which drives the catalog-clone prefill.
 */
const composeConfigReadAction: ActionDescriptor<TruenasActionContext> = {
  id: 'compose.config.read',
  label: 'Read app compose YAML',
  description: 'Returns the current Docker Compose configuration (YAML) of a single custom app.',
  module: 'Containers',
  riskLevel: 'read' as const,
  deviceCount: 1 as const,
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, description: 'App name to read the compose config of' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const name = str(input, 'name');
    if (!name) return { success: false, details: { error: 'App name is required' } };

    // app.query with retrieve_config returns the full config. Long budget +
    // retry — on a busy appliance (250+ apps) this query can take 30 s+, and
    // silently falling back to app.config would return a DIFFERENT shape and
    // break the clone prefill.
    let cfg: Record<string, unknown> | null = null;
    // Row-level custom_app flag — ALWAYS present on TrueNAS 26 and the most
    // reliable catalog-vs-custom signal (the config object itself omits it).
    let rowCustomApp: boolean | null = null;
    try {
      const rows = await ctx.client.call<Record<string, unknown>[]>('app.query', [[], { extra: { retrieve_config: true } }], ctx.creds, 45_000);
      for (const r of rows ?? []) {
        if ((pickString(r, ['name']) ?? '') === name) {
          const c = r['config'];
          cfg = c && typeof c === 'object' ? (c as Record<string, unknown>) : null;
          rowCustomApp = typeof r['custom_app'] === 'boolean' ? (r['custom_app'] as boolean) : null;
          break;
        }
      }
    } catch (e) {
      return { success: false, details: { error: `Could not read config for "${name}": ${e instanceof Error ? e.message : String(e)}` } };
    }
    if (!cfg) {
      // Not found in the query — try app.config directly (older appliances).
      try {
        cfg = await ctx.client.call<Record<string, unknown>>('app.config', [name], ctx.creds);
      } catch (e) {
        return { success: false, details: { error: `Could not read config for "${name}": ${e instanceof Error ? e.message : String(e)}` } };
      }
    }

    const cfgCustomApp = typeof cfg['custom_app'] === 'boolean' ? (cfg['custom_app'] as boolean) : null;
    // Prefer the row flag; fall back to the config's own field on older boxes.
    const isCatalog = rowCustomApp !== null ? rowCustomApp === false : (cfgCustomApp === false || typeof pickString(cfg, ['catalog_app']) === 'string');

    // Catalog apps have no editable compose string — their configuration is the
    // saved `values` map plus the template identity. Return those so the webapp's
    // clone/duplicate flow can re-open the catalog form pre-filled (change one
    // setting, redeploy). Custom apps keep the existing YAML payload.
    if (isCatalog) {
      const catalogApp = pickString(cfg, ['catalog_app']);
      const valuesRaw = cfg['values'];
      return {
        success: true,
        details: {
          name,
          yaml: '',
          customApp: false,
          catalogApp,
          train: pickString(cfg, ['train']) ?? 'stable',
          values: valuesRaw && typeof valuesRaw === 'object' && !Array.isArray(valuesRaw) ? (valuesRaw as Record<string, unknown>) : {},
        },
      };
    }

    // Custom apps — the original compose string when present (older appliances);
    // otherwise reconstruct editable YAML from the structured config. The
    // top-level `networks:` map MUST be included — it's where users change the
    // network of a cloned app.
    const yamlStr = pickString(cfg, ['custom_compose_config_string']);
    let yaml: string;
    if (yamlStr && yamlStr.trim() !== '') {
      yaml = yamlStr;
    } else {
      yaml = serializeComposeYaml(cfg);
    }
    if (yaml.trim() === '') return { success: false, details: { error: `No editable compose config found for "${name}"` } };

    return { success: true, details: { name, yaml, customApp: true } };
  },
};

/**
 * Reads the recent log output of one app's container(s). TrueNAS 26 exposes NO
 * RPC for app/container logs (verified against the full core.get_methods
 * catalog — no app.logs / docker.logs / journal method exists), so this runs
 * `docker logs --tail N` over the shared SSH pool — the same channel used for
 * per-container enrichment. Requires a bound `ssh` credential slot; without one
 * it reports a clear "bind an SSH secret" error instead of failing opaquely.
 */
const containersLogsReadAction: ActionDescriptor<TruenasActionContext> = {
  id: 'containers.logs.read',
  label: 'Read container logs',
  description: 'Returns the recent log output (docker logs --tail) of a single app\'s container(s). Requires an SSH credential bound to this device.',
  module: 'Containers',
  riskLevel: 'read' as const,
  deviceCount: 1 as const,
  timeoutMs: 60_000,
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, description: 'App name to read the logs of' },
    tail: { type: 'number', required: false, min: 20, max: 5000, default: 300, description: 'Number of trailing log lines (default 300)' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const name = str(input, 'name');
    if (!name) return { success: false, details: { error: 'App name is required' } };
    const tailRaw = typeof input['tail'] === 'number' ? Math.floor(input['tail']) : 300;
    const tail = Math.min(5000, Math.max(20, Number.isFinite(tailRaw) ? tailRaw : 300));

    // SSH slot — the ONLY log path on TrueNAS (no API method exists).
    const sshCreds = resolveSshCredentials(ctx.rawCredentials ?? undefined, { slotOnly: true });
    if (!sshCreds) {
      return { success: false, details: { error: 'No SSH credential is bound to this device — container logs need the optional "SSH" secret slot (username/password or key pair).' } };
    }

    // Resolve the app's docker container ids via RPC (no SSH needed for this).
    let idMap: Record<string, { id?: string; service_name?: string; state?: string }> | null = null;
    try {
      const r = await ctx.client.call<Record<string, { id?: string; service_name?: string; state?: string }>>('app.container_ids', [name, { alive_only: false }], ctx.creds, 20_000);
      if (r && typeof r === 'object' && Object.keys(r).length > 0) idMap = r;
    } catch (e) {
      return { success: false, details: { error: `Could not resolve containers for "${name}": ${e instanceof Error ? e.message : String(e)}` } };
    }
    if (!idMap || Object.keys(idMap).length === 0) {
      return { success: false, details: { error: `App "${name}" has no containers (it may not exist or is not deployed yet)` } };
    }

    // ONE combined SSH command — every container in a single exec (reuses the pooled session).
    const parts = Object.values(idMap)
      .map((c) => c.id ?? '')
      .filter((id) => /^[a-f0-9]{12,64}$/i.test(id))
      .slice(0, 32); // defensive cap — a single app should never have more than a handful
    if (parts.length === 0) return { success: false, details: { error: `App "${name}" has no resolvable container ids` } };

    const host = (ctx.host ?? '').trim().replace(/^https?:\/\//i, '').replace(/\/+$/, '');
    if (!host) return { success: false, details: { error: 'No management address available for the SSH log read' } };

    // ONE combined SSH command — every container in a single exec (reuses the pooled session).
    const cmd = parts.map((id) => `echo "=== ${id}"; docker logs --tail ${tail} --timestamps ${id} 2>&1 | tail -c 512000`).join(' ; ');
    try {
      // The dynamic host-key verifier pins the SSH handshake against UNM's inventory.
      const client = await sshPool.get(host, 22, sshCreds, { hostKeyVerifier: dynamicSshHostVerifier(host) });
      const r = await client.exec(cmd, sshCreds);
      if (r.code !== 0 && !r.stdout) {
        return { success: false, details: { error: `docker logs over SSH failed (exit ${r.code}): ${r.stderr.slice(0, 300) || 'no output'}` } };
      }
      // Split the combined output back into per-container sections. Markers are
      // full 64-char ids in command order — locate each marker, section ends at
      // the NEXT marker (or end of output).
      const byId = new Map(Object.values(idMap).map((c) => [c.id ?? '', c]));
      const markers: Array<{ id: string; idx: number }> = [];
      for (const id of parts) {
        const idx = r.stdout.indexOf(`=== ${id}`);
        if (idx !== -1) markers.push({ id, idx });
      }
      const containers: Array<{ id: string; service?: string; state?: string; logs: string }> = [];
      for (let i = 0; i < markers.length; i++) {
        const m = markers[i];
        const end = i + 1 < markers.length ? markers[i + 1].idx : r.stdout.length;
        const c = byId.get(m.id);
        containers.push({ id: m.id, service: c?.service_name, state: c?.state, logs: r.stdout.slice(m.idx + (`=== ${m.id}`).length, end).trim() });
      }
      if (containers.length === 0) {
        return { success: false, details: { error: `docker logs over SSH returned no parseable output${r.stderr ? ` (${r.stderr.slice(0, 200)})` : ''}` } };
      }
      return { success: true, details: { name, tail, containers } };
    } catch (e) {
      if (e instanceof SshError) return { success: false, details: { error: `SSH to the appliance failed: ${e.message}` } };
      return { success: false, details: { error: e instanceof Error ? e.message : String(e) } };
    }
  },
};

const containersUpdateAction: ActionDescriptor<TruenasActionContext> = {
  id: 'containers.update',
  label: 'Edit app compose YAML',
  description:
    'Applies an edited Docker Compose configuration to a single custom app (app.update with custom_compose_config_string). The app is redeployed.',
  module: 'Containers',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 300_000,
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, description: 'App name to update' },
    composeString: { type: 'string', required: true, minLength: 2, description: 'New Docker Compose YAML for the app' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const name = str(input, 'name');
    const composeString = str(input, 'composeString');
    if (!name || !composeString) return { success: false, details: { error: 'App name and compose YAML are required' } };

    try {
      const result = await ctx.client.call('app.update', [name, { custom_compose_config_string: composeString }], ctx.creds);
      return { success: true, applied: true, details: describeAccepted(result) };
    } catch (e) {
      if (e instanceof TruenasRpcError && /timed out|closed|unresponsive/i.test(e.message)) {
        return { success: true, applied: true, details: { note: 'Update accepted — connection dropped while the app redeployed.' } };
      }
      throw e;
    }
  },
};

// --- Catalog (app store) + install -------------------------------------------------
// TrueNAS 25.04+/26 renamed the community-apps API: `communityapps.*` is gone,
// replaced by `catalog.trains`, `catalog.apps({trains:[...]})` and
// `catalog.get_app_details(name, {train})`. Installation is `app.create` — a
// JOB method (returns a job id; the work runs server-side). Verified live on
// 26.0.0-BETA: AppCreateArgs = { custom_app, app_name, catalog_app?, train?
// ('stable'), version? ('latest'), values{}, custom_compose_config_string }.

/** One template summary as surfaced to the webapp's Create-app dialog. */
interface CatalogTemplateSummary {
  name: string; // catalog slug (catalog_app)
  title: string;
  description?: string;
  iconUrl?: string;
  latestVersion?: string;
  latestHumanVersion?: string;
  categories?: string[];
  tags?: string[];
  recommended?: boolean;
  healthy?: boolean;
}

/** TrueNAS question-schema node (the appliance's own form definition). */
interface TnQuestion {
  variable: string;
  label?: string;
  group?: string;
  schema?: Record<string, unknown>;
}

function strOr(input: Record<string, unknown>, key: string, fallback: string): string {
  const v = input[key];
  return typeof v === 'string' && v.trim() !== '' ? v : fallback;
}

/** Maps a TrueNAS scalar type onto the UNM InputSchemaProperty types. */
function scalarType(t: string): 'string' | 'number' | 'boolean' {
  if (t === 'number') return 'number';
  if (t === 'boolean') return 'boolean';
  return 'string';
}

/** Converts a leaf attr (no group nesting expected below attrs). */
function convertAttr(a: TnQuestion): Record<string, unknown> | null {
  const s = a.schema ?? {};
  const type = String(s['type'] ?? 'string');
  if (type === 'dict' || type === 'list') return convertQuestion({ ...a, schema: s });
  const out: Record<string, unknown> = { type: scalarType(type), label: a.label || undefined, description: pickString(s, ['description']) };
  if (s['required'] === true) out['required'] = true;
  if (s['default'] !== undefined) out['default'] = s['default'];
  const enumRaw = s['enum'];
  if (Array.isArray(enumRaw)) {
    // TrueNAS enums are [{value, description?}] — flatten to values.
    out['enum'] = enumRaw.map((e: unknown) => (e && typeof e === 'object' ? (e as Record<string, unknown>)['value'] : e));
  }
  const validChars = pickString(s, ['valid_chars']);
  if (validChars) out['pattern'] = validChars;
  return out;
}

/**
 * Converts one TrueNAS question-schema node into the UNM InputSchemaProperty
 * shape (the subset SchemaForm renders). Handles the nesting styles observed
 * in real templates: dict groups with `attrs[]`, list-of-dict rows, enums as
 * {value, description}[], valid_chars → pattern. show_if is dropped — fields
 * are always rendered; the appliance re-validates everything on install.
 */
function convertQuestion(q: TnQuestion): Record<string, unknown> | null {
  const s = q.schema ?? {};
  const type = String(s['type'] ?? 'string');

  if (type === 'dict') {
    // Group container — its fields live in attrs[].
    const attrs = Array.isArray(s['attrs']) ? (s['attrs'] as TnQuestion[]) : [];
    const properties: Record<string, unknown> = {};
    for (const a of attrs) {
      if (!a.variable) continue;
      const sub = convertAttr(a);
      if (sub) properties[a.variable] = sub;
    }
    return { type: 'object', label: q.label || undefined, description: pickString(s, ['description']), properties };
  }

  if (type === 'list') {
    const itemsRaw = Array.isArray(s['items']) ? s['items'] : [];
    const first = itemsRaw.length > 0 ? (itemsRaw[0] as TnQuestion) : null;
    let itemProp: Record<string, unknown> = { type: 'string' };
    if (first) {
      const isDict = String((first.schema ?? {})['type']) === 'dict';
      if (isDict) {
        const attrs = Array.isArray((first.schema ?? {})['attrs']) ? ((first.schema as Record<string, unknown>)['attrs'] as TnQuestion[]) : [];
        const properties: Record<string, unknown> = {};
        for (const a of attrs) {
          if (!a.variable) continue;
          const sub = convertAttr(a);
          if (sub) properties[a.variable] = sub;
        }
        itemProp = { type: 'object', properties };
      } else {
        itemProp = convertAttr(first) ?? { type: 'string' };
      }
    }
    return {
      type: 'array',
      label: q.label || undefined,
      description: pickString(s, ['description']),
      default: s['default'] !== undefined ? s['default'] : [],
      items: itemProp,
    };
  }

  // Scalar (string/number/boolean) — may carry an enum of {value, description}.
  const out: Record<string, unknown> = { type: scalarType(type), label: q.label || undefined, description: pickString(s, ['description']) };
  if (s['required'] === true) out['required'] = true;
  if (s['default'] !== undefined) out['default'] = s['default'];
  const enumRaw = s['enum'];
  if (Array.isArray(enumRaw)) {
    out['enum'] = enumRaw.map((e: unknown) => (e && typeof e === 'object' ? (e as Record<string, unknown>)['value'] : e));
  }
  const validChars = pickString(s, ['valid_chars']);
  if (validChars) out['pattern'] = validChars;
  return out;
}

/** Picks the version entry to use: explicit `version` input, else latest. */
function pickVersionEntry(versions: Record<string, unknown>, wanted?: string): { key: string; entry: Record<string, unknown> } | null {
  if (!versions || typeof versions !== 'object') return null;
  const keys = Object.keys(versions);
  if (keys.length === 0) return null;
  if (wanted && versions[wanted]) return { key: wanted, entry: versions[wanted] as Record<string, unknown> };
  // "latest" or no preference → the highest version-ish key.
  const sorted = [...keys].sort((a, b) => looseCompareVersions(b, a));
  return { key: sorted[0], entry: versions[sorted[0]] as Record<string, unknown> };
}

/** Loose version comparator (handles "1.2.3" and "26.04.3.2.1_1.5.28" style).
 * Local to this file — the SDK's `compareVersions` (imported above) is a
 * different, stricter contract used for OS-release comparisons. */
function looseCompareVersions(a: string, b: string): number {
  const pa = a.split(/[._-]/).map((x) => parseInt(x, 10)).filter((n) => !Number.isNaN(n));
  const pb = b.split(/[._-]/).map((x) => parseInt(x, 10)).filter((n) => !Number.isNaN(n));
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? 0;
    const y = pb[i] ?? 0;
    if (x !== y) return x - y;
  }
  return 0;
}

/** catalog.templates.list — read-only template gallery for the Create-app dialog. */
const catalogTemplatesListAction: ActionDescriptor<TruenasActionContext> = {
  id: 'catalog.templates.list',
  label: 'List app store templates',
  description:
    "Returns the appliance's community-app catalog (per train) with name, title, description, icon and latest version — drives the Create-app dialog. Read-only.",
  module: 'Containers',
  riskLevel: 'read' as const,
  deviceCount: 1 as const,
  timeoutMs: 60_000, // catalog.apps can be slow right after a catalog sync
  inputSchema: {
    train: { type: 'string', required: false, description: 'Catalog train to list (default: stable)' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const train = strOr(input, 'train', 'stable');

    let trains: string[];
    try {
      const t = await callWithRetry<unknown>(ctx, 'catalog.trains', []);
      trains = Array.isArray(t) ? (t as string[]) : ['stable'];
    } catch {
      trains = [train]; // catalog.trains missing on older boxes — fall back to the requested train
    }

    let byTrain: Record<string, unknown>;
    try {
      const r = await callWithRetry<Record<string, unknown>>(ctx, 'catalog.apps', [{ trains: [train] }]);
      byTrain = r && typeof r === 'object' ? r : {};
    } catch (e) {
      // Pre-25.04 boxes lack the catalog.* namespace — surface a clear error so
      // the dialog can hide itself for this device.
      return { success: false, details: { error: `Catalog API unavailable on this appliance (${e instanceof Error ? e.message : String(e)})` } };
    }

    const appMap = (byTrain[train] ?? {}) as Record<string, Record<string, unknown>>;
    const templates: CatalogTemplateSummary[] = Object.values(appMap).map((a) => ({
      name: pickString(a, ['name']) ?? '',
      title: pickString(a, ['title']) ?? pickString(a, ['name']) ?? '',
      description: pickString(a, ['description']),
      iconUrl: pickString(a, ['icon_url']),
      latestVersion: pickString(a, ['latest_version']),
      latestHumanVersion: pickString(a, ['latest_human_version']),
      categories: Array.isArray(a['categories']) ? (a['categories'] as string[]) : undefined,
      tags: Array.isArray(a['tags']) ? (a['tags'] as string[]) : undefined,
      recommended: typeof a['recommended'] === 'boolean' ? (a['recommended'] as boolean) : undefined,
      healthy: typeof a['healthy'] === 'boolean' ? (a['healthy'] as boolean) : undefined,
    })).filter((t) => t.name !== '');

    return { success: true, details: { train, trains, templates } };
  },
};

/** template.details.read — one template's config schema for the form. */
const templateDetailsReadAction: ActionDescriptor<TruenasActionContext> = {
  id: 'template.details.read',
  label: 'Read template config schema',
  description:
    "Returns one catalog template's configuration questions (converted to UNM form fields) plus its default values — pre-fills the Create-app dialog. Read-only.",
  module: 'Containers',
  riskLevel: 'read' as const,
  deviceCount: 1 as const,
  timeoutMs: 60_000,
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, description: 'Catalog template slug (e.g. "collabora")' },
    train: { type: 'string', required: false, description: 'Catalog train (default: stable)' },
    version: { type: 'string', required: false, description: 'Specific version to read the schema of (default: latest)' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const name = str(input, 'name');
    if (!name) return { success: false, details: { error: 'Template name is required' } };
    const train = strOr(input, 'train', 'stable');

    let d: Record<string, unknown>;
    try {
      d = await callWithRetry<Record<string, unknown>>(ctx, 'catalog.get_app_details', [name, { train }]);
    } catch (e) {
      return { success: false, details: { error: `Could not read template "${name}" from train "${train}": ${e instanceof Error ? e.message : String(e)}` } };
    }

    const versions = (d['versions'] ?? {}) as Record<string, unknown>;
    const picked = pickVersionEntry(versions, str(input, 'version'));
    if (!picked) return { success: false, details: { error: `Template "${name}" has no version entries` } };
    const ve = picked.entry;

    // Convert the question schema into UNM InputSchema shape.
    const questions = (((ve['schema'] as Record<string, unknown> | undefined)?.['questions']) ?? []) as TnQuestion[];
    const fields: Record<string, unknown> = {};
    for (const q of questions) {
      if (!q.variable) continue;
      const converted = convertQuestion(q);
      if (converted) fields[q.variable] = converted;
    }

    // Group layout for the dialog's collapsible sections. TrueNAS questions
    // carry a `group` name; dict containers are self-contained sub-forms and
    // become their own section; ungrouped scalars land in "General". Order of
    // first appearance is preserved (matches the appliance's form order).
    const groupOrder: string[] = [];
    const groupsByTitle: Record<string, string[]> = {};
    for (const q of questions) {
      if (!q.variable || !fields[q.variable]) continue;
      const converted = fields[q.variable] as Record<string, unknown>;
      let title: string;
      if (converted['type'] === 'object' && converted['properties']) {
        title = String(converted['label'] ?? q.label ?? q.variable); // dict sub-form → own section
      } else if (typeof q.group === 'string' && q.group.trim() !== '') {
        title = q.group;
      } else {
        title = 'General';
      }
      if (!groupsByTitle[title]) {
        groupsByTitle[title] = [];
        groupOrder.push(title);
      }
      groupsByTitle[title].push(q.variable);
    }
    const groups = groupOrder.map((title) => ({ title, fields: groupsByTitle[title] }));

    // Default values shipped with the template (the appliance's own defaults).
    const values = (ve['values'] ?? {}) as Record<string, unknown>;

    return {
      success: true,
      details: {
        name,
        train,
        version: picked.key,
        humanVersion: pickString(ve, ['human_version']),
        title: pickString(d, ['title']) ?? name,
        description: pickString(d, ['description']),
        fields, // InputSchema-compatible map for SchemaForm
        values, // defaults to pre-fill the form (appliance-side source of truth)
        groups, // [{title, fields[]}] — section layout for the dialog
      },
    };
  },
};

/** Waits for a TrueNAS job (by id from app.create etc.) until it settles or budget runs out. */
async function waitForJob(
  ctx: TruenasActionContext,
  jobId: number,
  budgetMs: number,
): Promise<{ state: string; error?: string }> {
  const deadline = Date.now() + budgetMs;
  for (;;) {
    let jobs: Record<string, unknown>[];
    try {
      jobs = await ctx.client.call<Record<string, unknown>[]>('core.get_jobs', [], ctx.creds);
    } catch (e) {
      return { state: 'UNKNOWN', error: `Lost track of job ${jobId}: ${e instanceof Error ? e.message : String(e)}` };
    }
    const j = (jobs ?? []).find((x) => x['id'] === jobId);
    if (!j) return { state: 'UNKNOWN', error: `Job ${jobId} no longer listed` };
    const state = pickString(j, ['state']) ?? '';
    if (state !== 'RUNNING') {
      const errRaw = j['error'];
      return { state, ...(errRaw ? { error: String(errRaw) } : {}) };
    }
    if (Date.now() >= deadline) return { state: 'RUNNING', error: `Still running after ${Math.round(budgetMs / 1000)}s — the install continues on the appliance; check its Apps page.` };
    await new Promise((r) => setTimeout(r, 3_000));
  }
}

/** containers.install — creates a NEW app (catalog template or custom compose). */
const containersInstallAction: ActionDescriptor<TruenasActionContext> = {
  id: 'containers.install',
  label: 'Create app (install)',
  description:
    'Creates a new app on the appliance via app.create — either from a catalog template (with its config values) or as a custom Docker Compose stack. Runs to completion (image pulls included), so it may take several minutes.',
  module: 'Containers',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 900_000, // image pulls dominate — give the plan executor a 15-min budget
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, maxLength: 40, pattern: '^[a-z]([-a-z0-9]*[a-z0-9])?$', description: 'App instance name (lowercase slug — TrueNAS enforces this)' },
    mode: { type: 'string', required: true, enum: ['catalog', 'custom'], description: 'catalog = install a store template; custom = deploy your own compose YAML' },
    catalogApp: { type: 'string', required: false, description: 'Catalog template slug (required when mode=catalog)' },
    train: { type: 'string', required: false, description: 'Catalog train (default stable)' },
    version: { type: 'string', required: false, description: 'Template version to install (default latest)' },
    config: { type: 'object', required: false, properties: {}, description: 'Template configuration values (mode=catalog)' },
    composeString: { type: 'string', required: false, minLength: 2, description: 'Docker Compose YAML (required when mode=custom)' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const name = str(input, 'name');
    if (!name) return { success: false, details: { error: 'App name is required' } };
    const mode = strOr(input, 'mode', 'catalog');

    // Idempotency guard — an app with this name already exists.
    try {
      const apps = await listApps(ctx);
      if (apps.some((a) => a.name === name)) {
        return { success: false, details: { error: `An app named "${name}" already exists on this appliance` } };
      }
    } catch { /* best-effort guard — app.create will reject duplicates anyway */ }

    let params: Record<string, unknown>;
    if (mode === 'catalog') {
      const catalogApp = str(input, 'catalogApp');
      if (!catalogApp) return { success: false, details: { error: 'catalogApp is required when mode=catalog' } };
      params = {
        custom_app: false,
        app_name: name,
        catalog_app: catalogApp,
        train: strOr(input, 'train', 'stable'),
        version: strOr(input, 'version', 'latest'),
        values: input['config'] && typeof input['config'] === 'object' ? (input['config'] as Record<string, unknown>) : {},
      };
    } else if (mode === 'custom') {
      const composeString = str(input, 'composeString');
      if (!composeString) return { success: false, details: { error: 'composeString is required when mode=custom' } };
      params = { custom_app: true, app_name: name, custom_compose_config_string: composeString };
    } else {
      return { success: false, details: { error: `Unknown mode "${mode}" (expected catalog|custom)` } };
    }

    // app.create is a JOB method — it returns the job id immediately.
    let jobId: number;
    try {
      const r = await ctx.client.call<unknown>('app.create', [params], ctx.creds);
      if (typeof r !== 'number') return { success: false, details: { error: `Unexpected app.create result: ${JSON.stringify(r)}` } };
      jobId = r;
    } catch (e) {
      // The socket can drop while a long install runs — treat as "initiated" only
      // when the transport died AFTER dispatch (same convention as reboot).
      if (e instanceof TruenasRpcError && /timed out|closed|unresponsive/i.test(e.message)) {
        return { success: true, applied: true, details: { note: 'Install accepted — connection dropped while the appliance worked; check its Apps page.' } };
      }
      throw e;
    }

    // Wait for the job to settle (budget = our timeout minus a safety margin).
    const wait = await waitForJob(ctx, jobId, 840_000);
    if (wait.state === 'RUNNING') {
      return { success: true, applied: true, details: { jobId, state: wait.state, note: wait.error } };
    }
    if (wait.state !== 'SUCCESS' && wait.state !== 'FINISHED') {
      return { success: false, details: { jobId, state: wait.state, error: wait.error ?? `Job ended in state ${wait.state}` } };
    }
    // Job SUCCESS is not enough — confirm the app actually exists now.
    const verified = await verifyAppStates(ctx, [name], new Set(['RUNNING', 'STOPPED']));
    return { success: true, applied: true, verified, details: { jobId, state: wait.state, name, mode } };
  },
};

// ---------------------------------------------------------------------------
// Services (Services page) — start/stop/restart ONE middleware service.
// `service.control [VERB, name]` is the appliance's own control entry point
// (job-based; verified against truenas/middleware ServiceService). It works for
// EVERY registered service — including the special ones the middleware manages
// outside the init system (smb/nfs/iscsi/s3/vm/docker/…). Verification re-reads
// `service.started` after the job settles.
// ---------------------------------------------------------------------------

/** True when a control call failed because the service is already in the target state. */
function isServiceAlreadyInState(e: unknown, verb: 'START' | 'STOP'): boolean {
  if (!(e instanceof TruenasRpcError)) return false;
  const m = e.message ?? '';
  if (verb === 'START') return /already running|is already started/i.test(m);
  return /not running|is not started|no such process/i.test(m);
}

function serviceControlAction(
  id: string,
  verb: 'START' | 'STOP' | 'RESTART',
  label: string,
  description: string,
): ActionDescriptor<TruenasActionContext> {
  return {
    id,
    label,
    description,
    module: 'Services',
    riskLevel: 'write' as const,
    deviceCount: 1 as const,
    timeoutMs: 120_000,
    inputSchema: {
      name: { type: 'string', required: true, minLength: 1, description: 'Service name (e.g. "smb", "nfs", "sshd")' },
    },
    async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
      const name = str(input, 'name');
      if (!name) return { success: false, details: { error: 'Service name is required' } };

      const notes: string[] = [];
      // service.control is a JOB method — it resolves to the job id immediately.
      let jobId: number | null = null;
      try {
        // Transport-tolerant — a lost response is confirmed by re-reading service.started.
        const dr = await dispatchWrite(ctx, 'service.control', [verb, name], {
          verify: async () => {
            try {
              const running = await ctx.client.call<boolean>('service.started', [name], ctx.creds);
              return verb === 'STOP' ? !running : !!running; // in the target state — applied
            } catch {
              return null;
            }
          },
        });
        if (dr.note) notes.push(dr.note);
        const r = dr.value;
        if (typeof r === 'number') jobId = r;
        else if (r && typeof r === 'object' && typeof (r as Record<string, unknown>)['id'] === 'number') {
          jobId = (r as Record<string, unknown>)['id'] as number;
        }
      } catch (e) {
        // Already in the target state → treat as success (idempotent), like containers.stop.
        if (verb !== 'RESTART' && isServiceAlreadyInState(e, verb)) {
          return { success: true, applied: true, verified: false, details: { service: name, note: `already ${verb === 'START' ? 'running' : 'stopped'}` } };
        }
        // Unknown service on this appliance (MatchNotFound) — a clear failure.
        if (e instanceof TruenasRpcError && /not found|no such/i.test(e.message)) {
          return { success: false, details: { error: `Service "${name}" not found on this appliance` } };
        }
        throw e;
      }

      // Wait for the job to settle (budget = our timeout minus a safety margin).
      let waitState = 'UNKNOWN';
      if (jobId !== null) {
        const wait = await waitForJob(ctx, jobId, 90_000);
        waitState = wait.state;
        if (wait.state === 'RUNNING') {
          return { success: true, applied: true, details: { service: name, jobId, state: waitState, note: wait.error } };
        }
        if (wait.state !== 'SUCCESS' && wait.state !== 'FINISHED') {
          return { success: false, details: { service: name, jobId, state: waitState, error: wait.error ?? `Job ended in state ${waitState}` } };
        }
      }

      // Verify the resulting live state (service.started is a cheap read).
      let verified = false;
      try {
        const running = await ctx.client.call<boolean>('service.started', [name], ctx.creds);
        verified = verb === 'STOP' ? !running : !!running;
      } catch { /* verification best-effort — the job already settled */ }
      return { success: true, applied: true, verified, details: { service: name, jobId, state: waitState, ...(notes.length > 0 ? { notes } : {}) } };
    },
  };
}

const servicesStartAction = serviceControlAction('services.start', 'START', 'Start a service',
  'Starts ONE named middleware service (service.control START). Services already running are skipped, not failed.');
const servicesStopAction = serviceControlAction('services.stop', 'STOP', 'Stop a service',
  'Stops ONE named middleware service (service.control STOP). Services already stopped are skipped, not failed.');
const servicesRestartAction = serviceControlAction('services.restart', 'RESTART', 'Restart a service',
  'Restarts ONE named middleware service (service.control RESTART) — stop + start with config regeneration.');

// ---------------------------------------------------------------------------
// Canonical fleet intents — network.create / network.delete + l2.topology.read.
//
// A "network" on TrueNAS SCALE is a named interface object (interface.assign is
// an UPSERT keyed by name): for a VLAN it carries {type:'VLAN',
// vlan_parent_interface, vlan_tag}; L3 addresses are STATIC properties on the
// SAME interface ({ipv4_4_addr, ipv4_4_bits} / {ipv6_6_addr, ipv6_6_bits}).
// The network NAME is the idempotency key (like RouterOS's VLAN naming). An
// appliance that only needs to KNOW the VLAN (no IP) gets a VLAN-only interface;
// one that also serves it as a gateway/host adds the STATIC addresses.
// ---------------------------------------------------------------------------

/** Splits "a.b.c.d/p" into [ip, prefix]; null when malformed. */
function splitV4Cidr(cidr: string): { ip: string; bits: number } | null {
  const m = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(cidr.trim());
  if (!m) return null;
  const bits = Number(m[2]);
  if (bits < 8 || bits > 30) return null; // /31+/32 are point-to-point/broadcast — not a LAN address
  return { ip: m[1], bits };
}

/** Splits an IPv6 CIDR into [addr, prefix]; null when malformed. */
function splitV6Cidr(cidr: string): { addr: string; bits: number } | null {
  const m = /^([0-9a-fA-F:.]+)\/(\d{1,3})$/.exec(cidr.trim());
  if (!m) return null;
  const bits = Number(m[2]);
  if (bits < 8 || bits > 126) return null;
  return { addr: m[1], bits };
}

/** Reads all interfaces once (interface.query rows). */
async function queryInterfaces(ctx: TruenasActionContext): Promise<Record<string, unknown>[]> {
  const ifaces = await ctx.client.call<Record<string, unknown>[]>('interface.query', [], ctx.creds);
  return Array.isArray(ifaces) ? ifaces : [];
}

/** Finds an interface row by its name (case-sensitive — TrueNAS names are exact). */
function findInterfaceByName(ifaces: Record<string, unknown>[], name: string): Record<string, unknown> | undefined {
  return ifaces.find((i) => pickString(i, ['name']) === name);
}

/** Finds a VLAN interface by tag (any parent) — for reuse instead of re-creation. */
function findVlanByTag(ifaces: Record<string, unknown>[], vlanId: number): Record<string, unknown> | undefined {
  return ifaces.find((i) => pickString(i, ['type']) === 'VLAN' && pickNumber(i, ['vlan_tag']) === vlanId);
}

/** The v4/v6 addresses currently on one interface (from its aliases). */
function ifaceAddresses(iface: Record<string, unknown>): { v4?: string; v6?: string } {
  const out: { v4?: string; v6?: string } = {};
  const aliasesRaw = iface['aliases'];
  if (!Array.isArray(aliasesRaw)) return out;
  for (const a of aliasesRaw) {
    let alias: Record<string, unknown> | undefined;
    if (typeof a === 'string') { try { alias = JSON.parse(a) as Record<string, unknown>; } catch { continue; } }
    else if (a && typeof a === 'object') alias = a as Record<string, unknown>;
    if (!alias) continue;
    const ip = pickString(alias, ['address']);
    if (!ip) continue;
    if (pickString(alias, ['type']) === 'INET6') { if (!out.v6) out.v6 = `${ip}/${pickNumber(alias, ['netmask', 'prefixlen']) ?? 64}`; }
    else if (!out.v4) out.v4 = `${ip}/${pickNumber(alias, ['netmask', 'prefixlen']) ?? 24}`;
  }
  return out;
}

/** Builds the L2 topology from interface.query rows (physical NICs + bridges). */
async function readTruenasL2Topology(ctx: TruenasActionContext): Promise<L2Topology> {
  const ifaces = await queryInterfaces(ctx);
  const physicalPorts: Array<{ name: string; assignment: string | null }> = [];
  const bridges: Array<{ name: string; members: string[] }> = [];
  const l3Interfaces: Record<string, string[]> = {};
  for (const i of ifaces) {
    const name = pickString(i, ['name']);
    if (!name || /^lo\d*$/.test(name)) continue; // loopbacks are never attach points
    const type = pickString(i, ['type']) ?? '';
    const desc = pickString(i, ['description']) ?? '';
    const label = desc || name;
    if (type === 'BRIDGE') {
      const membersRaw = i['members'];
      const members = Array.isArray(membersRaw) ? membersRaw.map((m) => String(m)).filter(Boolean) : [];
      bridges.push({ name, members });
    } else if (type === 'PHYSICAL' || type === '') {
      physicalPorts.push({ name, assignment: label });
    }
    const addrs = ifaceAddresses(i);
    if (addrs.v4 || addrs.v6) l3Interfaces[name] = [label];
  }
  return { physicalPorts, bridges, bundles: [], l3Interfaces };
}

/** Picks the parent interface for a new VLAN — explicit `interface` wins when it exists. */
function pickVlanParent(topo: L2Topology, preferred?: string): string | null {
  if (preferred) {
    const known = topo.physicalPorts.some((p) => p.name === preferred || p.assignment === preferred)
      || topo.bridges.some((b) => b.name === preferred);
    if (known) return preferred;
  }
  // Prefer a bridge that carries L3 networks (the appliance's LAN domain), else the first physical NIC.
  for (const b of topo.bridges) {
    const nets = [...new Set([b.name, ...b.members].flatMap((ifc) => topo.l3Interfaces?.[ifc] ?? []))];
    if (nets.length > 0) return b.name;
  }
  for (const b of topo.bridges) if (b.members.length > 0) return b.name;
  const first = topo.physicalPorts.find((p) => p.name);
  return first?.name ?? null;
}

/** network.create — ensure a named VLAN interface (+ optional STATIC addresses). */
const networkCreateAction: ActionDescriptor<TruenasActionContext> = {
  id: INTENT_NETWORK_CREATE,
  label: 'Create network (VLAN + optional L3 address)',
  description:
    'Creates a named VLAN interface on the appliance (interface.assign upsert) and optionally binds static IPv4/IPv6 addresses to it. Idempotent by name — an existing interface with the same name is reused; missing addresses are added, present ones left untouched.',
  module: 'Network',
  riskLevel: 'write' as const,
  // Canonical fleet intent — FANS OUT across the batch (one step per appliance).
  deviceCount: 'N' as const,
  timeoutMs: 90_000,
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, maxLength: 64, description: 'Network name — becomes the interface name (idempotency key)' },
    vlanId: { type: 'number', min: 1, max: 4094, description: 'VLAN ID — a VLAN interface is created/attached on the parent. Omit for an L3-only network on an existing interface.' },
    cidr: { type: 'string', pattern: '^\\d{1,3}(\\.\\d{1,3}){3}/\\d{1,2}$', description: 'Optional static IPv4 address as CIDR (e.g. 10.42.0.1/24) — omit when the appliance only needs to know the VLAN' },
    cidrV6: { type: 'string', pattern: '^[0-9a-fA-F:.]*:[0-9a-fA-F:.]*/\\d{1,3}$', description: 'Optional static IPv6 address as CIDR (dual-stack when set alongside cidr)' },
    interface: { type: 'string', maxLength: 64, description: 'Parent interface for the VLAN (physical NIC or bridge) — resolved per device in preflight' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const name = str(input, 'name')?.trim();
    if (!name) return { success: false, details: { error: 'Network name is required' } };
    const vlanId = typeof input.vlanId === 'number' ? Math.floor(input.vlanId as number) : null;
    const v4 = typeof input.cidr === 'string' && input.cidr.trim() ? splitV4Cidr(String(input.cidr)) : null;
    if (typeof input.cidr === 'string' && input.cidr.trim() && !v4) return { success: false, details: { error: `Invalid IPv4 CIDR "${input.cidr}"` } };
    const v6 = typeof input.cidrV6 === 'string' && input.cidrV6.trim() ? splitV6Cidr(String(input.cidrV6)) : null;
    if (typeof input.cidrV6 === 'string' && input.cidrV6.trim() && !v6) return { success: false, details: { error: `Invalid IPv6 CIDR "${input.cidrV6}"` } };

    const topo = await readTruenasL2Topology(ctx);
    let ifaces = await queryInterfaces(ctx);
    const existing = findInterfaceByName(ifaces, name);
    const details: Record<string, unknown> = {};

    // interface.assign is an UPSERT that replaces the interface's FULL property
    // set — so every assign below carries BOTH the VLAN identity (when this is a
    // VLAN) AND the STATIC addresses. Sending only one kind would strip the other.
    const vlanProps: Record<string, unknown> = {};
    if (vlanId !== null) {
      if (existing && pickString(existing, ['type']) === 'VLAN' && pickNumber(existing, ['vlan_tag']) === vlanId) {
        Object.assign(vlanProps, { type: 'VLAN', vlan_parent_interface: existing['vlan_parent_interface'], vlan_tag: vlanId });
        details.vlan = `reused existing VLAN interface ${name} (tag ${vlanId})`;
      } else if (existing) {
        return { success: false, details: { error: `Interface "${name}" already exists but is not a VLAN with tag ${vlanId} — refusing to overwrite it` } };
      } else {
        const parent = pickVlanParent(topo, str(input, 'interface')?.trim());
        if (!parent) return { success: false, details: { error: 'No parent interface found for the VLAN — set `interface` explicitly' } };
        Object.assign(vlanProps, { type: 'VLAN', vlan_parent_interface: parent, vlan_tag: vlanId });
      }
    } else if (!existing) {
      // L3-only: the target must be an EXISTING interface (we never create a bare NIC).
      return { success: false, details: { error: `No VLAN requested and no interface named "${name}" exists — L3-only networks need an existing interface` } };
    }

    // The desired STATIC properties (empty = this appliance only knows the VLAN).
    const staticProps: Record<string, unknown> = {};
    if (v4) Object.assign(staticProps, { ipv4_4_addr: v4.ip, ipv4_4_bits: v4.bits });
    if (v6) Object.assign(staticProps, { ipv6_6_addr: v6.addr, ipv6_6_bits: v6.bits });

    // Current addresses on the target — decide whether a write is needed at all.
    const cur = ifaceAddresses(existing ?? {});
    const wantV4 = v4 ? `${v4.ip}/${v4.bits}` : null;
    const wantV6 = v6 ? `${v6.addr}/${v6.bits}` : null;
    const vlanChanged = !existing || (vlanId !== null && !(pickString(existing, ['type']) === 'VLAN' && pickNumber(existing, ['vlan_tag']) === vlanId));
    const addrsChanged = (wantV4 !== null && cur.v4 !== wantV4) || (wantV6 !== null && cur.v6 !== wantV6);

    if (!vlanChanged && !addrsChanged) {
      return { success: true, applied: false, verified: true, details: { skipped: `interface "${name}" already matches the requested network`, ...details } };
    }

    // One assign with the complete property set (VLAN identity + STATIC addrs).
    const properties: Record<string, unknown> = { ...vlanProps, ...(Object.keys(staticProps).length > 0 ? staticProps : {}) };
    if (Object.keys(properties).length === 0) return { success: false, details: { error: 'Nothing to write — no VLAN and no addresses requested' } };
    await dispatchWrite(ctx, 'interface.assign', [{ name, properties }], { verify: async () => {
      const i = findInterfaceByName(await queryInterfaces(ctx), name);
      if (!i) return false;
      if (vlanId !== null && !(pickString(i, ['type']) === 'VLAN' && pickNumber(i, ['vlan_tag']) === vlanId)) return false;
      const a = ifaceAddresses(i);
      if (wantV4 && a.v4 !== wantV4) return false;
      if (wantV6 && a.v6 !== wantV6) return false;
      return true;
    } });

    // Verify by re-read.
    const finalIfaces = await queryInterfaces(ctx);
    const finalAddrs = ifaceAddresses(findInterfaceByName(finalIfaces, name) ?? {});
    if (wantV4 && finalAddrs.v4 !== wantV4) return { success: false, details: { error: `Verification failed — ${wantV4} not present on ${name} after write` } };
    if (wantV6 && finalAddrs.v6 !== wantV6) return { success: false, details: { error: `Verification failed — ${wantV6} not present on ${name} after write` } };

    const assigned = [wantV4, wantV6].filter((x): x is string => !!x);
    return { success: true, applied: true, verified: true, details: { interface: name, addresses: assigned, ...details } };
  },
};

/** network.delete — remove the named interface (VLAN + its addresses go with it). */
const networkDeleteAction: ActionDescriptor<TruenasActionContext> = {
  id: INTENT_NETWORK_DELETE,
  label: 'Delete network',
  description: 'Removes the named VLAN/interface from the appliance (interface.delete) — its static addresses are removed with it. Idempotent: a missing name is a no-op.',
  module: 'Network',
  riskLevel: 'write' as const,
  // Canonical fleet intent — FANS OUT across the batch (one step per appliance).
  deviceCount: 'N' as const,
  timeoutMs: 60_000,
  inputSchema: { name: { type: 'string', required: true, minLength: 1, maxLength: 64, description: 'Network (interface) name to remove' } },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const name = str(input, 'name')?.trim();
    if (!name) return { success: false, details: { error: 'Network name is required' } };

    const ifaces = await queryInterfaces(ctx);
    const existing = findInterfaceByName(ifaces, name);
    if (!existing) return { success: true, applied: false, verified: true, details: { skipped: `no interface named "${name}" on this appliance` } };

    // Never delete the management interface — that would lock UNM out. The API's
    // own address is not in scope here; a user deleting it by name gets a clear
    // appliance-side error (in-use) rather than a silent lockout.
    await dispatchWrite(ctx, 'interface.delete', [name], { verify: async () => !findInterfaceByName(await queryInterfaces(ctx), name) });

    const after = await queryInterfaces(ctx);
    if (findInterfaceByName(after, name)) return { success: false, details: { error: `Verification failed — interface ${name} still present after delete` } };
    return { success: true, applied: true, verified: true, details: { removed: name, type: pickString(existing, ['type']) ?? 'unknown' } };
  },
};

/** l2.topology.read — the appliance's L2 hierarchy (physical NICs + bridges). */
const l2TopologyReadAction: ActionDescriptor<TruenasActionContext> = {
  id: INTENT_L2_TOPOLOGY_READ,
  label: 'Read L2 topology',
  description: 'Physical interfaces and bridge groups from interface.query — the attach-point source for network.create preflight.',
  module: 'Network',
  riskLevel: 'read' as const,
  deviceCount: 1 as const,
  inputSchema: {},
  async execute(ctx: TruenasActionContext): Promise<ActionResult> {
    const topo = await readTruenasL2Topology(ctx);
    return { success: true, details: { topology: topo } };
  },
};

/** Preflight resolver for network.create — suggests the VLAN parent + reuse hints. */
export async function preflightNetworkCreate(ctx: TruenasActionContext, inputs: Record<string, unknown>): Promise<PreflightResult> {
  const values: Array<{ key: string; value: unknown; confidence: 'high' | 'medium' | 'low'; note?: string }> = [];
  try {
    const ifaces = await queryInterfaces(ctx);
    const topo = await readTruenasL2Topology(ctx);
    const name = str(inputs, 'name')?.trim();
    const vlanId = typeof inputs.vlanId === 'number' ? Math.floor(inputs.vlanId as number) : null;

    if (vlanId !== null) {
      const parent = pickVlanParent(topo, str(inputs, 'interface')?.trim());
      if (parent) values.push({ key: 'interface', value: parent, confidence: 'medium', note: `new VLAN ${vlanId} would be created on ${parent}` });
      const byTag = findVlanByTag(ifaces, vlanId);
      if (byTag) {
        const tName = pickString(byTag, ['name']);
        values.push({ key: 'interface', value: tName ?? parent ?? '', confidence: 'high', note: `VLAN ${vlanId} already exists as "${tName}" — it will be reused` });
      }
    }
    if (name && findInterfaceByName(ifaces, name)) {
      values.push({ key: 'name', value: name, confidence: 'high', note: `interface "${name}" already exists — the step will be a no-op / address top-up only` });
    }

    // Platform note — TrueNAS VLANs ride their parent NIC/LAGG; there is no per-port concept.
    if (vlanId !== null) {
      const last = [...values].reverse().find((v) => v.key === 'interface');
      if (last?.note) last.note += ' · The VLAN is created on the selected parent interface — choose NIC/LAGG in “interface”; per-port selection is not available';
    }
  } catch (e) {
    return { deviceId: ctx.deviceId ?? '', values, degraded: true, error: e instanceof Error ? e.message : String(e) };
  }
  return { deviceId: ctx.deviceId ?? '', values, capabilities: { vlanPorts: false } };
}

export const PREFLIGHT_RESOLVERS: Record<string, (ctx: TruenasActionContext, inputs: Record<string, unknown>) => Promise<PreflightResult>> = {
  [INTENT_NETWORK_CREATE]: preflightNetworkCreate,
};

export const registry = createRegistry<TruenasActionContext>([
  systemInfoAction,
  poolsReadAction,
  interfacesReadAction,
  networkCreateAction,
  networkDeleteAction,
  l2TopologyReadAction,
  systemRebootAction,
  systemTimezoneReadAction,
  systemTimezoneSetAction,
  systemClockSyncAction,
  systemShutdownAction,
  systemFirmwareUpdateAction,
  configBackupDownloadAction,
  configRestoreAction,
  configResetAction,
  updateProfileReadAction,
  updateProfileSetAction,
  firmwareUpdateFileAction,
  bootEnvReadAction,
  bootEnvActivateAction,
  bootEnvDestroyAction,
  bootEnvKeepAction,
  alertsDismissAction,
  alertsUndismissAction,
  containersStopAction,
  containersStartAction,
  containersRestartAction,
  containersUpgradeAction,
  containersDeleteAction,
  vmsStartAction,
  vmsStopAction,
  vmsKillAction,
  vmsRestartAction,
  vmsSuspendAction,
  vmsResumeAction,
  vmsDeleteAction,
  vmsNicChoicesAction,
  vmsNicAttachAction,
  vmsNicDetachAction,
  vmsCreateChoicesAction,
  vmsCreateAction,
  vmsIsoUploadAction,
  vmsIsoChoicesAction,
  vmsCdromAttachAction,
  vmsDeviceDetachAction,
  vmsDeviceUpdateAction,
  vmsDeviceGetAction,
  vmsVmEditSchemaAction,
  vmsVmGetAction,
  vmsVmUpdateAction,
  vmsSerialConsolesAction,
  vmsDeviceTypesAction,
  vmsDiskChoicesAction,
  vmsPciChoicesAction,
  vmsUsbChoicesAction,
  vmsDiskAttachAction,
  vmsDisplayAttachAction,
  vmsPciAttachAction,
  vmsUsbAttachAction,
  storageScrubAction,
  storageBootScrubAction,
  storageSnapshotAction,
  storageQuotaSetAction,
  storageMountAction,
  storageUnmountAction,
  storageDeleteAction,
  smbShareCreateAction,
  smbShareUpdateAction,
  smbShareDeleteAction,
  nfsShareCreateAction,
  nfsShareUpdateAction,
  nfsShareDeleteAction,
  iscsiTargetCreateAction,
  iscsiTargetDeleteAction,
  nvmeofSubsystemCreateAction,
  nvmeofSubsystemDeleteAction,
  imagesPullAction,
  imagesUpdateAction,
  imagesPruneAction,
  imagesDeleteAction,
  composeConfigReadAction,
  containersLogsReadAction,
  containersUpdateAction,
  catalogTemplatesListAction,
  templateDetailsReadAction,
  containersInstallAction,
  servicesStartAction,
  servicesStopAction,
  servicesRestartAction,
]);
