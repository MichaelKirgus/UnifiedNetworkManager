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

import { ActionDescriptor, ActionResult, compareVersions, configBackupFileName, createFileRepoClient, createRegistry, dynamicSshHostVerifier, FileRepoClient, pickNumber, pickString, pollUntil, resolveSshCredentials, SshError } from '@unm/plugin-sdk';
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
    await ctx.client.call<unknown>('system.general.update', [{ timezone: tz }], ctx.creds);
    return { success: true, applied: true, details: { timezone: tz } };
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
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const version = str(input, 'version');
    const train = str(input, 'train');

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

    const options: Record<string, unknown> = {};
    if (train) options['train'] = train;
    if (version) options['version'] = version;

    try {
      const result = await ctx.client.call<unknown>('update.run', [options], ctx.creds);
      return { success: true, applied: true, details: describeJobResult(result) };
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
      const updated = await ctx.client.call<Record<string, unknown>>('update.update', [{ profile }], ctx.creds);
      return { success: true, applied: true, details: { profile: pickString(updated, ['profile']) ?? profile, note: 'Update branch changed — future updates now target this track. No reboot required.' } };
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
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const path = str(input, 'path');
    const b64 = typeof input['fileBase64'] === 'string' && (input['fileBase64'] as string).length > 0 ? (input['fileBase64'] as string) : undefined;
    if (!path && !b64) return { success: false, details: { error: 'Either path (a file already on the appliance) or fileBase64 (uploaded content) is required' } };

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

    try {
      if (path) {
        // File already lives on the appliance → update.manual job.
        const r = await runUpdateJobWithResume(ctx, async () => jobIdOf(await ctx.client.call<unknown>('update.manual', [{ path }])), 'update.manual', [{ path, resume: true }], 3_600_000);
        if (r.state === 'RUNNING') return { success: true, applied: true, details: { jobId: r.jobId, note: 'Update job still in progress on the appliance — it will reboot into the new boot environment.' } };
        if (r.state !== 'SUCCESS' && r.state !== 'FINISHED') return { success: false, details: { jobId: r.jobId, error: r.error ?? `Job ended in state ${r.state}` } };
        return { success: true, applied: true, details: describeJobResult(r.jobId) };
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

      const r = await runUpdateJobWithResume(ctx, startUpload, 'update.file', [{ resume: true }], 3_600_000);
      if (r.state === 'RUNNING') return { success: true, applied: true, details: { jobId: r.jobId, note: 'Update job still in progress on the appliance — it will reboot into the new boot environment.' } };
      if (r.state !== 'SUCCESS' && r.state !== 'FINISHED') return { success: false, details: { jobId: r.jobId, error: r.error ?? `Job ended in state ${r.state}` } };
      return { success: true, applied: true, details: { jobId: r.jobId, fileName: payload.fileName, note: 'Update installed — the appliance is rebooting into the new boot environment. Unreachable while down; verification is impossible by design.' } };
    } catch (e) {
      // The socket dies when the appliance reboots into the new BE — EXPECTED.
      if (e instanceof TruenasRpcError && /timed out|closed|unresponsive/i.test(e.message)) {
        return { success: true, applied: true, details: { note: 'Update initiated — connection lost as expected while the appliance rebooted.' } };
      }
      throw e;
    }
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
    const missing: string[] = [];
    for (const k of keys) {
      const uuids = byKey.get(k);
      if (!uuids || uuids.length === 0) {
        missing.push(k); // already gone or already dismissed — nothing to do
        continue;
      }
      for (const uuid of uuids) {
        try {
          await ctx.client.call('alert.dismiss', [uuid], ctx.creds);
          dismissed++;
        } catch (e) {
          if (!(e instanceof TruenasRpcError)) throw e; // transport error — surface it
          // Method error = alert vanished or was dismissed in the meantime.
        }
      }
    }
    return { success: true, details: { dismissed, missing } };
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
    const missing: string[] = [];
    for (const k of keys) {
      const uuids = byKey.get(k);
      if (!uuids || uuids.length === 0) {
        missing.push(k); // never dismissed or already gone — nothing to do
        continue;
      }
      for (const uuid of uuids) {
        try {
          await ctx.client.call('alert.undismiss', [uuid], ctx.creds);
          undismissed++;
        } catch (e) {
          if (!(e instanceof TruenasRpcError)) throw e; // transport error — surface it
          // Method error = alert vanished or was re-enabled in the meantime.
        }
      }
    }
    return { success: true, details: { undismissed, missing } };
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
    if (!(e instanceof TruenasRpcError) || !/timed out/i.test(e.message)) throw e;
    return await ctx.client.call<T>(method, params, ctx.creds, 15_000);
  }
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
    const errors: Record<string, string> = {};
    for (const n of toRun) {
      try {
        await ctx.client.call('app.stop', [n], ctx.creds);
        stopped++;
      } catch (e) {
        if (isAlreadyInState(e)) skipped[n] = 'already stopped';
        else errors[n] = e instanceof Error ? e.message : String(e);
      }
    }
    // Verify: app.stop is a server-side job — every driven app must actually
    // reach STOPPED for this step to count as verified.
    const verified = Object.keys(errors).length === 0 && (await verifyAppStates(ctx, toRun, new Set(['STOPPED'])));
    return { success: Object.keys(errors).length === 0, applied: true, verified, details: { stopped, skipped, missing, ...(Object.keys(errors).length ? { errors } : {}) } };
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
    const errors: Record<string, string> = {};
    for (const n of toRun) {
      try {
        await ctx.client.call('app.start', [n], ctx.creds);
        started++;
      } catch (e) {
        if (isAlreadyInState(e)) skipped[n] = 'already running';
        else errors[n] = e instanceof Error ? e.message : String(e);
      }
    }
    // Verify: every driven app must actually reach RUNNING.
    const verified = Object.keys(errors).length === 0 && (await verifyAppStates(ctx, toRun, new Set(['RUNNING'])));
    return { success: Object.keys(errors).length === 0, applied: true, verified, details: { started, skipped, missing, ...(Object.keys(errors).length ? { errors } : {}) } };
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
    const missing: string[] = [];
    const errors: Record<string, string> = {};
    for (const n of names) {
      const app = byName.get(n);
      if (!app) {
        missing.push(n); // already gone — nothing to do
        continue;
      }
      try {
        // Stop first unless it is not running, then start.
        if (normState(app.state) !== 'STOPPED') {
          await ctx.client.call('app.stop', [n], ctx.creds);
        }
        await ctx.client.call('app.start', [n], ctx.creds);
        restarted++;
      } catch (e) {
        errors[n] = e instanceof Error ? e.message : String(e);
      }
    }
    // Verify: a restart is only done when every driven app is RUNNING again.
    const verified = Object.keys(errors).length === 0 && (await verifyAppStates(ctx, names.filter((n) => byName.has(n)), new Set(['RUNNING'])));
    return { success: Object.keys(errors).length === 0, applied: true, verified, details: { restarted, missing, ...(Object.keys(errors).length ? { errors } : {}) } };
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
        await ctx.client.call('app.upgrade', [n, { app_version: 'latest' }], ctx.creds);
        upgraded++;
      } catch (e) {
        errors[n] = e instanceof Error ? e.message : String(e);
      }
    }
    // Verify: an upgrade redeploys the app server-side — every driven app must
    // settle back into a stable state (RUNNING or STOPPED), not stay DEPLOYING.
    const upgradedNames = names.filter((n) => byName.has(n) && !skipped[n]);
    const verified = Object.keys(errors).length === 0 && (await verifyAppStates(ctx, upgradedNames, new Set(['RUNNING', 'STOPPED'])));
    return { success: Object.keys(errors).length === 0, applied: true, verified, details: { upgraded, skipped, missing, ...(Object.keys(errors).length ? { errors } : {}) } };
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
    const missing: string[] = [];
    const errors: Record<string, string> = {};
    for (const n of names) {
      if (!byName.has(n)) {
        missing.push(n); // already gone — nothing to do
        continue;
      }
      try {
        await ctx.client.call('app.delete', [n, { remove_images: true, force_remove_custom_app: true }], ctx.creds);
        deleted++;
      } catch (e) {
        errors[n] = e instanceof Error ? e.message : String(e);
      }
    }
    // Verify: every driven app must be gone from app.query.
    const verified = Object.keys(errors).length === 0 && (await verifyAppStates(ctx, names.filter((n) => byName.has(n)), new Set(['gone'])));
    return { success: Object.keys(errors).length === 0, applied: true, verified, details: { deleted, missing, ...(Object.keys(errors).length ? { errors } : {}) } };
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
    const errors: Record<string, string> = {};
    for (const vm of toRun) {
      try {
        await ctx.client.call('vm.start', [vm.id], ctx.creds);
        started++;
      } catch (e) {
        if (isAlreadyInState(e)) skipped[vm.name] = 'already running';
        else errors[vm.name] = e instanceof Error ? e.message : String(e);
      }
    }
    // Verify: every driven VM must actually reach RUNNING.
    const verified = Object.keys(errors).length === 0 && (await verifyVmStates(ctx, toRun.map((v) => v.name), new Set(['RUNNING'])));
    return { success: Object.keys(errors).length === 0, applied: true, verified, details: { started, skipped, missing, ...(Object.keys(errors).length ? { errors } : {}) } };
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
    const notes: Record<string, string> = {};
    const errors: Record<string, string> = {};
    for (const vm of toRun) {
      try {
        // vm.stop is a JOB method — the ACPI powerdown runs server-side and the
        // job settles when the guest acks or its shutdown timeout elapses. Wait
        // with a bounded budget so an unresponsive guest surfaces as a per-VM
        // error (the user can then Kill it) instead of a silent "accepted".
        const r = await ctx.client.call<unknown>('vm.stop', [vm.id], ctx.creds);
        const job = describeAccepted(r);
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
    const verified = Object.keys(errors).length === 0 && (await verifyVmStates(ctx, toRun.map((v) => v.name), new Set(['STOPPED'])));
    return { success: Object.keys(errors).length === 0, applied: true, verified, details: { stopped, skipped, missing, ...(Object.keys(notes).length ? { notes } : {}), ...(Object.keys(errors).length ? { errors } : {}) } };
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
    const errors: Record<string, string> = {};
    for (const vm of toRun) {
      try {
        await ctx.client.call('vm.poweroff', [vm.id], ctx.creds);
        killed++;
      } catch (e) {
        if (isAlreadyInState(e)) skipped[vm.name] = 'already stopped';
        else errors[vm.name] = e instanceof Error ? e.message : String(e);
      }
    }
    // Verify: a hard kill must leave every driven VM STOPPED.
    const verified = Object.keys(errors).length === 0 && (await verifyVmStates(ctx, toRun.map((v) => v.name), new Set(['STOPPED'])));
    return { success: Object.keys(errors).length === 0, applied: true, verified, details: { killed, skipped, missing, ...(Object.keys(errors).length ? { errors } : {}) } };
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
          await ctx.client.call('vm.start', [vm.id], ctx.creds);
        } else {
          const r = await ctx.client.call<unknown>('vm.restart', [vm.id], ctx.creds);
          const job = describeAccepted(r);
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
    const verified = Object.keys(errors).length === 0 && (await verifyVmStates(ctx, names.filter((n) => byName.has(n)), new Set(['RUNNING'])));
    return { success: Object.keys(errors).length === 0, applied: true, verified, details: { restarted, missing, ...(Object.keys(notes).length ? { notes } : {}), ...(Object.keys(errors).length ? { errors } : {}) } };
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
    const errors: Record<string, string> = {};
    for (const vm of toRun) {
      if (vm.state !== 'RUNNING') {
        skipped[vm.name] = `not running (${vm.state.toLowerCase()})`;
        continue;
      }
      try {
        await ctx.client.call('vm.suspend', [vm.id], ctx.creds);
        suspended++;
      } catch (e) {
        if (isAlreadyInState(e)) skipped[vm.name] = 'already suspended';
        else errors[vm.name] = e instanceof Error ? e.message : String(e);
      }
    }
    // Verify: every driven VM must actually be SUSPENDED.
    const verified = Object.keys(errors).length === 0 && (await verifyVmStates(ctx, toRun.map((v) => v.name), new Set(['SUSPENDED'])));
    return { success: Object.keys(errors).length === 0, applied: true, verified, details: { suspended, skipped, missing, ...(Object.keys(errors).length ? { errors } : {}) } };
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
    const skipped: Record<string, string> = {};
    const missing: string[] = [];
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
        await ctx.client.call('vm.resume', [vm.id], ctx.creds);
        resumed++;
      } catch (e) {
        if (isAlreadyInState(e)) skipped[n] = 'already running';
        else errors[n] = e instanceof Error ? e.message : String(e);
      }
    }
    // Verify: every driven VM must actually be RUNNING again.
    const verified = Object.keys(errors).length === 0 && (await verifyVmStates(ctx, names.filter((n) => byName.has(n)), new Set(['RUNNING'])));
    return { success: Object.keys(errors).length === 0, applied: true, verified, details: { resumed, skipped, missing, ...(Object.keys(errors).length ? { errors } : {}) } };
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
          const r = await ctx.client.call<unknown>('vm.stop', [vm.id], ctx.creds);
          const job = describeAccepted(r);
          if (typeof job['jobId'] === 'number') {
            const wait = await waitForJob(ctx, job['jobId'], 150_000);
            if (wait.state !== 'RUNNING' && wait.state !== 'SUCCESS' && wait.state !== 'FINISHED') {
              errors[n] = `Could not stop before delete: ${wait.error ?? `stop job ended in state ${wait.state}`}`;
              continue;
            }
          }
        }
        await ctx.client.call('vm.delete', [vm.id, removeStorage ? { zvols: true } : {}], ctx.creds);
        deleted++;
      } catch (e) {
        errors[n] = e instanceof Error ? e.message : String(e);
      }
    }
    // Verify: every driven VM must be gone from vm.query.
    const verified = Object.keys(errors).length === 0 && (await verifyVmStates(ctx, names.filter((n) => byName.has(n)), new Set(['gone'])));
    return { success: Object.keys(errors).length === 0, applied: true, verified, details: { deleted, missing, removeStorage, ...(Object.keys(errors).length ? { errors } : {}) } };
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
      await ctx.client.call('vm.device.create', [vmDeviceCreateArg(v26, vm.id, attributes)], ctx.creds, 30_000);
      // Verify by re-reading the VM's devices. When a MAC was requested it must
      // appear; when omitted the appliance assigns one — then we confirm the NIC
      // count grew instead (the new device is dtype NIC on nicAttach).
      let verified = false;
      if (mac) {
        verified = await verifyVmNic(ctx, name, mac, true);
      } else {
        const beforeCount = vm.devices.filter((d) => normalizeVmDevice(d)?.dtype === 'NIC').length;
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
          { timeoutMs: 30_000, intervalMs: 2_000 },
        );
        verified = wait.ok;
      }
      return { success: true, applied: true, verified, details: { name, nicAttach, type, ...(mac ? { mac } : {}) } };
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
      await ctx.client.call('vm.device.delete', [deviceId, force ? { force: true } : {}], ctx.creds);
      // Verify by re-reading the VM's devices — the NIC with this MAC must be gone.
      const verified = await verifyVmNic(ctx, name, mac, false);
      return { success: true, applied: true, verified, details: { name, mac: mac.toUpperCase(), deviceId } };
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
      const created = await ctx.client.call<Record<string, unknown>>('vm.create', [create], ctx.creds);
      vmId = typeof created?.['id'] === 'number' ? (created['id'] as number) : null;
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
      await ctx.client.call('vm.device.create', [vmDeviceCreateArg(v26, vmId, diskAttrs)], ctx.creds, 60_000);
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
        await ctx.client.call('vm.device.create', [vmDeviceCreateArg(v26, vmId, nicAttrs)], ctx.creds, 30_000);
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
      if (cdromId !== null) {
        // vm.device.update keeps the [id, {attributes}] shape on both API generations.
        await ctx.client.call('vm.device.update', [cdromId, { attributes: { dtype: 'CDROM', path } }], ctx.creds, 120_000);
      } else {
        // Observed live (KIRGUSBANDE, 26.0.0-BETA.2): vm.device.create for a CDROM takes
        // ~60s EVEN VIA THE WEB UI — the appliance-side work is just slow there, and the
        // Web UI only survives it because its WS session has no per-call timeout. Give
        // this call 120s of headroom; if it still times out we fall through to re-read.
        await ctx.client.call('vm.device.create', [vmDeviceCreateArg(v26, vm.id, { dtype: 'CDROM', path })], ctx.creds, 120_000);
      }
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      // A TIMEOUT does not mean the device wasn't created — the appliance may simply be
      // slow validating the ISO on a degraded pool. Fall through to re-read: if the CDROM
      // shows up, report success with a note; only fail when it's genuinely absent.
      if (/timed out/i.test(msg)) rpcError = msg;
      else return { success: false, details: { error: `${await poolHealthNote(ctx, path.replace(/^\/mnt\//, ''))}CD-ROM attach failed: ${msg}`.trim() } };
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

    try {
      await ctx.client.call('vm.device.delete', [deviceId, opts], ctx.creds);
    } catch (e) {
      return { success: false, details: { error: e instanceof Error ? e.message : String(e) } };
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
    return { success: true, applied: true, verified: wait.ok, details: { name, deviceId, removeStorage: input['removeStorage'] === true } };
  },
};

const vmsDeviceEditAction: ActionDescriptor<TruenasActionContext> = {
  id: 'vms.device-edit',
  label: 'Edit VM device attributes',
  description:
    'Updates ONE attached device\'s attributes in place (vm.device.update) — e.g. a NIC\'s bridge, a display\'s resolution/port, or a CD-ROM\'s ISO path. The full attribute set is replaced; include every field that must survive.',
  module: 'VMs',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 120_000,
  inputSchema: {
    deviceId: { type: 'number', required: true, min: 1, description: 'Integer device id from the VM inventory row' },
    dtype: { type: 'string', required: true, enum: ['NIC', 'DISK', 'CDROM', 'DISPLAY', 'PCI', 'USB'], description: 'Device type (must match the existing device)' },
    attributes: { type: 'object', required: true, properties: {}, description: 'Full replacement attribute set for the device (without dtype — it is added automatically)' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const deviceId = num(input, 'deviceId', -1);
    if (deviceId < 1) return { success: false, details: { error: 'deviceId (integer device id) is required' } };
    const dtype = strOr(input, 'dtype', '').toUpperCase();
    if (!dtype) return { success: false, details: { error: 'dtype is required' } };
    const attrsRaw = input['attributes'];
    if (!attrsRaw || typeof attrsRaw !== 'object' || Array.isArray(attrsRaw)) {
      return { success: false, details: { error: 'attributes (object) is required' } };
    }

    try {
      await ctx.client.call('vm.device.update', [deviceId, { attributes: { dtype, ...(attrsRaw as Record<string, unknown>) } }], ctx.creds);
    } catch (e) {
      return { success: false, details: { error: e instanceof Error ? e.message : String(e) } };
    }

    // Verify the device still exists after the update (attribute values are
    // normalized by the appliance — existence is the honest check here).
    let verified = false;
    try {
      const rows = await ctx.client.call<Record<string, unknown>[]>('vm.device.query', [[['id', '=', deviceId]]], ctx.creds);
      verified = (rows ?? []).length > 0;
    } catch { /* unverified */ }
    return { success: true, applied: true, verified, details: { deviceId, dtype } };
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
        await ctx.client.call('pool.scrub', [n], ctx.creds);
        started++;
      } catch (e) {
        if (/already|in progress/i.test(e instanceof Error ? e.message : String(e))) skipped[n] = 'scrub already in progress';
        else errors[n] = e instanceof Error ? e.message : String(e);
      }
    }
    return { success: Object.keys(errors).length === 0, applied: true, details: { started, skipped, missing, ...(Object.keys(errors).length ? { errors } : {}) } };
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
    const recursive = input['recursive'] === true;
    const retentionRaw = typeof input['retentionDays'] === 'number' ? (input['retentionDays'] as number) : undefined;

    // Timestamped snapshot name — sortable, and the `unm-` prefix marks it as
    // ours so the retention cleanup only ever touches snapshots we created.
    const ts = new Date().toISOString().replace(/[-:TZ]/g, '').slice(0, 14); // YYYYMMDDHHmmss
    const snapName = `${name}@unm-${ts}`;

    let jobId: number | null = null;
    try {
      const r = await ctx.client.call<unknown>('pool.snapshot.create', [{ dataset: name, snapshot_name: `unm-${ts}`, recursive }], ctx.creds);
      if (typeof r === 'number') jobId = r;
      else if (r && typeof r === 'object' && typeof (r as Record<string, unknown>)['id'] === 'number') jobId = (r as Record<string, unknown>)['id'] as number;
    } catch (e) {
      return { success: false, details: { error: e instanceof Error ? e.message : String(e), snapshot: snapName } };
    }

    // pool.snapshot.create is a JOB method — wait for it to settle so the
    // retention cleanup below sees the new snapshot.
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

    return { success: Object.keys(pruneErrors).length === 0, applied: true, details: { snapshot: snapName, pruned, ...(note ? { note } : {}), ...(Object.keys(pruneErrors).length ? { pruneErrors } : {}) } };
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
      await ctx.client.call('pool.dataset.update', [name, { quota }], ctx.creds);
      return { success: true, applied: true, details: { name, quota, note: quota === null ? 'Quota cleared' : `Quota set to ${quota} bytes` } };
    } catch (e) {
      return { success: false, details: { error: e instanceof Error ? e.message : String(e), name } };
    }
  },
};

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
    let mounted = 0;
    const skipped: Record<string, string> = {};
    const errors: Record<string, string> = {};
    for (const n of names) {
      try {
        await ctx.client.call('pool.dataset.mount', [n], ctx.creds);
        mounted++;
      } catch (e) {
        if (/already|mounted/i.test(e instanceof Error ? e.message : String(e))) skipped[n] = 'already mounted';
        else errors[n] = e instanceof Error ? e.message : String(e);
      }
    }
    return { success: Object.keys(errors).length === 0, applied: true, details: { mounted, skipped, ...(Object.keys(errors).length ? { errors } : {}) } };
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
    const force = input['force'] === true;
    let unmounted = 0;
    const skipped: Record<string, string> = {};
    const errors: Record<string, string> = {};
    for (const n of names) {
      try {
        await ctx.client.call('pool.dataset.unmount', [n, force ? { force: true } : {}], ctx.creds);
        unmounted++;
      } catch (e) {
        if (/not mounted|unmounted/i.test(e instanceof Error ? e.message : String(e))) skipped[n] = 'already unmounted';
        else errors[n] = e instanceof Error ? e.message : String(e);
      }
    }
    return { success: Object.keys(errors).length === 0, applied: true, details: { unmounted, force, skipped, ...(Object.keys(errors).length ? { errors } : {}) } };
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
    const recursive = input['recursive'] === true;
    const force = input['force'] === true;

    let deleted = 0;
    const errors: Record<string, string> = {};
    for (const n of names) {
      try {
        await ctx.client.call('pool.dataset.delete', [n, recursive || force ? { recursive, force } : {}], ctx.creds);
        deleted++;
      } catch (e) {
        errors[n] = e instanceof Error ? e.message : String(e);
      }
    }
    return { success: Object.keys(errors).length === 0, applied: true, details: { deleted, recursive, force, ...(Object.keys(errors).length ? { errors } : {}) } };
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
      await ctx.client.call('sharing.smb.create', [params], ctx.creds);
      return { success: true, applied: true, details: { name, path } };
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
      await ctx.client.call('sharing.smb.update', [found.id, params], ctx.creds);
      return { success: true, applied: true, details: { name } };
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
    const missing: string[] = [];
    const errors: Record<string, string> = {};
    for (const n of names) {
      const found = await findShareId(ctx, 'sharing.smb.query', n);
      if (!found) { missing.push(n); continue; } // already gone — idempotent skip
      try {
        await ctx.client.call('sharing.smb.delete', [found.id], ctx.creds);
        deleted++;
      } catch (e) {
        errors[n] = e instanceof Error ? e.message : String(e);
      }
    }
    return { success: Object.keys(errors).length === 0, applied: true, details: { deleted, missing, ...(Object.keys(errors).length ? { errors } : {}) } };
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
      await ctx.client.call('sharing.nfs.create', [params], ctx.creds);
      return { success: true, applied: true, details: { path } };
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
      await ctx.client.call('sharing.nfs.update', [found.id, params], ctx.creds);
      return { success: true, applied: true, details: { path } };
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
    const missing: string[] = [];
    const errors: Record<string, string> = {};
    for (const p of paths) {
      const found = await findShareId(ctx, 'sharing.nfs.query', undefined, p);
      if (!found) { missing.push(p); continue; } // already gone — idempotent skip
      try {
        await ctx.client.call('sharing.nfs.delete', [found.id], ctx.creds);
        deleted++;
      } catch (e) {
        errors[p] = e instanceof Error ? e.message : String(e);
      }
    }
    return { success: Object.keys(errors).length === 0, applied: true, details: { deleted, missing, ...(Object.keys(errors).length ? { errors } : {}) } };
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
      await ctx.client.call('iscsi.target.create', [{ name }], ctx.creds);
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
            await ctx.client.call('iscsi.extent.create', [{ name: extentName, type: 'FILE', path }], ctx.creds);
            extent = await findShareId(ctx, 'iscsi.extent.query', undefined, path) ?? (await findShareId(ctx, 'iscsi.extent.query', extentName));
          }
          if (!extent) return { success: true, applied: true, details: { name, note: `Target created but LUN could not be resolved for ${path}` } };
          await ctx.client.call('iscsi.targetextent.create', [{ target: target.id, extent: extent.id }], ctx.creds);
        } catch (e) {
          return { success: true, applied: true, details: { name, note: `Target created but LUN attach failed: ${e instanceof Error ? e.message : String(e)}` } };
        }
      }
      return { success: true, applied: true, details: { name, ...(path ? { path } : {}) } };
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
    const missing: string[] = [];
    const errors: Record<string, string> = {};
    for (const n of names) {
      const found = await findShareId(ctx, 'iscsi.target.query', n);
      if (!found) { missing.push(n); continue; } // already gone — idempotent skip
      try {
        await ctx.client.call('iscsi.target.delete', [found.id], ctx.creds);
        deleted++;
      } catch (e) {
        errors[n] = e instanceof Error ? e.message : String(e);
      }
    }
    return { success: Object.keys(errors).length === 0, applied: true, details: { deleted, missing, ...(Object.keys(errors).length ? { errors } : {}) } };
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
      await ctx.client.call('nvmet.subsys.create', [{ name }], ctx.creds);
      const path = inStr(input, 'path');
      if (path) {
        const found = await findShareId(ctx, 'nvmet.subsys.query', name);
        if (found) {
          try {
            // namespace.create requires subsys_id + device_type + device_path.
            // A dataset-backed namespace is a FILE-type namespace on its mountpoint.
            await ctx.client.call('nvmet.namespace.create', [{ subsys_id: found.id, device_type: 'FILE', device_path: path }], ctx.creds);
          } catch (e) {
            return { success: true, applied: true, details: { name, note: `Subsystem created but namespace attach failed: ${e instanceof Error ? e.message : String(e)}` } };
          }
        }
      }
      return { success: true, applied: true, details: { name, ...(path ? { path } : {}) } };
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
    const missing: string[] = [];
    const errors: Record<string, string> = {};
    for (const n of names) {
      const found = await findShareId(ctx, 'nvmet.subsys.query', n);
      if (!found) { missing.push(n); continue; } // already gone — idempotent skip
      try {
        await ctx.client.call('nvmet.subsys.delete', [found.id], ctx.creds);
        deleted++;
      } catch (e) {
        errors[n] = e instanceof Error ? e.message : String(e);
      }
    }
    return { success: Object.keys(errors).length === 0, applied: true, details: { deleted, missing, ...(Object.keys(errors).length ? { errors } : {}) } };
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
        await ctx.client.call('app.image.delete', [target, { force: false }], ctx.creds);
        deleted++;
      } catch (e) {
        errors[ref] = e instanceof Error ? e.message : String(e);
      }
    }
    return { success: Object.keys(errors).length === 0, applied: true, details: { deleted, missing, ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

/**
 * Re-pull docker images (TrueNAS `app.image.pull` job — one per image ref).
 * Used by the Updates page for local images whose upstream tag moved (the
 * appliance flags them via app.image.query's update_available). Pulling is a
 * no-op when the digest already matches, so re-running is safe. Verification:
 * after all pulls settle, re-query app.image.query — an image that still shows
 * update_available=true did not actually change.
 */
const imagesUpdateAction: ActionDescriptor<TruenasActionContext> = {
  id: 'images.update',
  label: 'Pull updated image(s)',
  description:
    'Re-pulls the selected docker images from their registries (app.image.pull, one job per image). Safe to re-run — a pull is a no-op when the local digest already matches upstream.',
  module: 'Containers',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 900_000, // large image pulls dominate — give the plan executor a 15-min budget
  inputSchema: {
    images: { type: 'array', required: true, items: { type: 'string', minLength: 2 }, description: 'Image references to pull (registry/repository:tag)' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const refs = strArray(input, 'images');
    if (refs.length === 0) return { success: false, details: { error: 'No image references provided' } };

    // Known images up front — a ref that is not in the local store at all is
    // reported as missing instead of failing the whole step.
    const rows = await callWithRetry<Record<string, unknown>[]>(ctx, 'app.image.query', []);
    const knownRefs = new Set<string>();
    for (const r of rows ?? []) {
      for (const t of Array.isArray(r['repo_tags']) ? (r['repo_tags'] as unknown[]) : []) {
        if (typeof t === 'string' && t.length > 0) knownRefs.add(t);
      }
    }

    let pulled = 0;
    const missing: string[] = [];
    const errors: Record<string, string> = {};
    for (const ref of refs) {
      if (!knownRefs.has(ref)) {
        missing.push(ref); // not in the local store — nothing to update
        continue;
      }
      try {
        // app.image.pull is a JOB method — it returns the job id immediately.
        const r = await ctx.client.call<unknown>('app.image.pull', [{ image: ref }], ctx.creds);
        let jobId: number | undefined;
        if (typeof r === 'number') jobId = r;
        else if (r && typeof r === 'object' && typeof (r as Record<string, unknown>)['id'] === 'number') jobId = (r as Record<string, unknown>)['id'] as number;
        if (jobId !== undefined) {
          const wait = await waitForJob(ctx, jobId, 840_000);
          if (wait.state !== 'SUCCESS' && wait.state !== 'FINISHED') {
            errors[ref] = wait.error ?? `Pull job ended in state ${wait.state}`;
            continue;
          }
        }
        pulled++;
      } catch (e) {
        errors[ref] = e instanceof Error ? e.message : String(e);
      }
    }

    // Verify: re-query the image store — a successfully pulled image must no
    // longer be flagged update_available.
    let verified: boolean | undefined;
    if (Object.keys(errors).length === 0 && pulled > 0) {
      try {
        const after = await callWithRetry<Record<string, unknown>[]>(ctx, 'app.image.query', []);
        const stillStale = new Set<string>();
        for (const r of after ?? []) {
          if (r['update_available'] !== true) continue;
          for (const t of Array.isArray(r['repo_tags']) ? (r['repo_tags'] as unknown[]) : []) {
            if (typeof t === 'string') stillStale.add(t);
          }
        }
        verified = refs.every((ref) => !stillStale.has(ref));
      } catch { /* verification is best-effort — the pulls themselves succeeded */ }
    }

    return { success: Object.keys(errors).length === 0, applied: true, verified, details: { pulled, missing, ...(Object.keys(errors).length ? { errors } : {}) } };
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

      // service.control is a JOB method — it resolves to the job id immediately.
      let jobId: number | null = null;
      try {
        const r = await ctx.client.call<unknown>('service.control', [verb, name], ctx.creds);
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
      return { success: true, applied: true, verified, details: { service: name, jobId, state: waitState } };
    },
  };
}

const servicesStartAction = serviceControlAction('services.start', 'START', 'Start a service',
  'Starts ONE named middleware service (service.control START). Services already running are skipped, not failed.');
const servicesStopAction = serviceControlAction('services.stop', 'STOP', 'Stop a service',
  'Stops ONE named middleware service (service.control STOP). Services already stopped are skipped, not failed.');
const servicesRestartAction = serviceControlAction('services.restart', 'RESTART', 'Restart a service',
  'Restarts ONE named middleware service (service.control RESTART) — stop + start with config regeneration.');

export const registry = createRegistry<TruenasActionContext>([
  systemInfoAction,
  poolsReadAction,
  interfacesReadAction,
  systemRebootAction,
  systemTimezoneReadAction,
  systemTimezoneSetAction,
  systemShutdownAction,
  systemFirmwareUpdateAction,
  configBackupDownloadAction,
  configRestoreAction,
  configResetAction,
  updateProfileReadAction,
  updateProfileSetAction,
  firmwareUpdateFileAction,
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
  vmsDeviceEditAction,
  storageScrubAction,
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
  imagesDeleteAction,
  imagesUpdateAction,
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
